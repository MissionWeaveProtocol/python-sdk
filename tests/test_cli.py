from __future__ import annotations

import json
import ssl
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from fastapi import FastAPI
from typer.testing import CliRunner

import missionweave.cli as cli
from missionweave.auth import AgentIdentity
from missionweave.canonical import canonical_bytes
from missionweave.models import AgentCard, Capability

ROOT = Path(__file__).resolve().parents[1]
INPUT_HASH = f"sha256:{'a' * 64}"
OUTPUT_HASH = f"sha256:{'b' * 64}"


def _registry(tmp_path: Path) -> Path:
    identity = AgentIdentity.generate("urn:missionweave:agent:cli")
    card = AgentCard(
        agent_id=identity.agent_id,
        version=1,
        display_name="CLI Agent",
        owner="MissionWeave tests",
        public_key=identity.public_key,
        capabilities=(
            Capability(
                id="cli.test",
                version=1,
                input_schema="https://schemas.example.test/cli-input.json",
                output_schema="https://schemas.example.test/cli-output.json",
                constraints={
                    "inputSchemaHash": INPUT_HASH,
                    "outputSchemaHash": OUTPUT_HASH,
                },
                verified_evidence=("urn:missionweave:evidence:cli-test",),
            ),
        ),
        issued_at=datetime.now(UTC),
        signature="organization-signature",
    )
    path = tmp_path / "registry.json"
    path.write_text(
        json.dumps({"agentCards": [card.model_dump(mode="json", by_alias=True)]}),
        encoding="utf-8",
    )
    return path


def test_conformance_entrypoint_runs_repository_manifest() -> None:
    result = CliRunner().invoke(cli.conformance_app, ["--root", str(ROOT)])

    assert result.exit_code == 0, result.output
    assert "conformance vectors passed" in result.output


def test_server_entrypoint_composes_gateway_and_uvicorn(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    calls: list[tuple[FastAPI, dict[str, Any]]] = []

    def fake_run(app: FastAPI, **kwargs: Any) -> None:
        calls.append((app, kwargs))

    monkeypatch.setattr(cli.uvicorn, "run", fake_run)
    result = CliRunner().invoke(
        cli.server_app,
        [
            "--registry",
            str(_registry(tmp_path)),
            "--database-url",
            "sqlite+aiosqlite:///:memory:",
            "--host",
            "127.0.0.2",
            "--port",
            "9876",
            "--allow-insecure",
        ],
    )

    assert result.exit_code == 0, result.output
    assert len(calls) == 1
    app, options = calls[0]
    assert isinstance(app, FastAPI)
    assert options["host"] == "127.0.0.2"
    assert options["port"] == 9876
    assert "ssl_context_factory" not in options
    assert any(route.path == "/ws" for route in app.routes)


def test_tls13_context_factory_restricts_both_protocol_bounds() -> None:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    calls = 0

    def default_factory() -> ssl.SSLContext:
        nonlocal calls
        calls += 1
        return context

    result = cli.tls13_context_factory(object(), default_factory)

    assert result is context
    assert calls == 1
    assert result.minimum_version is ssl.TLSVersion.TLSv1_3
    assert result.maximum_version is ssl.TLSVersion.TLSv1_3


def test_server_passes_tls13_context_factory_to_uvicorn(
    tmp_path: Path,
    monkeypatch: Any,
) -> None:
    calls: list[dict[str, Any]] = []

    def fake_run(_app: FastAPI, **kwargs: Any) -> None:
        calls.append(kwargs)

    monkeypatch.setattr(cli.uvicorn, "run", fake_run)
    certfile = tmp_path / "server.crt"
    keyfile = tmp_path / "server.key"
    result = CliRunner().invoke(
        cli.server_app,
        [
            "--registry",
            str(_registry(tmp_path)),
            "--tls-certfile",
            str(certfile),
            "--tls-keyfile",
            str(keyfile),
            "--allow-insecure",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == [
        {
            "host": "127.0.0.1",
            "port": 8765,
            "ssl_certfile": str(certfile),
            "ssl_keyfile": str(keyfile),
            "ssl_context_factory": cli.tls13_context_factory,
        }
    ]


def test_server_requires_tls_unless_local_insecure_mode_is_explicit(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        cli.server_app,
        ["--registry", str(_registry(tmp_path))],
    )

    assert result.exit_code != 0
    assert "MissionWeave requires TLS" in result.output


def test_registry_trust_root_rejects_unsigned_or_tampered_agent_cards(tmp_path: Path) -> None:
    path = _registry(tmp_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    card = AgentCard.model_validate(document["agentCards"][0])
    organization = AgentIdentity.generate("urn:missionweave:organization:test")
    signed = card.model_copy(
        update={
            "signature": organization.sign(
                canonical_bytes(
                    card.model_dump(mode="python", by_alias=True, exclude={"signature"})
                )
            )
        }
    )
    path.write_text(
        json.dumps({"agentCards": [signed.model_dump(mode="json", by_alias=True)]}),
        encoding="utf-8",
    )

    assert cli.load_agent_cards(
        path,
        organization_public_key=organization.public_key,
    ) == (signed,)
    tampered = signed.model_copy(update={"display_name": "Tampered"})
    path.write_text(
        json.dumps({"agentCards": [tampered.model_dump(mode="json", by_alias=True)]}),
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="Organization signature"):
        cli.load_agent_cards(path, organization_public_key=organization.public_key)


@pytest.mark.parametrize(
    ("capability", "message"),
    [
        (Capability(id="cli.test", version=1), "schema URIs"),
        (
            Capability(
                id="cli.test",
                version=1,
                input_schema="https://schemas.example.test/input.json",
                output_schema="https://schemas.example.test/output.json",
                constraints={"outputSchemaHash": OUTPUT_HASH},
                verified_evidence=("urn:missionweave:evidence:cli-test",),
            ),
            "inputSchemaHash",
        ),
        (
            Capability(
                id="cli.test",
                version=1,
                input_schema="https://schemas.example.test/input.json",
                output_schema="https://schemas.example.test/output.json",
                constraints={"inputSchemaHash": INPUT_HASH},
                verified_evidence=("urn:missionweave:evidence:cli-test",),
            ),
            "outputSchemaHash",
        ),
        (
            Capability(
                id="cli.test",
                version=1,
                input_schema="https://schemas.example.test/input.json",
                output_schema="https://schemas.example.test/output.json",
                constraints={
                    "inputSchemaHash": INPUT_HASH,
                    "outputSchemaHash": OUTPUT_HASH,
                },
            ),
            "verified evidence",
        ),
    ],
)
def test_production_registry_requires_complete_capability_provenance(
    tmp_path: Path,
    capability: Capability,
    message: str,
) -> None:
    path = _registry(tmp_path)
    document = json.loads(path.read_text(encoding="utf-8"))
    card = AgentCard.model_validate(document["agentCards"][0])
    organization = AgentIdentity.generate("urn:missionweave:organization:test")
    unsigned = card.model_copy(update={"capabilities": (capability,), "signature": "pending"})
    signed = unsigned.model_copy(
        update={
            "signature": organization.sign(
                canonical_bytes(
                    unsigned.model_dump(mode="python", by_alias=True, exclude={"signature"})
                )
            )
        }
    )
    path.write_text(
        json.dumps({"agentCards": [signed.model_dump(mode="json", by_alias=True)]}),
        encoding="utf-8",
    )

    assert cli.load_agent_cards(path) == (signed,)
    with pytest.raises(ValueError, match=message):
        cli.load_agent_cards(path, organization_public_key=organization.public_key)


def test_demo_entrypoint_is_a_thin_poc_dispatcher(monkeypatch: Any) -> None:
    class Report:
        passed = True

        def to_dict(self) -> dict[str, Any]:
            return {"passed": self.passed, "scenario": "two-mission-poc"}

    monkeypatch.setattr(cli, "_resolve_poc_runner", lambda: lambda _workdir: Report())

    result = CliRunner().invoke(cli.demo_app)

    assert result.exit_code == 0, result.output
    assert json.loads(result.output) == {
        "passed": True,
        "scenario": "two-mission-poc",
    }
