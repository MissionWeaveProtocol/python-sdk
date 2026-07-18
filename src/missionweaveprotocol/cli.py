"""Console entry points for the MissionWeaveProtocol reference implementation."""

from __future__ import annotations

import json
import re
import ssl
from collections.abc import AsyncIterator, Callable, Sequence
from contextlib import asynccontextmanager
from importlib import import_module
from pathlib import Path
from typing import Annotated, Any, Protocol, cast

import typer
import uvicorn
from fastapi import FastAPI
from pydantic import JsonValue, ValidationError

from .auth import AgentKeyRegistry, SessionAuthority, default_agent_key_id
from .canonical import canonical_hash, canonical_json
from .conformance import ConformanceReport, run_manifest
from .core import Core
from .crypto import encode_public_key, generate_keypair, load_private_key, verify_canonical
from .gateway import CoreGatewayAdapter, GroupGateway
from .models import (
    AgentCard,
    Command,
    CommandKind,
    Principal,
    Query,
    QueryKind,
    RegisterAgentCardPayload,
    SignatureEnvelope,
)
from .store import SQLStore


class POCReport(Protocol):
    @property
    def passed(self) -> bool: ...

    def to_dict(self) -> dict[str, Any]: ...


POCRunner = Callable[[Path | None], POCReport]

_ABSOLUTE_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


def tls13_context_factory(
    _config: object,
    default_factory: Callable[[], ssl.SSLContext],
) -> ssl.SSLContext:
    """Create Uvicorn's configured server context restricted to TLS 1.3."""

    context = default_factory()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    return context


server_app = typer.Typer(add_completion=False, no_args_is_help=False)
demo_app = typer.Typer(add_completion=False, no_args_is_help=False)
conformance_app = typer.Typer(add_completion=False, no_args_is_help=False)


def load_agent_cards(
    path: Path,
    *,
    organization_public_key: str | None = None,
) -> tuple[AgentCard, ...]:
    """Load the organization-controlled Agent Registry document."""

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read Agent Registry {path}: {error}") from error
    values: object = document.get("agentCards") if isinstance(document, dict) else document
    if not isinstance(values, list):
        raise ValueError("Agent Registry must be an array or an object with agentCards")
    try:
        cards = tuple(AgentCard.model_validate(item) for item in values)
    except ValidationError as error:
        raise ValueError(f"Agent Registry contains an invalid Agent Card: {error}") from error
    identifiers = [card.agent_id for card in cards]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Agent Registry contains duplicate Agent IDs")
    if not cards:
        raise ValueError("Agent Registry must contain at least one Agent Card")
    if organization_public_key is not None:
        for card in cards:
            if not verify_canonical(
                card.model_dump(mode="python", by_alias=True, exclude={"signature"}),
                card.signature,
                organization_public_key,
            ):
                raise ValueError(
                    f"Agent Registry Card {card.agent_id} lacks a valid Organization signature"
                )
        _validate_production_capabilities(cards)
    return cards


def _validate_production_capabilities(cards: Sequence[AgentCard]) -> None:
    for card in cards:
        for capability in card.capabilities:
            if (
                capability.input_schema is None
                or not _ABSOLUTE_URI.fullmatch(capability.input_schema)
                or capability.output_schema is None
                or not _ABSOLUTE_URI.fullmatch(capability.output_schema)
            ):
                raise ValueError(
                    f"Agent Registry capability {capability.id} requires input and output "
                    "schema URIs"
                )
            input_hash = capability.constraints.get("inputSchemaHash")
            output_hash = capability.constraints.get("outputSchemaHash")
            if not isinstance(input_hash, str) or not _SHA256.fullmatch(input_hash):
                raise ValueError(f"Agent Registry capability {capability.id} lacks inputSchemaHash")
            if not isinstance(output_hash, str) or not _SHA256.fullmatch(output_hash):
                raise ValueError(
                    f"Agent Registry capability {capability.id} lacks outputSchemaHash"
                )
            if not capability.verified_evidence:
                raise ValueError(
                    f"Agent Registry capability {capability.id} lacks verified evidence"
                )


async def _bootstrap_agent_cards(core: Core, cards: Sequence[AgentCard]) -> None:
    for card in cards:
        current = await core.query(Query(kind=QueryKind.AGENT_CARD, entity_id=card.agent_id))
        if current == card:
            continue
        if current is not None:
            if not isinstance(current, AgentCard):
                raise RuntimeError("Core returned a non-Agent-Card registry value")
            if current.version >= card.version:
                raise RuntimeError(
                    f"Agent Registry Card for {card.agent_id} does not advance durable version "
                    f"{current.version}"
                )
        payload = RegisterAgentCardPayload(card=card).model_dump(mode="json", by_alias=True)
        await core.perform(
            Command(
                action_id=f"registry-bootstrap:{canonical_hash(card)}",
                kind=CommandKind.REGISTER_AGENT_CARD,
                actor=Principal.system("organization-registry"),
                issued_at=card.issued_at,
                payload=cast(dict[str, JsonValue], payload),
                signature=SignatureEnvelope(
                    key_id="organization-registry:command-key",
                    created_at=card.issued_at,
                    value=card.signature,
                ),
            )
        )


def create_gateway_app(
    *,
    database_url: str,
    agent_cards: Sequence[AgentCard],
    session_secret: bytes | None = None,
    authority_key_id: str = "urn:missionweaveprotocol:key:group-gateway",
    authority_private_key: str | None = None,
) -> FastAPI:
    """Compose the runnable gateway from typed adapters and one trusted Registry snapshot."""

    store = SQLStore(database_url)
    resolved_authority_private_key = authority_private_key or generate_keypair()[0]
    authority_public_key = encode_public_key(
        load_private_key(resolved_authority_private_key).public_key()
    )
    core = Core(
        store,
        snapshot_authority_key_id=authority_key_id,
        snapshot_authority_public_key=authority_public_key,
    )
    keys = AgentKeyRegistry()
    for card in agent_cards:
        keys.register(
            card.agent_id,
            card.public_key,
            key_id=default_agent_key_id(card.agent_id),
            valid_from=card.issued_at,
        )
    adapter = CoreGatewayAdapter(
        core,
        keys,
        authority_key_id=authority_key_id,
        authority_private_key=resolved_authority_private_key,
    )
    sessions = SessionAuthority(keys, secret=session_secret)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await store.initialize()
        try:
            await _bootstrap_agent_cards(core, agent_cards)
            yield
        finally:
            await store.close()

    app = FastAPI(title="MissionWeaveProtocol Group Gateway", version="0.1.0", lifespan=lifespan)
    GroupGateway(adapter, sessions, app=app)
    return app


def _secret_bytes(value: str | None) -> bytes | None:
    if value is None:
        return None
    secret = value.encode("utf-8")
    if len(secret) < 32:
        raise typer.BadParameter("session secret must contain at least 32 UTF-8 bytes")
    return secret


@server_app.callback(invoke_without_command=True)
def _server_command(
    registry: Annotated[
        Path,
        typer.Option(
            "--registry",
            envvar="MISSIONWEAVEPROTOCOL_AGENT_REGISTRY",
            exists=True,
            dir_okay=False,
            readable=True,
            help="Organization-controlled JSON Agent Registry.",
        ),
    ],
    database_url: Annotated[
        str,
        typer.Option("--database-url", envvar="MISSIONWEAVEPROTOCOL_DATABASE_URL"),
    ] = "sqlite+aiosqlite:///./missionweaveprotocol.db",
    host: Annotated[str, typer.Option("--host", envvar="MISSIONWEAVEPROTOCOL_HOST")] = "127.0.0.1",
    port: Annotated[
        int, typer.Option("--port", envvar="MISSIONWEAVEPROTOCOL_PORT", min=1, max=65535)
    ] = 8765,
    session_secret: Annotated[
        str | None,
        typer.Option("--session-secret", envvar="MISSIONWEAVEPROTOCOL_SESSION_SECRET", hidden=True),
    ] = None,
    authority_key_id: Annotated[
        str,
        typer.Option("--authority-key-id", envvar="MISSIONWEAVEPROTOCOL_AUTHORITY_KEY_ID"),
    ] = "urn:missionweaveprotocol:key:group-gateway",
    authority_private_key: Annotated[
        str | None,
        typer.Option(
            "--authority-private-key",
            envvar="MISSIONWEAVEPROTOCOL_AUTHORITY_PRIVATE_KEY",
            hidden=True,
        ),
    ] = None,
    organization_public_key: Annotated[
        str | None,
        typer.Option(
            "--organization-public-key",
            envvar="MISSIONWEAVEPROTOCOL_ORGANIZATION_PUBLIC_KEY",
            help="Ed25519 trust-root key used to verify every Agent Card.",
        ),
    ] = None,
    tls_certfile: Annotated[
        Path | None,
        typer.Option("--tls-certfile", envvar="MISSIONWEAVEPROTOCOL_TLS_CERTFILE", dir_okay=False),
    ] = None,
    tls_keyfile: Annotated[
        Path | None,
        typer.Option("--tls-keyfile", envvar="MISSIONWEAVEPROTOCOL_TLS_KEYFILE", dir_okay=False),
    ] = None,
    allow_insecure: Annotated[
        bool,
        typer.Option(
            "--allow-insecure",
            help=(
                "Permit ws:// for local development; MissionWeaveProtocol deployments require TLS."
            ),
        ),
    ] = False,
) -> None:
    if (tls_certfile is None) != (tls_keyfile is None):
        raise typer.BadParameter("TLS certificate and key must be supplied together")
    if tls_certfile is None and not allow_insecure:
        raise typer.BadParameter(
            "MissionWeaveProtocol requires TLS; supply --tls-certfile and --tls-keyfile or "
            "explicitly use "
            "--allow-insecure for local development"
        )
    if authority_private_key is None and not allow_insecure:
        raise typer.BadParameter(
            "production gateways require --authority-private-key to sign durable Events"
        )
    if organization_public_key is None and not allow_insecure:
        raise typer.BadParameter(
            "production gateways require --organization-public-key to verify Agent Cards"
        )
    try:
        cards = load_agent_cards(
            registry,
            organization_public_key=organization_public_key,
        )
    except ValueError as error:
        raise typer.BadParameter(str(error), param_hint="--registry") from error
    app = create_gateway_app(
        database_url=database_url,
        agent_cards=cards,
        session_secret=_secret_bytes(session_secret),
        authority_key_id=authority_key_id,
        authority_private_key=authority_private_key,
    )
    if tls_certfile is None:
        uvicorn.run(app, host=host, port=port)
    else:
        assert tls_keyfile is not None
        uvicorn.run(
            app,
            host=host,
            port=port,
            ssl_certfile=str(tls_certfile),
            ssl_keyfile=str(tls_keyfile),
            ssl_context_factory=tls13_context_factory,
        )


def _resolve_poc_runner() -> POCRunner:
    try:
        module = import_module("missionweaveprotocol.poc")
    except ModuleNotFoundError as error:
        if error.name != "missionweaveprotocol.poc":
            raise
        raise RuntimeError("the MissionWeaveProtocol POC runner is not installed") from error
    candidate = getattr(module, "run_poc_sync", None)
    if not callable(candidate):
        raise RuntimeError("missionweaveprotocol.poc does not expose run_poc_sync")
    return cast(POCRunner, candidate)


@demo_app.callback(invoke_without_command=True)
def _demo_command(
    workdir: Annotated[
        Path | None,
        typer.Option("--workdir", file_okay=False, help="Directory for POC artifacts."),
    ] = None,
) -> None:
    try:
        report = _resolve_poc_runner()(workdir)
    except (AssertionError, RuntimeError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=1) from error
    typer.echo(canonical_json(report.to_dict()))
    if not report.passed:
        raise typer.Exit(code=1)


def _print_conformance(report: ConformanceReport) -> None:
    typer.echo(report.summary())
    for result in report.results:
        if result.passed:
            continue
        expected = "valid" if result.expected_valid else "invalid"
        actual = "valid" if result.actual_valid else "invalid"
        detail = f": {result.error}" if result.error else ""
        typer.echo(f"FAIL {result.name}: expected {expected}, got {actual}{detail}", err=True)


@conformance_app.callback(invoke_without_command=True)
def _conformance_command(
    root: Annotated[
        Path,
        typer.Option(
            "--root", exists=True, file_okay=False, help="MissionWeaveProtocol repository root."
        ),
    ] = Path("."),
    manifest: Annotated[
        Path | None,
        typer.Option("--manifest", exists=True, dir_okay=False),
    ] = None,
) -> None:
    try:
        report = run_manifest(root.resolve(), manifest.resolve() if manifest else None)
    except (OSError, ValueError) as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=1) from error
    _print_conformance(report)
    if not report.passed:
        raise typer.Exit(code=1)


def server() -> None:
    """Run the authenticated WebSocket Group gateway."""

    server_app(prog_name="missionweaveprotocol-server")


def demo() -> None:
    """Run the executable MissionWeaveProtocol proof of concept."""

    demo_app(prog_name="missionweaveprotocol-demo")


def conformance() -> None:
    """Run the implementation-neutral conformance vectors."""

    conformance_app(prog_name="missionweaveprotocol-conformance")
