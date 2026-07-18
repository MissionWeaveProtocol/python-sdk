from __future__ import annotations

import json
import tomllib
from pathlib import Path

from jsonschema.validators import validator_for

ROOT = Path(__file__).resolve().parents[1]

EXPECTED_SCHEMAS = {
    "agent-card.schema.json",
    "approval.schema.json",
    "artifact.schema.json",
    "command.schema.json",
    "common.schema.json",
    "context-package.schema.json",
    "conversation.schema.json",
    "error.schema.json",
    "event.schema.json",
    "evidence.schema.json",
    "extension-profile.schema.json",
    "group-snapshot.schema.json",
    "group.schema.json",
    "lease.schema.json",
    "membership.schema.json",
    "message.schema.json",
    "mission.schema.json",
    "presence-record.schema.json",
    "websocket-frame.schema.json",
    "work-contract.schema.json",
    "work-item.schema.json",
}


def test_distribution_and_import_identity_are_exclusively_missionweaveprotocol() -> None:
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = configuration["project"]

    assert project["name"] == "missionweaveprotocol"
    assert project["scripts"] == {
        "missionweaveprotocol-conformance": "missionweaveprotocol.cli:conformance",
        "missionweaveprotocol-demo": "missionweaveprotocol.cli:demo",
        "missionweaveprotocol-server": "missionweaveprotocol.cli:server",
    }
    retired_import = "".join(("mission", "weave"))
    assert not (ROOT / "src" / retired_import).exists()


def test_package_configuration_includes_typed_marker_and_complete_schema_directory() -> None:
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    force_include = configuration["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]

    assert force_include["src/missionweaveprotocol/py.typed"] == "missionweaveprotocol/py.typed"
    assert force_include["schemas"] == "missionweaveprotocol/schemas"
    assert force_include["cryptography"] == "missionweaveprotocol/cryptography"
    assert force_include["PROTOCOL_PIN.json"] == "missionweaveprotocol/PROTOCOL_PIN.json"
    assert (ROOT / "src" / "missionweaveprotocol" / "py.typed").is_file()


def test_packaged_cryptography_tree_includes_binary_and_canonical_json_artifacts() -> None:
    cryptography = ROOT / "cryptography"

    assert (cryptography / "manifest.json").is_file()
    assert (
        cryptography / "vectors" / "signed-documents" / "invalid" / "command-invalid-utf8.bin"
    ).is_file()
    assert (cryptography / "vectors" / "canonicalization" / "command.signing.jcs").is_file()


def test_all_21_packaged_normative_schemas_are_present_and_valid() -> None:
    schema_paths = set((ROOT / "schemas").glob("*.json"))

    assert {path.name for path in schema_paths} == EXPECTED_SCHEMAS
    assert len(schema_paths) == 21
    for path in schema_paths:
        schema = json.loads(path.read_text(encoding="utf-8"))
        validator_for(schema).check_schema(schema)
