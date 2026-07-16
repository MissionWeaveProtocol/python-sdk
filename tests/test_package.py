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


def test_package_configuration_includes_typed_marker_and_complete_schema_directory() -> None:
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    force_include = configuration["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]

    assert force_include["src/missionweave/py.typed"] == "missionweave/py.typed"
    assert force_include["schemas"] == "missionweave/schemas"
    assert (ROOT / "src" / "missionweave" / "py.typed").is_file()


def test_all_21_packaged_normative_schemas_are_present_and_valid() -> None:
    schema_paths = set((ROOT / "schemas").glob("*.json"))

    assert {path.name for path in schema_paths} == EXPECTED_SCHEMAS
    assert len(schema_paths) == 21
    for path in schema_paths:
        schema = json.loads(path.read_text(encoding="utf-8"))
        validator_for(schema).check_schema(schema)
