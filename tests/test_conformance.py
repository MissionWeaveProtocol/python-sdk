from __future__ import annotations

import json
from pathlib import Path

from missionweaveprotocol.conformance import run_manifest


def test_repository_conformance_manifest() -> None:
    root = Path(__file__).resolve().parents[1]
    report = run_manifest(root)

    failures = [result for result in report.results if not result.passed]
    assert len(report.results) == 43
    assert not failures, failures


def test_manifest_runner_checks_expected_validity(tmp_path) -> None:
    schemas = tmp_path / "schemas"
    vectors = tmp_path / "conformance" / "vectors"
    schemas.mkdir()
    vectors.mkdir(parents=True)
    (schemas / "value.json").write_text(
        json.dumps(
            {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "https://missionweaveprotocol.dev/schema/test-value.json",
                "type": "object",
                "required": ["value"],
                "properties": {"value": {"type": "integer"}},
                "additionalProperties": False,
            }
        )
    )
    (vectors / "valid.json").write_text('{"value":1}')
    (vectors / "invalid.json").write_text('{"value":"wrong"}')
    (tmp_path / "conformance" / "manifest.json").write_text(
        json.dumps(
            [
                {
                    "name": "valid",
                    "schema": "schemas/value.json",
                    "instance": "conformance/vectors/valid.json",
                    "valid": True,
                },
                {
                    "name": "invalid",
                    "schema": "schemas/value.json",
                    "instance": "conformance/vectors/invalid.json",
                    "valid": False,
                },
            ]
        )
    )

    report = run_manifest(tmp_path)

    assert report.passed
    assert report.summary() == "2/2 conformance vectors passed"
