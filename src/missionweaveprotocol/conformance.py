"""Implementation-neutral JSON Schema conformance-vector runner."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import FormatChecker, ValidationError
from jsonschema.validators import validator_for
from referencing import Registry, Resource


@dataclass(frozen=True, slots=True)
class VectorResult:
    name: str
    expected_valid: bool
    actual_valid: bool
    error: str | None = None

    @property
    def passed(self) -> bool:
        return self.expected_valid == self.actual_valid


@dataclass(frozen=True, slots=True)
class ConformanceReport:
    results: tuple[VectorResult, ...]

    @property
    def passed(self) -> bool:
        return all(result.passed for result in self.results)

    def summary(self) -> str:
        passed = sum(result.passed for result in self.results)
        return f"{passed}/{len(self.results)} conformance vectors passed"


def _load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def _schema_registry(schema_root: Path) -> Registry:
    resources: list[tuple[str, Resource[Any]]] = []
    for path in sorted(schema_root.rglob("*.json")):
        schema = _load_json(path)
        if not isinstance(schema, dict):
            continue
        identifier = schema.get("$id")
        if isinstance(identifier, str):
            resources.append((identifier, Resource.from_contents(schema)))
    return Registry().with_resources(resources)


def default_schema_root() -> Path:
    """Locate schemas in an installed wheel or a source checkout."""

    packaged = Path(__file__).with_name("schemas")
    if packaged.is_dir():
        return packaged
    checkout = Path(__file__).resolve().parents[2] / "schemas"
    if checkout.is_dir():
        return checkout
    raise FileNotFoundError("MissionWeaveProtocol normative schemas are not installed")


class SchemaCatalog:
    """Validate named documents against one resolved normative schema set."""

    def __init__(self, schema_root: Path | None = None) -> None:
        self._root = (schema_root or default_schema_root()).resolve()
        self._registry = _schema_registry(self._root)

    def validate(self, schema_name: str, instance: Any) -> None:
        schema = _load_json(self._root / schema_name)
        validator_type = validator_for(schema)
        validator_type.check_schema(schema)
        validator_type(
            schema,
            registry=self._registry,
            format_checker=FormatChecker(),
        ).validate(instance)


def run_manifest(root: Path, manifest_path: Path | None = None) -> ConformanceReport:
    """Run all valid and invalid vectors declared by a repository manifest."""

    manifest_file = manifest_path or root / "conformance" / "manifest.json"
    manifest = _load_json(manifest_file)
    if not isinstance(manifest, list):
        raise ValueError("conformance manifest must be a JSON array")
    catalog = SchemaCatalog(root / "schemas")
    results: list[VectorResult] = []
    for item in manifest:
        if not isinstance(item, dict):
            raise ValueError("conformance manifest entries must be objects")
        name = str(item["name"])
        instance = _load_json(root / str(item["instance"]))
        expected_valid = bool(item["valid"])
        try:
            catalog.validate(str(item["schema"]).removeprefix("schemas/"), instance)
            actual_valid = True
            error = None
        except ValidationError as validation_error:
            actual_valid = False
            error = validation_error.message
        results.append(
            VectorResult(
                name=name,
                expected_valid=expected_valid,
                actual_valid=actual_valid,
                error=error,
            )
        )
    return ConformanceReport(results=tuple(results))
