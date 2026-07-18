"""Verification for pinned MissionWeaveProtocol release artifacts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import NoReturn, cast

from .canonical import canonical_hash

_EXPECTED_CRYPTOGRAPHY_PIN: dict[str, object] = {
    "path": "cryptography/manifest.json",
    "sourceCommit": "235aee85ba88934641822e1639e08efd2c9e29b6",
    "profileId": "missionweaveprotocol.signed-document-verification.v0.1",
    "manifestVersion": 1,
    "artifactDigest": "sha256:487e18c1ea7053432953f28d1496ae4fdb8e9d42c2eeb8e94f9b21f8cc2596a2",
    "artifactCount": 94,
    "caseCount": 22,
    "evaluationCount": 58,
}
_SHA256_IDENTIFIER = re.compile(r"^sha256:[0-9a-f]{64}$")
_ALLOWED_ARTIFACT_ROOTS = frozenset({"cryptography", "schemas"})


class BundleVerificationError(ValueError):
    """A pinned protocol bundle is malformed, unsafe, incomplete, or changed."""


@dataclass(frozen=True, slots=True)
class CryptographyBundleSummary:
    """Verified identity and counts for one cryptography bundle."""

    source_commit: str
    profile_id: str
    manifest_version: int
    artifact_digest: str
    artifact_count: int
    case_count: int
    evaluation_count: int


def default_bundle_root() -> Path:
    """Locate the bundle in an installed wheel or source checkout."""

    packaged = Path(__file__).resolve().parent
    if (packaged / "PROTOCOL_PIN.json").is_file() and (
        packaged / "cryptography" / "manifest.json"
    ).is_file():
        return packaged
    checkout = Path(__file__).resolve().parents[2]
    if (checkout / "PROTOCOL_PIN.json").is_file() and (
        checkout / "cryptography" / "manifest.json"
    ).is_file():
        return checkout
    raise FileNotFoundError("MissionWeaveProtocol cryptography bundle is not installed")


def verify_cryptography_bundle(root: Path | None = None) -> CryptographyBundleSummary:
    """Verify the pinned cryptography manifest and every digest-protected artifact."""

    bundle_root = (root or default_bundle_root()).resolve()
    pin = _strict_json_object(
        _safe_file(bundle_root, "PROTOCOL_PIN.json", artifact=False).read_bytes(),
        "PROTOCOL_PIN.json",
    )
    pin_entry = _object_member(pin, "cryptography", "PROTOCOL_PIN.json")
    if not _exact_json_object_match(pin_entry, _EXPECTED_CRYPTOGRAPHY_PIN):
        raise BundleVerificationError("PROTOCOL_PIN.json has an unexpected cryptography pin")

    manifest_path = cast(str, pin_entry["path"])
    manifest = _strict_json_object(
        _safe_file(bundle_root, manifest_path, artifact=False).read_bytes(),
        manifest_path,
    )
    _require_equal(manifest, "profileId", pin_entry["profileId"], manifest_path)
    _require_equal(manifest, "manifestVersion", pin_entry["manifestVersion"], manifest_path)
    _require_equal(manifest, "artifactDigest", pin_entry["artifactDigest"], manifest_path)
    _require_equal(manifest, "protocolVersion", pin.get("protocolVersion"), manifest_path)

    artifacts = _array_member(manifest, "artifacts", manifest_path)
    cases = _array_member(manifest, "cases", manifest_path)
    evaluation_count = 0
    for index, value in enumerate(cases):
        case = _require_object(value, f"{manifest_path}.cases[{index}]")
        evaluation_count += len(
            _array_member(case, "evaluations", f"{manifest_path}.cases[{index}]")
        )

    _require_count("artifacts", len(artifacts), pin_entry["artifactCount"])
    _require_count("cases", len(cases), pin_entry["caseCount"])
    _require_count("evaluations", evaluation_count, pin_entry["evaluationCount"])

    seen_paths: set[str] = set()
    for index, value in enumerate(artifacts):
        label = f"{manifest_path}.artifacts[{index}]"
        artifact = _require_object(value, label)
        if set(artifact) != {"path", "byteLength", "sha256"}:
            raise BundleVerificationError(f"{label} must contain path, byteLength, and sha256")
        logical_path = artifact["path"]
        byte_length = artifact["byteLength"]
        expected_hash = artifact["sha256"]
        if not isinstance(logical_path, str):
            raise BundleVerificationError(f"{label}.path must be a string")
        if logical_path in seen_paths:
            raise BundleVerificationError(f"duplicate cryptography artifact path: {logical_path}")
        seen_paths.add(logical_path)
        if type(byte_length) is not int or byte_length < 0:
            raise BundleVerificationError(f"{label}.byteLength must be a non-negative integer")
        if not isinstance(expected_hash, str) or not _SHA256_IDENTIFIER.fullmatch(expected_hash):
            raise BundleVerificationError(f"{label}.sha256 is not a canonical SHA-256 identifier")

        artifact_path = _safe_file(bundle_root, logical_path, artifact=True)
        content = artifact_path.read_bytes()
        if len(content) != byte_length:
            raise BundleVerificationError(
                f"{logical_path} byte length mismatch: expected {byte_length}, got {len(content)}"
            )
        actual_hash = f"sha256:{hashlib.sha256(content).hexdigest()}"
        if actual_hash != expected_hash:
            raise BundleVerificationError(
                f"{logical_path} digest mismatch: expected {expected_hash}, got {actual_hash}"
            )

    unsigned_manifest = dict(manifest)
    removed_digest = unsigned_manifest.pop("artifactDigest", None)
    if removed_digest is None:
        raise BundleVerificationError(f"{manifest_path} is missing artifactDigest")
    actual_digest = canonical_hash(unsigned_manifest)
    if actual_digest != pin_entry["artifactDigest"]:
        raise BundleVerificationError(
            f"cryptography artifact digest mismatch: expected {pin_entry['artifactDigest']}, "
            f"got {actual_digest}"
        )

    return CryptographyBundleSummary(
        source_commit=cast(str, pin_entry["sourceCommit"]),
        profile_id=cast(str, pin_entry["profileId"]),
        manifest_version=cast(int, pin_entry["manifestVersion"]),
        artifact_digest=pin_entry["artifactDigest"],
        artifact_count=len(artifacts),
        case_count=len(cases),
        evaluation_count=evaluation_count,
    )


def _strict_json_object(raw: bytes, label: str) -> dict[str, object]:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise BundleVerificationError(f"{label} must not contain a UTF-8 BOM")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BundleVerificationError(f"{label} is not valid UTF-8") from error

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise BundleVerificationError(f"{label} contains duplicate member {key!r}")
            result[key] = value
        return result

    def reject_constant(value: str) -> NoReturn:
        raise BundleVerificationError(f"{label} contains non-JSON number {value}")

    try:
        value = json.loads(
            text,
            object_pairs_hook=reject_duplicates,
            parse_constant=reject_constant,
        )
    except BundleVerificationError:
        raise
    except json.JSONDecodeError as error:
        raise BundleVerificationError(f"{label} is not exactly one JSON value: {error}") from error
    _require_well_formed_unicode(value, label)
    return _require_object(value, label)


def _require_well_formed_unicode(value: object, label: str) -> None:
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as error:
            raise BundleVerificationError(
                f"{label} contains an unpaired Unicode surrogate"
            ) from error
    elif isinstance(value, dict):
        for key, item in value.items():
            _require_well_formed_unicode(key, label)
            _require_well_formed_unicode(item, label)
    elif isinstance(value, list):
        for item in value:
            _require_well_formed_unicode(item, label)


def _safe_file(root: Path, logical_path: str, *, artifact: bool) -> Path:
    if not logical_path or "\\" in logical_path or "\0" in logical_path:
        raise BundleVerificationError(f"unsafe bundle path: {logical_path!r}")
    relative = PurePosixPath(logical_path)
    if (
        relative.is_absolute()
        or relative.as_posix() != logical_path
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise BundleVerificationError(f"unsafe bundle path: {logical_path!r}")
    if artifact:
        if relative.parts[0] not in _ALLOWED_ARTIFACT_ROOTS:
            raise BundleVerificationError(f"artifact path is outside allowed roots: {logical_path}")
        if logical_path == "cryptography/manifest.json":
            raise BundleVerificationError(
                "cryptography/manifest.json must not be a digest artifact"
            )
        if relative.name.casefold() == "readme.md":
            raise BundleVerificationError("README files must not be digest artifacts")

    candidate = root.joinpath(*relative.parts)
    cursor = root
    for part in relative.parts:
        cursor /= part
        if cursor.is_symlink():
            raise BundleVerificationError(
                f"bundle path must not traverse a symlink: {logical_path}"
            )
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as error:
        raise BundleVerificationError(f"bundle file is missing: {logical_path}") from error
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise BundleVerificationError(f"unsafe bundle file: {logical_path}")
    return resolved


def _require_object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise BundleVerificationError(f"{label} must be a JSON object")
    return cast(dict[str, object], value)


def _object_member(value: dict[str, object], name: str, label: str) -> dict[str, object]:
    return _require_object(value.get(name), f"{label}.{name}")


def _array_member(value: dict[str, object], name: str, label: str) -> list[object]:
    member = value.get(name)
    if not isinstance(member, list):
        raise BundleVerificationError(f"{label}.{name} must be an array")
    return cast(list[object], member)


def _require_equal(value: dict[str, object], name: str, expected: object, label: str) -> None:
    actual = value.get(name)
    if type(actual) is not type(expected) or actual != expected:
        raise BundleVerificationError(f"{label}.{name} does not match PROTOCOL_PIN.json")


def _require_count(name: str, actual: int, expected: object) -> None:
    if type(expected) is not int or actual != expected:
        raise BundleVerificationError(
            f"cryptography {name} count mismatch: expected {expected}, got {actual}"
        )


def _exact_json_object_match(actual: dict[str, object], expected: dict[str, object]) -> bool:
    return actual.keys() == expected.keys() and all(
        type(actual[name]) is type(expected_value) and actual[name] == expected_value
        for name, expected_value in expected.items()
    )
