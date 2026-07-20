from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from missionweaveprotocol import (
    BundleVerificationError,
    CryptographyBundleSummary,
    verify_cryptography_bundle,
)

ROOT = Path(__file__).resolve().parents[1]


def _json_files(root: Path) -> list[Path]:
    return sorted(path for path in root.rglob("*.json") if path.is_file())


def _tree_digest(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def test_vendored_protocol_artifacts_match_pin() -> None:
    pin = json.loads((ROOT / "PROTOCOL_PIN.json").read_text(encoding="utf-8"))
    all_paths: list[Path] = []

    assert pin["repository"] == ("https://github.com/missionweaveprotocol/missionweaveprotocol")
    assert pin["commit"] == "33e47ad8a7318f942de77fb72dbb054d85881b40"
    assert pin["protocolVersion"] == "0.1"
    assert pin["wireNamespace"] == "missionweaveprotocol"

    for name in ("schemas", "conformance"):
        artifact = pin["artifacts"][name]
        paths = _json_files(ROOT / artifact["path"])
        assert len(paths) == artifact["files"]
        assert _tree_digest(paths) == artifact["sha256"]
        all_paths.extend(paths)

    assert _tree_digest(sorted(all_paths)) == pin["bundleSha256"]


def test_vendored_cryptography_bundle_matches_independent_pin() -> None:
    assert verify_cryptography_bundle(ROOT) == CryptographyBundleSummary(
        source_commit="235aee85ba88934641822e1639e08efd2c9e29b6",
        profile_id="missionweaveprotocol.signed-document-verification.v0.1",
        manifest_version=1,
        artifact_digest=("sha256:159a4900987723537d0d110ec6724c5e1ee52854951a9c69278386d751baae08"),
        artifact_count=94,
        case_count=22,
        evaluation_count=58,
    )


def test_cryptography_bundle_rejects_duplicate_manifest_member(tmp_path: Path) -> None:
    bundle = _copy_cryptography_bundle(tmp_path)
    manifest_path = bundle / "cryptography" / "manifest.json"
    manifest = manifest_path.read_text(encoding="utf-8")
    member = '"profileId": "missionweaveprotocol.signed-document-verification.v0.1",'
    manifest_path.write_text(manifest.replace(member, f"{member}\n  {member}", 1), encoding="utf-8")

    with pytest.raises(BundleVerificationError, match="duplicate member 'profileId'"):
        verify_cryptography_bundle(bundle)


def test_cryptography_bundle_rejects_tampered_artifact(tmp_path: Path) -> None:
    bundle = _copy_cryptography_bundle(tmp_path)
    artifact_path = (
        bundle / "cryptography" / "vectors" / "canonicalization" / "agent-card.signing.jcs"
    )
    content = artifact_path.read_bytes()
    artifact_path.write_bytes(b"[" + content[1:])

    with pytest.raises(BundleVerificationError, match="digest mismatch"):
        verify_cryptography_bundle(bundle)


def test_cryptography_bundle_rejects_semantic_manifest_mutation(tmp_path: Path) -> None:
    bundle = _copy_cryptography_bundle(tmp_path)
    manifest_path = bundle / "cryptography" / "manifest.json"
    manifest = manifest_path.read_text(encoding="utf-8")
    manifest_path.write_text(
        manifest.replace('"canonicalization"', '"canonicalization-mutated"', 1),
        encoding="utf-8",
    )

    with pytest.raises(BundleVerificationError, match="artifact digest mismatch"):
        verify_cryptography_bundle(bundle)


@pytest.mark.parametrize(
    ("replacement", "message"),
    [
        ("../registry-key-alias.json", "unsafe bundle path"),
        ("cryptography/README.md", "README files must not be digest artifacts"),
        (
            "cryptography/manifest.json",
            "cryptography/manifest.json must not be a digest artifact",
        ),
        ("cryptography//keys/registry-key-alias.json", "unsafe bundle path"),
    ],
)
def test_cryptography_bundle_rejects_unsafe_artifact_paths(
    tmp_path: Path, replacement: str, message: str
) -> None:
    bundle = _copy_cryptography_bundle(tmp_path)
    manifest_path = bundle / "cryptography" / "manifest.json"
    manifest = manifest_path.read_text(encoding="utf-8")
    manifest_path.write_text(
        manifest.replace("cryptography/keys/registry-key-alias.json", replacement, 1),
        encoding="utf-8",
    )

    with pytest.raises(BundleVerificationError, match=message):
        verify_cryptography_bundle(bundle)


def test_cryptography_bundle_rejects_pin_mismatch(tmp_path: Path) -> None:
    bundle = _copy_cryptography_bundle(tmp_path)
    pin_path = bundle / "PROTOCOL_PIN.json"
    pin = pin_path.read_text(encoding="utf-8")
    pin_path.write_text(pin.replace('"caseCount": 22', '"caseCount": 23', 1), encoding="utf-8")

    with pytest.raises(BundleVerificationError, match="unexpected cryptography pin"):
        verify_cryptography_bundle(bundle)


def _copy_cryptography_bundle(destination: Path) -> Path:
    shutil.copy2(ROOT / "PROTOCOL_PIN.json", destination / "PROTOCOL_PIN.json")
    shutil.copytree(ROOT / "cryptography", destination / "cryptography")
    shutil.copytree(ROOT / "schemas", destination / "schemas")
    return destination
