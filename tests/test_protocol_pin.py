from __future__ import annotations

import hashlib
import json
from pathlib import Path

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
    assert pin["commit"] == "6f10987627d62fb296e3490ceceb5539b1e94b70"
    assert pin["protocolVersion"] == "0.1"
    assert pin["wireNamespace"] == "missionweaveprotocol"

    for name in ("schemas", "conformance"):
        artifact = pin["artifacts"][name]
        paths = _json_files(ROOT / artifact["path"])
        assert len(paths) == artifact["files"]
        assert _tree_digest(paths) == artifact["sha256"]
        all_paths.extend(paths)

    assert _tree_digest(sorted(all_paths)) == pin["bundleSha256"]
