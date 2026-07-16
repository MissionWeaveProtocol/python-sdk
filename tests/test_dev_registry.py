from __future__ import annotations

import json
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from missionweave.cli import load_agent_cards

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("preexisting", [False, True])
def test_dev_private_keys_are_written_with_owner_only_permissions(
    tmp_path: Path,
    preexisting: bool,
) -> None:
    registry_path = tmp_path / "dev-registry.json"
    keys_path = tmp_path / "dev-keys.json"
    if preexisting:
        keys_path.write_text("permissive placeholder", encoding="utf-8")
        keys_path.chmod(0o644)

    subprocess.run(
        [
            sys.executable,
            str(ROOT / "examples" / "create_dev_registry.py"),
            "--output",
            str(registry_path),
            "--keys-output",
            str(keys_path),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert stat.S_IMODE(keys_path.stat().st_mode) == 0o600
    keys = json.loads(keys_path.read_text(encoding="utf-8"))
    assert "authorityPrivateKey" in keys
    assert keys["agentKeyId"] == "urn:missionweave:key:developer"
    cards = load_agent_cards(
        registry_path,
        organization_public_key=keys["organizationPublicKey"],
    )
    assert cards[0].capabilities[0].verified_evidence
