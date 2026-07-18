"""Create disposable keys and an Organization-signed MissionWeaveProtocol Agent Registry."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path

from missionweaveprotocol.auth import default_agent_key_id
from missionweaveprotocol.crypto import generate_keypair, sign_canonical
from missionweaveprotocol.models import AgentCard, Capability

_OBJECT_SCHEMA_HASH = "sha256:" + hashlib.sha256(b'{"type":"object"}').hexdigest()


def _write_private_text(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as output:
            output.write(content)
    finally:
        os.close(descriptor)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output", type=Path, default=Path(".missionweaveprotocol/dev-registry.json")
    )
    parser.add_argument(
        "--keys-output", type=Path, default=Path(".missionweaveprotocol/dev-keys.json")
    )
    parser.add_argument(
        "--agent-registry-snapshot-output",
        type=Path,
        default=Path(".missionweaveprotocol/dev-agent-registry-snapshot.json"),
    )
    args = parser.parse_args()

    organization_private, organization_public = generate_keypair()
    agent_private, agent_public = generate_keypair()
    authority_private, authority_public = generate_keypair()
    agent_id = "urn:missionweaveprotocol:agent:developer"
    agent_key_id = default_agent_key_id(agent_id)
    issued_at = datetime.now(UTC)
    unsigned = AgentCard(
        agent_id=agent_id,
        version=1,
        display_name="Development Agent",
        owner="local-development",
        public_key=agent_public,
        capabilities=(
            Capability(
                id="software.python",
                version=1,
                input_schema="https://missionweaveprotocol.dev/schemas/capabilities/software-python-input.json",
                output_schema="https://missionweaveprotocol.dev/schemas/capabilities/software-python-output.json",
                constraints={
                    "inputSchemaHash": _OBJECT_SCHEMA_HASH,
                    "outputSchemaHash": _OBJECT_SCHEMA_HASH,
                },
                verified_evidence=("urn:missionweaveprotocol:evidence:developer-python",),
            ),
            Capability(
                id="software.review",
                version=1,
                input_schema="https://missionweaveprotocol.dev/schemas/capabilities/software-review-input.json",
                output_schema="https://missionweaveprotocol.dev/schemas/capabilities/software-review-output.json",
                constraints={
                    "inputSchemaHash": _OBJECT_SCHEMA_HASH,
                    "outputSchemaHash": _OBJECT_SCHEMA_HASH,
                },
                verified_evidence=("urn:missionweaveprotocol:evidence:developer-review",),
            ),
        ),
        issued_at=issued_at,
        signature="pending",
    )
    card = unsigned.model_copy(
        update={
            "signature": sign_canonical(
                unsigned.model_dump(mode="python", by_alias=True, exclude={"signature"}),
                organization_private,
            )
        }
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.keys_output.parent.mkdir(parents=True, exist_ok=True)
    args.agent_registry_snapshot_output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(
            {"agentCards": [card.model_dump(mode="json", by_alias=True)]},
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _write_private_text(
        args.keys_output,
        json.dumps(
            {
                "agentKeyId": agent_key_id,
                "agentPrivateKey": agent_private,
                "authorityPrivateKey": authority_private,
                "authorityPublicKey": authority_public,
                "organizationPrivateKey": organization_private,
                "organizationPublicKey": organization_public,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    valid_from = issued_at.isoformat().replace("+00:00", "Z")
    args.agent_registry_snapshot_output.write_text(
        json.dumps(
            {
                "organizationId": "urn:missionweaveprotocol:organization:local-development",
                "bindings": [
                    {
                        "keyId": agent_key_id,
                        "principal": {"type": "agent", "id": agent_id},
                        "algorithm": "Ed25519",
                        "publicKey": agent_public,
                        "validFrom": valid_from,
                        "validityHistory": [],
                    },
                    {
                        "keyId": "urn:missionweaveprotocol:key:group-gateway",
                        "principal": {
                            "type": "service",
                            "id": "urn:missionweaveprotocol:service:group-gateway",
                        },
                        "algorithm": "Ed25519",
                        "publicKey": authority_public,
                        "validFrom": valid_from,
                        "validityHistory": [],
                    },
                    {
                        "keyId": "urn:missionweaveprotocol:key:organization-registry",
                        "principal": {
                            "type": "service",
                            "id": "urn:missionweaveprotocol:service:organization-registry",
                        },
                        "algorithm": "Ed25519",
                        "publicKey": organization_public,
                        "validFrom": valid_from,
                        "validityHistory": [],
                    },
                ],
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    print(args.output)
    print(args.keys_output)
    print(args.agent_registry_snapshot_output)


if __name__ == "__main__":
    main()
