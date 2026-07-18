"""Sign and verify a Command through the public SignedDocumentCodec adapters.

The bundled key and Registry files are deterministic test-only fixtures. Production callers must
connect SigningKey and KeyResolver to organization-controlled key infrastructure.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from missionweaveprotocol import (
    KeyRegistryCompleteness,
    KeyRegistrySnapshot,
    KeyResolutionRequest,
    SignedDocumentCodec,
    SignedDocumentKind,
)

ROOT = Path(__file__).resolve().parents[1]


class FixtureSigningKey:
    algorithm = "Ed25519"

    def __init__(self, fixture: dict[str, object]) -> None:
        self.key_id = str(fixture["keyId"])
        seed = base64.urlsafe_b64decode(str(fixture["seed"]) + "==")
        self._private_key = Ed25519PrivateKey.from_private_bytes(seed)
        self.public_key_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)


class FixtureKeyResolver:
    def __init__(self, registry_bytes: bytes) -> None:
        self._registry_bytes = registry_bytes

    def resolve(self, request: KeyResolutionRequest) -> KeyRegistrySnapshot:
        print(f"resolving {request.key_id} for {request.kind.value}")
        return KeyRegistrySnapshot(
            completeness=KeyRegistryCompleteness.ORGANIZATION_WIDE,
            registry_bytes=self._registry_bytes,
        )


def read_json(path: str) -> dict[str, object]:
    value = json.loads((ROOT / path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"{path} is not a JSON object")
    return value


def main() -> None:
    unsigned = read_json("cryptography/vectors/signed-documents/valid/command.json")
    unsigned.pop("signature")
    signing_key = FixtureSigningKey(read_json("cryptography/keys/signing-coordinator.json"))
    resolver = FixtureKeyResolver((ROOT / "cryptography/keys/registry-valid.json").read_bytes())
    codec = SignedDocumentCodec()

    signed = codec.sign(SignedDocumentKind.COMMAND, unsigned, signing_key)
    verified = codec.verify(
        SignedDocumentKind.COMMAND,
        signed.canonical_document_bytes,
        resolver,
    )
    print(verified.signing_hash)
    print(verified.document_hash)
    print(verified.resolved_key.principal.id)


if __name__ == "__main__":
    main()
