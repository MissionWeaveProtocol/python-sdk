"""Ed25519 helpers for MissionWeave Commands, Events, and Artifact manifests."""

from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import canonical_bytes

type PrivateKeyLike = Ed25519PrivateKey | bytes | str
type PublicKeyLike = Ed25519PublicKey | bytes | str


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _decode(encoded: str) -> bytes:
    padding = "=" * (-len(encoded) % 4)
    try:
        return base64.urlsafe_b64decode(encoded + padding)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid base64url key or signature") from exc


def load_private_key(value: PrivateKeyLike) -> Ed25519PrivateKey:
    if isinstance(value, Ed25519PrivateKey):
        return value
    raw = _decode(value) if isinstance(value, str) else value
    if len(raw) != 32:
        raise ValueError("an Ed25519 private key must contain 32 raw bytes")
    return Ed25519PrivateKey.from_private_bytes(raw)


def load_public_key(value: PublicKeyLike) -> Ed25519PublicKey:
    if isinstance(value, Ed25519PublicKey):
        return value
    raw = _decode(value) if isinstance(value, str) else value
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key must contain 32 raw bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def encode_private_key(key: Ed25519PrivateKey) -> str:
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return _encode(raw)


def encode_public_key(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _encode(raw)


def generate_keypair() -> tuple[str, str]:
    """Generate a base64url ``(private_key, public_key)`` pair."""

    private_key = Ed25519PrivateKey.generate()
    return encode_private_key(private_key), encode_public_key(private_key.public_key())


def sign_bytes(value: bytes, private_key: PrivateKeyLike) -> str:
    return _encode(load_private_key(private_key).sign(value))


def verify_bytes(value: bytes, signature: str, public_key: PublicKeyLike) -> bool:
    try:
        load_public_key(public_key).verify(_decode(signature), value)
    except (InvalidSignature, ValueError):
        return False
    return True


def sign_canonical(value: Any, private_key: PrivateKeyLike) -> str:
    """Sign the canonical JSON representation of ``value``."""

    return sign_bytes(canonical_bytes(value), private_key)


def verify_canonical(value: Any, signature: str, public_key: PublicKeyLike) -> bool:
    """Verify an Ed25519 signature over canonical JSON."""

    return verify_bytes(canonical_bytes(value), signature, public_key)
