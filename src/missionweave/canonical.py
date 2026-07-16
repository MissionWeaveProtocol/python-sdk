"""Canonical JSON and content hashing helpers.

MissionWeave signs a deliberately conservative JSON subset.  Domain values are normalized before the
standard encoder is used: object keys are sorted, insignificant whitespace is removed, times are
UTC RFC 3339 values, sets are deterministically ordered, and non-finite numbers are rejected.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
from collections.abc import Mapping, Sequence, Set
from datetime import UTC, date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import UUID

import rfc8785
from pydantic import BaseModel


class CanonicalizationError(ValueError):
    """Raised when a value cannot be represented by MissionWeave canonical JSON."""


def _canonical_sort_key(value: Any) -> bytes:
    return rfc8785.dumps(_normalize(value))


def _normalize(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _normalize(value.model_dump(mode="python", by_alias=True))
    if isinstance(value, Enum):
        return _normalize(value.value)
    if isinstance(value, datetime):
        if value.tzinfo is None or value.utcoffset() is None:
            raise CanonicalizationError("canonical datetimes must include a timezone")
        utc = value.astimezone(UTC)
        rendered = utc.isoformat(timespec="microseconds").replace("+00:00", "Z")
        return rendered.replace(".000000Z", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, bytes):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise CanonicalizationError("canonical numbers must be finite")
        # Decimal is encoded as an exact string so no implementation-specific precision is lost.
        return format(value, "f")
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError("canonical numbers must be finite")
        if value == 0:
            return 0
        if value.is_integer() and abs(value) <= 9_007_199_254_740_991:
            return int(value)
        return value
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("canonical JSON object keys must be strings")
            normalized[key] = _normalize(item)
        return normalized
    if isinstance(value, Set):
        return [_normalize(item) for item in sorted(value, key=_canonical_sort_key)]
    if isinstance(value, Sequence):
        return [_normalize(item) for item in value]
    raise CanonicalizationError(f"unsupported canonical JSON value: {type(value).__name__}")


def canonical_json(value: Any) -> str:
    """Return RFC 8785 JCS text used by hashes and signatures."""

    try:
        return rfc8785.dumps(_normalize(value)).decode("utf-8")
    except (rfc8785.CanonicalizationError, TypeError, ValueError) as exc:
        if isinstance(exc, CanonicalizationError):
            raise
        raise CanonicalizationError(str(exc)) from exc


def canonical_bytes(value: Any) -> bytes:
    """Return canonical JSON encoded as UTF-8 bytes."""

    return canonical_json(value).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    """Return a lowercase SHA-256 digest without a scheme prefix."""

    return hashlib.sha256(value).hexdigest()


def canonical_hash(value: Any) -> str:
    """Return the MissionWeave content identifier for a canonicalizable value."""

    return f"sha256:{sha256_hex(canonical_bytes(value))}"


def verify_canonical_hash(value: Any, expected: str) -> bool:
    """Compare a value with an expected hash without timing-dependent string comparison."""

    return hmac.compare_digest(canonical_hash(value), expected)
