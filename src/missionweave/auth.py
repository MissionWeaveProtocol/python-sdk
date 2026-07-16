"""Organization-controlled Agent authentication and session fencing."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from missionweave.canonical import canonical_bytes


class AuthenticationError(ValueError):
    """Raised when identity proof or a session grant is invalid."""


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _canonical(value: object) -> bytes:
    return canonical_bytes(value)


@dataclass(frozen=True, slots=True)
class AgentIdentity:
    """Private signing identity used by one Agent runtime."""

    agent_id: str
    _private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls, agent_id: str) -> AgentIdentity:
        return cls(agent_id=agent_id, _private_key=Ed25519PrivateKey.generate())

    @property
    def public_key(self) -> str:
        raw = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return _b64encode(raw)

    def sign(self, payload: bytes) -> str:
        return _b64encode(self._private_key.sign(payload))


@dataclass(frozen=True, slots=True)
class Challenge:
    protocol_version: str
    challenge_id: str
    agent_id: str
    key_id: str
    client_nonce: str
    server_nonce: str
    expires_at: datetime

    @property
    def nonce(self) -> str:
        """Compatibility alias for the server-generated nonce."""

        return self.server_nonce

    def signing_bytes(self) -> bytes:
        return _canonical(
            {
                "agentId": self.agent_id,
                "challengeId": self.challenge_id,
                "clientNonce": self.client_nonce,
                "expiresAt": self.expires_at.isoformat(),
                "keyId": self.key_id,
                "protocolVersion": self.protocol_version,
                "serverNonce": self.server_nonce,
            }
        )


@dataclass(frozen=True, slots=True)
class SessionGrant:
    agent_id: str
    key_id: str
    protocol_version: str
    session_epoch: int
    issued_at: datetime
    expires_at: datetime
    token: str


@dataclass(frozen=True, slots=True)
class _RegisteredAgentKey:
    key_id: str
    public_key: Ed25519PublicKey
    valid_from: datetime
    valid_until: datetime | None
    revoked_at: datetime | None


def default_agent_key_id(agent_id: str) -> str:
    """Derive the compatibility key ID used by single-key Agent Cards."""

    normalized = agent_id.rstrip("/")
    name = normalized.rsplit("/", 1)[-1].rsplit(":", 1)[-1]
    if not name:
        raise AuthenticationError("Agent ID cannot be mapped to a default key ID")
    return f"urn:missionweave:key:{name}"


def _aware_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise AuthenticationError(f"{field} must include a timezone")
    return value.astimezone(UTC)


class AgentKeyRegistry:
    """Organization-owned lifecycle registry for Agent signing keys."""

    def __init__(self) -> None:
        self._keys: dict[tuple[str, str], _RegisteredAgentKey] = {}

    def register(
        self,
        agent_id: str,
        public_key: str,
        *,
        key_id: str | None = None,
        valid_from: datetime | None = None,
        valid_until: datetime | None = None,
        revoked_at: datetime | None = None,
    ) -> None:
        selected_key_id = key_id or default_agent_key_id(agent_id)
        starts_at = _aware_utc(
            valid_from or datetime.min.replace(tzinfo=UTC),
            field="key valid_from",
        )
        ends_at = (
            _aware_utc(valid_until, field="key valid_until") if valid_until is not None else None
        )
        revoked = _aware_utc(revoked_at, field="key revoked_at") if revoked_at is not None else None
        if ends_at is not None and ends_at <= starts_at:
            raise AuthenticationError("key valid_until must be later than valid_from")
        try:
            raw = _b64decode(public_key)
            parsed_key = Ed25519PublicKey.from_public_bytes(raw)
        except (ValueError, TypeError) as error:
            raise AuthenticationError("invalid Ed25519 Agent public key") from error
        self._keys[(agent_id, selected_key_id)] = _RegisteredAgentKey(
            key_id=selected_key_id,
            public_key=parsed_key,
            valid_from=starts_at,
            valid_until=ends_at,
            revoked_at=revoked,
        )

    def resolve(
        self,
        agent_id: str,
        key_id: str | None = None,
        *,
        at: datetime | None = None,
    ) -> Ed25519PublicKey:
        selected_key_id = key_id or self._select_legacy_key_id(agent_id)
        try:
            record = self._keys[(agent_id, selected_key_id)]
        except KeyError as error:
            raise AuthenticationError("unknown Agent key ID") from error
        effective_at = _aware_utc(at or datetime.now(UTC), field="key resolution time")
        if effective_at < record.valid_from:
            raise AuthenticationError("Agent key is not yet valid")
        if record.valid_until is not None and effective_at >= record.valid_until:
            raise AuthenticationError("Agent key expired")
        if record.revoked_at is not None and effective_at >= record.revoked_at:
            raise AuthenticationError("Agent key was revoked")
        return record.public_key

    def revoke(
        self,
        agent_id: str,
        key_id: str,
        *,
        revoked_at: datetime | None = None,
    ) -> None:
        try:
            record = self._keys[(agent_id, key_id)]
        except KeyError as error:
            raise AuthenticationError("unknown Agent key ID") from error
        effective_at = _aware_utc(
            revoked_at or datetime.now(UTC),
            field="key revocation time",
        )
        if record.revoked_at is not None:
            effective_at = min(effective_at, record.revoked_at)
        self._keys[(agent_id, key_id)] = _RegisteredAgentKey(
            key_id=record.key_id,
            public_key=record.public_key,
            valid_from=record.valid_from,
            valid_until=record.valid_until,
            revoked_at=effective_at,
        )

    def _select_legacy_key_id(self, agent_id: str) -> str:
        default_key_id = default_agent_key_id(agent_id)
        if (agent_id, default_key_id) in self._keys:
            return default_key_id
        candidates = [
            key_id for registered_agent, key_id in self._keys if registered_agent == agent_id
        ]
        if len(candidates) == 1:
            return candidates[0]
        if not candidates:
            raise AuthenticationError("unknown Agent identity")
        raise AuthenticationError("Agent key ID is required when multiple keys are registered")


class SessionAuthority:
    """Issues one-use challenges and short-lived fenced Agent sessions."""

    def __init__(
        self,
        registry: AgentKeyRegistry,
        *,
        secret: bytes | None = None,
        challenge_ttl: timedelta = timedelta(seconds=30),
        session_ttl: timedelta = timedelta(minutes=15),
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._registry = registry
        self._secret = secret or secrets.token_bytes(32)
        self._challenge_ttl = challenge_ttl
        self._session_ttl = session_ttl
        self._clock = clock or (lambda: datetime.now(UTC))
        self._challenges: dict[str, Challenge] = {}
        self._epochs: dict[str, int] = {}

    def issue_challenge(
        self,
        agent_id: str,
        *,
        key_id: str | None = None,
        client_nonce: str | None = None,
        protocol_version: str = "0.1",
    ) -> Challenge:
        now = _aware_utc(self._clock(), field="SessionAuthority clock")
        selected_key_id = key_id or default_agent_key_id(agent_id)
        self._registry.resolve(agent_id, selected_key_id, at=now)
        challenge = Challenge(
            protocol_version=protocol_version,
            challenge_id=secrets.token_urlsafe(18),
            agent_id=agent_id,
            key_id=selected_key_id,
            client_nonce=(client_nonce if client_nonce is not None else secrets.token_urlsafe(18)),
            server_nonce=secrets.token_urlsafe(32),
            expires_at=now + self._challenge_ttl,
        )
        self._challenges[challenge.challenge_id] = challenge
        return challenge

    def open_session(self, challenge_id: str, signature: str) -> SessionGrant:
        challenge = self._challenges.pop(challenge_id, None)
        if challenge is None:
            raise AuthenticationError("challenge is missing, consumed, or unknown")
        now = _aware_utc(self._clock(), field="SessionAuthority clock")
        if challenge.expires_at <= now:
            raise AuthenticationError("challenge expired")

        key = self._registry.resolve(challenge.agent_id, challenge.key_id, at=now)
        try:
            key.verify(_b64decode(signature), challenge.signing_bytes())
        except (InvalidSignature, ValueError) as error:
            raise AuthenticationError("invalid Agent challenge signature") from error

        epoch = self._epochs.get(challenge.agent_id, 0) + 1
        self._epochs[challenge.agent_id] = epoch
        expires_at = now + self._session_ttl
        claims = {
            "agentId": challenge.agent_id,
            "expiresAt": expires_at.isoformat(),
            "issuedAt": now.isoformat(),
            "keyId": challenge.key_id,
            "protocolVersion": challenge.protocol_version,
            "sessionEpoch": epoch,
        }
        payload = _b64encode(_canonical(claims))
        signature_bytes = hmac.new(self._secret, payload.encode(), hashlib.sha256).digest()
        return SessionGrant(
            agent_id=challenge.agent_id,
            key_id=challenge.key_id,
            protocol_version=challenge.protocol_version,
            session_epoch=epoch,
            issued_at=now,
            expires_at=expires_at,
            token=f"{payload}.{_b64encode(signature_bytes)}",
        )

    def verify_session(self, token: str) -> SessionGrant:
        try:
            payload, encoded_signature = token.split(".", 1)
            supplied_signature = _b64decode(encoded_signature)
        except (ValueError, TypeError) as error:
            raise AuthenticationError("malformed session token") from error

        expected = hmac.new(self._secret, payload.encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(expected, supplied_signature):
            raise AuthenticationError("invalid session token signature")

        try:
            claims = json.loads(_b64decode(payload))
            agent_id = claims["agentId"]
            key_id = claims["keyId"]
            protocol_version = claims["protocolVersion"]
            epoch = int(claims["sessionEpoch"])
            issued_at = _aware_utc(
                datetime.fromisoformat(str(claims["issuedAt"])),
                field="session issuedAt",
            )
            expires_at = _aware_utc(
                datetime.fromisoformat(str(claims["expiresAt"])),
                field="session expiresAt",
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise AuthenticationError("invalid session token claims") from error

        if not isinstance(agent_id, str) or not isinstance(key_id, str):
            raise AuthenticationError("invalid session token claims")
        if not isinstance(protocol_version, str):
            raise AuthenticationError("invalid session token claims")
        now = _aware_utc(self._clock(), field="SessionAuthority clock")
        if issued_at >= expires_at:
            raise AuthenticationError("invalid session token lifetime")
        if expires_at <= now:
            raise AuthenticationError("session token expired")
        if self._epochs.get(agent_id) != epoch:
            raise AuthenticationError("stale Agent session epoch")
        self._registry.resolve(agent_id, key_id, at=now)
        return SessionGrant(
            agent_id=agent_id,
            key_id=key_id,
            protocol_version=protocol_version,
            session_epoch=epoch,
            issued_at=issued_at,
            expires_at=expires_at,
            token=token,
        )

    def synchronize_epoch(
        self,
        agent_id: str,
        authoritative_epoch: int,
        *,
        key_id: str | None = None,
    ) -> None:
        """Advance the local epoch cache to an authoritative durable value.

        Session tokens are issued in-process, while fencing state is durable in the Core.  A
        restarted gateway calls this before issuing a new grant so its next epoch remains ahead
        of every runtime that the Core has already accepted.
        """

        self._registry.resolve(agent_id, key_id, at=self._clock())
        if authoritative_epoch < 0:
            raise AuthenticationError("authoritative session epoch cannot be negative")
        self._epochs[agent_id] = max(
            authoritative_epoch,
            self._epochs.get(agent_id, 0),
        )

    def current_epoch(self, agent_id: str) -> int:
        return self._epochs.get(agent_id, 0)
