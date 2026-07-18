from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from missionweaveprotocol.auth import (
    AgentIdentity,
    AgentKeyRegistry,
    AuthenticationError,
    Challenge,
    SessionAuthority,
)

KEY_ID = "urn:missionweaveprotocol:key:reviewer"
CLIENT_NONCE = "Y2xpZW50LW5vbmNl"


def _authority(now: list[datetime]) -> tuple[AgentIdentity, SessionAuthority]:
    identity = AgentIdentity.generate("agent://acme/reviewer")
    registry = AgentKeyRegistry()
    registry.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    authority = SessionAuthority(
        registry,
        secret=b"test-secret" * 4,
        challenge_ttl=timedelta(seconds=5),
        session_ttl=timedelta(minutes=1),
        clock=lambda: now[0],
    )
    return identity, authority


def _challenge(authority: SessionAuthority, identity: AgentIdentity) -> Challenge:
    return authority.issue_challenge(
        identity.agent_id,
        key_id=KEY_ID,
        client_nonce=CLIENT_NONCE,
        protocol_version="0.1",
    )


def test_signed_challenge_opens_session() -> None:
    now = [datetime(2026, 7, 15, tzinfo=UTC)]
    identity, authority = _authority(now)
    challenge = _challenge(authority, identity)

    grant = authority.open_session(challenge.challenge_id, identity.sign(challenge.signing_bytes()))

    assert grant.session_epoch == 1
    assert grant.key_id == KEY_ID
    assert authority.verify_session(grant.token).agent_id == identity.agent_id


def test_challenge_signature_binds_the_complete_hello_transcript() -> None:
    now = [datetime(2026, 7, 15, tzinfo=UTC)]
    identity, authority = _authority(now)
    challenge = _challenge(authority, identity)

    transcript = json.loads(challenge.signing_bytes())

    assert transcript == {
        "agentId": identity.agent_id,
        "challengeId": challenge.challenge_id,
        "clientNonce": CLIENT_NONCE,
        "expiresAt": challenge.expires_at.isoformat(),
        "keyId": KEY_ID,
        "protocolVersion": "0.1",
        "serverNonce": challenge.server_nonce,
    }


def test_challenge_rejects_unknown_or_inactive_key_id() -> None:
    now = [datetime(2026, 7, 15, tzinfo=UTC)]
    identity, authority = _authority(now)

    with pytest.raises(AuthenticationError, match="key"):
        authority.issue_challenge(
            identity.agent_id,
            key_id="urn:missionweaveprotocol:key:unknown",
            client_nonce=CLIENT_NONCE,
        )


def test_challenge_is_one_use() -> None:
    now = [datetime(2026, 7, 15, tzinfo=UTC)]
    identity, authority = _authority(now)
    challenge = _challenge(authority, identity)
    signature = identity.sign(challenge.signing_bytes())
    authority.open_session(challenge.challenge_id, signature)

    with pytest.raises(AuthenticationError, match="consumed"):
        authority.open_session(challenge.challenge_id, signature)


def test_expired_challenge_is_rejected() -> None:
    now = [datetime(2026, 7, 15, tzinfo=UTC)]
    identity, authority = _authority(now)
    challenge = _challenge(authority, identity)
    now[0] += timedelta(seconds=6)

    with pytest.raises(AuthenticationError, match="expired"):
        authority.open_session(challenge.challenge_id, identity.sign(challenge.signing_bytes()))


def test_new_session_fences_previous_runtime() -> None:
    now = [datetime(2026, 7, 15, tzinfo=UTC)]
    identity, authority = _authority(now)

    first = _challenge(authority, identity)
    old_grant = authority.open_session(first.challenge_id, identity.sign(first.signing_bytes()))
    second = _challenge(authority, identity)
    new_grant = authority.open_session(second.challenge_id, identity.sign(second.signing_bytes()))

    with pytest.raises(AuthenticationError, match="stale"):
        authority.verify_session(old_grant.token)
    assert authority.verify_session(new_grant.token).session_epoch == 2


def test_tampered_session_token_is_rejected() -> None:
    now = [datetime(2026, 7, 15, tzinfo=UTC)]
    identity, authority = _authority(now)
    challenge = _challenge(authority, identity)
    grant = authority.open_session(challenge.challenge_id, identity.sign(challenge.signing_bytes()))

    with pytest.raises(AuthenticationError, match="signature"):
        authority.verify_session(grant.token[:-1] + ("A" if grant.token[-1] != "A" else "B"))


def test_expired_session_token_is_rejected() -> None:
    now = [datetime(2026, 7, 15, tzinfo=UTC)]
    identity, authority = _authority(now)
    challenge = _challenge(authority, identity)
    grant = authority.open_session(challenge.challenge_id, identity.sign(challenge.signing_bytes()))
    now[0] += timedelta(minutes=1)

    with pytest.raises(AuthenticationError, match="expired"):
        authority.verify_session(grant.token)


def test_agent_registry_enforces_key_id_validity_and_revocation() -> None:
    now = datetime(2026, 7, 15, tzinfo=UTC)
    identity = AgentIdentity.generate("agent://acme/reviewer")
    registry = AgentKeyRegistry()
    registry.register(
        identity.agent_id,
        identity.public_key,
        key_id=KEY_ID,
        valid_from=now,
        valid_until=now + timedelta(hours=1),
    )

    registry.resolve(identity.agent_id, KEY_ID, at=now)
    with pytest.raises(AuthenticationError, match="not yet valid"):
        registry.resolve(identity.agent_id, KEY_ID, at=now - timedelta(seconds=1))
    with pytest.raises(AuthenticationError, match="expired"):
        registry.resolve(identity.agent_id, KEY_ID, at=now + timedelta(hours=1))

    registry.revoke(identity.agent_id, KEY_ID, revoked_at=now + timedelta(minutes=30))
    registry.resolve(identity.agent_id, KEY_ID, at=now + timedelta(minutes=29))
    with pytest.raises(AuthenticationError, match="revoked"):
        registry.resolve(identity.agent_id, KEY_ID, at=now + timedelta(minutes=30))


def test_revoking_authenticated_key_fences_its_session() -> None:
    now = [datetime(2026, 7, 15, tzinfo=UTC)]
    identity = AgentIdentity.generate("agent://acme/reviewer")
    registry = AgentKeyRegistry()
    registry.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    authority = SessionAuthority(
        registry,
        secret=b"test-secret" * 4,
        clock=lambda: now[0],
    )
    challenge = _challenge(authority, identity)
    grant = authority.open_session(challenge.challenge_id, identity.sign(challenge.signing_bytes()))
    registry.revoke(identity.agent_id, KEY_ID, revoked_at=now[0])

    with pytest.raises(AuthenticationError, match="revoked"):
        authority.verify_session(grant.token)
