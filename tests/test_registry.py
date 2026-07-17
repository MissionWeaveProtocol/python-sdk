from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from missionweaveprotocol.auth import AgentIdentity
from missionweaveprotocol.registry import (
    AgentCard,
    AgentRegistry,
    CapabilityDescriptor,
    CapabilityPerformance,
    PresenceRecord,
    RegistryError,
)


def _card(
    organization: AgentIdentity,
    identity: AgentIdentity,
    *,
    version: str = "1.0.0",
) -> AgentCard:
    return AgentCard(
        agent_id=identity.agent_id,
        owner="team-platform",
        version=version,
        public_key=identity.public_key,
        capabilities=(
            CapabilityDescriptor(
                name="org.acme.software.code-review",
                version="2.0",
                verified_evidence=("artifact://tests/reviewer-cert",),
            ),
        ),
        issued_at=datetime(2026, 7, 15, tzinfo=UTC),
    ).signed_by(organization)


def test_registry_requires_organization_signature() -> None:
    organization = AgentIdentity.generate("organization://acme")
    attacker = AgentIdentity.generate("organization://attacker")
    worker = AgentIdentity.generate("agent://acme/reviewer")
    registry = AgentRegistry(organization.public_key)

    with pytest.raises(RegistryError, match="signature"):
        registry.register(_card(attacker, worker))


def test_presence_is_ephemeral_and_does_not_change_card() -> None:
    organization = AgentIdentity.generate("organization://acme")
    worker = AgentIdentity.generate("agent://acme/reviewer")
    registry = AgentRegistry(organization.public_key, presence_ttl=timedelta(seconds=10))
    card = _card(organization, worker)
    registry.register(card)
    heartbeat = datetime(2026, 7, 15, tzinfo=UTC)
    registry.update_presence(
        PresenceRecord(
            agent_id=worker.agent_id,
            status="online",
            available_slots=2,
            heartbeat_at=heartbeat,
        )
    )

    active = registry.presence(worker.agent_id, now=heartbeat)
    expired = registry.presence(worker.agent_id, now=heartbeat + timedelta(seconds=11))
    assert active is not None and active.available_slots == 2
    assert expired is not None and expired.status == "offline"
    assert registry.card(worker.agent_id) == card


def test_candidates_use_capability_version_presence_and_contextual_performance() -> None:
    organization = AgentIdentity.generate("organization://acme")
    first = AgentIdentity.generate("agent://acme/reviewer-one")
    second = AgentIdentity.generate("agent://acme/reviewer-two")
    registry = AgentRegistry(organization.public_key)
    registry.register(_card(organization, first))
    registry.register(_card(organization, second))
    now = datetime(2026, 7, 15, tzinfo=UTC)
    registry.update_presence(
        PresenceRecord(
            agent_id=first.agent_id,
            status="online",
            available_slots=1,
            heartbeat_at=now,
        )
    )
    registry.update_presence(
        PresenceRecord(agent_id=second.agent_id, status="busy", available_slots=0, heartbeat_at=now)
    )
    registry.record_performance(
        CapabilityPerformance(
            agent_id=first.agent_id,
            capability="org.acme.software.code-review",
            completed=8,
            failed=2,
        )
    )

    candidates = registry.candidates("org.acme.software.code-review", major_version=2, now=now)

    assert [item.agent_id for item in candidates] == [first.agent_id, second.agent_id]
    assert candidates[0].reliability == 0.8
