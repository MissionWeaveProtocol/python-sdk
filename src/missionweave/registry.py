"""Organization-controlled Agent Cards, Presence Records, and performance evidence."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field

from missionweave.auth import AgentIdentity
from missionweave.canonical import canonical_bytes


class RegistryError(ValueError):
    """Raised when organization-controlled registry data is invalid."""


def _canonical(value: object) -> bytes:
    return canonical_bytes(value)


def _decode_key(value: str) -> Ed25519PublicKey:
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    return Ed25519PublicKey.from_public_bytes(raw)


class CapabilityDescriptor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[a-z0-9]+(?:[.-][a-z0-9]+)+$")
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+(?:\.[0-9]+)?$")
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    constraints: dict[str, Any] = Field(default_factory=dict)
    verified_evidence: tuple[str, ...] = ()


class AgentCard(BaseModel):
    """Stable organization-signed identity and verified capability description."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str = Field(pattern=r"^agent://")
    owner: str
    version: str = Field(pattern=r"^[0-9]+\.[0-9]+\.[0-9]+$")
    public_key: str
    capabilities: tuple[CapabilityDescriptor, ...]
    issued_at: datetime
    signature: str = ""

    def signing_bytes(self) -> bytes:
        return _canonical(self.model_dump(mode="json", exclude={"signature"}))

    def signed_by(self, organization: AgentIdentity) -> AgentCard:
        return self.model_copy(update={"signature": organization.sign(self.signing_bytes())})


class PresenceRecord(BaseModel):
    """Ephemeral Agent availability, deliberately separate from AgentCard."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str
    status: Literal["online", "busy", "offline", "draining"]
    available_slots: int = Field(ge=0)
    capability_availability: dict[str, bool] = Field(default_factory=dict)
    estimated_response_seconds: int | None = Field(default=None, ge=0)
    heartbeat_at: datetime


class CapabilityPerformance(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str
    capability: str
    accepted: int = Field(default=0, ge=0)
    completed: int = Field(default=0, ge=0)
    failed: int = Field(default=0, ge=0)
    reassigned: int = Field(default=0, ge=0)
    human_changes_requested: int = Field(default=0, ge=0)
    average_deadline_variance_seconds: float = 0.0
    average_budget_variance: float = 0.0

    @property
    def reliability(self) -> float:
        terminal = self.completed + self.failed + self.reassigned
        return self.completed / terminal if terminal else 1.0


class Candidate(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    agent_id: str
    agent_card_version: str
    capability: str
    capability_version: str
    online: bool
    available_slots: int
    reliability: float


class AgentRegistry:
    """Deep Module for stable Cards, dynamic Presence, and contextual performance."""

    def __init__(
        self,
        organization_public_key: str,
        *,
        presence_ttl: timedelta = timedelta(seconds=30),
    ) -> None:
        self._organization_key = _decode_key(organization_public_key)
        self._presence_ttl = presence_ttl
        self._cards: dict[str, AgentCard] = {}
        self._presence: dict[str, PresenceRecord] = {}
        self._performance: dict[tuple[str, str], CapabilityPerformance] = {}

    def register(self, card: AgentCard) -> None:
        try:
            signature = base64.urlsafe_b64decode(card.signature + "=" * (-len(card.signature) % 4))
            self._organization_key.verify(signature, card.signing_bytes())
        except (InvalidSignature, ValueError) as error:
            raise RegistryError("Agent Card lacks a valid organization signature") from error
        previous = self._cards.get(card.agent_id)
        if previous is not None and previous.issued_at > card.issued_at:
            raise RegistryError("Agent Card update is older than the registered Card")
        self._cards[card.agent_id] = card

    def card(self, agent_id: str) -> AgentCard:
        try:
            return self._cards[agent_id]
        except KeyError as error:
            raise RegistryError("unknown Agent") from error

    def update_presence(self, record: PresenceRecord) -> None:
        if record.agent_id not in self._cards:
            raise RegistryError("Presence Record references an unknown Agent")
        self._presence[record.agent_id] = record

    def presence(self, agent_id: str, *, now: datetime | None = None) -> PresenceRecord | None:
        record = self._presence.get(agent_id)
        if record is None:
            return None
        current = now or datetime.now(UTC)
        if record.heartbeat_at + self._presence_ttl <= current:
            return record.model_copy(update={"status": "offline", "available_slots": 0})
        return record

    def record_performance(self, performance: CapabilityPerformance) -> None:
        if performance.agent_id not in self._cards:
            raise RegistryError("performance references an unknown Agent")
        self._performance[(performance.agent_id, performance.capability)] = performance

    def candidates(
        self,
        capability: str,
        *,
        major_version: int,
        now: datetime | None = None,
    ) -> list[Candidate]:
        result: list[Candidate] = []
        for card in self._cards.values():
            descriptor = next(
                (
                    item
                    for item in card.capabilities
                    if item.name == capability
                    and int(item.version.split(".", 1)[0]) == major_version
                ),
                None,
            )
            if descriptor is None:
                continue
            presence = self.presence(card.agent_id, now=now)
            performance = self._performance.get((card.agent_id, capability))
            online = presence is not None and presence.status in {"online", "busy"}
            result.append(
                Candidate(
                    agent_id=card.agent_id,
                    agent_card_version=card.version,
                    capability=descriptor.name,
                    capability_version=descriptor.version,
                    online=online,
                    available_slots=presence.available_slots if presence is not None else 0,
                    reliability=performance.reliability if performance is not None else 1.0,
                )
            )
        return sorted(
            result,
            key=lambda item: (item.online, item.available_slots, item.reliability),
            reverse=True,
        )
