"""Durable Agent Event replay, projection, and Scheduler reconstruction."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from missionweaveprotocol.local_store import SQLiteAgentStore
from missionweaveprotocol.models import Event
from missionweaveprotocol.scheduler import (
    AdmissionDecision,
    AdmissionReason,
    Scheduler,
    SchedulerPolicy,
    WorkOffer,
)


class ReplayError(ValueError):
    """Base error for an invalid authoritative replay stream."""


class ReplayGroupError(ReplayError):
    """A replay source returned an Event from another Group."""


class ReplaySequenceError(ReplayError):
    """A replay source returned a gap, stale sequence, or invalid Event position."""


class ReplayProjectionError(ReplayError):
    """A projected Scheduler offer conflicts with already projected work."""


@dataclass(frozen=True, slots=True)
class EventProjection:
    """Agent-local effects derived from one authoritative Event."""

    work_offers: tuple[WorkOffer, ...] = ()


@dataclass(frozen=True, slots=True)
class GroupReplayResult:
    """Durable progress made while reconciling one Group."""

    group_id: str
    start_cursor: int
    end_cursor: int
    applied_events: int
    duplicate_events: int
    admissions: tuple[AdmissionDecision, ...]


class ReplaySource(Protocol):
    async def __call__(self, group_id: str, *, after: int) -> Sequence[Event]: ...


class EventProjector(Protocol):
    async def __call__(self, event: Event) -> EventProjection | None: ...


Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


class AgentReplay:
    """Reconcile authoritative Group Events into durable Agent-local projections.

    The projector is invoked at least once for every new Event. Its work and any Scheduler
    snapshot must succeed before the Event is marked seen and its Group Cursor advances. A
    projector should therefore keep non-Scheduler effects idempotent across process crashes.
    """

    def __init__(
        self,
        agent_id: str,
        store: SQLiteAgentStore,
        replay_source: ReplaySource,
        projector: EventProjector,
        *,
        scheduler: Scheduler | None = None,
        scheduler_policy: SchedulerPolicy | None = None,
        clock: Clock = _utc_now,
    ) -> None:
        if not agent_id.strip():
            raise ValueError("agent_id must not be empty")
        if scheduler is not None and scheduler_policy is not None:
            raise ValueError("scheduler_policy cannot be supplied with an existing Scheduler")
        self.agent_id = agent_id
        self._store = store
        self._replay_source = replay_source
        self._projector = projector
        self._lock = asyncio.Lock()
        if scheduler is not None:
            self._scheduler = scheduler
        else:
            snapshot = store.load_scheduler(agent_id)
            self._scheduler = (
                Scheduler(scheduler_policy, clock=clock)
                if snapshot is None
                else Scheduler.rebuild(snapshot, scheduler_policy, clock=clock)
            )
            if snapshot is not None:
                store.save_scheduler(agent_id, self._scheduler.snapshot())

    @property
    def scheduler(self) -> Scheduler:
        return self._scheduler

    async def reconcile(
        self,
        groups: str | Iterable[str],
    ) -> dict[str, GroupReplayResult]:
        """Replay one or many Groups from each durable Cursor.

        Groups are reconciled in caller order under one local lock. Progress is committed after
        each Event, so a later disconnect or invalid Event preserves every earlier Cursor.
        """

        group_ids = self._normalize_groups(groups)
        async with self._lock:
            results: dict[str, GroupReplayResult] = {}
            for group_id in group_ids:
                results[group_id] = await self._reconcile_group(group_id)
            return results

    async def _reconcile_group(self, group_id: str) -> GroupReplayResult:
        start_cursor = self._store.cursor(self.agent_id, group_id)
        cursor = start_cursor
        applied = 0
        duplicates = 0
        admissions: list[AdmissionDecision] = []
        events = await self._replay_source(group_id, after=start_cursor)
        for event in events:
            sequence = self._event_sequence(event, group_id)
            expected = cursor + 1
            if self._store.has_event(self.agent_id, event.id):
                position = self._store.event_position(self.agent_id, event.id)
                if position is not None and position != (group_id, sequence):
                    raise ReplaySequenceError(
                        f"Event ID {event.id} was already recorded at Group {position[0]} "
                        f"sequence {position[1]}"
                    )
                if sequence > expected:
                    raise ReplaySequenceError(
                        f"Group {group_id} expected sequence {expected}, got {sequence}"
                    )
                if sequence == expected:
                    self._store.acknowledge(self.agent_id, group_id, sequence)
                    cursor = sequence
                duplicates += 1
                continue
            if sequence != expected:
                raise ReplaySequenceError(
                    f"Group {group_id} expected sequence {expected}, got {sequence}"
                )

            projection = await self._projector(event)
            projected_offers = () if projection is None else projection.work_offers
            self._validate_offers(projected_offers, group_id)
            event_admissions = tuple(self._scheduler.admit(offer) for offer in projected_offers)
            collision = next(
                (
                    decision
                    for decision in event_admissions
                    if decision.reason is AdmissionReason.IDENTIFIER_COLLISION
                ),
                None,
            )
            if collision is not None:
                raise ReplayProjectionError(
                    f"projected WorkOffer {collision.work_id} conflicts with Scheduler state"
                )
            if projected_offers:
                self._store.save_scheduler(self.agent_id, self._scheduler.snapshot())
            self._store.remember_event(
                self.agent_id,
                event.id,
                group_id=group_id,
                sequence=sequence,
            )
            self._store.acknowledge(self.agent_id, group_id, sequence)
            cursor = sequence
            applied += 1
            admissions.extend(event_admissions)

        return GroupReplayResult(
            group_id=group_id,
            start_cursor=start_cursor,
            end_cursor=cursor,
            applied_events=applied,
            duplicate_events=duplicates,
            admissions=tuple(admissions),
        )

    @staticmethod
    def _normalize_groups(groups: str | Iterable[str]) -> tuple[str, ...]:
        candidates = (groups,) if isinstance(groups, str) else tuple(groups)
        if not candidates:
            raise ValueError("at least one Group is required")
        normalized: list[str] = []
        seen: set[str] = set()
        for group_id in candidates:
            if not group_id.strip():
                raise ValueError("group_id must not be empty")
            if group_id not in seen:
                normalized.append(group_id)
                seen.add(group_id)
        return tuple(normalized)

    @staticmethod
    def _event_sequence(event: Event, group_id: str) -> int:
        if event.group_id != group_id:
            raise ReplayGroupError(
                f"replay for Group {group_id} returned Event {event.id} from {event.group_id}"
            )
        if event.sequence is None or event.sequence < 1:
            raise ReplaySequenceError(
                f"Event {event.id} in Group {group_id} lacks a positive Group sequence"
            )
        return event.sequence

    @staticmethod
    def _validate_offers(offers: tuple[WorkOffer, ...], group_id: str) -> None:
        wrong_group = next((offer for offer in offers if offer.group_id != group_id), None)
        if wrong_group is not None:
            raise ReplayProjectionError(
                f"projected WorkOffer {wrong_group.work_id} belongs to Group "
                f"{wrong_group.group_id}, not {group_id}"
            )


__all__ = [
    "AgentReplay",
    "EventProjection",
    "EventProjector",
    "GroupReplayResult",
    "ReplayError",
    "ReplayGroupError",
    "ReplayProjectionError",
    "ReplaySequenceError",
    "ReplaySource",
]
