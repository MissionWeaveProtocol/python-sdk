from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

import pytest

from missionweave.local_store import SQLiteAgentStore
from missionweave.models import Event, EventKind, Principal
from missionweave.replay import (
    AgentReplay,
    EventProjection,
    ReplayGroupError,
    ReplaySequenceError,
)
from missionweave.scheduler import SchedulerPolicy, WorkOffer

NOW = datetime(2026, 7, 16, tzinfo=UTC)
AGENT_ID = "urn:missionweave:agent:worker"
GROUP_A = "urn:missionweave:group:a"
GROUP_B = "urn:missionweave:group:b"


def _event(group_id: str, sequence: int, *, event_id: str | None = None) -> Event:
    identifier = event_id or f"urn:missionweave:event:{group_id.rsplit(':', 1)[-1]}:{sequence}"
    return Event(
        id=identifier,
        kind=EventKind.WORK_OFFER_ACCEPTED,
        group_id=group_id,
        sequence=sequence,
        actor=Principal.agent(AGENT_ID),
        action_id=f"urn:missionweave:action:{identifier.rsplit(':', 1)[-1]}",
        command_hash=f"hash:{identifier}",
        payload={"workItemId": f"work:{group_id.rsplit(':', 1)[-1]}:{sequence}"},
        occurred_at=NOW,
    )


class ReplayFeed:
    def __init__(self, events: dict[str, list[Event]]) -> None:
        self.events = events
        self.calls: list[tuple[str, int]] = []
        self.fail_next: set[str] = set()

    async def __call__(self, group_id: str, *, after: int) -> Sequence[Event]:
        self.calls.append((group_id, after))
        if group_id in self.fail_next:
            self.fail_next.remove(group_id)
            raise ConnectionError(f"disconnected from {group_id}")
        return [event for event in self.events.get(group_id, ()) if (event.sequence or 0) > after]


def _offer_projection(event: Event) -> EventProjection:
    assert event.group_id is not None
    work_id = event.payload["workItemId"]
    assert isinstance(work_id, str)
    return EventProjection(work_offers=(WorkOffer(work_id=work_id, group_id=event.group_id),))


@pytest.mark.asyncio
async def test_reconcile_projects_and_admits_before_advancing_and_deduplicates(tmp_path) -> None:
    first = _event(GROUP_A, 1)
    second = _event(GROUP_A, 2)
    feed = ReplayFeed({GROUP_A: [first, first, second]})
    store = SQLiteAgentStore(tmp_path / "agent.sqlite3")
    projected: list[tuple[str, int]] = []

    async def project(event: Event) -> EventProjection:
        projected.append((event.id, store.cursor(AGENT_ID, GROUP_A)))
        return _offer_projection(event)

    replay = AgentReplay(
        AGENT_ID,
        store,
        feed,
        project,
        scheduler_policy=SchedulerPolicy(capacity_slots=2),
        clock=lambda: NOW,
    )

    result = (await replay.reconcile(GROUP_A))[GROUP_A]

    assert projected == [(first.id, 0), (second.id, 1)]
    assert result.start_cursor == 0
    assert result.end_cursor == 2
    assert result.applied_events == 2
    assert result.duplicate_events == 1
    assert store.cursor(AGENT_ID, GROUP_A) == 2
    assert {record.offer.work_id for record in replay.scheduler.snapshot().records} == {
        "work:a:1",
        "work:a:2",
    }


@pytest.mark.asyncio
async def test_duplicate_event_id_cannot_move_to_another_sequence(tmp_path) -> None:
    event_id = "urn:missionweave:event:shared"
    feed = ReplayFeed(
        {GROUP_A: [_event(GROUP_A, 1, event_id=event_id), _event(GROUP_A, 2, event_id=event_id)]}
    )
    store = SQLiteAgentStore(tmp_path / "agent.sqlite3")
    projected: list[str] = []

    async def project(event: Event) -> None:
        projected.append(event.id)

    replay = AgentReplay(AGENT_ID, store, feed, project, clock=lambda: NOW)

    with pytest.raises(ReplaySequenceError, match="already recorded"):
        await replay.reconcile(GROUP_A)

    assert projected == [event_id]
    assert store.cursor(AGENT_ID, GROUP_A) == 1
    assert store.event_position(AGENT_ID, event_id) == (GROUP_A, 1)


@pytest.mark.asyncio
async def test_failed_projection_leaves_event_and_cursor_replayable(tmp_path) -> None:
    event = _event(GROUP_A, 1)
    feed = ReplayFeed({GROUP_A: [event]})
    store = SQLiteAgentStore(tmp_path / "agent.sqlite3")

    async def fail_projection(_event: Event) -> EventProjection:
        raise RuntimeError("projection failed")

    failed = AgentReplay(AGENT_ID, store, feed, fail_projection, clock=lambda: NOW)
    with pytest.raises(RuntimeError, match="projection failed"):
        await failed.reconcile(GROUP_A)

    assert store.cursor(AGENT_ID, GROUP_A) == 0
    assert store.has_event(AGENT_ID, event.id) is False

    projected: list[str] = []

    async def project(replayed: Event) -> EventProjection:
        projected.append(replayed.id)
        return _offer_projection(replayed)

    recovered = AgentReplay(AGENT_ID, store, feed, project, clock=lambda: NOW)
    result = (await recovered.reconcile(GROUP_A))[GROUP_A]

    assert projected == [event.id]
    assert result.end_cursor == 1
    assert store.has_event(AGENT_ID, event.id) is True


@pytest.mark.asyncio
async def test_reconcile_rejects_sequence_gaps_without_advancing_cursor(tmp_path) -> None:
    store = SQLiteAgentStore(tmp_path / "agent.sqlite3")
    feed = ReplayFeed({GROUP_A: [_event(GROUP_A, 2)]})
    projected: list[str] = []

    async def project(event: Event) -> None:
        projected.append(event.id)

    replay = AgentReplay(AGENT_ID, store, feed, project, clock=lambda: NOW)

    with pytest.raises(ReplaySequenceError, match="expected sequence 1"):
        await replay.reconcile(GROUP_A)

    assert projected == []
    assert store.cursor(AGENT_ID, GROUP_A) == 0


@pytest.mark.asyncio
async def test_reconcile_rejects_events_from_the_wrong_group(tmp_path) -> None:
    store = SQLiteAgentStore(tmp_path / "agent.sqlite3")
    feed = ReplayFeed({GROUP_A: [_event(GROUP_B, 1)]})

    async def project(_event: Event) -> None:
        raise AssertionError("wrong-Group Event must not reach the projector")

    replay = AgentReplay(AGENT_ID, store, feed, project, clock=lambda: NOW)

    with pytest.raises(ReplayGroupError, match=GROUP_B):
        await replay.reconcile(GROUP_A)

    assert store.cursor(AGENT_ID, GROUP_A) == 0
    assert store.cursor(AGENT_ID, GROUP_B) == 0


@pytest.mark.asyncio
async def test_restart_restores_scheduler_and_replays_only_the_durable_tail(tmp_path) -> None:
    path = tmp_path / "agent.sqlite3"
    feed = ReplayFeed({GROUP_A: [_event(GROUP_A, 1), _event(GROUP_A, 2)]})
    first_store = SQLiteAgentStore(path)

    async def project(event: Event) -> EventProjection:
        return _offer_projection(event)

    first = AgentReplay(AGENT_ID, first_store, feed, project, clock=lambda: NOW)
    await first.reconcile(GROUP_A)
    first_store.close()

    feed.events[GROUP_A].append(_event(GROUP_A, 3))
    second_store = SQLiteAgentStore(path)
    restarted = AgentReplay(AGENT_ID, second_store, feed, project, clock=lambda: NOW)

    assert {record.offer.work_id for record in restarted.scheduler.snapshot().records} == {
        "work:a:1",
        "work:a:2",
    }
    result = (await restarted.reconcile(GROUP_A))[GROUP_A]

    assert feed.calls[-1] == (GROUP_A, 2)
    assert result.applied_events == 1
    assert result.end_cursor == 3
    assert {record.offer.work_id for record in restarted.scheduler.snapshot().records} == {
        "work:a:1",
        "work:a:2",
        "work:a:3",
    }


@pytest.mark.asyncio
async def test_disconnect_reconnect_replays_each_groups_independent_durable_tail(tmp_path) -> None:
    feed = ReplayFeed({GROUP_A: [_event(GROUP_A, 1)], GROUP_B: [_event(GROUP_B, 1)]})
    store = SQLiteAgentStore(tmp_path / "agent.sqlite3")

    async def project(event: Event) -> EventProjection:
        return _offer_projection(event)

    replay = AgentReplay(
        AGENT_ID,
        store,
        feed,
        project,
        scheduler_policy=SchedulerPolicy(capacity_slots=4),
        clock=lambda: NOW,
    )
    await replay.reconcile((GROUP_A, GROUP_B))
    assert store.cursor(AGENT_ID, GROUP_A) == 1
    assert store.cursor(AGENT_ID, GROUP_B) == 1

    feed.events[GROUP_A].extend((_event(GROUP_A, 2), _event(GROUP_A, 3)))
    feed.events[GROUP_B].append(_event(GROUP_B, 2))
    feed.fail_next.add(GROUP_A)
    with pytest.raises(ConnectionError, match="disconnected"):
        await replay.reconcile((GROUP_A, GROUP_B))

    assert store.cursor(AGENT_ID, GROUP_A) == 1
    assert store.cursor(AGENT_ID, GROUP_B) == 1

    results = await replay.reconcile((GROUP_A, GROUP_B))

    assert results[GROUP_A].start_cursor == 1
    assert results[GROUP_A].end_cursor == 3
    assert results[GROUP_B].start_cursor == 1
    assert results[GROUP_B].end_cursor == 2
    assert feed.calls[-2:] == [(GROUP_A, 1), (GROUP_B, 1)]
    assert store.cursor(AGENT_ID, GROUP_A) == 3
    assert store.cursor(AGENT_ID, GROUP_B) == 2
