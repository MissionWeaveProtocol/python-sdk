from __future__ import annotations

from datetime import UTC, datetime

import pytest

from missionweave.local_store import LocalStoreError, SQLiteAgentStore
from missionweave.scheduler import (
    CheckpointRef,
    Dispatch,
    Scheduler,
    SchedulerPolicy,
    TransitionKind,
    WorkOffer,
    WorkTransition,
)


def test_cursor_dedup_and_outbox_survive_restart(tmp_path) -> None:
    path = tmp_path / "agent.sqlite3"
    store = SQLiteAgentStore(path)
    store.acknowledge("worker", "group-a", 5)
    store.acknowledge("worker", "group-a", 3)
    assert store.remember_event("worker", "event-1") is True
    assert store.remember_event("worker", "event-1") is False
    store.enqueue_action("worker", "action-1", {"value": 1})
    store.enqueue_action("worker", "action-1", {"value": 1})
    with pytest.raises(LocalStoreError, match="collision"):
        store.enqueue_action("worker", "action-1", {"value": 2})
    store.close()

    reopened = SQLiteAgentStore(path)
    assert reopened.cursor("worker", "group-a") == 5
    assert reopened.pending_actions("worker") == [{"value": 1}]


def test_scheduler_snapshot_and_group_context_are_rebuildable(tmp_path) -> None:
    now = datetime(2026, 7, 15, tzinfo=UTC)
    scheduler = Scheduler(clock=lambda: now)
    scheduler.admit(WorkOffer(work_id="work-a", group_id="group-a"), now=now)
    scheduler.admit(WorkOffer(work_id="work-b", group_id="group-b"), now=now)
    store = SQLiteAgentStore(tmp_path / "agent.sqlite3")
    store.save_scheduler("worker", scheduler.snapshot())
    store.save_group_context("worker", "group-a", 2, {"summary": "only-a"})

    snapshot = store.load_scheduler("worker")

    assert snapshot is not None
    rebuilt = Scheduler.rebuild(snapshot, clock=lambda: now)
    assert {record.offer.group_id for record in rebuilt.snapshot().records} == {
        "group-a",
        "group-b",
    }
    assert store.group_context("worker", "group-a") == (2, {"summary": "only-a"})
    assert store.group_context("worker", "group-b") is None


def test_checkpoint_content_survives_restart(tmp_path) -> None:
    path = tmp_path / "agent.sqlite3"
    store = SQLiteAgentStore(path)
    store.save_checkpoint(
        "worker",
        "group-a",
        "work-a",
        "checkpoint-a",
        {"phase": "review", "state": {"cursor": 3}},
    )
    store.close()

    reopened = SQLiteAgentStore(path)

    assert reopened.load_checkpoint("worker", "group-a", "work-a", "checkpoint-a") == {
        "phase": "review",
        "state": {"cursor": 3},
    }


def test_checkpoint_content_is_immutable_and_idempotent(tmp_path) -> None:
    store = SQLiteAgentStore(tmp_path / "agent.sqlite3")
    store.save_checkpoint(
        "worker",
        "group-a",
        "work-a",
        "checkpoint-a",
        {"phase": "review", "state": {"cursor": 3}},
    )

    store.save_checkpoint(
        "worker",
        "group-a",
        "work-a",
        "checkpoint-a",
        {"state": {"cursor": 3}, "phase": "review"},
    )
    with pytest.raises(LocalStoreError, match=r"checkpoint.*collision"):
        store.save_checkpoint(
            "worker",
            "group-a",
            "work-a",
            "checkpoint-a",
            {"phase": "changed"},
        )

    loaded = store.load_checkpoint("worker", "group-a", "work-a", "checkpoint-a")
    assert loaded == {"phase": "review", "state": {"cursor": 3}}
    assert loaded is not None
    loaded["phase"] = "mutated-copy"
    assert store.load_checkpoint("worker", "group-a", "work-a", "checkpoint-a") == {
        "phase": "review",
        "state": {"cursor": 3},
    }


def test_checkpoint_content_is_strictly_scoped_and_delete_is_idempotent(tmp_path) -> None:
    store = SQLiteAgentStore(tmp_path / "agent.sqlite3")
    checkpoint_id = "checkpoint-shared-name"
    store.save_checkpoint("worker", "group-a", "work-a", checkpoint_id, {"value": "a"})
    store.save_checkpoint("worker", "group-b", "work-a", checkpoint_id, {"value": "b"})
    store.save_checkpoint("worker", "group-a", "work-b", checkpoint_id, {"value": "work-b"})
    store.save_checkpoint("other", "group-a", "work-a", checkpoint_id, {"value": "other"})

    assert store.load_checkpoint("worker", "group-a", "work-a", checkpoint_id) == {"value": "a"}
    assert store.load_checkpoint("worker", "group-b", "work-a", checkpoint_id) == {"value": "b"}
    assert store.load_checkpoint("worker", "group-a", "work-b", checkpoint_id) == {
        "value": "work-b"
    }
    assert store.load_checkpoint("other", "group-a", "work-a", checkpoint_id) == {"value": "other"}
    assert store.load_checkpoint("worker", "group-a", "missing", checkpoint_id) is None

    assert store.delete_checkpoint("worker", "group-a", "work-a", checkpoint_id) is True
    assert store.delete_checkpoint("worker", "group-a", "work-a", checkpoint_id) is False
    assert store.load_checkpoint("worker", "group-a", "work-a", checkpoint_id) is None
    assert store.load_checkpoint("worker", "group-b", "work-a", checkpoint_id) == {"value": "b"}
    assert store.load_checkpoint("worker", "group-a", "work-b", checkpoint_id) == {
        "value": "work-b"
    }
    assert store.load_checkpoint("other", "group-a", "work-a", checkpoint_id) == {"value": "other"}


@pytest.mark.parametrize(
    "scope",
    (
        ("", "group-a", "work-a", "checkpoint-a"),
        ("worker", "", "work-a", "checkpoint-a"),
        ("worker", "group-a", "", "checkpoint-a"),
        ("worker", "group-a", "work-a", ""),
    ),
)
def test_checkpoint_scope_identifiers_must_be_nonempty(tmp_path, scope) -> None:
    store = SQLiteAgentStore(tmp_path / "agent.sqlite3")

    with pytest.raises(ValueError, match="checkpoint scope"):
        store.save_checkpoint(*scope, {})
    with pytest.raises(ValueError, match="checkpoint scope"):
        store.load_checkpoint(*scope)
    with pytest.raises(ValueError, match="checkpoint scope"):
        store.delete_checkpoint(*scope)


def test_scheduler_checkpoint_references_and_content_survive_restart_by_group(
    tmp_path,
) -> None:
    now = datetime(2026, 7, 15, tzinfo=UTC)
    policy = SchedulerPolicy(capacity_slots=2)
    scheduler = Scheduler(policy, clock=lambda: now)
    scheduler.admit(WorkOffer(work_id="work-a", group_id="group-a"), now=now)
    scheduler.admit(WorkOffer(work_id="work-b", group_id="group-b"), now=now)
    dispatches = {
        action.group_id: action
        for action in scheduler.schedule(now=now)
        if isinstance(action, Dispatch)
    }
    assert set(dispatches) == {"group-a", "group-b"}

    path = tmp_path / "agent.sqlite3"
    store = SQLiteAgentStore(path)
    references: dict[str, CheckpointRef] = {}
    for group_id, dispatch in dispatches.items():
        checkpoint = CheckpointRef(
            checkpoint_id="checkpoint-current",
            work_id=dispatch.work_id,
            group_id=group_id,
            run_id=dispatch.run_id,
            created_at=now,
        )
        references[group_id] = checkpoint
        scheduler.apply(
            WorkTransition(
                work_id=dispatch.work_id,
                kind=TransitionKind.CHECKPOINT_SAVED,
                run_id=dispatch.run_id,
                checkpoint=checkpoint,
            ),
            now=now,
        )
        store.save_checkpoint(
            "worker",
            group_id,
            dispatch.work_id,
            checkpoint.checkpoint_id,
            {"group": group_id, "resumeToken": f"resume-{group_id}"},
        )
    store.save_scheduler("worker", scheduler.snapshot())
    store.close()

    reopened = SQLiteAgentStore(path)
    snapshot = reopened.load_scheduler("worker")
    assert snapshot is not None
    persisted_references = {record.offer.group_id: record.checkpoint for record in snapshot.records}
    assert persisted_references == references
    for group_id, checkpoint in references.items():
        assert reopened.load_checkpoint(
            "worker",
            group_id,
            checkpoint.work_id,
            checkpoint.checkpoint_id,
        ) == {"group": group_id, "resumeToken": f"resume-{group_id}"}
    assert reopened.load_checkpoint("worker", "group-a", "work-b", "checkpoint-current") is None
    assert reopened.load_checkpoint("worker", "group-b", "work-a", "checkpoint-current") is None

    rebuilt = Scheduler.rebuild(snapshot, policy, clock=lambda: now)
    resumed = {
        action.group_id: action.resume_from
        for action in rebuilt.schedule(now=now)
        if isinstance(action, Dispatch)
    }
    assert resumed == references
