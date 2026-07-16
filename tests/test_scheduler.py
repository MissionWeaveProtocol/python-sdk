from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from missionweave.agent import ActiveSessionError, AgentRuntime, StaleSessionEpochError
from missionweave.scheduler import (
    AdmissionReason,
    CheckpointRef,
    Dispatch,
    EstimateBand,
    GroupSchedulingPolicy,
    Preempt,
    Scheduler,
    SchedulerPolicy,
    SchedulingEstimate,
    TransitionKind,
    WorkOffer,
    WorkTransition,
)

NOW = datetime(2026, 7, 15, 9, 0, tzinfo=UTC)


def offer(
    work_id: str,
    group_id: str,
    *,
    priority: int = 0,
    deadline: datetime | None = None,
    effort: EstimateBand = EstimateBand.UNKNOWN,
    slots: int = 1,
    capability: str | None = None,
    preemptible: bool = True,
) -> WorkOffer:
    return WorkOffer(
        work_id=work_id,
        group_id=group_id,
        organizational_priority=priority,
        deadline=deadline,
        estimate=SchedulingEstimate(effort=effort, slots=slots),
        capability=capability,
        preemptible=preemptible,
    )


def finish(scheduler: Scheduler, dispatch: Dispatch, *, now: datetime = NOW) -> None:
    scheduler.apply(
        WorkTransition(
            work_id=dispatch.work_id,
            kind=TransitionKind.COMPLETED,
            run_id=dispatch.run_id,
        ),
        now=now,
    )


def test_weighted_fairness_does_not_starve_a_lighter_group() -> None:
    scheduler = Scheduler(
        SchedulerPolicy(
            groups={
                "heavy": GroupSchedulingPolicy(weight=3),
                "light": GroupSchedulingPolicy(weight=1),
            },
            fairness_weight=100.0,
        ),
        clock=lambda: NOW,
    )
    for index in range(9):
        assert scheduler.admit(offer(f"heavy-{index}", "heavy"), now=NOW).accepted
    for index in range(3):
        assert scheduler.admit(offer(f"light-{index}", "light"), now=NOW).accepted

    selected: list[str] = []
    for step in range(12):
        actions = scheduler.schedule(now=NOW + timedelta(seconds=step))
        dispatch = next(action for action in actions if isinstance(action, Dispatch))
        selected.append(dispatch.group_id)
        finish(scheduler, dispatch, now=NOW + timedelta(seconds=step))

    assert selected.count("heavy") == 9
    assert selected.count("light") == 3
    assert "light" in selected[:4]


def test_priority_deadline_aging_and_group_quota_affect_ranking() -> None:
    priority_scheduler = Scheduler(clock=lambda: NOW)
    priority_scheduler.admit(offer("low", "g", priority=1), now=NOW)
    priority_scheduler.admit(offer("high", "g", priority=20), now=NOW)
    first = priority_scheduler.schedule(now=NOW)[0]
    assert isinstance(first, Dispatch)
    assert first.work_id == "high"

    deadline_scheduler = Scheduler(
        SchedulerPolicy(deadline_horizon=timedelta(hours=2)),
        clock=lambda: NOW,
    )
    deadline_scheduler.admit(offer("ordinary", "g", priority=5), now=NOW)
    deadline_scheduler.admit(
        offer("urgent", "g", deadline=NOW + timedelta(minutes=1)),
        now=NOW,
    )
    urgent = deadline_scheduler.schedule(now=NOW)[0]
    assert isinstance(urgent, Dispatch)
    assert urgent.work_id == "urgent"

    aging_scheduler = Scheduler(
        SchedulerPolicy(
            aging_interval=timedelta(minutes=1),
            aging_weight=100.0,
        ),
        clock=lambda: NOW,
    )
    aging_scheduler.admit(offer("old-low", "g", priority=0), now=NOW)
    aging_scheduler.admit(
        offer("fresh-high", "g", priority=5),
        now=NOW + timedelta(minutes=10),
    )
    aged = aging_scheduler.schedule(now=NOW + timedelta(minutes=10))[0]
    assert isinstance(aged, Dispatch)
    assert aged.work_id == "old-low"

    quota_scheduler = Scheduler(
        SchedulerPolicy(
            capacity_slots=2,
            groups={"a": GroupSchedulingPolicy(weight=5, slot_quota=1)},
        ),
        clock=lambda: NOW,
    )
    quota_scheduler.admit(offer("a-1", "a", priority=20), now=NOW)
    quota_scheduler.admit(offer("a-2", "a", priority=20), now=NOW)
    quota_scheduler.admit(offer("b-1", "b", priority=0), now=NOW)
    quota_actions = quota_scheduler.schedule(now=NOW)
    dispatched_groups = [
        action.group_id for action in quota_actions if isinstance(action, Dispatch)
    ]
    assert sorted(dispatched_groups) == ["a", "b"]


def test_preemption_requires_a_durable_safe_checkpoint_and_confirmation() -> None:
    scheduler = Scheduler(
        SchedulerPolicy(preemption_margin=0.0),
        clock=lambda: NOW,
    )
    scheduler.admit(offer("low", "g", priority=0), now=NOW)
    low = scheduler.schedule(now=NOW)[0]
    assert isinstance(low, Dispatch)
    scheduler.admit(offer("high", "g", priority=50), now=NOW)

    # Capacity stays occupied and unsafe execution is never interrupted.
    assert scheduler.schedule(now=NOW) == ()
    unsafe = CheckpointRef(
        checkpoint_id="unsafe",
        work_id=low.work_id,
        group_id=low.group_id,
        run_id=low.run_id,
        created_at=NOW,
        durable=False,
        safe=True,
    )
    scheduler.apply(
        WorkTransition(
            work_id=low.work_id,
            kind=TransitionKind.CHECKPOINT_SAVED,
            run_id=low.run_id,
            checkpoint=unsafe,
        ),
        now=NOW,
    )
    assert scheduler.schedule(now=NOW) == ()

    safe = CheckpointRef(
        checkpoint_id="safe-cp",
        work_id=low.work_id,
        group_id=low.group_id,
        run_id=low.run_id,
        created_at=NOW,
    )
    scheduler.apply(
        WorkTransition(
            work_id=low.work_id,
            kind=TransitionKind.CHECKPOINT_SAVED,
            run_id=low.run_id,
            checkpoint=safe,
        ),
        now=NOW,
    )
    request = scheduler.schedule(now=NOW)[0]
    assert isinstance(request, Preempt)
    assert request.work_id == "low"

    # A preemption request still owns capacity until the runtime confirms it stopped.
    assert scheduler.schedule(now=NOW) == ()
    scheduler.apply(
        WorkTransition(
            work_id=low.work_id,
            kind=TransitionKind.PREEMPTED,
            run_id=low.run_id,
            checkpoint=safe,
        ),
        now=NOW,
    )
    high = scheduler.schedule(now=NOW)[0]
    assert isinstance(high, Dispatch)
    assert high.work_id == "high"

    finish(scheduler, high)
    resumed = scheduler.schedule(now=NOW)[0]
    assert isinstance(resumed, Dispatch)
    assert resumed.work_id == "low"
    assert resumed.resume_from == safe


def test_capacity_slots_limit_concurrency() -> None:
    scheduler = Scheduler(SchedulerPolicy(capacity_slots=2), clock=lambda: NOW)
    for work_id in ("one", "two", "three"):
        scheduler.admit(offer(work_id, "g"), now=NOW)

    first_batch = scheduler.schedule(now=NOW)
    dispatches = [action for action in first_batch if isinstance(action, Dispatch)]
    assert len(dispatches) == 2
    assert scheduler.schedule(now=NOW) == ()

    finish(scheduler, dispatches[0])
    next_batch = scheduler.schedule(now=NOW)
    next_dispatches = [action for action in next_batch if isinstance(action, Dispatch)]
    assert len(next_dispatches) == 1
    assert next_dispatches[0].work_id == "three"


def test_blocked_work_releases_capacity_and_requeues_when_due() -> None:
    scheduler = Scheduler(clock=lambda: NOW)
    scheduler.admit(offer("blocked", "g", priority=10), now=NOW)
    blocked = scheduler.schedule(now=NOW)[0]
    assert isinstance(blocked, Dispatch)
    scheduler.admit(offer("other", "g"), now=NOW)

    retry_at = NOW + timedelta(minutes=5)
    scheduler.apply(
        WorkTransition(
            work_id=blocked.work_id,
            kind=TransitionKind.BLOCKED,
            run_id=blocked.run_id,
            retry_at=retry_at,
            reason="waiting-for-input",
        ),
        now=NOW,
    )
    other = scheduler.schedule(now=NOW)[0]
    assert isinstance(other, Dispatch)
    assert other.work_id == "other"
    finish(scheduler, other)

    assert scheduler.schedule(now=retry_at - timedelta(seconds=1)) == ()
    released = scheduler.schedule(now=retry_at)[0]
    assert isinstance(released, Dispatch)
    assert released.work_id == "blocked"


def test_admission_declines_work_the_worker_cannot_safely_accept() -> None:
    scheduler = Scheduler(
        SchedulerPolicy(
            capacity_slots=1,
            supported_capabilities=frozenset({"code-review/v1"}),
            allowed_groups=frozenset({"allowed"}),
        ),
        clock=lambda: NOW,
    )

    oversized = scheduler.admit(offer("large", "allowed", slots=2), now=NOW)
    unsupported = scheduler.admit(
        offer("translate", "allowed", capability="translation/v1"),
        now=NOW,
    )
    wrong_group = scheduler.admit(offer("foreign", "other"), now=NOW)

    assert (oversized.accepted, oversized.reason) == (
        False,
        AdmissionReason.EXCEEDS_CAPACITY,
    )
    assert (unsupported.accepted, unsupported.reason) == (
        False,
        AdmissionReason.UNSUPPORTED_CAPABILITY,
    )
    assert (wrong_group.accepted, wrong_group.reason) == (
        False,
        AdmissionReason.GROUP_NOT_ALLOWED,
    )


def test_snapshot_rebuilds_per_group_queues_and_resumes_safe_work() -> None:
    scheduler = Scheduler(clock=lambda: NOW)
    scheduler.admit(offer("running", "alpha", priority=20), now=NOW)
    scheduler.admit(offer("queued", "beta"), now=NOW)
    running = scheduler.schedule(now=NOW)[0]
    assert isinstance(running, Dispatch)
    checkpoint = CheckpointRef(
        checkpoint_id="alpha-checkpoint",
        work_id=running.work_id,
        group_id=running.group_id,
        run_id=running.run_id,
        created_at=NOW,
    )
    scheduler.apply(
        WorkTransition(
            work_id=running.work_id,
            kind=TransitionKind.CHECKPOINT_SAVED,
            run_id=running.run_id,
            checkpoint=checkpoint,
        ),
        now=NOW,
    )

    rebuilt = Scheduler.rebuild(scheduler.snapshot(), clock=lambda: NOW)
    first = rebuilt.schedule(now=NOW)[0]
    assert isinstance(first, Dispatch)
    assert first.work_id == "running"
    assert first.resume_from == checkpoint
    finish(rebuilt, first)
    second = rebuilt.schedule(now=NOW)[0]
    assert isinstance(second, Dispatch)
    assert second.work_id == "queued"
    assert second.group_id == "beta"


def test_agent_session_is_single_and_never_mixes_group_context() -> None:
    scheduler = Scheduler(clock=lambda: NOW)
    runtime = AgentRuntime("worker-7", scheduler)
    session = runtime.start_session(1, session_id="session-one")
    with pytest.raises(ActiveSessionError):
        runtime.start_session(2)

    session.install_group_context(
        "alpha",
        {"document": "alpha-only", "nested": {"value": 1}},
        revision=4,
    )
    session.install_group_context(
        "beta",
        {"document": "beta-only", "nested": {"value": 2}},
        revision=9,
    )
    session.install_group_credentials("alpha", {"token": "alpha-secret"}, revision=2)
    session.install_group_credentials("beta", {"token": "beta-secret"}, revision=3)
    scheduler.admit(offer("beta-work", "beta"), now=NOW)
    dispatch = scheduler.schedule(now=NOW)[0]
    assert isinstance(dispatch, Dispatch)

    execution = session.prepare(dispatch)
    assert execution.group_id == "beta"
    assert execution.context_revision == 9
    assert execution.values["document"] == "beta-only"
    assert execution.credential_revision == 3
    assert execution.credentials["token"] == "beta-secret"
    assert "alpha-only" not in repr(execution)
    assert "alpha-secret" not in repr(execution)
    assert "alpha-only" not in repr(scheduler.snapshot())
    assert "alpha-secret" not in repr(scheduler.snapshot())
    with pytest.raises(TypeError):
        execution.values["leak"] = "attempt"  # type: ignore[index]
    with pytest.raises(TypeError):
        execution.credentials["leak"] = "attempt"  # type: ignore[index]

    session.close()
    with pytest.raises(StaleSessionEpochError):
        runtime.start_session(1)
    replacement = runtime.start_session(2, session_id="session-two")
    assert replacement.descriptor.session_epoch == 2
    replacement.close()
