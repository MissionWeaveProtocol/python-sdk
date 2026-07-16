"""Worker-local scheduling for MissionWeave Protocol WorkItems.

The Scheduler is deliberately a deep Module.  Its public Interface admits sanitized
``WorkOffer`` records, returns dispatch/preemption actions, accepts lifecycle transitions,
and exports an immutable reconstruction snapshot.  Per-Group ready queues, fairness
credits, admission policy, checkpoint fencing, and ranking remain in the Implementation.

Only scheduling metadata belongs here.  Work Contract text, Messages, Artifacts, and
Context Packages must stay in their Group-scoped stores and must never enter a
``WorkOffer`` or ``SchedulerSnapshot``.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Any

type Clock = Callable[[], datetime]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _aware(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


class EstimateBand(IntEnum):
    """A coarse effort estimate that avoids retaining exact private measurements."""

    TINY = 1
    SMALL = 2
    MEDIUM = 4
    UNKNOWN = 6
    LARGE = 8
    HUGE = 16


@dataclass(frozen=True, slots=True)
class SchedulingEstimate:
    """Banded scheduling inputs; no prompts, tokens, prices, or exact durations."""

    effort: EstimateBand = EstimateBand.UNKNOWN
    slots: int = 1

    def __post_init__(self) -> None:
        if self.slots < 1:
            raise ValueError("estimate slots must be at least one")


@dataclass(frozen=True, slots=True)
class WorkOffer:
    """The complete, privacy-preserving input the Scheduler needs for one WorkItem."""

    work_id: str
    group_id: str
    organizational_priority: int = 0
    deadline: datetime | None = None
    estimate: SchedulingEstimate = field(default_factory=SchedulingEstimate)
    capability: str | None = None
    preemptible: bool = True

    def __post_init__(self) -> None:
        if not self.work_id:
            raise ValueError("work_id must not be empty")
        if not self.group_id:
            raise ValueError("group_id must not be empty")
        if not -100 <= self.organizational_priority <= 100:
            raise ValueError("organizational_priority must be between -100 and 100")
        if self.deadline is not None:
            object.__setattr__(self, "deadline", _aware(self.deadline, "deadline"))

    @classmethod
    def from_work_item(
        cls,
        work_item: Any,
        *,
        organizational_priority: int = 0,
        estimate: SchedulingEstimate | None = None,
        capability: str | None = None,
        preemptible: bool = True,
    ) -> WorkOffer:
        """Adapt a core WorkItem without copying its Work Contract or Group content."""

        contract = getattr(work_item, "contract", None)
        deadline = getattr(contract, "deadline", None)
        return cls(
            work_id=str(work_item.id),
            group_id=str(work_item.group_id),
            organizational_priority=organizational_priority,
            deadline=deadline,
            estimate=estimate or SchedulingEstimate(),
            capability=capability,
            preemptible=preemptible,
        )


@dataclass(frozen=True, slots=True)
class GroupSchedulingPolicy:
    """Organization policy for one Group's share of a Worker."""

    weight: int = 1
    slot_quota: int | None = None
    priority_bias: int = 0

    def __post_init__(self) -> None:
        if self.weight < 1:
            raise ValueError("Group weight must be at least one")
        if self.slot_quota is not None and self.slot_quota < 0:
            raise ValueError("Group slot_quota must not be negative")
        if not -100 <= self.priority_bias <= 100:
            raise ValueError("Group priority_bias must be between -100 and 100")


@dataclass(frozen=True, slots=True)
class SchedulerPolicy:
    """Configuration for ranking, admission, fairness, and Worker capacity."""

    capacity_slots: int = 1
    groups: Mapping[str, GroupSchedulingPolicy] = field(default_factory=dict)
    default_group: GroupSchedulingPolicy = field(default_factory=GroupSchedulingPolicy)
    supported_capabilities: frozenset[str] | None = None
    allowed_groups: frozenset[str] | None = None
    max_work_items: int = 10_000
    max_work_items_per_group: int = 1_000
    decline_expired: bool = False
    aging_interval: timedelta = timedelta(minutes=5)
    deadline_horizon: timedelta = timedelta(hours=1)
    priority_weight: float = 100.0
    deadline_weight: float = 1_000.0
    aging_weight: float = 25.0
    fairness_weight: float = 10.0
    quota_pressure_weight: float = 50.0
    estimate_weight: float = 1.0
    preemption_margin: float = 1.0

    def __post_init__(self) -> None:
        if self.capacity_slots < 1:
            raise ValueError("capacity_slots must be at least one")
        if self.max_work_items < 1 or self.max_work_items_per_group < 1:
            raise ValueError("admission limits must be at least one")
        if self.aging_interval.total_seconds() <= 0:
            raise ValueError("aging_interval must be positive")
        if self.deadline_horizon.total_seconds() <= 0:
            raise ValueError("deadline_horizon must be positive")
        if self.preemption_margin < 0:
            raise ValueError("preemption_margin must not be negative")

        object.__setattr__(self, "groups", MappingProxyType(dict(self.groups)))
        if self.supported_capabilities is not None:
            object.__setattr__(
                self,
                "supported_capabilities",
                frozenset(self.supported_capabilities),
            )
        if self.allowed_groups is not None:
            object.__setattr__(self, "allowed_groups", frozenset(self.allowed_groups))


class AdmissionReason(StrEnum):
    ACCEPTED = "accepted"
    DUPLICATE = "duplicate"
    IDENTIFIER_COLLISION = "identifier_collision"
    ALREADY_TERMINAL = "already_terminal"
    WORKER_FULL = "worker_full"
    GROUP_FULL = "group_full"
    GROUP_NOT_ALLOWED = "group_not_allowed"
    GROUP_QUOTA_DISABLED = "group_quota_disabled"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    EXCEEDS_CAPACITY = "exceeds_capacity"
    DEADLINE_EXPIRED = "deadline_expired"


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    accepted: bool
    reason: AdmissionReason
    work_id: str


class WorkState(StrEnum):
    READY = "ready"
    RUNNING = "running"
    PREEMPTING = "preempting"
    BLOCKED = "blocked"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class CheckpointRef:
    """An opaque reference; checkpoint content remains in its Group-scoped store."""

    checkpoint_id: str
    work_id: str
    group_id: str
    run_id: str
    created_at: datetime
    durable: bool = True
    safe: bool = True

    def __post_init__(self) -> None:
        if not self.checkpoint_id:
            raise ValueError("checkpoint_id must not be empty")
        object.__setattr__(self, "created_at", _aware(self.created_at, "checkpoint created_at"))


class TransitionKind(StrEnum):
    CHECKPOINT_SAVED = "checkpoint_saved"
    BLOCKED = "blocked"
    RELEASED = "released"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    PREEMPTED = "preempted"
    PREEMPTION_FAILED = "preemption_failed"


@dataclass(frozen=True, slots=True)
class WorkTransition:
    work_id: str
    kind: TransitionKind
    run_id: str | None = None
    checkpoint: CheckpointRef | None = None
    retry_at: datetime | None = None
    reason: str | None = None

    def __post_init__(self) -> None:
        if self.retry_at is not None:
            object.__setattr__(self, "retry_at", _aware(self.retry_at, "retry_at"))


@dataclass(frozen=True, slots=True)
class Dispatch:
    work_id: str
    group_id: str
    run_id: str
    slots: int
    capability: str | None
    resume_from: CheckpointRef | None = None


@dataclass(frozen=True, slots=True)
class Preempt:
    work_id: str
    group_id: str
    run_id: str
    checkpoint: CheckpointRef


type ScheduleAction = Dispatch | Preempt


@dataclass(frozen=True, slots=True)
class QueueRecord:
    """Durable, content-free reconstruction record for one local WorkItem."""

    offer: WorkOffer
    state: WorkState
    sequence: int
    admitted_at: datetime
    ready_since: datetime | None
    accumulated_ready_seconds: float
    generation: int
    run_id: str | None
    checkpoint: CheckpointRef | None
    retry_at: datetime | None
    blocked_reason: str | None


@dataclass(frozen=True, slots=True)
class SchedulerSnapshot:
    """Immutable local projection suitable for a durable store Adapter."""

    version: int
    records: tuple[QueueRecord, ...]
    fair_credit: tuple[tuple[str, float], ...]
    next_sequence: int


class SchedulerStateError(RuntimeError):
    """Raised when a stale or unsafe Worker transition crosses the Interface."""


@dataclass(slots=True)
class _Entry:
    offer: WorkOffer
    state: WorkState
    sequence: int
    admitted_at: datetime
    ready_since: datetime | None
    accumulated_ready_seconds: float = 0.0
    generation: int = 0
    run_id: str | None = None
    checkpoint: CheckpointRef | None = None
    retry_at: datetime | None = None
    blocked_reason: str | None = None


class Scheduler:
    """One weighted-fair Scheduler across all of a Worker's per-Group queues."""

    def __init__(
        self,
        policy: SchedulerPolicy | None = None,
        *,
        clock: Clock = _utc_now,
    ) -> None:
        self._policy = policy or SchedulerPolicy()
        self._clock = clock
        self._entries: dict[str, _Entry] = {}
        self._ready: dict[str, dict[str, _Entry]] = {}
        self._fair_credit: dict[str, float] = {}
        self._next_sequence = 0

    @classmethod
    def rebuild(
        cls,
        source: SchedulerSnapshot | Iterable[WorkOffer],
        policy: SchedulerPolicy | None = None,
        *,
        clock: Clock = _utc_now,
    ) -> Scheduler:
        """Reconstruct queues from a snapshot or authoritative eligible WorkOffers.

        A previous runtime's running work is never assumed to still execute.  A running
        record with a durable safe checkpoint becomes ready to resume.  One without such
        a checkpoint becomes blocked until lease/session reconciliation explicitly releases it.
        """

        scheduler = cls(policy, clock=clock)
        if not isinstance(source, SchedulerSnapshot):
            for offer in source:
                scheduler.admit(offer)
            return scheduler

        if source.version != 1:
            raise ValueError(f"unsupported SchedulerSnapshot version {source.version}")

        now = scheduler._now()
        scheduler._next_sequence = source.next_sequence
        scheduler._fair_credit = dict(source.fair_credit)
        for record in source.records:
            if record.offer.work_id in scheduler._entries:
                raise ValueError(f"duplicate work_id in snapshot: {record.offer.work_id}")

            state = record.state
            ready_since = record.ready_since
            run_id = record.run_id
            retry_at = record.retry_at
            blocked_reason = record.blocked_reason
            checkpoint = record.checkpoint

            if state in {WorkState.RUNNING, WorkState.PREEMPTING}:
                run_id = None
                if checkpoint is not None and checkpoint.durable and checkpoint.safe:
                    state = WorkState.READY
                    ready_since = now
                    retry_at = None
                    blocked_reason = None
                else:
                    state = WorkState.BLOCKED
                    ready_since = None
                    retry_at = None
                    blocked_reason = "runtime-session-lost"

            entry = _Entry(
                offer=record.offer,
                state=state,
                sequence=record.sequence,
                admitted_at=record.admitted_at,
                ready_since=ready_since,
                accumulated_ready_seconds=record.accumulated_ready_seconds,
                generation=record.generation,
                run_id=run_id,
                checkpoint=checkpoint,
                retry_at=retry_at,
                blocked_reason=blocked_reason,
            )
            scheduler._entries[entry.offer.work_id] = entry
            if entry.state is WorkState.READY:
                scheduler._put_ready(entry, now, preserve_ready_since=True)
        return scheduler

    def admit(self, offer: WorkOffer, *, now: datetime | None = None) -> AdmissionDecision:
        """Admit a sanitized WorkOffer into its Group's durable ready queue."""

        current = self._entries.get(offer.work_id)
        if current is not None:
            if current.offer != offer:
                return AdmissionDecision(
                    False,
                    AdmissionReason.IDENTIFIER_COLLISION,
                    offer.work_id,
                )
            if current.state in {WorkState.COMPLETED, WorkState.CANCELLED}:
                return AdmissionDecision(False, AdmissionReason.ALREADY_TERMINAL, offer.work_id)
            return AdmissionDecision(True, AdmissionReason.DUPLICATE, offer.work_id)

        when = self._resolve_now(now)
        group_policy = self._group_policy(offer.group_id)
        active_entries = [entry for entry in self._entries.values() if not self._terminal(entry)]
        group_entries = [
            entry for entry in active_entries if entry.offer.group_id == offer.group_id
        ]

        reason: AdmissionReason | None = None
        if (
            self._policy.allowed_groups is not None
            and offer.group_id not in self._policy.allowed_groups
        ):
            reason = AdmissionReason.GROUP_NOT_ALLOWED
        elif group_policy.slot_quota == 0:
            reason = AdmissionReason.GROUP_QUOTA_DISABLED
        elif offer.estimate.slots > self._policy.capacity_slots or (
            group_policy.slot_quota is not None and offer.estimate.slots > group_policy.slot_quota
        ):
            reason = AdmissionReason.EXCEEDS_CAPACITY
        elif (
            offer.capability is not None
            and self._policy.supported_capabilities is not None
            and offer.capability not in self._policy.supported_capabilities
        ):
            reason = AdmissionReason.UNSUPPORTED_CAPABILITY
        elif len(active_entries) >= self._policy.max_work_items:
            reason = AdmissionReason.WORKER_FULL
        elif len(group_entries) >= self._policy.max_work_items_per_group:
            reason = AdmissionReason.GROUP_FULL
        elif self._policy.decline_expired and offer.deadline is not None and offer.deadline <= when:
            reason = AdmissionReason.DEADLINE_EXPIRED

        if reason is not None:
            return AdmissionDecision(False, reason, offer.work_id)

        entry = _Entry(
            offer=offer,
            state=WorkState.READY,
            sequence=self._next_sequence,
            admitted_at=when,
            ready_since=when,
        )
        self._next_sequence += 1
        self._entries[offer.work_id] = entry
        self._put_ready(entry, when, preserve_ready_since=True)
        return AdmissionDecision(True, AdmissionReason.ACCEPTED, offer.work_id)

    def schedule(self, *, now: datetime | None = None) -> tuple[ScheduleAction, ...]:
        """Fill free slots, then request at most one safe checkpoint preemption."""

        when = self._resolve_now(now)
        self._release_due(when)
        actions: list[ScheduleAction] = []

        while self._free_slots() > 0:
            eligible = self._eligible_ready(self._free_slots())
            if not eligible:
                break

            ready_groups = self._ready_group_ids()
            total_weight = self._accrue_fair_credit(ready_groups)
            entry = max(
                eligible,
                key=lambda candidate: (
                    self._score(candidate, when),
                    -candidate.sequence,
                ),
            )
            self._fair_credit[entry.offer.group_id] -= total_weight
            actions.append(self._dispatch(entry, when))

        preemption = self._request_preemption(when)
        if preemption is not None:
            actions.append(preemption)
        return tuple(actions)

    def apply(self, transition: WorkTransition, *, now: datetime | None = None) -> None:
        """Apply one fenced runtime transition and update capacity/queue state."""

        when = self._resolve_now(now)
        entry = self._entry(transition.work_id)

        if transition.kind is TransitionKind.CHECKPOINT_SAVED:
            self._require_state(entry, WorkState.RUNNING)
            self._require_current_run(entry, transition.run_id)
            checkpoint = transition.checkpoint
            if checkpoint is None:
                raise SchedulerStateError("checkpoint_saved requires a checkpoint")
            self._validate_checkpoint(entry, checkpoint)
            entry.checkpoint = checkpoint
            return

        if transition.kind is TransitionKind.BLOCKED:
            if entry.state is WorkState.READY:
                self._leave_ready(entry, when)
            elif entry.state in {WorkState.RUNNING, WorkState.PREEMPTING}:
                self._require_current_run(entry, transition.run_id)
            else:
                raise SchedulerStateError(
                    f"cannot block {entry.offer.work_id} from {entry.state.value}"
                )
            if transition.checkpoint is not None:
                self._validate_checkpoint(entry, transition.checkpoint)
                entry.checkpoint = transition.checkpoint
            entry.state = WorkState.BLOCKED
            entry.run_id = None
            entry.ready_since = None
            entry.retry_at = transition.retry_at
            entry.blocked_reason = transition.reason
            return

        if transition.kind is TransitionKind.RELEASED:
            self._require_state(entry, WorkState.BLOCKED)
            entry.retry_at = None
            entry.blocked_reason = None
            self._put_ready(entry, when)
            return

        if transition.kind in {TransitionKind.COMPLETED, TransitionKind.CANCELLED}:
            if entry.state is WorkState.READY:
                self._leave_ready(entry, when)
            elif entry.state in {WorkState.RUNNING, WorkState.PREEMPTING}:
                self._require_current_run(entry, transition.run_id)
            elif entry.state not in {WorkState.BLOCKED}:
                raise SchedulerStateError(
                    f"cannot terminate {entry.offer.work_id} from {entry.state.value}"
                )
            entry.state = (
                WorkState.COMPLETED
                if transition.kind is TransitionKind.COMPLETED
                else WorkState.CANCELLED
            )
            entry.run_id = None
            entry.ready_since = None
            entry.retry_at = None
            entry.blocked_reason = transition.reason
            entry.checkpoint = None
            return

        if transition.kind is TransitionKind.PREEMPTED:
            self._require_state(entry, WorkState.PREEMPTING)
            self._require_current_run(entry, transition.run_id)
            checkpoint = transition.checkpoint or entry.checkpoint
            if checkpoint is None or not checkpoint.durable or not checkpoint.safe:
                raise SchedulerStateError("preempted work requires its durable safe checkpoint")
            self._validate_checkpoint(entry, checkpoint)
            entry.checkpoint = checkpoint
            entry.run_id = None
            self._put_ready(entry, when)
            return

        if transition.kind is TransitionKind.PREEMPTION_FAILED:
            self._require_state(entry, WorkState.PREEMPTING)
            self._require_current_run(entry, transition.run_id)
            entry.state = WorkState.RUNNING
            # Execution continued after the checkpoint, so a new checkpoint is required.
            entry.checkpoint = None
            return

        raise SchedulerStateError(f"unsupported transition {transition.kind}")

    def snapshot(self) -> SchedulerSnapshot:
        """Return a durable local projection containing no Group content."""

        records = tuple(
            QueueRecord(
                offer=entry.offer,
                state=entry.state,
                sequence=entry.sequence,
                admitted_at=entry.admitted_at,
                ready_since=entry.ready_since,
                accumulated_ready_seconds=entry.accumulated_ready_seconds,
                generation=entry.generation,
                run_id=entry.run_id,
                checkpoint=entry.checkpoint,
                retry_at=entry.retry_at,
                blocked_reason=entry.blocked_reason,
            )
            for entry in sorted(self._entries.values(), key=lambda item: item.sequence)
        )
        return SchedulerSnapshot(
            version=1,
            records=records,
            fair_credit=tuple(sorted(self._fair_credit.items())),
            next_sequence=self._next_sequence,
        )

    def _now(self) -> datetime:
        return _aware(self._clock(), "clock result")

    def _resolve_now(self, now: datetime | None) -> datetime:
        return self._now() if now is None else _aware(now, "now")

    def _group_policy(self, group_id: str) -> GroupSchedulingPolicy:
        return self._policy.groups.get(group_id, self._policy.default_group)

    @staticmethod
    def _terminal(entry: _Entry) -> bool:
        return entry.state in {WorkState.COMPLETED, WorkState.CANCELLED}

    def _entry(self, work_id: str) -> _Entry:
        try:
            return self._entries[work_id]
        except KeyError as error:
            raise SchedulerStateError(f"unknown work_id {work_id}") from error

    @staticmethod
    def _require_state(entry: _Entry, expected: WorkState) -> None:
        if entry.state is not expected:
            raise SchedulerStateError(
                f"{entry.offer.work_id} is {entry.state.value}, expected {expected.value}"
            )

    @staticmethod
    def _require_current_run(entry: _Entry, run_id: str | None) -> None:
        if run_id is None or entry.run_id != run_id:
            raise SchedulerStateError(
                f"stale run for {entry.offer.work_id}: {run_id!r} != {entry.run_id!r}"
            )

    @staticmethod
    def _validate_checkpoint(entry: _Entry, checkpoint: CheckpointRef) -> None:
        if checkpoint.work_id != entry.offer.work_id:
            raise SchedulerStateError("checkpoint belongs to another WorkItem")
        if checkpoint.group_id != entry.offer.group_id:
            raise SchedulerStateError("checkpoint belongs to another Group")
        if checkpoint.run_id != entry.run_id:
            raise SchedulerStateError("checkpoint belongs to a stale run")

    def _put_ready(
        self,
        entry: _Entry,
        now: datetime,
        *,
        preserve_ready_since: bool = False,
    ) -> None:
        entry.state = WorkState.READY
        entry.run_id = None
        entry.retry_at = None
        entry.blocked_reason = None
        if not preserve_ready_since or entry.ready_since is None:
            entry.ready_since = now
        self._ready.setdefault(entry.offer.group_id, {})[entry.offer.work_id] = entry
        self._fair_credit.setdefault(entry.offer.group_id, 0.0)

    def _leave_ready(self, entry: _Entry, now: datetime) -> None:
        if entry.ready_since is not None:
            entry.accumulated_ready_seconds += max(
                0.0,
                (now - entry.ready_since).total_seconds(),
            )
        entry.ready_since = None
        group_queue = self._ready.get(entry.offer.group_id)
        if group_queue is not None:
            group_queue.pop(entry.offer.work_id, None)
            if not group_queue:
                self._ready.pop(entry.offer.group_id, None)

    def _release_due(self, now: datetime) -> None:
        due = [
            entry
            for entry in self._entries.values()
            if entry.state is WorkState.BLOCKED
            and entry.retry_at is not None
            and entry.retry_at <= now
        ]
        for entry in due:
            self._put_ready(entry, now)

    def _capacity_used(self) -> int:
        return sum(
            entry.offer.estimate.slots
            for entry in self._entries.values()
            if entry.state in {WorkState.RUNNING, WorkState.PREEMPTING}
        )

    def _free_slots(self) -> int:
        return self._policy.capacity_slots - self._capacity_used()

    def _group_running_slots(self, group_id: str) -> int:
        return sum(
            entry.offer.estimate.slots
            for entry in self._entries.values()
            if entry.offer.group_id == group_id
            and entry.state in {WorkState.RUNNING, WorkState.PREEMPTING}
        )

    def _fits_group_quota(self, entry: _Entry, *, releasing: _Entry | None = None) -> bool:
        group_policy = self._group_policy(entry.offer.group_id)
        quota = group_policy.slot_quota
        if quota is None:
            return True
        used = self._group_running_slots(entry.offer.group_id)
        if releasing is not None and releasing.offer.group_id == entry.offer.group_id:
            used -= releasing.offer.estimate.slots
        return used + entry.offer.estimate.slots <= quota

    def _eligible_ready(self, free_slots: int) -> list[_Entry]:
        return [
            entry
            for group in self._ready.values()
            for entry in group.values()
            if entry.offer.estimate.slots <= free_slots and self._fits_group_quota(entry)
        ]

    def _ready_group_ids(self) -> tuple[str, ...]:
        return tuple(sorted(group_id for group_id, queue in self._ready.items() if queue))

    def _accrue_fair_credit(self, group_ids: Iterable[str]) -> float:
        ids = tuple(group_ids)
        total_weight = float(sum(self._group_policy(group_id).weight for group_id in ids))
        for group_id in ids:
            self._fair_credit[group_id] = self._fair_credit.get(group_id, 0.0) + float(
                self._group_policy(group_id).weight
            )
        return total_weight

    def _waiting_seconds(self, entry: _Entry, now: datetime) -> float:
        current = 0.0
        if entry.state is WorkState.READY and entry.ready_since is not None:
            current = max(0.0, (now - entry.ready_since).total_seconds())
        return entry.accumulated_ready_seconds + current

    def _deadline_bonus(self, entry: _Entry, now: datetime) -> float:
        deadline = entry.offer.deadline
        if deadline is None:
            return 0.0
        horizon = self._policy.deadline_horizon.total_seconds()
        remaining = (deadline - now).total_seconds()
        if remaining <= 0:
            return self._policy.deadline_weight * (2.0 + min(abs(remaining) / horizon, 10.0))
        if remaining >= horizon:
            return 0.0
        return self._policy.deadline_weight * (1.0 - remaining / horizon)

    def _score(self, entry: _Entry, now: datetime) -> float:
        group_policy = self._group_policy(entry.offer.group_id)
        priority = entry.offer.organizational_priority + group_policy.priority_bias
        age_steps = self._waiting_seconds(entry, now) / self._policy.aging_interval.total_seconds()
        quota = group_policy.slot_quota or self._policy.capacity_slots
        quota_pressure = self._group_running_slots(entry.offer.group_id) / quota
        return (
            priority * self._policy.priority_weight
            + age_steps * self._policy.aging_weight
            + self._deadline_bonus(entry, now)
            + self._fair_credit.get(entry.offer.group_id, 0.0) * self._policy.fairness_weight
            - quota_pressure * self._policy.quota_pressure_weight
            - int(entry.offer.estimate.effort) * self._policy.estimate_weight
        )

    def _dispatch(self, entry: _Entry, now: datetime) -> Dispatch:
        self._leave_ready(entry, now)
        resume_from = entry.checkpoint
        entry.checkpoint = None
        entry.state = WorkState.RUNNING
        entry.generation += 1
        entry.run_id = f"{entry.offer.work_id}:{entry.generation}"
        return Dispatch(
            work_id=entry.offer.work_id,
            group_id=entry.offer.group_id,
            run_id=entry.run_id,
            slots=entry.offer.estimate.slots,
            capability=entry.offer.capability,
            resume_from=resume_from,
        )

    def _request_preemption(self, now: datetime) -> Preempt | None:
        if not self._ready:
            return None

        free_slots = self._free_slots()
        ready_candidates = [
            entry
            for queue in self._ready.values()
            for entry in queue.values()
            if entry.offer.estimate.slots <= self._policy.capacity_slots
        ]
        victims = [
            entry
            for entry in self._entries.values()
            if entry.state is WorkState.RUNNING
            and entry.offer.preemptible
            and entry.run_id is not None
            and entry.checkpoint is not None
            and entry.checkpoint.run_id == entry.run_id
            and entry.checkpoint.durable
            and entry.checkpoint.safe
        ]

        best: tuple[float, _Entry, _Entry] | None = None
        for candidate in ready_candidates:
            for victim in victims:
                if candidate.offer.work_id == victim.offer.work_id:
                    continue
                if free_slots + victim.offer.estimate.slots < candidate.offer.estimate.slots:
                    continue
                if not self._fits_group_quota(candidate, releasing=victim):
                    continue
                improvement = self._score(candidate, now) - self._score(victim, now)
                if improvement <= self._policy.preemption_margin:
                    continue
                choice = (improvement, candidate, victim)
                if best is None or (choice[0], -choice[1].sequence, choice[2].sequence) > (
                    best[0],
                    -best[1].sequence,
                    best[2].sequence,
                ):
                    best = choice

        if best is None:
            return None

        victim = best[2]
        checkpoint = victim.checkpoint
        if checkpoint is None or victim.run_id is None:  # narrowed above; protects refactors
            return None
        victim.state = WorkState.PREEMPTING
        return Preempt(
            work_id=victim.offer.work_id,
            group_id=victim.offer.group_id,
            run_id=victim.run_id,
            checkpoint=checkpoint,
        )


__all__ = [
    "AdmissionDecision",
    "AdmissionReason",
    "CheckpointRef",
    "Dispatch",
    "EstimateBand",
    "GroupSchedulingPolicy",
    "Preempt",
    "QueueRecord",
    "ScheduleAction",
    "Scheduler",
    "SchedulerPolicy",
    "SchedulerSnapshot",
    "SchedulerStateError",
    "SchedulingEstimate",
    "TransitionKind",
    "WorkOffer",
    "WorkState",
    "WorkTransition",
]
