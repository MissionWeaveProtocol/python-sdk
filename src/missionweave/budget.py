"""Serializable hierarchical Mission and WorkItem budget accounting."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .models import ResourceBudget, ResourceUsage

_DIMENSIONS = (
    "financial_microunits",
    "model_tokens",
    "tool_calls",
    "compute_seconds",
    "wall_clock_seconds",
    "external_actions",
)


def _to_camel(value: str) -> str:
    head, *tail = value.split("_")
    return head + "".join(part.capitalize() for part in tail)


class BudgetLedgerError(ValueError):
    """The budget hierarchy, allocation, usage, or requested account is invalid."""


class _FrozenState(BaseModel):
    model_config = ConfigDict(
        alias_generator=_to_camel,
        extra="forbid",
        frozen=True,
        populate_by_name=True,
    )


class BudgetLimitState(_FrozenState):
    """Immutable serializable form of a six-dimensional ResourceBudget."""

    financial_microunits: int | None = Field(default=None, ge=0)
    model_tokens: int | None = Field(default=None, ge=0)
    tool_calls: int | None = Field(default=None, ge=0)
    compute_seconds: int | None = Field(default=None, ge=0)
    wall_clock_seconds: int | None = Field(default=None, ge=0)
    external_actions: int | None = Field(default=None, ge=0)

    @classmethod
    def from_budget(cls, value: ResourceBudget) -> BudgetLimitState:
        return cls.model_validate(value.model_dump(mode="python"))

    def to_budget(self) -> ResourceBudget:
        return ResourceBudget.model_validate(self.model_dump(mode="python"))


class BudgetUsageState(_FrozenState):
    """Immutable serializable form of cumulative six-dimensional ResourceUsage."""

    financial_microunits: int = Field(default=0, ge=0)
    model_tokens: int = Field(default=0, ge=0)
    tool_calls: int = Field(default=0, ge=0)
    compute_seconds: int = Field(default=0, ge=0)
    wall_clock_seconds: int = Field(default=0, ge=0)
    external_actions: int = Field(default=0, ge=0)

    @classmethod
    def from_usage(cls, value: ResourceUsage) -> BudgetUsageState:
        return cls.model_validate(value.model_dump(mode="python"))

    def to_usage(self) -> ResourceUsage:
        return ResourceUsage.model_validate(self.model_dump(mode="python"))


class MissionBudgetState(_FrozenState):
    mission_id: str = Field(min_length=1)
    parent_mission_id: str | None = None
    parent_work_item_id: str | None = None
    limit: BudgetLimitState
    usage: BudgetUsageState = Field(default_factory=BudgetUsageState)


class WorkItemBudgetState(_FrozenState):
    work_item_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    parent_work_item_id: str | None = None
    limit: BudgetLimitState
    direct_usage: BudgetUsageState = Field(default_factory=BudgetUsageState)
    usage: BudgetUsageState = Field(default_factory=BudgetUsageState)


class BudgetLedgerSnapshot(_FrozenState):
    """Deeply immutable, JSON-ready authoritative ledger snapshot."""

    schema_version: Literal[2] = 2
    missions: tuple[MissionBudgetState, ...] = ()
    work_items: tuple[WorkItemBudgetState, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True)


class WorkItemBudgetStateV1(_FrozenState):
    work_item_id: str = Field(min_length=1)
    mission_id: str = Field(min_length=1)
    limit: BudgetLimitState
    usage: BudgetUsageState = Field(default_factory=BudgetUsageState)


class BudgetLedgerSnapshotV1(_FrozenState):
    schema_version: Literal[1] = 1
    missions: tuple[MissionBudgetState, ...] = ()
    work_items: tuple[WorkItemBudgetStateV1, ...] = ()


type AccountRef = tuple[Literal["mission", "work_item"], str]


class BudgetLedger:
    """Reserve hierarchical limits and atomically account WorkItem resource usage."""

    def __init__(self) -> None:
        self._missions: dict[str, MissionBudgetState] = {}
        self._work_items: dict[str, WorkItemBudgetState] = {}

    def register_mission(
        self,
        mission_id: str,
        limit: ResourceBudget,
        *,
        parent_mission_id: str | None = None,
        parent_work_item_id: str | None = None,
    ) -> None:
        """Register a root, direct child, or parent-WorkItem-backed child Mission."""

        _require_identifier(mission_id, "Mission ID")
        if parent_mission_id is not None:
            _require_identifier(parent_mission_id, "parent Mission ID")
        if parent_work_item_id is not None:
            _require_identifier(parent_work_item_id, "parent WorkItem ID")
        if mission_id in self._missions or mission_id in self._work_items:
            raise BudgetLedgerError(f"budget account already exists: {mission_id}")
        if parent_mission_id == mission_id:
            raise BudgetLedgerError("Mission budget hierarchy contains a cycle")
        if parent_mission_id is not None and parent_mission_id not in self._missions:
            raise BudgetLedgerError(f"unknown parent Mission budget: {parent_mission_id}")
        if parent_work_item_id is not None and parent_work_item_id not in self._work_items:
            raise BudgetLedgerError(f"unknown parent WorkItem budget: {parent_work_item_id}")

        candidate = dict(self._missions)
        candidate[mission_id] = MissionBudgetState(
            mission_id=mission_id,
            parent_mission_id=parent_mission_id,
            parent_work_item_id=parent_work_item_id,
            limit=BudgetLimitState.from_budget(limit),
        )
        _validate_state(candidate, self._work_items)
        self._missions = candidate

    def register_work_item(
        self,
        work_item_id: str,
        mission_id: str,
        limit: ResourceBudget,
        *,
        parent_work_item_id: str | None = None,
    ) -> None:
        """Reserve one top-level or delegated WorkItem under its immediate parent."""

        _require_identifier(work_item_id, "WorkItem ID")
        _require_identifier(mission_id, "Mission ID")
        if parent_work_item_id is not None:
            _require_identifier(parent_work_item_id, "parent WorkItem ID")
        if work_item_id in self._missions or work_item_id in self._work_items:
            raise BudgetLedgerError(f"budget account already exists: {work_item_id}")
        if mission_id not in self._missions:
            raise BudgetLedgerError(f"unknown Mission budget: {mission_id}")
        if parent_work_item_id is not None and parent_work_item_id not in self._work_items:
            raise BudgetLedgerError(f"unknown parent WorkItem budget: {parent_work_item_id}")

        candidate = dict(self._work_items)
        candidate[work_item_id] = WorkItemBudgetState(
            work_item_id=work_item_id,
            mission_id=mission_id,
            parent_work_item_id=parent_work_item_id,
            limit=BudgetLimitState.from_budget(limit),
        )
        _validate_state(self._missions, candidate)
        self._work_items = candidate

    def consume(self, work_item_id: str, delta: ResourceUsage) -> ResourceUsage:
        """Atomically charge a nonnegative delta to a WorkItem and its complete ancestry."""

        account = self._work_items.get(work_item_id)
        if account is None:
            if work_item_id in self._missions:
                raise BudgetLedgerError(f"budget account is not a WorkItem: {work_item_id}")
            raise BudgetLedgerError(f"unknown WorkItem budget: {work_item_id}")
        try:
            usage_delta = BudgetUsageState.from_usage(delta)
        except ValidationError as error:
            raise BudgetLedgerError("resource usage must be nonnegative") from error

        missions = dict(self._missions)
        work_items = dict(self._work_items)
        current: AccountRef | None = ("work_item", work_item_id)
        seen: set[AccountRef] = set()
        target = True
        while current is not None:
            if current in seen:
                raise BudgetLedgerError("budget account ancestry contains a cycle")
            seen.add(current)
            kind, account_id = current
            if kind == "work_item":
                work = work_items[account_id]
                update: dict[str, BudgetUsageState] = {"usage": _add_usage(work.usage, usage_delta)}
                if target:
                    update["direct_usage"] = _add_usage(work.direct_usage, usage_delta)
                work_items[account_id] = work.model_copy(update=update)
            else:
                mission = missions[account_id]
                missions[account_id] = mission.model_copy(
                    update={"usage": _add_usage(mission.usage, usage_delta)}
                )
            current = _parent_account(current, missions, work_items)
            target = False

        _validate_state(missions, work_items)
        self._missions = missions
        self._work_items = work_items
        return work_items[work_item_id].usage.to_usage()

    def remaining(self, account_id: str) -> ResourceBudget:
        """Return consumption capacity remaining on a Mission or WorkItem account."""

        if account_id in self._missions:
            current: AccountRef | None = ("mission", account_id)
        elif account_id in self._work_items:
            current = ("work_item", account_id)
        else:
            raise BudgetLedgerError(f"unknown budget account: {account_id}")

        effective: BudgetLimitState | None = None
        seen: set[AccountRef] = set()
        while current is not None:
            if current in seen:
                raise BudgetLedgerError("budget account ancestry contains a cycle")
            seen.add(current)
            limit, usage = _account_limit_and_usage(current, self._missions, self._work_items)
            local = _remaining(limit, usage)
            effective = local if effective is None else _minimum_remaining(effective, local)
            current = _parent_account(current, self._missions, self._work_items)
        if effective is None:  # pragma: no cover - every validated account visits itself
            raise BudgetLedgerError(f"unknown budget account: {account_id}")
        return effective.to_budget()

    def snapshot(self) -> BudgetLedgerSnapshot:
        return BudgetLedgerSnapshot(
            missions=tuple(self._missions[key] for key in sorted(self._missions)),
            work_items=tuple(self._work_items[key] for key in sorted(self._work_items)),
        )

    @classmethod
    def rebuild(
        cls,
        snapshot: BudgetLedgerSnapshot | Mapping[str, object],
    ) -> BudgetLedger:
        """Rebuild after validating serialized hierarchy, allocation, and usage invariants."""

        try:
            if isinstance(snapshot, BudgetLedgerSnapshot):
                value = snapshot
            elif _snapshot_version(snapshot) == 1:
                value = _migrate_v1(BudgetLedgerSnapshotV1.model_validate(snapshot))
            else:
                value = BudgetLedgerSnapshot.model_validate(snapshot)
        except ValidationError as error:
            raise BudgetLedgerError("budget ledger snapshot is invalid") from error

        missions: dict[str, MissionBudgetState] = {}
        work_items: dict[str, WorkItemBudgetState] = {}
        for mission_account in value.missions:
            if mission_account.mission_id in missions or mission_account.mission_id in work_items:
                raise BudgetLedgerError(
                    f"duplicate budget account in snapshot: {mission_account.mission_id}"
                )
            missions[mission_account.mission_id] = mission_account
        for work_account in value.work_items:
            if work_account.work_item_id in missions or work_account.work_item_id in work_items:
                raise BudgetLedgerError(
                    f"duplicate budget account in snapshot: {work_account.work_item_id}"
                )
            work_items[work_account.work_item_id] = work_account

        _validate_state(missions, work_items)
        ledger = cls()
        ledger._missions = dict(missions)
        ledger._work_items = dict(work_items)
        return ledger


def _validate_state(
    missions: Mapping[str, MissionBudgetState],
    work_items: Mapping[str, WorkItemBudgetState],
) -> None:
    _validate_identifiers_and_references(missions, work_items)
    _validate_account_cycles(missions, work_items)
    _validate_limits(missions, work_items)
    _validate_allocations(missions, work_items)
    _validate_usage(missions, work_items)


def _validate_identifiers_and_references(
    missions: Mapping[str, MissionBudgetState],
    work_items: Mapping[str, WorkItemBudgetState],
) -> None:
    bound_work_items: dict[str, str] = {}
    for key, mission in missions.items():
        _require_identifier(key, "Mission ID")
        if key != mission.mission_id:
            raise BudgetLedgerError("Mission budget map key does not match its account ID")
        parent_id = mission.parent_mission_id
        parent_work_id = mission.parent_work_item_id
        if parent_id is None:
            if parent_work_id is not None:
                raise BudgetLedgerError("a root Mission cannot bind a parent WorkItem")
            continue
        if parent_id not in missions:
            raise BudgetLedgerError(f"unknown parent Mission budget: {parent_id}")
        if parent_work_id is None:
            continue
        parent_work = work_items.get(parent_work_id)
        if parent_work is None:
            raise BudgetLedgerError(f"unknown parent WorkItem budget: {parent_work_id}")
        if parent_work.mission_id != parent_id:
            raise BudgetLedgerError("parent WorkItem does not belong to the parent Mission")
        previous_child = bound_work_items.get(parent_work_id)
        if previous_child is not None:
            raise BudgetLedgerError(
                f"parent WorkItem already backs child Mission: {previous_child}"
            )
        bound_work_items[parent_work_id] = mission.mission_id

    for key, work_item in work_items.items():
        _require_identifier(key, "WorkItem ID")
        if key != work_item.work_item_id:
            raise BudgetLedgerError("WorkItem budget map key does not match its account ID")
        if work_item.mission_id not in missions:
            raise BudgetLedgerError(f"unknown Mission budget: {work_item.mission_id}")
        parent_work_id = work_item.parent_work_item_id
        if parent_work_id is None:
            continue
        parent_work = work_items.get(parent_work_id)
        if parent_work is None:
            raise BudgetLedgerError(f"unknown parent WorkItem budget: {parent_work_id}")
        if parent_work.mission_id != work_item.mission_id:
            raise BudgetLedgerError("parent WorkItem does not belong to the WorkItem Mission")


def _validate_account_cycles(
    missions: Mapping[str, MissionBudgetState],
    work_items: Mapping[str, WorkItemBudgetState],
) -> None:
    visiting: set[AccountRef] = set()
    visited: set[AccountRef] = set()

    def visit(account: AccountRef) -> None:
        if account in visited:
            return
        if account in visiting:
            raise BudgetLedgerError("budget account hierarchy contains a cycle")
        visiting.add(account)
        parent = _parent_account(account, missions, work_items)
        if parent is not None:
            visit(parent)
        visiting.remove(account)
        visited.add(account)

    for mission_id in missions:
        visit(("mission", mission_id))
    for work_item_id in work_items:
        visit(("work_item", work_item_id))


def _validate_limits(
    missions: Mapping[str, MissionBudgetState],
    work_items: Mapping[str, WorkItemBudgetState],
) -> None:
    for mission in missions.values():
        parent_id = mission.parent_mission_id
        if parent_id is None:
            continue
        if mission.parent_work_item_id is None:
            parent_limit = missions[parent_id].limit
            parent_label = f"parent Mission {parent_id}"
        else:
            parent_limit = work_items[mission.parent_work_item_id].limit
            parent_label = f"parent WorkItem {mission.parent_work_item_id}"
        _require_limit_contains(parent_limit, mission.limit, mission.mission_id, parent_label)

    for work_item in work_items.values():
        if work_item.parent_work_item_id is None:
            parent_limit = missions[work_item.mission_id].limit
            parent_label = f"Mission {work_item.mission_id}"
        else:
            parent_limit = work_items[work_item.parent_work_item_id].limit
            parent_label = f"parent WorkItem {work_item.parent_work_item_id}"
        _require_limit_contains(
            parent_limit,
            work_item.limit,
            work_item.work_item_id,
            parent_label,
        )


def _validate_allocations(
    missions: Mapping[str, MissionBudgetState],
    work_items: Mapping[str, WorkItemBudgetState],
) -> None:
    for mission in missions.values():
        direct_limits = [
            work_item.limit
            for work_item in work_items.values()
            if work_item.mission_id == mission.mission_id and work_item.parent_work_item_id is None
        ]
        direct_limits.extend(
            child.limit
            for child in missions.values()
            if child.parent_mission_id == mission.mission_id and child.parent_work_item_id is None
        )
        allocated = _sum_limits(direct_limits)
        for field_name in _DIMENSIONS:
            value = getattr(allocated, field_name)
            limit = getattr(mission.limit, field_name)
            if value > 0 and limit is None:
                raise BudgetLedgerError(
                    f"Mission {mission.mission_id} allocation exceeds unspecified {field_name}"
                )
            if limit is not None and value > limit:
                raise BudgetLedgerError(
                    f"Mission {mission.mission_id} allocation exceeds budget: {field_name}"
                )

    for work_item in work_items.values():
        direct_limits = [
            child.limit
            for child in work_items.values()
            if child.parent_work_item_id == work_item.work_item_id
        ]
        direct_limits.extend(
            child.limit
            for child in missions.values()
            if child.parent_work_item_id == work_item.work_item_id
        )
        allocated = _sum_limits(direct_limits)
        for field_name in _DIMENSIONS:
            value = getattr(allocated, field_name)
            limit = getattr(work_item.limit, field_name)
            if value > 0 and limit is None:
                raise BudgetLedgerError(
                    f"WorkItem {work_item.work_item_id} allocation exceeds unspecified {field_name}"
                )
            if limit is not None and value > limit:
                raise BudgetLedgerError(
                    f"WorkItem {work_item.work_item_id} allocation exceeds budget: {field_name}"
                )


def _validate_usage(
    missions: Mapping[str, MissionBudgetState],
    work_items: Mapping[str, WorkItemBudgetState],
) -> None:
    for mission in missions.values():
        _require_usage_within_limit(mission.mission_id, mission.usage, mission.limit)
    for work_item in work_items.values():
        _require_usage_within_limit(work_item.work_item_id, work_item.usage, work_item.limit)

    for mission in missions.values():
        direct_usage = [
            work_item.usage
            for work_item in work_items.values()
            if work_item.mission_id == mission.mission_id and work_item.parent_work_item_id is None
        ]
        direct_usage.extend(
            child.usage
            for child in missions.values()
            if child.parent_mission_id == mission.mission_id and child.parent_work_item_id is None
        )
        expected = _sum_usage(direct_usage)
        if expected != mission.usage:
            raise BudgetLedgerError(
                f"Mission {mission.mission_id} cumulative usage does not match its children"
            )

    for work_item in work_items.values():
        child_usage = [
            child.usage
            for child in work_items.values()
            if child.parent_work_item_id == work_item.work_item_id
        ]
        child_usage.extend(
            child.usage
            for child in missions.values()
            if child.parent_work_item_id == work_item.work_item_id
        )
        expected = _add_usage(work_item.direct_usage, _sum_usage(child_usage))
        if expected != work_item.usage:
            raise BudgetLedgerError(
                f"WorkItem {work_item.work_item_id} cumulative usage does not match its children"
            )


def _parent_account(
    account: AccountRef,
    missions: Mapping[str, MissionBudgetState],
    work_items: Mapping[str, WorkItemBudgetState],
) -> AccountRef | None:
    kind, account_id = account
    if kind == "mission":
        mission = missions[account_id]
        if mission.parent_work_item_id is not None:
            return ("work_item", mission.parent_work_item_id)
        if mission.parent_mission_id is not None:
            return ("mission", mission.parent_mission_id)
        return None
    work_item = work_items[account_id]
    if work_item.parent_work_item_id is not None:
        return ("work_item", work_item.parent_work_item_id)
    return ("mission", work_item.mission_id)


def _account_limit_and_usage(
    account: AccountRef,
    missions: Mapping[str, MissionBudgetState],
    work_items: Mapping[str, WorkItemBudgetState],
) -> tuple[BudgetLimitState, BudgetUsageState]:
    kind, account_id = account
    if kind == "mission":
        mission = missions[account_id]
        return mission.limit, mission.usage
    work_item = work_items[account_id]
    return work_item.limit, work_item.usage


def _require_limit_contains(
    parent: BudgetLimitState,
    child: BudgetLimitState,
    child_id: str,
    parent_label: str,
) -> None:
    for field_name in _DIMENSIONS:
        child_value = getattr(child, field_name)
        if child_value is None:
            continue
        parent_value = getattr(parent, field_name)
        if parent_value is None or child_value > parent_value:
            raise BudgetLedgerError(f"budget for {child_id} exceeds {parent_label}: {field_name}")


def _require_usage_within_limit(
    account_id: str,
    usage: BudgetUsageState,
    limit: BudgetLimitState,
) -> None:
    for field_name in _DIMENSIONS:
        used = getattr(usage, field_name)
        allowed = getattr(limit, field_name)
        if used > 0 and allowed is None:
            raise BudgetLedgerError(f"budget overflow for {account_id}: unspecified {field_name}")
        if allowed is not None and used > allowed:
            raise BudgetLedgerError(f"budget overflow for {account_id}: {field_name}")


def _sum_limits(values: list[BudgetLimitState]) -> BudgetUsageState:
    totals = {field_name: 0 for field_name in _DIMENSIONS}
    for value in values:
        for field_name in _DIMENSIONS:
            amount = getattr(value, field_name)
            if amount is not None:
                totals[field_name] += amount
    return BudgetUsageState.model_validate(totals)


def _sum_usage(values: list[BudgetUsageState]) -> BudgetUsageState:
    total = BudgetUsageState()
    for value in values:
        total = _add_usage(total, value)
    return total


def _add_usage(left: BudgetUsageState, right: BudgetUsageState) -> BudgetUsageState:
    return BudgetUsageState(
        **{
            field_name: getattr(left, field_name) + getattr(right, field_name)
            for field_name in _DIMENSIONS
        }
    )


def _remaining(limit: BudgetLimitState, usage: BudgetUsageState) -> BudgetLimitState:
    values: dict[str, int | None] = {}
    for field_name in _DIMENSIONS:
        maximum = getattr(limit, field_name)
        values[field_name] = None if maximum is None else maximum - getattr(usage, field_name)
    return BudgetLimitState.model_validate(values)


def _minimum_remaining(left: BudgetLimitState, right: BudgetLimitState) -> BudgetLimitState:
    values: dict[str, int | None] = {}
    for field_name in _DIMENSIONS:
        left_value = getattr(left, field_name)
        right_value = getattr(right, field_name)
        values[field_name] = (
            None if left_value is None or right_value is None else min(left_value, right_value)
        )
    return BudgetLimitState.model_validate(values)


def _subtract_usage(total: BudgetUsageState, rolled_up: BudgetUsageState) -> BudgetUsageState:
    values: dict[str, int] = {}
    for field_name in _DIMENSIONS:
        value = getattr(total, field_name) - getattr(rolled_up, field_name)
        if value < 0:
            raise BudgetLedgerError("legacy parent WorkItem usage is below its child Mission usage")
        values[field_name] = value
    return BudgetUsageState.model_validate(values)


def _snapshot_version(snapshot: Mapping[str, object]) -> int:
    value = snapshot.get("schemaVersion", snapshot.get("schema_version", 2))
    return value if isinstance(value, int) else -1


def _migrate_v1(snapshot: BudgetLedgerSnapshotV1) -> BudgetLedgerSnapshot:
    work_items: list[WorkItemBudgetState] = []
    for work_item in snapshot.work_items:
        child_usage = _sum_usage(
            [
                mission.usage
                for mission in snapshot.missions
                if mission.parent_work_item_id == work_item.work_item_id
            ]
        )
        work_items.append(
            WorkItemBudgetState(
                work_item_id=work_item.work_item_id,
                mission_id=work_item.mission_id,
                limit=work_item.limit,
                direct_usage=_subtract_usage(work_item.usage, child_usage),
                usage=work_item.usage,
            )
        )
    return BudgetLedgerSnapshot(
        missions=snapshot.missions,
        work_items=tuple(work_items),
    )


def _require_identifier(value: str, label: str) -> None:
    if not value.strip():
        raise BudgetLedgerError(f"{label} must be nonempty")


__all__ = [
    "BudgetLedger",
    "BudgetLedgerError",
    "BudgetLedgerSnapshot",
    "BudgetLimitState",
    "BudgetUsageState",
    "MissionBudgetState",
    "WorkItemBudgetState",
]
