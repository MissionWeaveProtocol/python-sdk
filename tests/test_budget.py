from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from missionweaveprotocol.budget import (
    BudgetLedger,
    BudgetLedgerError,
    BudgetLedgerSnapshot,
    BudgetLimitState,
    BudgetUsageState,
    MissionBudgetState,
    WorkItemBudgetState,
)
from missionweaveprotocol.models import ResourceBudget
from missionweaveprotocol.policy import ResourceUsage

DIMENSIONS = tuple(ResourceUsage.model_fields)


def _full_budget(value: int) -> ResourceBudget:
    return ResourceBudget(**{dimension: value for dimension in DIMENSIONS})


def _full_usage(value: int) -> ResourceUsage:
    return ResourceUsage(**{dimension: value for dimension in DIMENSIONS})


def test_bound_child_mission_reuses_parent_work_reservation_and_rolls_up_once() -> None:
    ledger = BudgetLedger()
    ledger.register_mission("mission:root", _full_budget(100))
    ledger.register_work_item("work:parent", "mission:root", _full_budget(60))
    ledger.register_mission(
        "mission:child",
        _full_budget(60),
        parent_mission_id="mission:root",
        parent_work_item_id="work:parent",
    )
    ledger.register_work_item("work:child", "mission:child", _full_budget(60))
    ledger.register_work_item("work:root-sibling", "mission:root", _full_budget(40))

    ledger.consume("work:child", _full_usage(10))

    snapshot = ledger.snapshot()
    mission_usage = {account.mission_id: account.usage for account in snapshot.missions}
    work_usage = {account.work_item_id: account.usage for account in snapshot.work_items}
    assert mission_usage["mission:child"] == BudgetUsageState.from_usage(_full_usage(10))
    assert mission_usage["mission:root"] == BudgetUsageState.from_usage(_full_usage(10))
    assert work_usage["work:child"] == BudgetUsageState.from_usage(_full_usage(10))
    assert work_usage["work:parent"] == BudgetUsageState.from_usage(_full_usage(10))
    assert ledger.remaining("mission:root") == _full_budget(90)
    assert ledger.remaining("work:parent") == _full_budget(50)

    ledger.consume("work:parent", _full_usage(50))
    before_overflow = ledger.snapshot()
    with pytest.raises(BudgetLedgerError, match="work:parent"):
        ledger.consume("work:child", _full_usage(1))
    assert ledger.snapshot() == before_overflow
    assert ledger.remaining("mission:root") == _full_budget(40)
    assert ledger.remaining("work:parent") == _full_budget(0)
    assert ledger.remaining("mission:child") == _full_budget(0)


def test_nested_work_items_reuse_parent_reservation_and_roll_up_once() -> None:
    ledger = BudgetLedger()
    ledger.register_mission("mission:root", _full_budget(100))
    ledger.register_work_item("work:parent", "mission:root", _full_budget(60))
    ledger.register_work_item(
        "work:child-a",
        "mission:root",
        _full_budget(35),
        parent_work_item_id="work:parent",
    )
    ledger.register_work_item(
        "work:child-b",
        "mission:root",
        _full_budget(25),
        parent_work_item_id="work:parent",
    )
    ledger.register_work_item("work:root-sibling", "mission:root", _full_budget(40))

    ledger.consume("work:child-a", _full_usage(10))

    snapshot = ledger.snapshot()
    work = {account.work_item_id: account for account in snapshot.work_items}
    mission = {account.mission_id: account for account in snapshot.missions}
    expected = BudgetUsageState.from_usage(_full_usage(10))
    assert work["work:child-a"].direct_usage == expected
    assert work["work:child-a"].usage == expected
    assert work["work:parent"].direct_usage == BudgetUsageState()
    assert work["work:parent"].usage == expected
    assert mission["mission:root"].usage == expected
    assert ledger.remaining("work:child-a") == _full_budget(25)
    assert ledger.remaining("work:parent") == _full_budget(50)
    assert ledger.remaining("mission:root") == _full_budget(90)

    before = ledger.snapshot()
    with pytest.raises(BudgetLedgerError, match="work:parent"):
        ledger.register_work_item(
            "work:child-overflow",
            "mission:root",
            _full_budget(1),
            parent_work_item_id="work:parent",
        )
    assert ledger.snapshot() == before


def test_bound_child_mission_effective_remaining_is_capped_by_prior_parent_usage() -> None:
    ledger = BudgetLedger()
    ledger.register_mission("mission:root", ResourceBudget(model_tokens=100))
    ledger.register_work_item(
        "work:parent",
        "mission:root",
        ResourceBudget(model_tokens=60),
    )
    ledger.consume("work:parent", ResourceUsage(model_tokens=50))
    ledger.register_mission(
        "mission:child",
        ResourceBudget(model_tokens=60),
        parent_mission_id="mission:root",
        parent_work_item_id="work:parent",
    )
    ledger.register_work_item(
        "work:child",
        "mission:child",
        ResourceBudget(model_tokens=60),
    )
    assert ledger.remaining("mission:child").model_tokens == 10
    assert ledger.remaining("work:child").model_tokens == 10

    ledger.consume("work:child", ResourceUsage(model_tokens=10))

    assert ledger.remaining("mission:child").model_tokens == 0
    assert ledger.remaining("work:parent").model_tokens == 0
    assert ledger.remaining("mission:root").model_tokens == 40


def test_mixed_work_and_child_mission_ancestry_rolls_up_generically() -> None:
    ledger = BudgetLedger()
    ledger.register_mission("mission:root", ResourceBudget(model_tokens=100))
    ledger.register_work_item(
        "work:root",
        "mission:root",
        ResourceBudget(model_tokens=80),
    )
    ledger.register_work_item(
        "work:delegated",
        "mission:root",
        ResourceBudget(model_tokens=60),
        parent_work_item_id="work:root",
    )
    ledger.register_mission(
        "mission:child",
        ResourceBudget(model_tokens=50),
        parent_mission_id="mission:root",
        parent_work_item_id="work:delegated",
    )
    ledger.register_work_item(
        "work:leaf",
        "mission:child",
        ResourceBudget(model_tokens=50),
    )

    ledger.consume("work:leaf", ResourceUsage(model_tokens=7))

    snapshot = ledger.snapshot()
    missions = {account.mission_id: account for account in snapshot.missions}
    work_items = {account.work_item_id: account for account in snapshot.work_items}
    assert missions["mission:child"].usage.model_tokens == 7
    assert missions["mission:root"].usage.model_tokens == 7
    assert work_items["work:leaf"].direct_usage.model_tokens == 7
    assert work_items["work:delegated"].direct_usage.model_tokens == 0
    assert work_items["work:delegated"].usage.model_tokens == 7
    assert work_items["work:root"].usage.model_tokens == 7

    ledger.consume("work:root", ResourceUsage(model_tokens=70))
    assert ledger.remaining("work:leaf").model_tokens == 3
    assert ledger.remaining("mission:child").model_tokens == 3
    before = ledger.snapshot()
    with pytest.raises(BudgetLedgerError, match="work:root"):
        ledger.consume("work:leaf", ResourceUsage(model_tokens=4))
    assert ledger.snapshot() == before


def test_direct_child_and_work_reservations_are_aggregate_and_atomic() -> None:
    ledger = BudgetLedger()
    ledger.register_mission("mission:root", ResourceBudget(model_tokens=100))
    ledger.register_mission(
        "mission:child",
        ResourceBudget(model_tokens=60),
        parent_mission_id="mission:root",
    )
    ledger.register_work_item(
        "work:root",
        "mission:root",
        ResourceBudget(model_tokens=40),
    )
    before = ledger.snapshot()

    with pytest.raises(BudgetLedgerError, match="allocation exceeds budget: model_tokens"):
        ledger.register_work_item(
            "work:overflow",
            "mission:root",
            ResourceBudget(model_tokens=1),
        )
    assert ledger.snapshot() == before

    ledger.register_work_item(
        "work:child-a",
        "mission:child",
        ResourceBudget(model_tokens=35),
    )
    with pytest.raises(BudgetLedgerError, match="allocation exceeds budget: model_tokens"):
        ledger.register_work_item(
            "work:child-b",
            "mission:child",
            ResourceBudget(model_tokens=26),
        )


def test_limits_must_fit_parent_mission_or_parent_work_item() -> None:
    ledger = BudgetLedger()
    ledger.register_mission("mission:root", ResourceBudget(model_tokens=100))
    with pytest.raises(BudgetLedgerError, match="exceeds parent Mission"):
        ledger.register_mission(
            "mission:too-large",
            ResourceBudget(model_tokens=101),
            parent_mission_id="mission:root",
        )

    ledger.register_work_item(
        "work:parent",
        "mission:root",
        ResourceBudget(model_tokens=60),
    )
    with pytest.raises(BudgetLedgerError, match="exceeds parent WorkItem"):
        ledger.register_mission(
            "mission:child",
            ResourceBudget(model_tokens=61),
            parent_mission_id="mission:root",
            parent_work_item_id="work:parent",
        )


def test_unspecified_dimensions_reserve_and_consume_zero() -> None:
    ledger = BudgetLedger()
    ledger.register_mission("mission:root", ResourceBudget(model_tokens=10))
    ledger.register_work_item(
        "work:no-token-allocation",
        "mission:root",
        ResourceBudget(),
    )
    assert ledger.remaining("work:no-token-allocation") == ResourceBudget()

    with pytest.raises(BudgetLedgerError, match="unspecified model_tokens"):
        ledger.consume(
            "work:no-token-allocation",
            ResourceUsage(model_tokens=1),
        )

    ledger_without_tools = BudgetLedger()
    ledger_without_tools.register_mission(
        "mission:no-tools",
        ResourceBudget(model_tokens=10),
    )
    with pytest.raises(BudgetLedgerError, match="tool_calls"):
        ledger_without_tools.register_work_item(
            "work:tool",
            "mission:no-tools",
            ResourceBudget(tool_calls=1),
        )


@pytest.mark.parametrize("dimension", DIMENSIONS)
def test_each_budget_dimension_overflow_is_rejected_atomically(dimension: str) -> None:
    ledger = BudgetLedger()
    budget = ResourceBudget(**{dimension: 5})
    ledger.register_mission("mission:root", budget)
    ledger.register_work_item("work:item", "mission:root", budget)
    ledger.consume("work:item", ResourceUsage(**{dimension: 3}))
    before = ledger.snapshot()

    with pytest.raises(BudgetLedgerError, match=dimension):
        ledger.consume("work:item", ResourceUsage(**{dimension: 3}))

    assert ledger.snapshot() == before
    assert getattr(ledger.remaining("work:item"), dimension) == 2
    assert getattr(ledger.remaining("mission:root"), dimension) == 2


def test_unbound_child_usage_rolls_up_to_all_ancestor_missions() -> None:
    ledger = BudgetLedger()
    ledger.register_mission("mission:root", ResourceBudget(model_tokens=100))
    ledger.register_mission(
        "mission:child",
        ResourceBudget(model_tokens=60),
        parent_mission_id="mission:root",
    )
    ledger.register_mission(
        "mission:grandchild",
        ResourceBudget(model_tokens=40),
        parent_mission_id="mission:child",
    )
    ledger.register_work_item(
        "work:leaf",
        "mission:grandchild",
        ResourceBudget(model_tokens=40),
    )

    ledger.consume("work:leaf", ResourceUsage(model_tokens=7))

    assert ledger.remaining("work:leaf").model_tokens == 33
    assert ledger.remaining("mission:grandchild").model_tokens == 33
    assert ledger.remaining("mission:child").model_tokens == 53
    assert ledger.remaining("mission:root").model_tokens == 93


def test_duplicate_unknown_and_invalid_parent_accounts_are_rejected() -> None:
    ledger = BudgetLedger()
    ledger.register_mission("mission:root", ResourceBudget(model_tokens=10))

    with pytest.raises(BudgetLedgerError, match="already exists"):
        ledger.register_mission("mission:root", ResourceBudget(model_tokens=10))
    with pytest.raises(BudgetLedgerError, match="already exists"):
        ledger.register_work_item(
            "mission:root",
            "mission:root",
            ResourceBudget(),
        )
    with pytest.raises(BudgetLedgerError, match="unknown parent Mission"):
        ledger.register_mission(
            "mission:orphan",
            ResourceBudget(),
            parent_mission_id="mission:missing",
        )
    with pytest.raises(BudgetLedgerError, match="unknown Mission"):
        ledger.register_work_item("work:orphan", "mission:missing", ResourceBudget())
    with pytest.raises(BudgetLedgerError, match="unknown WorkItem"):
        ledger.consume("work:missing", ResourceUsage())
    with pytest.raises(BudgetLedgerError, match="unknown budget account"):
        ledger.remaining("missing")


def test_parent_work_binding_requires_matching_parent_and_is_unique() -> None:
    ledger = BudgetLedger()
    ledger.register_mission("mission:a", ResourceBudget(model_tokens=10))
    ledger.register_mission("mission:b", ResourceBudget(model_tokens=10))
    ledger.register_work_item("work:a", "mission:a", ResourceBudget(model_tokens=10))

    with pytest.raises(BudgetLedgerError, match="does not belong"):
        ledger.register_mission(
            "mission:wrong-parent",
            ResourceBudget(model_tokens=10),
            parent_mission_id="mission:b",
            parent_work_item_id="work:a",
        )

    ledger.register_mission(
        "mission:child",
        ResourceBudget(model_tokens=10),
        parent_mission_id="mission:a",
        parent_work_item_id="work:a",
    )
    with pytest.raises(BudgetLedgerError, match="already backs child Mission"):
        ledger.register_mission(
            "mission:second-child",
            ResourceBudget(model_tokens=10),
            parent_mission_id="mission:a",
            parent_work_item_id="work:a",
        )


def test_negative_usage_is_rejected_without_mutation() -> None:
    ledger = BudgetLedger()
    ledger.register_mission("mission:root", ResourceBudget(model_tokens=10))
    ledger.register_work_item(
        "work:item",
        "mission:root",
        ResourceBudget(model_tokens=10),
    )
    before = ledger.snapshot()
    invalid = ResourceUsage.model_construct(model_tokens=-1)

    with pytest.raises(BudgetLedgerError, match="nonnegative"):
        ledger.consume("work:item", invalid)
    assert ledger.snapshot() == before


def test_snapshot_is_immutable_json_serializable_and_rebuildable() -> None:
    ledger = BudgetLedger()
    ledger.register_mission("mission:root", ResourceBudget(model_tokens=10))
    ledger.register_work_item(
        "work:item",
        "mission:root",
        ResourceBudget(model_tokens=8),
    )
    ledger.consume("work:item", ResourceUsage(model_tokens=3))
    snapshot = ledger.snapshot()

    with pytest.raises(ValidationError):
        snapshot.missions[0].usage.model_tokens = 0
    encoded = json.loads(json.dumps(snapshot.to_dict()))
    rebuilt = BudgetLedger.rebuild(encoded)

    assert encoded["schemaVersion"] == 2
    assert rebuilt.snapshot() == snapshot
    assert rebuilt.remaining("work:item").model_tokens == 5
    assert rebuilt.remaining("mission:root").model_tokens == 7


def test_rebuild_migrates_v1_parent_work_rollup_into_direct_usage() -> None:
    ledger = BudgetLedger()
    ledger.register_mission("mission:root", ResourceBudget(model_tokens=100))
    ledger.register_work_item(
        "work:parent",
        "mission:root",
        ResourceBudget(model_tokens=60),
    )
    ledger.consume("work:parent", ResourceUsage(model_tokens=50))
    ledger.register_mission(
        "mission:child",
        ResourceBudget(model_tokens=60),
        parent_mission_id="mission:root",
        parent_work_item_id="work:parent",
    )
    ledger.register_work_item(
        "work:child",
        "mission:child",
        ResourceBudget(model_tokens=60),
    )
    ledger.consume("work:child", ResourceUsage(model_tokens=10))
    legacy = ledger.snapshot().to_dict()
    legacy["schemaVersion"] = 1
    for work_item in legacy["workItems"]:
        work_item.pop("parentWorkItemId", None)
        work_item.pop("directUsage", None)

    rebuilt = BudgetLedger.rebuild(legacy)
    work_items = {account.work_item_id: account for account in rebuilt.snapshot().work_items}

    assert rebuilt.snapshot().schema_version == 2
    assert work_items["work:parent"].direct_usage.model_tokens == 50
    assert work_items["work:parent"].usage.model_tokens == 60
    assert work_items["work:child"].direct_usage.model_tokens == 10
    assert rebuilt.remaining("mission:child").model_tokens == 0


def test_rebuild_rejects_cycles_duplicates_allocation_and_usage_corruption() -> None:
    limit = BudgetLimitState.from_budget(ResourceBudget(model_tokens=10))
    cycle = BudgetLedgerSnapshot(
        missions=(
            MissionBudgetState(
                mission_id="mission:a",
                parent_mission_id="mission:b",
                limit=limit,
            ),
            MissionBudgetState(
                mission_id="mission:b",
                parent_mission_id="mission:a",
                limit=limit,
            ),
        )
    )
    with pytest.raises(BudgetLedgerError, match="cycle"):
        BudgetLedger.rebuild(cycle)

    duplicate = BudgetLedgerSnapshot(
        missions=(MissionBudgetState(mission_id="same", limit=limit),),
        work_items=(WorkItemBudgetState(work_item_id="same", mission_id="same", limit=limit),),
    )
    with pytest.raises(BudgetLedgerError, match="duplicate"):
        BudgetLedger.rebuild(duplicate)

    overallocated = BudgetLedgerSnapshot(
        missions=(MissionBudgetState(mission_id="mission:root", limit=limit),),
        work_items=(
            WorkItemBudgetState(
                work_item_id="work:a",
                mission_id="mission:root",
                limit=BudgetLimitState.from_budget(ResourceBudget(model_tokens=6)),
            ),
            WorkItemBudgetState(
                work_item_id="work:b",
                mission_id="mission:root",
                limit=BudgetLimitState.from_budget(ResourceBudget(model_tokens=5)),
            ),
        ),
    )
    with pytest.raises(BudgetLedgerError, match="allocation exceeds budget"):
        BudgetLedger.rebuild(overallocated)

    corrupted_usage = BudgetLedgerSnapshot(
        missions=(
            MissionBudgetState(
                mission_id="mission:root",
                limit=limit,
                usage=BudgetUsageState(model_tokens=2),
            ),
        ),
        work_items=(
            WorkItemBudgetState(
                work_item_id="work:item",
                mission_id="mission:root",
                limit=limit,
                usage=BudgetUsageState(model_tokens=3),
            ),
        ),
    )
    with pytest.raises(BudgetLedgerError, match="does not match its children"):
        BudgetLedger.rebuild(corrupted_usage)

    work_cycle = BudgetLedgerSnapshot(
        missions=(MissionBudgetState(mission_id="mission:root", limit=limit),),
        work_items=(
            WorkItemBudgetState(
                work_item_id="work:a",
                mission_id="mission:root",
                parent_work_item_id="work:b",
                limit=limit,
            ),
            WorkItemBudgetState(
                work_item_id="work:b",
                mission_id="mission:root",
                parent_work_item_id="work:a",
                limit=limit,
            ),
        ),
    )
    with pytest.raises(BudgetLedgerError, match="cycle"):
        BudgetLedger.rebuild(work_cycle)

    corrupted_rollup = BudgetLedgerSnapshot(
        missions=(
            MissionBudgetState(
                mission_id="mission:root",
                limit=limit,
                usage=BudgetUsageState(model_tokens=1),
            ),
        ),
        work_items=(
            WorkItemBudgetState(
                work_item_id="work:item",
                mission_id="mission:root",
                limit=limit,
                usage=BudgetUsageState(model_tokens=1),
            ),
        ),
    )
    with pytest.raises(BudgetLedgerError, match="WorkItem work:item"):
        BudgetLedger.rebuild(corrupted_rollup)

    with pytest.raises(BudgetLedgerError, match="snapshot is invalid"):
        BudgetLedger.rebuild({"schemaVersion": 99})
