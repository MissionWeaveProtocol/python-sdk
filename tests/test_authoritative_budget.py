from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import asyncpg  # type: ignore[import-untyped]
import pytest

from missionweaveprotocol.auth import AgentIdentity
from missionweaveprotocol.canonical import canonical_hash
from missionweaveprotocol.core import ActionIdCollision, BudgetExceeded, Core
from missionweaveprotocol.crypto import load_private_key, sign_canonical, verify_canonical
from missionweaveprotocol.local_store import SQLiteAgentStore
from missionweaveprotocol.models import (
    AcceptWorkOfferPayload,
    AddMembershipPayload,
    AgentCard,
    Command,
    CommandKind,
    CreateChildMissionPayload,
    CreateMissionPayload,
    CreateWorkItemPayload,
    Event,
    EventKind,
    Membership,
    OfferWorkItemPayload,
    PostMessagePayload,
    Principal,
    Query,
    QueryKind,
    RecordResourceUsagePayload,
    ResourceBudget,
    ResourceUsage,
    Role,
    SelectionBasis,
    StartWorkItemPayload,
    WorkContract,
    WorkItem,
)
from missionweaveprotocol.offline import (
    OfflineExecutionPolicy,
    OfflineLimits,
    rebase_offline_command,
)
from missionweaveprotocol.store import (
    AuthoritativeStore,
    InMemoryStore,
    PostgreSQLStore,
    SQLiteStore,
)
from tests.test_core import MutableClock, Scenario

GROUP_ID = "group:budget"
MISSION_ID = "mission:budget"
COORDINATOR_ID = "agent:coordinator"
WORKER_ID = "agent:worker"
DIMENSIONS = tuple(ResourceUsage.model_fields)


def _full_budget(value: int) -> ResourceBudget:
    return ResourceBudget(**{dimension: value for dimension in DIMENSIONS})


def _full_usage(value: int) -> ResourceUsage:
    return ResourceUsage(**{dimension: value for dimension in DIMENSIONS})


async def _scenario(
    *,
    store: AuthoritativeStore | None = None,
    root_budget: ResourceBudget | None = None,
) -> Scenario:
    clock = MutableClock(datetime(2026, 7, 15, 8, 0, tzinfo=UTC))
    scenario = Scenario(Core(store or InMemoryStore(), clock=clock), clock)
    await scenario.register(COORDINATOR_ID, "coordination", "software.python")
    await scenario.register(WORKER_ID, "software.python")
    await scenario.core.perform(
        scenario.command(
            CommandKind.CREATE_MISSION,
            scenario.owner,
            CreateMissionPayload(
                mission_id=MISSION_ID,
                group_id=GROUP_ID,
                coordinator_id=COORDINATOR_ID,
                title="Authoritative budget integration",
                objective="Prove aggregate budget accounting",
                definition_of_done=("authoritative usage is bounded",),
                budget=root_budget or _full_budget(100),
                deadline=clock() + timedelta(hours=4),
                coordinator_lease_seconds=7_200,
            ),
            group_id=GROUP_ID,
        )
    )
    await scenario.core.perform(
        scenario.command(
            CommandKind.ADD_MEMBERSHIP,
            Principal.agent(COORDINATOR_ID),
            AddMembershipPayload(
                principal=Principal.agent(WORKER_ID),
                roles=(Role.WORKER,),
            ),
            group_id=GROUP_ID,
            coordinator_epoch=1,
        )
    )
    return scenario


def _contract(scenario: Scenario, budget: ResourceBudget) -> WorkContract:
    return WorkContract(
        goal="Consume an authoritative budget",
        deliverables=("usage receipt",),
        acceptance_criteria=("remaining budget is correct",),
        deadline=scenario.clock() + timedelta(hours=1),
        budget=budget,
    )


async def _create_work(
    scenario: Scenario,
    work_item_id: str,
    budget: ResourceBudget,
    *,
    group_id: str = GROUP_ID,
    parent_work_item_id: str | None = None,
) -> None:
    await scenario.core.perform(
        scenario.command(
            CommandKind.CREATE_WORK_ITEM,
            Principal.agent(COORDINATOR_ID),
            CreateWorkItemPayload(
                work_item_id=work_item_id,
                contract=_contract(scenario, budget),
                parent_work_item_id=parent_work_item_id,
            ),
            group_id=group_id,
            coordinator_epoch=1,
        )
    )


async def _start_work(
    scenario: Scenario,
    work_item_id: str,
    *,
    group_id: str = GROUP_ID,
) -> WorkItem:
    await scenario.core.perform(
        scenario.command(
            CommandKind.OFFER_WORK_ITEM,
            Principal.agent(COORDINATOR_ID),
            OfferWorkItemPayload(
                work_item_id=work_item_id,
                candidate_agent_ids=(WORKER_ID,),
                selection_basis=SelectionBasis(
                    verified_capability_matches=("software.python",),
                ),
                offer_expires_in_seconds=600,
            ),
            group_id=group_id,
            coordinator_epoch=1,
        )
    )
    await scenario.core.perform(
        scenario.command(
            CommandKind.ACCEPT_WORK_OFFER,
            Principal.agent(WORKER_ID),
            AcceptWorkOfferPayload(work_item_id=work_item_id),
            group_id=group_id,
        )
    )
    accepted = await scenario.core.query(Query(kind=QueryKind.WORK_ITEM, entity_id=work_item_id))
    assert isinstance(accepted, WorkItem)
    await scenario.core.perform(
        scenario.command(
            CommandKind.START_WORK_ITEM,
            Principal.agent(WORKER_ID),
            StartWorkItemPayload(
                work_item_id=work_item_id,
                ownership_epoch=accepted.ownership_epoch,
                execution_lease_seconds=600,
            ),
            group_id=group_id,
        )
    )
    active = await scenario.core.query(Query(kind=QueryKind.WORK_ITEM, entity_id=work_item_id))
    assert isinstance(active, WorkItem)
    assert active.execution_lease_id is not None
    return active


def _signed_usage_command(
    scenario: Scenario,
    work: WorkItem,
    usage: ResourceUsage,
    *,
    action_id: str,
) -> Command:
    assert work.execution_lease_id is not None
    unsigned = scenario.command(
        CommandKind.RECORD_RESOURCE_USAGE,
        Principal.agent(WORKER_ID),
        RecordResourceUsagePayload(
            work_item_id=work.id,
            ownership_epoch=work.ownership_epoch,
            execution_lease_id=work.execution_lease_id,
            usage_delta=usage,
        ),
        group_id=work.group_id,
        action_id=action_id,
    ).model_copy(update={"signature": None})
    signature = sign_canonical(unsigned.signing_payload(), scenario.private_keys[WORKER_ID])
    return unsigned.model_copy(update={"signature": signature})


@pytest.mark.asyncio
async def test_aggregate_sibling_allocation_is_rejected_without_state_change() -> None:
    scenario = await _scenario(root_budget=_full_budget(100))
    await _create_work(scenario, "work:a", _full_budget(60))
    before = await scenario.core.replay(GROUP_ID)

    with pytest.raises(BudgetExceeded, match="allocation exceeds budget"):
        await _create_work(scenario, "work:b", _full_budget(41))

    assert await scenario.core.query(Query(kind=QueryKind.WORK_ITEM, entity_id="work:b")) is None
    assert await scenario.core.replay(GROUP_ID) == before
    assert await scenario.core.query(
        Query(kind=QueryKind.BUDGET_REMAINING, entity_id=MISSION_ID)
    ) == _full_budget(100)


@pytest.mark.asyncio
async def test_nested_work_and_child_mission_usage_rolls_up_without_double_reservation() -> None:
    scenario = await _scenario(root_budget=_full_budget(100))
    await _create_work(scenario, "work:parent", _full_budget(80))
    await _create_work(
        scenario,
        "work:delegated",
        _full_budget(60),
        parent_work_item_id="work:parent",
    )
    await _create_work(scenario, "work:sibling", _full_budget(20))
    await scenario.core.perform(
        scenario.command(
            CommandKind.CREATE_CHILD_MISSION,
            Principal.agent(COORDINATOR_ID),
            CreateChildMissionPayload(
                mission_id="mission:child",
                group_id="group:child",
                parent_work_item_id="work:delegated",
                coordinator_id=COORDINATOR_ID,
                title="Child budget",
                objective="Roll usage through a parent WorkItem",
                definition_of_done=("usage rolled up",),
                budget=_full_budget(50),
                deadline=scenario.clock() + timedelta(hours=1),
                coordinator_lease_seconds=600,
            ),
            group_id=GROUP_ID,
            coordinator_epoch=1,
        )
    )
    await scenario.core.perform(
        scenario.command(
            CommandKind.ADD_MEMBERSHIP,
            Principal.agent(COORDINATOR_ID),
            AddMembershipPayload(
                principal=Principal.agent(WORKER_ID),
                roles=(Role.WORKER,),
            ),
            group_id="group:child",
            coordinator_epoch=1,
        )
    )
    await _create_work(scenario, "work:leaf", _full_budget(50), group_id="group:child")
    leaf = await _start_work(scenario, "work:leaf", group_id="group:child")

    event = await scenario.core.perform(
        _signed_usage_command(
            scenario,
            leaf,
            _full_usage(10),
            action_id="usage:nested",
        )
    )

    assert event.kind is EventKind.RESOURCE_USAGE_RECORDED
    for account_id, remaining in (
        ("work:leaf", 40),
        ("mission:child", 40),
        ("work:delegated", 50),
        ("work:parent", 70),
        (MISSION_ID, 90),
    ):
        assert await scenario.core.query(
            Query(kind=QueryKind.BUDGET_REMAINING, entity_id=account_id)
        ) == _full_budget(remaining)


@pytest.mark.asyncio
async def test_signed_usage_is_idempotent_collision_safe_and_atomic_on_overflow() -> None:
    scenario = await _scenario(root_budget=_full_budget(5))
    await _create_work(scenario, "work:usage", _full_budget(5))
    work = await _start_work(scenario, "work:usage")
    command = _signed_usage_command(
        scenario,
        work,
        _full_usage(2),
        action_id="usage:stable",
    )
    assert command.signature is not None
    card = await scenario.core.query(Query(kind=QueryKind.AGENT_CARD, entity_id=WORKER_ID))
    assert isinstance(card, AgentCard)
    assert verify_canonical(
        command.signing_payload(),
        command.signature,
        card.public_key,
    )

    accepted = await scenario.core.perform(command)
    duplicate = await scenario.core.perform(command)
    assert accepted.id == duplicate.id
    assert accepted.payload["usageDelta"] == _full_usage(2).model_dump(mode="json", by_alias=True)
    assert accepted.payload["remainingBudget"] == _full_budget(3).model_dump(
        mode="json", by_alias=True
    )
    assert await scenario.core.query(
        Query(kind=QueryKind.BUDGET_REMAINING, entity_id=work.id)
    ) == _full_budget(3)

    collision = _signed_usage_command(
        scenario,
        work,
        _full_usage(1),
        action_id="usage:stable",
    )
    with pytest.raises(ActionIdCollision):
        await scenario.core.perform(collision)

    before = await scenario.core.replay(GROUP_ID)
    before_hash = canonical_hash(before[-1])
    with pytest.raises(BudgetExceeded):
        await scenario.core.perform(
            _signed_usage_command(
                scenario,
                work,
                _full_usage(4),
                action_id="usage:overflow",
            )
        )
    after = await scenario.core.replay(GROUP_ID)
    assert len(after) == len(before)
    assert canonical_hash(after[-1]) == before_hash
    assert await scenario.core.query(
        Query(kind=QueryKind.BUDGET_REMAINING, entity_id=work.id)
    ) == _full_budget(3)


@pytest.mark.asyncio
async def test_concurrent_final_capacity_commands_accept_exactly_one() -> None:
    scenario = await _scenario(root_budget=_full_budget(5))
    await _create_work(scenario, "work:race", _full_budget(5))
    work = await _start_work(scenario, "work:race")
    await scenario.core.perform(
        _signed_usage_command(scenario, work, _full_usage(4), action_id="usage:initial")
    )
    commands = tuple(
        _signed_usage_command(scenario, work, _full_usage(1), action_id=f"usage:race:{index}")
        for index in range(2)
    )

    results = await asyncio.gather(
        *(scenario.core.perform(command) for command in commands),
        return_exceptions=True,
    )

    assert sum(isinstance(result, Event) for result in results) == 1
    assert sum(isinstance(result, BudgetExceeded) for result in results) == 1
    assert await scenario.core.query(
        Query(kind=QueryKind.BUDGET_REMAINING, entity_id=work.id)
    ) == _full_budget(0)


@pytest.mark.asyncio
async def test_offline_reconciliation_charges_old_lease_usage_atomically(
    tmp_path: Path,
) -> None:
    scenario = await _scenario(root_budget=_full_budget(5))
    await _create_work(scenario, "work:offline-budget", _full_budget(5))
    work = await _start_work(scenario, "work:offline-budget")
    assert work.execution_lease_id is not None
    old_lease_id = work.execution_lease_id
    identity = AgentIdentity(
        WORKER_ID,
        load_private_key(scenario.private_keys[WORKER_ID]),
    )
    local = SQLiteAgentStore(tmp_path / "offline-budget.sqlite3")
    policy = OfflineExecutionPolicy(
        local,
        identity,
        work,
        disconnected_at=scenario.clock(),
        limits=OfflineLimits(
            max_disconnect_grace=timedelta(minutes=1),
            max_actions=2,
            max_usage=ResourceUsage(model_tokens=10),
        ),
        clock=scenario.clock,
    )
    first = policy.buffer(
        scenario.command(
            CommandKind.POST_MESSAGE,
            Principal.agent(WORKER_ID),
            PostMessagePayload(
                message_id="message:offline-budget:first",
                conversation_id=work.conversation_id,
                content="first buffered progress",
            ),
            group_id=work.group_id,
            action_id="offline-budget:first",
        ),
        usage=ResourceUsage(model_tokens=2),
    )
    overflow = policy.buffer(
        scenario.command(
            CommandKind.POST_MESSAGE,
            Principal.agent(WORKER_ID),
            PostMessagePayload(
                message_id="message:offline-budget:overflow",
                conversation_id=work.conversation_id,
                content="this progress exceeds the authoritative remainder",
            ),
            group_id=work.group_id,
            action_id="offline-budget:overflow",
        ),
        usage=ResourceUsage(model_tokens=4),
    )

    scenario.clock.advance(seconds=5)
    current_session = await scenario.reopen(WORKER_ID)
    membership = await scenario.core.query(
        Query(
            kind=QueryKind.MEMBERSHIP,
            entity_id=WORKER_ID,
            group_id=work.group_id,
            actor_type=Principal.agent(WORKER_ID).type,
        )
    )
    assert isinstance(membership, Membership)
    membership_epoch = membership.epoch

    accepted = await scenario.core.perform(
        rebase_offline_command(
            first,
            identity,
            session_epoch=current_session,
            membership_epoch=membership_epoch,
            issued_at=scenario.clock(),
        )
    )
    assert accepted.kind is EventKind.MESSAGE_POSTED
    expected_remaining = _full_budget(5).model_copy(update={"model_tokens": 3})
    assert (
        await scenario.core.query(Query(kind=QueryKind.BUDGET_REMAINING, entity_id=work.id))
        == expected_remaining
    )
    reconciled_events = [
        event
        for event in await scenario.core.replay(work.group_id)
        if event.action_id == first.action_id
    ]
    assert [event.kind for event in reconciled_events] == [
        EventKind.RESOURCE_USAGE_RECORDED,
        EventKind.MESSAGE_POSTED,
    ]
    usage_event = reconciled_events[0]
    assert usage_event.payload["executionLeaseId"] == old_lease_id
    assert usage_event.payload["offlineReconciliation"]["reconciliationSessionEpoch"] == (
        current_session
    )

    before_overflow = await scenario.core.replay(work.group_id)
    with pytest.raises(BudgetExceeded):
        await scenario.core.perform(
            rebase_offline_command(
                overflow,
                identity,
                session_epoch=current_session,
                membership_epoch=membership_epoch,
                issued_at=scenario.clock(),
            )
        )
    assert await scenario.core.replay(work.group_id) == before_overflow
    assert (
        await scenario.core.query(
            Query(kind=QueryKind.MESSAGE, entity_id="message:offline-budget:overflow")
        )
        is None
    )
    assert (
        await scenario.core.query(Query(kind=QueryKind.BUDGET_REMAINING, entity_id=work.id))
        == expected_remaining
    )
    local.close()


async def _assert_sql_restart(store: AuthoritativeStore, reopened: AuthoritativeStore) -> None:
    scenario = await _scenario(store=store, root_budget=_full_budget(10))
    await _create_work(scenario, "work:persisted", _full_budget(10))
    work = await _start_work(scenario, "work:persisted")
    event = await scenario.core.perform(
        _signed_usage_command(scenario, work, _full_usage(3), action_id="usage:persisted")
    )
    await store.close()

    core = Core(reopened, clock=scenario.clock)
    assert await core.query(
        Query(kind=QueryKind.BUDGET_REMAINING, entity_id=work.id)
    ) == _full_budget(7)
    replayed = await core.replay(GROUP_ID, after=int(event.sequence or 0) - 1)
    assert [item.kind for item in replayed] == [EventKind.RESOURCE_USAGE_RECORDED]
    assert replayed[0].payload == event.payload
    await reopened.close()


@pytest.mark.asyncio
async def test_sqlite_restart_preserves_authoritative_usage(tmp_path: Path) -> None:
    path = tmp_path / "authoritative-budget.sqlite3"
    await _assert_sql_restart(SQLiteStore(path), SQLiteStore(path))


@pytest.mark.asyncio
async def test_postgresql_restart_preserves_authoritative_usage_when_available() -> None:
    url = os.getenv("MISSIONWEAVEPROTOCOL_TEST_POSTGRES_URL")
    if not url:
        pytest.skip("set MISSIONWEAVEPROTOCOL_TEST_POSTGRES_URL to run PostgreSQL integration")
    connection = await asyncpg.connect(url)
    await connection.execute("DROP TABLE IF EXISTS missionweaveprotocol_authoritative_state")
    await connection.close()
    await _assert_sql_restart(PostgreSQLStore(url), PostgreSQLStore(url))
