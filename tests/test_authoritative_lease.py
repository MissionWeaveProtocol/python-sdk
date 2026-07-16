from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from missionweave.conformance import SchemaCatalog
from missionweave.core import Core, LeaseExpired
from missionweave.lease import ExecutionLease, LeaseState
from missionweave.models import (
    AcceptWorkOfferPayload,
    Artifact,
    BlockWorkItemPayload,
    Checkpoint,
    CheckpointWorkItemPayload,
    Command,
    CommandKind,
    CreateWorkItemPayload,
    Event,
    EventKind,
    Evidence,
    OfferWorkItemPayload,
    Principal,
    PublishArtifactPayload,
    Query,
    QueryKind,
    RenewExecutionLeasePayload,
    SelectionBasis,
    StartWorkItemPayload,
    SubmitWorkItemPayload,
    WorkItem,
    WorkItemStatus,
)
from missionweave.store import AuthoritativeStore, InMemoryStore, SQLiteStore
from tests.test_core import MutableClock, Scenario

COORDINATOR_ID = "agent:coordinator"
WORKER_ONE = "agent:worker-1"
WORKER_TWO = "agent:worker-2"
ROOT_GROUP = "group:root"
ROOT_MISSION = "mission:root"


async def _scenario(
    *,
    store: AuthoritativeStore | None = None,
    groups: tuple[tuple[str, str], ...] = ((ROOT_MISSION, ROOT_GROUP),),
) -> Scenario:
    clock = MutableClock(value=datetime(2026, 7, 15, 8, 0, tzinfo=UTC))
    scenario = Scenario(Core(store or InMemoryStore(), clock=clock), clock)
    await scenario.register(COORDINATOR_ID, "coordination", "software.python")
    await scenario.register(WORKER_ONE, "software.python")
    await scenario.register(WORKER_TWO, "software.python")
    for mission_id, group_id in groups:
        await scenario.create_root(mission_id=mission_id, group_id=group_id)
        await scenario.add_worker(WORKER_ONE, group_id=group_id)
        await scenario.add_worker(WORKER_TWO, group_id=group_id)
    return scenario


async def _queue_work(
    scenario: Scenario,
    work_item_id: str,
    *,
    group_id: str = ROOT_GROUP,
    worker_id: str = WORKER_ONE,
    ownership_lease_seconds: int = 900,
) -> WorkItem:
    await scenario.core.perform(
        scenario.command(
            CommandKind.CREATE_WORK_ITEM,
            Principal.agent(COORDINATOR_ID),
            CreateWorkItemPayload(
                work_item_id=work_item_id,
                contract=scenario.contract(),
            ),
            group_id=group_id,
            coordinator_epoch=1,
        )
    )
    await scenario.core.perform(
        scenario.command(
            CommandKind.OFFER_WORK_ITEM,
            Principal.agent(COORDINATOR_ID),
            OfferWorkItemPayload(
                work_item_id=work_item_id,
                candidate_agent_ids=(worker_id,),
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
            Principal.agent(worker_id),
            AcceptWorkOfferPayload(
                work_item_id=work_item_id,
                ownership_lease_seconds=ownership_lease_seconds,
            ),
            group_id=group_id,
        )
    )
    queued = await scenario.core.query(Query(kind=QueryKind.WORK_ITEM, entity_id=work_item_id))
    assert isinstance(queued, WorkItem)
    assert queued.status is WorkItemStatus.QUEUED
    return queued


async def _start_queued_work(
    scenario: Scenario,
    queued: WorkItem,
    *,
    execution_lease_seconds: int = 300,
    action_id: str | None = None,
) -> tuple[WorkItem, ExecutionLease, Event, Command]:
    command = scenario.command(
        CommandKind.START_WORK_ITEM,
        Principal.agent(queued.assignee_id or WORKER_ONE),
        StartWorkItemPayload(
            work_item_id=queued.id,
            ownership_epoch=queued.ownership_epoch,
            execution_lease_seconds=execution_lease_seconds,
        ),
        group_id=queued.group_id,
        action_id=action_id,
    )
    event = await scenario.core.perform(command)
    active = await scenario.core.query(Query(kind=QueryKind.WORK_ITEM, entity_id=queued.id))
    assert isinstance(active, WorkItem)
    assert active.execution_lease_id is not None
    lease = await scenario.core.query(
        Query(kind=QueryKind.EXECUTION_LEASE, entity_id=active.execution_lease_id)
    )
    assert isinstance(lease, ExecutionLease)
    return active, lease, event, command


async def _activate_work(
    scenario: Scenario,
    work_item_id: str,
    *,
    group_id: str = ROOT_GROUP,
    worker_id: str = WORKER_ONE,
    ownership_lease_seconds: int = 900,
    execution_lease_seconds: int = 300,
) -> tuple[WorkItem, ExecutionLease]:
    queued = await _queue_work(
        scenario,
        work_item_id,
        group_id=group_id,
        worker_id=worker_id,
        ownership_lease_seconds=ownership_lease_seconds,
    )
    active, lease, _event, _command = await _start_queued_work(
        scenario,
        queued,
        execution_lease_seconds=execution_lease_seconds,
    )
    return active, lease


def _checkpoint(scenario: Scenario, work: WorkItem, phase: str) -> Checkpoint:
    return Checkpoint(
        phase=phase,
        completed_milestones=("state persisted",),
        next_step="resume safely",
        created_at=scenario.clock(),
    )


@pytest.mark.asyncio
async def test_start_persists_schema_valid_queryable_lease_and_work_item_pair() -> None:
    scenario = await _scenario()
    queued = await _queue_work(scenario, "work:start")

    active, lease, event, _command = await _start_queued_work(scenario, queued)

    SchemaCatalog().validate(
        "lease.schema.json",
        lease.model_dump(mode="json", by_alias=True, exclude_none=True),
    )
    assert active.status is WorkItemStatus.ACTIVE
    assert active.execution_lease_id == lease.lease_id
    assert active.execution_lease_expires_at == lease.expires_at
    assert lease.work_item_id == active.id
    assert lease.ownership_epoch == active.ownership_epoch
    assert lease.session_epoch == scenario.epochs[WORKER_ONE]
    assert event.payload["executionLease"]["leaseId"] == lease.lease_id


@pytest.mark.asyncio
async def test_duplicate_start_command_returns_the_same_execution_lease_id() -> None:
    scenario = await _scenario()
    queued = await _queue_work(scenario, "work:deduplicated-start")
    command = scenario.command(
        CommandKind.START_WORK_ITEM,
        Principal.agent(WORKER_ONE),
        StartWorkItemPayload(
            work_item_id=queued.id,
            ownership_epoch=queued.ownership_epoch,
            execution_lease_seconds=300,
        ),
        group_id=queued.group_id,
        action_id="action:stable-start",
    )

    first = await scenario.core.perform(command)
    duplicate = await scenario.core.perform(command)

    first_lease = ExecutionLease.model_validate(first.payload["executionLease"])
    duplicate_lease = ExecutionLease.model_validate(duplicate.payload["executionLease"])
    work = await scenario.core.query(Query(kind=QueryKind.WORK_ITEM, entity_id=queued.id))
    assert isinstance(work, WorkItem)
    assert duplicate == first
    assert duplicate_lease.lease_id == first_lease.lease_id == work.execution_lease_id


@pytest.mark.asyncio
async def test_renewal_retains_identity_increments_count_and_extends_projection() -> None:
    scenario = await _scenario()
    active, original = await _activate_work(scenario, "work:renew")
    scenario.clock.advance(seconds=60)

    await scenario.core.perform(
        scenario.command(
            CommandKind.RENEW_EXECUTION_LEASE,
            Principal.agent(WORKER_ONE),
            RenewExecutionLeasePayload(
                work_item_id=active.id,
                ownership_epoch=active.ownership_epoch,
                execution_lease_id=original.lease_id,
                lease_seconds=600,
            ),
            group_id=active.group_id,
        )
    )

    renewed = await scenario.core.query(
        Query(kind=QueryKind.EXECUTION_LEASE, entity_id=original.lease_id)
    )
    work = await scenario.core.query(Query(kind=QueryKind.WORK_ITEM, entity_id=active.id))
    assert isinstance(renewed, ExecutionLease)
    assert isinstance(work, WorkItem)
    assert renewed.lease_id == original.lease_id
    assert renewed.renewal_count == original.renewal_count + 1
    assert renewed.last_renewed_at == scenario.clock()
    assert renewed.expires_at > original.expires_at
    assert work.execution_lease_id == renewed.lease_id
    assert work.execution_lease_expires_at == renewed.expires_at


@pytest.mark.asyncio
async def test_stale_lease_id_is_rejected_after_new_lease_in_same_ownership_epoch() -> None:
    scenario = await _scenario()
    active, old_lease = await _activate_work(scenario, "work:lease-aba")
    await scenario.core.perform(
        scenario.command(
            CommandKind.CHECKPOINT_WORK_ITEM,
            Principal.agent(WORKER_ONE),
            CheckpointWorkItemPayload(
                work_item_id=active.id,
                ownership_epoch=active.ownership_epoch,
                execution_lease_id=old_lease.lease_id,
                checkpoint=_checkpoint(scenario, active, "first run"),
                resume_within_seconds=900,
            ),
            group_id=active.group_id,
        )
    )
    queued = await scenario.core.query(Query(kind=QueryKind.WORK_ITEM, entity_id=active.id))
    assert isinstance(queued, WorkItem)
    resumed, new_lease, _event, _command = await _start_queued_work(scenario, queued)

    assert new_lease.lease_id != old_lease.lease_id
    assert new_lease.ownership_epoch == old_lease.ownership_epoch == resumed.ownership_epoch
    with pytest.raises(LeaseExpired, match="stale Execution Lease ID"):
        await scenario.core.perform(
            scenario.command(
                CommandKind.RENEW_EXECUTION_LEASE,
                Principal.agent(WORKER_ONE),
                RenewExecutionLeasePayload(
                    work_item_id=resumed.id,
                    ownership_epoch=resumed.ownership_epoch,
                    execution_lease_id=old_lease.lease_id,
                    lease_seconds=600,
                ),
                group_id=resumed.group_id,
            )
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("transition", ["checkpoint", "block", "submit"])
async def test_execution_completion_transitions_release_the_lease(transition: str) -> None:
    scenario = await _scenario()
    active, lease = await _activate_work(scenario, f"work:{transition}")

    if transition == "checkpoint":
        payload = CheckpointWorkItemPayload(
            work_item_id=active.id,
            ownership_epoch=active.ownership_epoch,
            execution_lease_id=lease.lease_id,
            checkpoint=_checkpoint(scenario, active, "checkpoint"),
        )
        kind = CommandKind.CHECKPOINT_WORK_ITEM
        expected_status = WorkItemStatus.QUEUED
    elif transition == "block":
        payload = BlockWorkItemPayload(
            work_item_id=active.id,
            ownership_epoch=active.ownership_epoch,
            execution_lease_id=lease.lease_id,
            reason="waiting for dependency",
            checkpoint=_checkpoint(scenario, active, "blocked"),
        )
        kind = CommandKind.BLOCK_WORK_ITEM
        expected_status = WorkItemStatus.BLOCKED
    else:
        artifact = scenario.sign_artifact(
            Artifact(
                id="artifact:submitted",
                content_hash="sha256:" + "a" * 64,
                media_type="application/json",
                producing_agent_id=WORKER_ONE,
                agent_card_version=1,
                mission_id=active.mission_id,
                group_id=active.group_id,
                work_item_id=active.id,
                created_at=scenario.clock(),
                data_classification="internal",
                signature="pending",
            )
        )
        await scenario.core.perform(
            scenario.command(
                CommandKind.PUBLISH_ARTIFACT,
                Principal.agent(WORKER_ONE),
                PublishArtifactPayload(
                    artifact=artifact,
                    ownership_epoch=active.ownership_epoch,
                    execution_lease_id=lease.lease_id,
                ),
                group_id=active.group_id,
            )
        )
        payload = SubmitWorkItemPayload(
            work_item_id=active.id,
            ownership_epoch=active.ownership_epoch,
            execution_lease_id=lease.lease_id,
            artifact_ids=(artifact.id,),
            evidence=(Evidence(kind="tests", description="tests passed"),),
        )
        kind = CommandKind.SUBMIT_WORK_ITEM
        expected_status = WorkItemStatus.SUBMITTED

    await scenario.core.perform(
        scenario.command(
            kind,
            Principal.agent(WORKER_ONE),
            payload,
            group_id=active.group_id,
        )
    )

    terminal = await scenario.core.query(
        Query(kind=QueryKind.EXECUTION_LEASE, entity_id=lease.lease_id)
    )
    work = await scenario.core.query(Query(kind=QueryKind.WORK_ITEM, entity_id=active.id))
    assert isinstance(terminal, ExecutionLease)
    assert isinstance(work, WorkItem)
    assert terminal.state is LeaseState.RELEASED
    assert terminal.closed_at == scenario.clock()
    assert terminal.closure_reason
    assert work.status is expected_status
    assert work.execution_lease_id is None
    assert work.execution_lease_expires_at is None


@pytest.mark.asyncio
async def test_session_reopen_revokes_across_groups_and_restarts_with_new_epoch() -> None:
    groups = (("mission:one", "group:one"), ("mission:two", "group:two"))
    scenario = await _scenario(groups=groups)
    active_by_group: dict[str, WorkItem] = {}
    lease_by_group: dict[str, ExecutionLease] = {}
    for index, (_mission_id, group_id) in enumerate(groups, start=1):
        active, lease = await _activate_work(
            scenario,
            f"work:session:{index}",
            group_id=group_id,
            execution_lease_seconds=600,
        )
        active_by_group[group_id] = active
        lease_by_group[group_id] = lease
    old_session_epoch = scenario.epochs[WORKER_ONE]

    new_session_epoch = await scenario.reopen(WORKER_ONE)

    assert new_session_epoch == old_session_epoch + 1
    for _mission_id, group_id in groups:
        old_lease = lease_by_group[group_id]
        terminal = await scenario.core.query(
            Query(kind=QueryKind.EXECUTION_LEASE, entity_id=old_lease.lease_id)
        )
        work = await scenario.core.query(
            Query(kind=QueryKind.WORK_ITEM, entity_id=active_by_group[group_id].id)
        )
        revocations = [
            event
            for event in await scenario.core.replay(group_id)
            if event.kind is EventKind.EXECUTION_LEASE_REVOKED
        ]
        assert isinstance(terminal, ExecutionLease)
        assert isinstance(work, WorkItem)
        assert terminal.state is LeaseState.REVOKED
        assert terminal.closed_at == scenario.clock()
        assert work.status is WorkItemStatus.QUEUED
        assert work.execution_lease_id is None
        assert work.execution_lease_expires_at is None
        assert len(revocations) == 1
        assert revocations[0].payload["executionLeaseId"] == old_lease.lease_id
        assert revocations[0].payload["sessionEpoch"] == new_session_epoch

    queued = await scenario.core.query(
        Query(kind=QueryKind.WORK_ITEM, entity_id=active_by_group["group:one"].id)
    )
    assert isinstance(queued, WorkItem)
    restarted, new_lease, _event, _command = await _start_queued_work(scenario, queued)
    assert new_lease.lease_id != lease_by_group["group:one"].lease_id
    assert new_lease.session_epoch == new_session_epoch
    assert restarted.execution_lease_id == new_lease.lease_id


@pytest.mark.asyncio
async def test_expired_reassignment_closes_old_lease_as_expired() -> None:
    scenario = await _scenario()
    active, old_lease = await _activate_work(
        scenario,
        "work:expired-reassignment",
        ownership_lease_seconds=30,
        execution_lease_seconds=60,
    )
    scenario.clock.advance(seconds=61)

    await scenario.core.perform(
        scenario.command(
            CommandKind.OFFER_WORK_ITEM,
            Principal.agent(COORDINATOR_ID),
            OfferWorkItemPayload(
                work_item_id=active.id,
                candidate_agent_ids=(WORKER_TWO,),
                selection_basis=SelectionBasis(
                    verified_capability_matches=("software.python",),
                ),
                offer_expires_in_seconds=600,
            ),
            group_id=active.group_id,
            coordinator_epoch=1,
        )
    )
    await scenario.core.perform(
        scenario.command(
            CommandKind.ACCEPT_WORK_OFFER,
            Principal.agent(WORKER_TWO),
            AcceptWorkOfferPayload(work_item_id=active.id),
            group_id=active.group_id,
        )
    )

    terminal = await scenario.core.query(
        Query(kind=QueryKind.EXECUTION_LEASE, entity_id=old_lease.lease_id)
    )
    reassigned = await scenario.core.query(Query(kind=QueryKind.WORK_ITEM, entity_id=active.id))
    assert isinstance(terminal, ExecutionLease)
    assert isinstance(reassigned, WorkItem)
    assert terminal.state is LeaseState.EXPIRED
    assert terminal.closed_at == old_lease.expires_at
    assert "reached its expiry" in (terminal.closure_reason or "")
    assert reassigned.status is WorkItemStatus.QUEUED
    assert reassigned.assignee_id == WORKER_TWO
    assert reassigned.execution_lease_id is None


@pytest.mark.asyncio
async def test_sqlite_restart_persists_active_and_terminal_execution_leases(
    tmp_path: Path,
) -> None:
    path = tmp_path / "authoritative-leases.sqlite3"
    first_store = SQLiteStore(path)
    scenario = await _scenario(store=first_store)
    active_work, active_lease = await _activate_work(scenario, "work:persisted-active")
    terminal_work, terminal_lease = await _activate_work(scenario, "work:persisted-terminal")
    await scenario.core.perform(
        scenario.command(
            CommandKind.CHECKPOINT_WORK_ITEM,
            Principal.agent(WORKER_ONE),
            CheckpointWorkItemPayload(
                work_item_id=terminal_work.id,
                ownership_epoch=terminal_work.ownership_epoch,
                execution_lease_id=terminal_lease.lease_id,
                checkpoint=_checkpoint(scenario, terminal_work, "persisted terminal"),
            ),
            group_id=terminal_work.group_id,
        )
    )
    expected_terminal = await scenario.core.query(
        Query(kind=QueryKind.EXECUTION_LEASE, entity_id=terminal_lease.lease_id)
    )
    assert isinstance(expected_terminal, ExecutionLease)
    assert expected_terminal.state is LeaseState.RELEASED
    await first_store.close()

    reopened_store = SQLiteStore(path)
    reopened_core = Core(reopened_store, clock=scenario.clock)
    try:
        persisted_active = await reopened_core.query(
            Query(kind=QueryKind.EXECUTION_LEASE, entity_id=active_lease.lease_id)
        )
        persisted_terminal = await reopened_core.query(
            Query(kind=QueryKind.EXECUTION_LEASE, entity_id=terminal_lease.lease_id)
        )
        active_projection = await reopened_core.query(
            Query(kind=QueryKind.WORK_ITEM, entity_id=active_work.id)
        )
        terminal_projection = await reopened_core.query(
            Query(kind=QueryKind.WORK_ITEM, entity_id=terminal_work.id)
        )
        assert persisted_active == active_lease
        assert persisted_terminal == expected_terminal
        assert isinstance(active_projection, WorkItem)
        assert isinstance(terminal_projection, WorkItem)
        assert active_projection.execution_lease_id == active_lease.lease_id
        assert active_projection.execution_lease_expires_at == active_lease.expires_at
        assert terminal_projection.execution_lease_id is None
        assert terminal_projection.execution_lease_expires_at is None
    finally:
        await reopened_store.close()
