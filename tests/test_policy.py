from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from missionweave.crypto import generate_keypair, sign_canonical
from missionweave.lease import ExecutionLease, LeaseState
from missionweave.models import (
    Command,
    CommandKind,
    Event,
    EventKind,
    ExecutionApproval,
    GrantExecutionApprovalPayload,
    Membership,
    MembershipStatus,
    Mission,
    MissionStatus,
    Principal,
    Query,
    QueryKind,
    ResourceBudget,
    Role,
    WorkContract,
    WorkItem,
    WorkItemStatus,
)
from missionweave.policy import (
    AuthorizationService,
    BudgetMeter,
    CooperationLimits,
    ExecutionAuthorization,
    MembershipTokenService,
    PolicyError,
    PolicyGuard,
    ResourceUsage,
)

NOW = datetime(2026, 7, 15, 8, 0, tzinfo=UTC)
LEASE_EXPIRY = NOW + timedelta(minutes=5)


def _execution_lease(**updates: object) -> ExecutionLease:
    values: dict[str, object] = {
        "lease_id": "lease:execution:one",
        "mission_id": "mission:deploy",
        "group_id": "group:deploy",
        "work_item_id": "work:deploy",
        "holder_agent_id": "agent:worker",
        "session_epoch": 5,
        "ownership_epoch": 3,
        "issued_at": NOW,
        "starts_at": NOW,
        "expires_at": LEASE_EXPIRY,
    }
    values.update(updates)
    return ExecutionLease.model_validate(values)


@pytest.fixture
def execution_lease() -> ExecutionLease:
    return _execution_lease()


def test_membership_token_fences_session_membership_and_roles() -> None:
    service = MembershipTokenService(b"membership-secret" * 3)
    principal = Principal.agent("agent:worker")
    membership = Membership(
        group_id="group:one",
        principal=principal,
        roles=(Role.REVIEWER, Role.WORKER),
        status=MembershipStatus.ACTIVE,
        epoch=4,
        joined_at=NOW,
    )
    issued = service.issue_for_membership(
        membership,
        session_epoch=9,
        ttl=timedelta(minutes=5),
        now=NOW,
    )

    verified = service.verify_membership(
        issued.token,
        membership,
        session_epoch=9,
        now=NOW,
    )
    assert verified.token_id == issued.claims.token_id

    with pytest.raises(PolicyError, match="Membership token epoch"):
        service.verify_membership(
            issued.token,
            membership.model_copy(update={"epoch": 5}),
            session_epoch=9,
            now=NOW,
        )
    with pytest.raises(PolicyError, match="Session Epoch"):
        service.verify(
            issued.token,
            principal=principal,
            group_id="group:one",
            roles=(Role.WORKER, Role.REVIEWER),
            membership_epoch=4,
            session_epoch=10,
            now=NOW,
        )
    with pytest.raises(PolicyError, match="role scope"):
        service.verify(
            issued.token,
            principal=principal,
            group_id="group:one",
            roles=(Role.WORKER,),
            membership_epoch=4,
            session_epoch=9,
            now=NOW,
        )
    with pytest.raises(PolicyError, match="Group scope"):
        service.verify(
            issued.token,
            principal=principal,
            group_id="group:other",
            roles=(Role.WORKER, Role.REVIEWER),
            membership_epoch=4,
            session_epoch=9,
            now=NOW,
        )


def test_membership_tokens_are_short_lived_and_tamper_evident() -> None:
    service = MembershipTokenService(
        b"membership-secret" * 3,
        maximum_ttl=timedelta(minutes=10),
    )
    with pytest.raises(PolicyError, match="short-lived"):
        service.issue(
            principal=Principal.agent("agent:worker"),
            group_id="group:one",
            roles=(Role.WORKER,),
            membership_epoch=1,
            session_epoch=1,
            ttl=timedelta(minutes=11),
            now=NOW,
        )

    issued = service.issue(
        principal=Principal.agent("agent:worker"),
        group_id="group:one",
        roles=(Role.WORKER,),
        membership_epoch=1,
        session_epoch=1,
        ttl=timedelta(minutes=1),
        now=NOW,
    )
    payload, signature = issued.token.split(".", 1)
    tampered = f"{payload}.{('A' if signature[0] != 'A' else 'B')}{signature[1:]}"
    with pytest.raises(PolicyError, match="signature"):
        service.verify(
            tampered,
            principal=Principal.agent("agent:worker"),
            group_id="group:one",
            roles=(Role.WORKER,),
            membership_epoch=1,
            session_epoch=1,
            now=NOW,
        )
    with pytest.raises(PolicyError, match="expired"):
        service.verify(
            issued.token,
            principal=Principal.agent("agent:worker"),
            group_id="group:one",
            roles=(Role.WORKER,),
            membership_epoch=1,
            session_epoch=1,
            now=NOW + timedelta(minutes=1),
        )


def test_capability_grant_is_fenced_by_session_ownership_and_execution_lease(
    execution_lease: ExecutionLease,
) -> None:
    authorization = AuthorizationService(b"capability-secret" * 3)
    issued = authorization.issue(
        worker_id="agent:worker",
        session_epoch=execution_lease.session_epoch,
        work_item_id=execution_lease.work_item_id,
        ownership_epoch=execution_lease.ownership_epoch,
        execution_lease=execution_lease,
        ttl=timedelta(minutes=4),
        allowed_operations=("repository.read",),
        now=NOW,
    )

    assert (
        authorization.verify(
            issued.token,
            worker_id="agent:worker",
            session_epoch=execution_lease.session_epoch,
            work_item_id=execution_lease.work_item_id,
            ownership_epoch=execution_lease.ownership_epoch,
            execution_lease=execution_lease,
            operation="repository.read",
            now=NOW,
        ).grant_id
        == issued.claims.grant_id
    )
    with pytest.raises(PolicyError, match="Session Epoch"):
        authorization.verify(
            issued.token,
            worker_id="agent:worker",
            session_epoch=execution_lease.session_epoch + 1,
            work_item_id=execution_lease.work_item_id,
            ownership_epoch=execution_lease.ownership_epoch,
            execution_lease=execution_lease,
            now=NOW,
        )
    with pytest.raises(PolicyError, match="ownership"):
        authorization.verify(
            issued.token,
            worker_id="agent:worker",
            session_epoch=execution_lease.session_epoch,
            work_item_id=execution_lease.work_item_id,
            ownership_epoch=execution_lease.ownership_epoch + 1,
            execution_lease=execution_lease,
            now=NOW,
        )
    other_lease = _execution_lease(lease_id="lease:execution:other")
    with pytest.raises(PolicyError, match="Execution Lease ID"):
        authorization.verify(
            issued.token,
            worker_id="agent:worker",
            session_epoch=other_lease.session_epoch,
            work_item_id=other_lease.work_item_id,
            ownership_epoch=other_lease.ownership_epoch,
            execution_lease=other_lease,
            now=NOW,
        )


def test_capability_token_survives_valid_execution_lease_renewal(
    execution_lease: ExecutionLease,
) -> None:
    authorization = AuthorizationService(b"capability-secret" * 3)
    issued = authorization.issue(
        worker_id=execution_lease.holder_agent_id,
        session_epoch=execution_lease.session_epoch,
        work_item_id=execution_lease.work_item_id,
        ownership_epoch=execution_lease.ownership_epoch,
        execution_lease=execution_lease,
        ttl=timedelta(minutes=4),
        now=NOW,
    )
    renewed = execution_lease.renew(
        at=NOW + timedelta(minutes=1),
        expires_at=NOW + timedelta(minutes=7),
    )

    verified = authorization.verify(
        issued.token,
        worker_id=renewed.holder_agent_id,
        session_epoch=renewed.session_epoch,
        work_item_id=renewed.work_item_id,
        ownership_epoch=renewed.ownership_epoch,
        execution_lease=renewed,
        now=NOW + timedelta(minutes=2),
    )

    assert verified.execution_lease_id == renewed.lease_id
    assert verified.execution_lease_expires_at == execution_lease.expires_at


def test_capability_token_rejects_revoked_execution_lease(
    execution_lease: ExecutionLease,
) -> None:
    authorization = AuthorizationService(b"capability-secret" * 3)
    issued = authorization.issue(
        worker_id=execution_lease.holder_agent_id,
        session_epoch=execution_lease.session_epoch,
        work_item_id=execution_lease.work_item_id,
        ownership_epoch=execution_lease.ownership_epoch,
        execution_lease=execution_lease,
        ttl=timedelta(minutes=4),
        now=NOW,
    )
    revoked = execution_lease.close(
        LeaseState.REVOKED,
        at=NOW + timedelta(minutes=1),
        reason="session restarted",
    )

    with pytest.raises(PolicyError, match="Execution Lease is not active"):
        authorization.issue(
            worker_id=revoked.holder_agent_id,
            session_epoch=revoked.session_epoch,
            work_item_id=revoked.work_item_id,
            ownership_epoch=revoked.ownership_epoch,
            execution_lease=revoked,
            ttl=timedelta(minutes=1),
            now=NOW + timedelta(minutes=1),
        )
    with pytest.raises(PolicyError, match="Execution Lease is not active"):
        authorization.verify(
            issued.token,
            worker_id=revoked.holder_agent_id,
            session_epoch=revoked.session_epoch,
            work_item_id=revoked.work_item_id,
            ownership_epoch=revoked.ownership_epoch,
            execution_lease=revoked,
            now=NOW + timedelta(minutes=1),
        )


def test_capability_token_expiry_cannot_exceed_execution_lease() -> None:
    authorization = AuthorizationService(b"capability-secret" * 3)
    short_lease = _execution_lease(expires_at=NOW + timedelta(minutes=2))
    with pytest.raises(PolicyError, match="exceeds its Execution Lease"):
        authorization.issue(
            worker_id=short_lease.holder_agent_id,
            session_epoch=short_lease.session_epoch,
            work_item_id=short_lease.work_item_id,
            ownership_epoch=short_lease.ownership_epoch,
            execution_lease=short_lease,
            ttl=timedelta(minutes=3),
            now=NOW,
        )


def test_direct_high_risk_issue_cannot_trust_an_arbitrary_approval_id(
    execution_lease: ExecutionLease,
) -> None:
    authorization = AuthorizationService(b"capability-secret" * 3)
    with pytest.raises(PolicyError, match="ExecutionAuthorization"):
        authorization.issue(
            worker_id=execution_lease.holder_agent_id,
            session_epoch=execution_lease.session_epoch,
            work_item_id=execution_lease.work_item_id,
            ownership_epoch=execution_lease.ownership_epoch,
            execution_lease=execution_lease,
            ttl=timedelta(minutes=1),
            allowed_operations=("production.deploy",),
            high_risk=True,
            approval_id="approval:anything",
            now=NOW,
        )
    with pytest.raises(PolicyError, match="ExecutionAuthorization"):
        authorization.issue(
            worker_id=execution_lease.holder_agent_id,
            session_epoch=execution_lease.session_epoch,
            work_item_id=execution_lease.work_item_id,
            ownership_epoch=execution_lease.ownership_epoch,
            execution_lease=execution_lease,
            ttl=timedelta(minutes=1),
            allowed_operations=("production.deploy",),
            now=NOW,
        )


class FakePolicyCore:
    def __init__(
        self,
        *,
        mission: Mission,
        work_item: WorkItem,
        execution_lease: ExecutionLease,
        budget_remaining: ResourceBudget,
        session_epoch: int,
        approval: ExecutionApproval | None,
        event: Event | None,
        command: Command | None,
    ) -> None:
        self.mission = mission
        self.work_item = work_item
        self.execution_lease = execution_lease
        self.budget_remaining = budget_remaining
        self.session_epoch = session_epoch
        self.approval = approval
        self.event = event
        self.command = command

    async def query(self, query: Query) -> object:
        if query.kind is QueryKind.MISSION and query.entity_id == self.mission.id:
            return self.mission
        if query.kind is QueryKind.WORK_ITEM and query.entity_id == self.work_item.id:
            return self.work_item
        if (
            query.kind is QueryKind.EXECUTION_LEASE
            and query.entity_id == self.execution_lease.lease_id
        ):
            return self.execution_lease
        if query.kind is QueryKind.BUDGET_REMAINING and query.entity_id == self.work_item.id:
            return self.budget_remaining
        if query.kind is QueryKind.SESSION_EPOCH:
            return self.session_epoch
        if query.kind is QueryKind.EXECUTION_APPROVAL:
            return self.approval
        if query.kind is QueryKind.COMMAND and self.event is not None:
            return self.command if query.entity_id == self.event.id else None
        return None

    async def replay(
        self,
        group_id: str,
        *,
        after: int = 0,
        limit: int = 1_000,
    ) -> tuple[Event, ...]:
        del after, limit
        if self.event is None or group_id != self.mission.group_id:
            return ()
        return (self.event,)


def execution_state(
    *,
    forged: bool = False,
    operation: str = "production.deploy",
    execution_approval: str = "not_required",
    approval_expires_at: datetime = NOW + timedelta(minutes=5),
) -> tuple[FakePolicyCore, str]:
    private_key, public_key = generate_keypair()
    owner = Principal.human("human:owner")
    mission = Mission(
        id="mission:deploy",
        group_id="group:deploy",
        title="Deploy safely",
        objective="Authorize one production deployment",
        definition_of_done=("deployment verified",),
        owner=owner,
        coordinator_id="agent:coordinator",
        coordinator_epoch=1,
        coordinator_lease_expires_at=NOW + timedelta(hours=1),
        budget=ResourceBudget(model_tokens=1_000, tool_calls=10),
        deadline=NOW + timedelta(hours=2),
        permissions=(operation,),
        status=MissionStatus.ACTIVE,
        created_at=NOW,
        updated_at=NOW,
    )
    contract = WorkContract(
        goal="Deploy the verified release",
        deliverables=("deployment receipt",),
        acceptance_criteria=("health checks pass",),
        allowed_tools=("deployment.tool",),
        allowed_resources=("cluster:production",),
        deadline=NOW + timedelta(hours=1),
        budget=ResourceBudget(model_tokens=100, tool_calls=2, external_actions=1),
        execution_approval=execution_approval,
    )
    execution_lease = _execution_lease(
        mission_id=mission.id,
        group_id=mission.group_id,
        work_item_id="work:deploy",
        holder_agent_id="agent:worker",
        session_epoch=5,
        ownership_epoch=3,
    )
    work = WorkItem(
        id="work:deploy",
        mission_id=mission.id,
        group_id=mission.group_id,
        conversation_id="conversation:deploy",
        created_by=Principal.agent("agent:coordinator"),
        contract=contract,
        status=WorkItemStatus.ACTIVE,
        assignee_id="agent:worker",
        ownership_epoch=3,
        ownership_lease_expires_at=NOW + timedelta(minutes=10),
        execution_lease_id=execution_lease.lease_id,
        execution_lease_expires_at=execution_lease.expires_at,
        created_at=NOW,
        updated_at=NOW,
    )
    approval_payload = GrantExecutionApprovalPayload(
        approval_id="approval:deploy",
        work_item_id=work.id,
        ownership_epoch=work.ownership_epoch,
        operations=(operation,),
        resources=("cluster:production",),
        budget=ResourceBudget(model_tokens=100, tool_calls=2, external_actions=1),
        expires_in_seconds=int((approval_expires_at - NOW).total_seconds()),
        comments="Approve the production release gate",
    )
    unsigned = Command(
        action_id="action:approve-deploy",
        kind=CommandKind.GRANT_EXECUTION_APPROVAL,
        actor=owner,
        group_id=mission.group_id,
        issued_at=NOW,
        payload=approval_payload,
    )
    signature = sign_canonical(unsigned.signing_payload(), private_key)
    command = unsigned.model_copy(update={"signature": signature})
    approval = ExecutionApproval(
        id=approval_payload.approval_id,
        mission_id=mission.id,
        group_id=mission.group_id,
        work_item_id=work.id,
        ownership_epoch=work.ownership_epoch,
        operations=approval_payload.operations,
        resources=approval_payload.resources,
        budget=approval_payload.budget,
        approver=owner,
        approved_at=NOW,
        expires_at=approval_expires_at,
        comments=approval_payload.comments,
        signature=signature,
    )
    event = Event(
        id="event:approval",
        kind=EventKind.EXECUTION_APPROVAL_GRANTED,
        group_id=mission.group_id,
        sequence=1,
        actor=owner,
        action_id=command.action_id,
        command_hash="sha256:" + "b" * 64,
        payload={"approval": approval.model_dump(mode="json", by_alias=True)},
        occurred_at=NOW,
    )
    if forged:
        _other_private, public_key = generate_keypair()
    return (
        FakePolicyCore(
            mission=mission,
            work_item=work,
            execution_lease=execution_lease,
            budget_remaining=contract.budget,
            session_epoch=5,
            approval=approval,
            event=event,
            command=command,
        ),
        public_key,
    )


@pytest.mark.asyncio
async def test_execution_authorization_validates_live_state_and_persisted_signed_approval() -> None:
    core, public_key = execution_state()
    authorization = AuthorizationService(b"capability-secret" * 3)
    facade = ExecutionAuthorization(
        core,
        authorization,
        approval_key_resolver=lambda principal: (
            public_key if principal == core.mission.owner else None
        ),
        clock=lambda: NOW,
    )
    issued = await facade.issue(
        worker_id="agent:worker",
        session_epoch=5,
        work_item_id="work:deploy",
        ownership_epoch=3,
        ttl=timedelta(minutes=2),
        allowed_tools=("deployment.tool",),
        allowed_resources=("cluster:production",),
        allowed_operations=("production.deploy",),
        budget=ResourceBudget(model_tokens=50, tool_calls=1, external_actions=1),
        approval_id="approval:deploy",
    )

    assert issued.claims.approval_id == "approval:deploy"
    assert issued.claims.expires_at <= LEASE_EXPIRY
    assert (
        authorization.verify(
            issued.token,
            worker_id="agent:worker",
            session_epoch=5,
            work_item_id="work:deploy",
            ownership_epoch=3,
            execution_lease=core.execution_lease,
            operation="production.deploy",
            now=NOW,
        )
        == issued.claims
    )


@pytest.mark.asyncio
async def test_execution_authorization_rejects_missing_and_forged_high_risk_approval() -> None:
    core, public_key = execution_state()
    facade = ExecutionAuthorization(
        core,
        AuthorizationService(b"capability-secret" * 3),
        approval_key_resolver=lambda _principal: public_key,
        clock=lambda: NOW,
    )
    common = {
        "worker_id": "agent:worker",
        "session_epoch": 5,
        "work_item_id": "work:deploy",
        "ownership_epoch": 3,
        "ttl": timedelta(minutes=1),
        "allowed_tools": ("deployment.tool",),
        "allowed_resources": ("cluster:production",),
        "allowed_operations": ("production.deploy",),
    }
    with pytest.raises(PolicyError, match="persisted signed Approval"):
        await facade.issue(**common)

    forged_core, wrong_public_key = execution_state(forged=True)
    forged_facade = ExecutionAuthorization(
        forged_core,
        AuthorizationService(b"capability-secret" * 3),
        approval_key_resolver=lambda _principal: wrong_public_key,
        clock=lambda: NOW,
    )
    with pytest.raises(PolicyError, match="signature is invalid"):
        await forged_facade.issue(**common, approval_id="approval:deploy")


@pytest.mark.asyncio
async def test_contract_required_approval_gates_non_prefixed_operation_and_token_expiry() -> None:
    core, public_key = execution_state(
        operation="repository.release",
        execution_approval="human_required",
        approval_expires_at=NOW + timedelta(seconds=90),
    )
    facade = ExecutionAuthorization(
        core,
        AuthorizationService(b"capability-secret" * 3),
        approval_key_resolver=lambda _principal: public_key,
        clock=lambda: NOW,
    )
    common = {
        "worker_id": "agent:worker",
        "session_epoch": 5,
        "work_item_id": "work:deploy",
        "ownership_epoch": 3,
        "allowed_tools": ("deployment.tool",),
        "allowed_resources": ("cluster:production",),
        "allowed_operations": ("repository.release",),
    }

    with pytest.raises(PolicyError, match="persisted signed Approval"):
        await facade.issue(**common, ttl=timedelta(minutes=1))

    issued = await facade.issue(
        **common,
        ttl=timedelta(minutes=1),
        approval_id="approval:deploy",
    )
    assert issued.claims.approval_id == "approval:deploy"
    assert issued.claims.expires_at <= NOW + timedelta(seconds=90)

    with pytest.raises(PolicyError, match="Execution Approval"):
        await facade.issue(
            **common,
            ttl=timedelta(minutes=2),
            approval_id="approval:deploy",
        )


@pytest.mark.asyncio
async def test_execution_authorization_rejects_stale_state_and_budget_escalation() -> None:
    core, public_key = execution_state()
    facade = ExecutionAuthorization(
        core,
        AuthorizationService(b"capability-secret" * 3),
        approval_key_resolver=lambda _principal: public_key,
        clock=lambda: NOW,
    )
    with pytest.raises(PolicyError, match="Session Epoch"):
        await facade.issue(
            worker_id="agent:worker",
            session_epoch=4,
            work_item_id="work:deploy",
            ownership_epoch=3,
            ttl=timedelta(minutes=1),
        )
    with pytest.raises(PolicyError, match="Ownership Epoch"):
        await facade.issue(
            worker_id="agent:worker",
            session_epoch=5,
            work_item_id="work:deploy",
            ownership_epoch=2,
            ttl=timedelta(minutes=1),
        )
    with pytest.raises(PolicyError, match="budget exceeds"):
        await facade.issue(
            worker_id="agent:worker",
            session_epoch=5,
            work_item_id="work:deploy",
            ownership_epoch=3,
            ttl=timedelta(minutes=1),
            budget=ResourceBudget(model_tokens=101),
        )


@pytest.mark.asyncio
async def test_execution_authorization_rejects_revoked_authoritative_lease() -> None:
    core, public_key = execution_state()
    core.execution_lease = core.execution_lease.close(
        LeaseState.REVOKED,
        at=NOW,
        reason="session restarted",
    )
    facade = ExecutionAuthorization(
        core,
        AuthorizationService(b"capability-secret" * 3),
        approval_key_resolver=lambda _principal: public_key,
        clock=lambda: NOW,
    )

    with pytest.raises(PolicyError, match="Execution Lease scope is stale or inconsistent"):
        await facade.issue(
            worker_id="agent:worker",
            session_epoch=5,
            work_item_id="work:deploy",
            ownership_epoch=3,
            ttl=timedelta(minutes=1),
        )


@pytest.mark.asyncio
async def test_execution_authorization_uses_authoritative_remaining_budget() -> None:
    core, public_key = execution_state()
    core.budget_remaining = ResourceBudget(
        model_tokens=40,
        tool_calls=1,
        external_actions=1,
    )
    facade = ExecutionAuthorization(
        core,
        AuthorizationService(b"capability-secret" * 3),
        approval_key_resolver=lambda _principal: public_key,
        clock=lambda: NOW,
    )

    issued = await facade.issue(
        worker_id="agent:worker",
        session_epoch=5,
        work_item_id="work:deploy",
        ownership_epoch=3,
        ttl=timedelta(minutes=1),
    )

    assert issued.claims.budget == core.budget_remaining

    with pytest.raises(PolicyError, match="authoritative remaining budget"):
        await facade.issue(
            worker_id="agent:worker",
            session_epoch=5,
            work_item_id="work:deploy",
            ownership_epoch=3,
            ttl=timedelta(minutes=1),
            budget=ResourceBudget(
                model_tokens=41,
                tool_calls=1,
                external_actions=1,
            ),
        )


def test_budget_meter_rejects_overrun() -> None:
    meter = BudgetMeter(ResourceBudget(model_tokens=100, tool_calls=2))
    meter.consume(ResourceUsage(model_tokens=60, tool_calls=1))

    with pytest.raises(PolicyError, match="model_tokens"):
        meter.consume(ResourceUsage(model_tokens=41))


def test_budget_meter_treats_unspecified_dimensions_as_unallocated() -> None:
    meter = BudgetMeter(ResourceBudget(model_tokens=100))

    with pytest.raises(PolicyError, match="not allocated: tool_calls"):
        meter.consume(ResourceUsage(tool_calls=1))

    assert meter.usage == ResourceUsage()


def test_policy_limits_and_rates_reject_threshold_breaches_locally() -> None:
    guard = PolicyGuard(
        CooperationLimits(
            maximum_delegation_depth=2,
            maximum_queued_work_items=1,
            maximum_active_work_items=1,
            maximum_unresolved_clarifications=1,
            maximum_message_rate_per_minute=2,
            maximum_proposal_rate_per_minute=1,
            maximum_clarification_rate_per_minute=1,
        )
    )

    with pytest.raises(PolicyError, match="delegation"):
        guard.check_delegation_depth(3)
    with pytest.raises(PolicyError, match="queue"):
        guard.check_queue(2, 1)
    with pytest.raises(PolicyError, match="clarification"):
        guard.check_unresolved_clarifications(2)

    guard.check_message_rate("agent:worker", "group:one", now=NOW)
    guard.check_message_rate("agent:worker", "group:one", now=NOW)
    with pytest.raises(PolicyError, match="message rate"):
        guard.check_message_rate("agent:worker", "group:one", now=NOW)

    guard.check_proposal_rate("agent:worker", "group:one", now=NOW)
    with pytest.raises(PolicyError, match="proposal rate"):
        guard.check_proposal_rate("agent:worker", "group:one", now=NOW)

    guard.check_clarification_rate("agent:worker", "group:one", now=NOW)
    with pytest.raises(PolicyError, match="clarification rate"):
        guard.check_clarification_rate("agent:worker", "group:one", now=NOW)

    assert guard.classify_action("production.deploy") == "human_approval_required"
    assert guard.classify_action("repository.read") == "automatic"
