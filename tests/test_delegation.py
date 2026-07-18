from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from jsonschema import ValidationError as JSONSchemaValidationError
from pydantic import ValidationError as PydanticValidationError

from missionweaveprotocol.auth import default_agent_key_id
from missionweaveprotocol.conformance import SchemaCatalog
from missionweaveprotocol.core import (
    AuthorizationDenied,
    Core,
    InvalidTransition,
    LeaseExpired,
    PolicyViolation,
    RevisionConflict,
    StaleCoordinatorEpoch,
    StaleMembershipEpoch,
)
from missionweaveprotocol.crypto import generate_keypair
from missionweaveprotocol.models import (
    ActorType,
    AddMembershipPayload,
    AgentCard,
    CancelWorkItemPayload,
    Capability,
    CapabilityRequirement,
    Command,
    CommandKind,
    CooperationPolicyName,
    CreateMissionPayload,
    CreateWorkItemPayload,
    DelegationBudget,
    DelegationGrant,
    EndMembershipPayload,
    Event,
    EventKind,
    GrantCooperationOverridePayload,
    GrantDelegationPayload,
    Membership,
    OfferWorkItemPayload,
    OpenAgentSessionPayload,
    Principal,
    ProposeWorkItemPayload,
    Query,
    QueryKind,
    RegisterAgentCardPayload,
    ReplaceCoordinatorPayload,
    ResourceBudget,
    Role,
    SelectionBasis,
    SignatureEnvelope,
    WorkContract,
    WorkItem,
    WorkItemStatus,
)
from missionweaveprotocol.policy import CooperationLimits
from missionweaveprotocol.store import AuthoritativeStore, InMemoryStore, SQLiteStore


@dataclass
class MutableClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value

    def advance(self, *, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class DelegationHarness:
    def __init__(self, core: Core, store: AuthoritativeStore, clock: MutableClock) -> None:
        self.core = core
        self.store = store
        self.clock = clock
        self.system = Principal.system()
        self.owner = Principal.human("human:owner")
        self.coordinator = Principal.agent("agent:coordinator")
        self.delegate = Principal.agent("agent:delegate")
        self.other_delegate = Principal.agent("agent:other-delegate")
        self.worker = Principal.agent("agent:worker")
        self.epochs: dict[str, int] = {}
        self.action_number = 0

    def command(
        self,
        kind: CommandKind,
        actor: Principal,
        payload: Any,
        *,
        group_id: str | None = None,
        coordinator_epoch: int | None = None,
        cooperation_override_grant_id: str | None = None,
        action_id: str | None = None,
    ) -> Command:
        self.action_number += 1
        session_epoch = self.epochs.get(actor.id) if actor.type is ActorType.AGENT else None
        resolved_action_id = action_id or f"action:delegation:{self.action_number}"
        return Command(
            action_id=resolved_action_id,
            kind=kind,
            actor=actor,
            group_id=group_id,
            session_epoch=session_epoch,
            coordinator_epoch=coordinator_epoch,
            correlation_id=resolved_action_id,
            conversation_id=getattr(payload, "conversation_id", None),
            work_item_id=getattr(payload, "work_item_id", None),
            cooperation_override_grant_id=cooperation_override_grant_id,
            issued_at=self.clock(),
            payload=payload,
            signature=SignatureEnvelope(
                key_id=default_agent_key_id(actor.id),
                created_at=self.clock(),
                value="test-signature",
            ),
        )

    async def perform(self, command: Command) -> Event:
        if (
            command.group_id is not None
            and command.actor.type is not ActorType.SYSTEM
            and command.kind
            not in {CommandKind.CREATE_MISSION, CommandKind.CREATE_FOLLOW_UP_MISSION}
        ):
            membership = await self.core.query(
                Query(
                    kind=QueryKind.MEMBERSHIP,
                    entity_id=command.actor.id,
                    group_id=command.group_id,
                    actor_type=command.actor.type,
                )
            )
            if not isinstance(membership, Membership):
                raise AssertionError("test command issuer lacks an authoritative Membership")
            command = command.model_copy(update={"membership_epoch": membership.epoch})
        return await self.core.perform(command)

    async def register(self, agent_id: str, *, python_version: int = 3) -> None:
        _private_key, public_key = generate_keypair()
        card = AgentCard(
            agent_id=agent_id,
            version=1,
            display_name=agent_id,
            owner="test-organization",
            public_key=public_key,
            capabilities=(Capability(id="software.python", version=python_version),),
            issued_at=self.clock(),
            signature="organization-signature",
        )
        await self.perform(
            self.command(
                CommandKind.REGISTER_AGENT_CARD,
                self.system,
                RegisterAgentCardPayload(card=card),
            )
        )
        event = await self.perform(
            self.command(
                CommandKind.OPEN_AGENT_SESSION,
                self.system,
                OpenAgentSessionPayload(agent_id=agent_id),
            )
        )
        self.epochs[agent_id] = int(event.payload["sessionEpoch"])

    async def initialize(self) -> None:
        for agent_id in (
            self.coordinator.id,
            self.delegate.id,
            self.other_delegate.id,
            self.worker.id,
            "agent:replacement",
        ):
            await self.register(agent_id)
        await self.perform(
            self.command(
                CommandKind.CREATE_MISSION,
                self.owner,
                CreateMissionPayload(
                    mission_id="mission:root",
                    group_id="group:root",
                    coordinator_id=self.coordinator.id,
                    title="Delegate a bounded work tree",
                    objective="Verify scoped authority",
                    definition_of_done=("delegated work is bounded",),
                    budget=ResourceBudget(
                        financial_microunits=1_000_000,
                        model_tokens=10_000,
                        tool_calls=1_000,
                        compute_seconds=10_000,
                        wall_clock_seconds=14_400,
                        external_actions=100,
                    ),
                    deadline=self.clock() + timedelta(hours=4),
                    coordinator_lease_seconds=10_800,
                ),
                group_id="group:root",
            )
        )
        await self.add_member(self.delegate, (Role.WORK_DELEGATE,))
        await self.add_member(self.other_delegate, (Role.WORK_DELEGATE,))
        await self.add_member(self.worker, (Role.WORKER,))
        await self.create_coordinator_work(
            "work:root",
            self.contract(goal="Scope root", tokens=100, tool_calls=20),
        )

    async def add_member(self, principal: Principal, roles: tuple[Role, ...]) -> Event:
        return await self.perform(
            self.command(
                CommandKind.ADD_MEMBERSHIP,
                self.coordinator,
                AddMembershipPayload(principal=principal, roles=roles),
                group_id="group:root",
                coordinator_epoch=1,
            )
        )

    def contract(
        self,
        *,
        goal: str = "Implement delegated work",
        capability_id: str = "software.python",
        minimum_version: int = 2,
        tokens: int = 1,
        tool_calls: int = 0,
    ) -> WorkContract:
        return WorkContract(
            goal=goal,
            deliverables=("source",),
            acceptance_criteria=("tests pass",),
            required_capabilities=(
                CapabilityRequirement(id=capability_id, minimum_version=minimum_version),
            ),
            budget=ResourceBudget(model_tokens=tokens, tool_calls=tool_calls),
            deadline=self.clock() + timedelta(hours=1),
        )

    @staticmethod
    def grant_budget(*, tokens: int = 200, tool_calls: int = 40) -> DelegationBudget:
        return DelegationBudget(
            currency="USD",
            financial_microunits=0,
            model_tokens=tokens,
            tool_calls=tool_calls,
            compute_seconds=0,
            wall_clock_seconds=0,
            external_actions=0,
        )

    async def issue_grant(
        self,
        *,
        grant_id: str = "grant:scoped",
        grantee_agent_id: str | None = None,
        target_work_item_id: str = "work:root",
        allowed_capabilities: tuple[CapabilityRequirement, ...] | None = None,
        budget: DelegationBudget | None = None,
        max_descendant_depth: int = 2,
        expires_at: datetime | None = None,
        cooperation_override_grant_id: str | None = None,
        action_id: str | None = None,
    ) -> Event:
        return await self.perform(
            self.command(
                CommandKind.GRANT_DELEGATION,
                self.coordinator,
                GrantDelegationPayload(
                    grant_id=grant_id,
                    grantee_agent_id=grantee_agent_id or self.delegate.id,
                    target_work_item_id=target_work_item_id,
                    allowed_capabilities=allowed_capabilities
                    or (CapabilityRequirement(id="software.python", minimum_version=2),),
                    budget=budget or self.grant_budget(),
                    max_descendant_depth=max_descendant_depth,
                    expires_at=expires_at or self.clock() + timedelta(hours=2),
                ),
                group_id="group:root",
                coordinator_epoch=1,
                cooperation_override_grant_id=cooperation_override_grant_id,
                action_id=action_id,
            )
        )

    async def issue_cooperation_override(
        self,
        *,
        grant_id: str,
        beneficiary: Principal,
        target_command_kind: CommandKind,
        target_action_id: str,
    ) -> Event:
        return await self.perform(
            self.command(
                CommandKind.GRANT_COOPERATION_OVERRIDE,
                self.owner,
                GrantCooperationOverridePayload(
                    grant_id=grant_id,
                    policy_name=CooperationPolicyName.DELEGATION_DEPTH,
                    beneficiary=beneficiary,
                    target_command_kind=target_command_kind,
                    target_action_id=target_action_id,
                    reason="MissionOwner approved bounded extra delegation depth",
                    expires_at=self.clock() + timedelta(minutes=10),
                ),
                group_id="group:root",
            )
        )

    async def create_coordinator_work(
        self,
        work_item_id: str,
        contract: WorkContract,
        *,
        parent_work_item_id: str | None = None,
    ) -> Event:
        return await self.perform(
            self.command(
                CommandKind.CREATE_WORK_ITEM,
                self.coordinator,
                CreateWorkItemPayload(
                    work_item_id=work_item_id,
                    contract=contract,
                    parent_work_item_id=parent_work_item_id,
                ),
                group_id="group:root",
                coordinator_epoch=1,
            )
        )

    async def create_delegated_work(
        self,
        work_item_id: str,
        *,
        actor: Principal | None = None,
        parent_work_item_id: str = "work:root",
        contract: WorkContract | None = None,
        delegation_grant_id: str | None = "grant:scoped",
        proposal_id: str | None = None,
        cooperation_override_grant_id: str | None = None,
        action_id: str | None = None,
    ) -> Event:
        return await self.perform(
            self.command(
                CommandKind.CREATE_WORK_ITEM,
                actor or self.delegate,
                CreateWorkItemPayload(
                    work_item_id=work_item_id,
                    contract=contract or self.contract(),
                    parent_work_item_id=parent_work_item_id,
                    delegation_grant_id=delegation_grant_id,
                    proposal_id=proposal_id,
                ),
                group_id="group:root",
                cooperation_override_grant_id=cooperation_override_grant_id,
                action_id=action_id,
            )
        )

    async def offer_delegated_work(
        self,
        work_item_id: str,
        *,
        actor: Principal | None = None,
        delegation_grant_id: str | None = "grant:scoped",
    ) -> Event:
        work = await self.core.query(Query(kind=QueryKind.WORK_ITEM, entity_id=work_item_id))
        assert isinstance(work, WorkItem)
        return await self.perform(
            self.command(
                CommandKind.OFFER_WORK_ITEM,
                actor or self.delegate,
                OfferWorkItemPayload(
                    work_item_id=work_item_id,
                    candidate_agent_ids=(self.worker.id,),
                    selection_basis=SelectionBasis(
                        required_capabilities=work.contract.required_capabilities,
                        verified_capability_matches=tuple(
                            item.id for item in work.contract.required_capabilities
                        ),
                    ),
                    delegation_grant_id=delegation_grant_id,
                ),
                group_id="group:root",
            )
        )


async def _ready_harness(
    *,
    store: AuthoritativeStore | None = None,
    cooperation_limits: CooperationLimits | None = None,
) -> DelegationHarness:
    authoritative_store = store or InMemoryStore()
    clock = MutableClock(datetime(2026, 7, 15, 8, 0, tzinfo=UTC))
    harness = DelegationHarness(
        Core(
            authoritative_store,
            clock=clock,
            cooperation_limits=cooperation_limits,
        ),
        authoritative_store,
        clock,
    )
    await harness.initialize()
    return harness


@pytest.fixture
async def delegation() -> DelegationHarness:
    return await _ready_harness()


@pytest.mark.asyncio
async def test_scoped_grant_can_be_queried_and_used_to_offer_root_and_authorize_descendant(
    delegation: DelegationHarness,
) -> None:
    event = await delegation.issue_grant()
    grant = await delegation.core.query(
        Query(kind=QueryKind.DELEGATION_GRANT, entity_id="grant:scoped")
    )

    assert event.kind is EventKind.DELEGATION_GRANTED
    assert isinstance(grant, DelegationGrant)
    assert grant.granted_by == delegation.coordinator
    assert grant.coordinator_epoch == 1
    assert grant.grantee_membership_epoch == 1
    assert grant.budget.currency == "USD"

    await delegation.offer_delegated_work("work:root")
    await delegation.create_delegated_work(
        "work:child",
        contract=delegation.contract(goal="Scoped child", tokens=3),
    )
    await delegation.offer_delegated_work("work:child")
    root = await delegation.core.query(Query(kind=QueryKind.WORK_ITEM, entity_id="work:root"))
    child = await delegation.core.query(Query(kind=QueryKind.WORK_ITEM, entity_id="work:child"))

    assert isinstance(root, WorkItem)
    assert root.delegation_grant_id == grant.id
    assert root.status is WorkItemStatus.OFFERED
    assert isinstance(child, WorkItem)
    assert child.parent_work_item_id == root.id
    assert child.delegation_grant_id == grant.id
    assert child.delegation_depth == 1
    assert child.status is WorkItemStatus.OFFERED


@pytest.mark.asyncio
async def test_sqlite_restart_preserves_grant_and_allows_later_delegated_use(
    tmp_path: Path,
) -> None:
    path = tmp_path / "delegation.sqlite3"
    first_store = SQLiteStore(path)
    delegation = await _ready_harness(store=first_store)
    await delegation.issue_grant()
    await first_store.close()

    second_store = SQLiteStore(path)
    delegation.store = second_store
    delegation.core = Core(second_store, clock=delegation.clock)
    grant = await delegation.core.query(
        Query(kind=QueryKind.DELEGATION_GRANT, entity_id="grant:scoped")
    )
    await delegation.create_delegated_work("work:after-restart")
    child = await delegation.core.query(
        Query(kind=QueryKind.WORK_ITEM, entity_id="work:after-restart")
    )
    await second_store.close()

    assert isinstance(grant, DelegationGrant)
    assert grant.budget.currency == "USD"
    assert isinstance(child, WorkItem)
    assert child.delegation_grant_id == grant.id


@pytest.mark.asyncio
@pytest.mark.parametrize("grant_id", [None, "grant:forged"])
async def test_bare_delegate_role_and_unknown_grant_never_authorize(
    delegation: DelegationHarness,
    grant_id: str | None,
) -> None:
    with pytest.raises(AuthorizationDenied, match=r"Grant|grant"):
        await delegation.create_delegated_work(
            "work:unauthorized",
            delegation_grant_id=grant_id,
        )


@pytest.mark.asyncio
async def test_grant_cannot_authorize_outside_its_target_subtree(
    delegation: DelegationHarness,
) -> None:
    await delegation.create_coordinator_work(
        "work:unrelated",
        delegation.contract(goal="Unrelated root"),
    )
    await delegation.issue_grant()

    with pytest.raises(AuthorizationDenied, match="outside"):
        await delegation.create_delegated_work(
            "work:wrong-scope",
            parent_work_item_id="work:unrelated",
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("capability_id", "minimum_version", "message"),
    [
        ("software.rust", 2, "outside"),
        ("software.python", 1, "version 2"),
    ],
)
async def test_grant_enforces_capability_id_and_minimum_version(
    delegation: DelegationHarness,
    capability_id: str,
    minimum_version: int,
    message: str,
) -> None:
    await delegation.issue_grant()

    with pytest.raises(PolicyViolation, match=message):
        await delegation.create_delegated_work(
            "work:capability-violation",
            contract=delegation.contract(
                capability_id=capability_id,
                minimum_version=minimum_version,
            ),
        )


@pytest.mark.asyncio
async def test_grant_enforces_per_item_and_cumulative_six_dimension_budget(
    delegation: DelegationHarness,
) -> None:
    await delegation.issue_grant(budget=delegation.grant_budget(tokens=5))

    with pytest.raises(PolicyViolation, match="model_tokens"):
        await delegation.create_delegated_work(
            "work:too-large",
            contract=delegation.contract(tokens=6),
        )

    await delegation.create_delegated_work(
        "work:first-allocation",
        contract=delegation.contract(tokens=3),
    )
    with pytest.raises(PolicyViolation, match="model_tokens"):
        await delegation.create_delegated_work(
            "work:cumulative-overflow",
            contract=delegation.contract(tokens=3),
        )


@pytest.mark.asyncio
async def test_grant_maximum_descendant_depth_is_relative_to_scope_root(
    delegation: DelegationHarness,
) -> None:
    await delegation.issue_grant(max_descendant_depth=1)
    await delegation.create_delegated_work("work:depth-one")

    with pytest.raises(PolicyViolation, match="maximum descendant depth"):
        await delegation.create_delegated_work(
            "work:depth-two",
            parent_work_item_id="work:depth-one",
        )


@pytest.mark.asyncio
async def test_organization_depth_limit_requires_override_on_grant_and_use() -> None:
    delegation = await _ready_harness(
        cooperation_limits=CooperationLimits(maximum_delegation_depth=1),
    )

    with pytest.raises(PolicyViolation, match="Grant depth"):
        await delegation.issue_grant(max_descendant_depth=2)
    await delegation.issue_cooperation_override(
        grant_id="override:grant-depth",
        beneficiary=delegation.coordinator,
        target_command_kind=CommandKind.GRANT_DELEGATION,
        target_action_id="approved:grant-depth",
    )
    await delegation.issue_grant(
        max_descendant_depth=2,
        cooperation_override_grant_id="override:grant-depth",
        action_id="approved:grant-depth",
    )
    await delegation.create_delegated_work("work:depth-one")
    with pytest.raises(PolicyViolation, match="delegation depth"):
        await delegation.create_delegated_work(
            "work:depth-two-denied",
            parent_work_item_id="work:depth-one",
        )
    await delegation.issue_cooperation_override(
        grant_id="override:work-depth",
        beneficiary=delegation.delegate,
        target_command_kind=CommandKind.CREATE_WORK_ITEM,
        target_action_id="approved:work-depth",
    )
    await delegation.create_delegated_work(
        "work:depth-two-approved",
        parent_work_item_id="work:depth-one",
        cooperation_override_grant_id="override:work-depth",
        action_id="approved:work-depth",
    )


@pytest.mark.asyncio
async def test_coordinator_replacement_fences_existing_grant(
    delegation: DelegationHarness,
) -> None:
    await delegation.issue_grant()
    await delegation.perform(
        delegation.command(
            CommandKind.REPLACE_COORDINATOR,
            delegation.owner,
            ReplaceCoordinatorPayload(coordinator_id="agent:replacement", lease_seconds=3_600),
            group_id="group:root",
        )
    )

    with pytest.raises(StaleCoordinatorEpoch):
        await delegation.create_delegated_work("work:stale-coordinator")


@pytest.mark.asyncio
async def test_expired_grant_is_rejected(
    delegation: DelegationHarness,
) -> None:
    await delegation.issue_grant(expires_at=delegation.clock() + timedelta(seconds=30))
    delegation.clock.advance(seconds=31)

    with pytest.raises(LeaseExpired):
        await delegation.create_delegated_work("work:expired")


@pytest.mark.asyncio
async def test_grant_is_nontransferable_to_another_delegate(
    delegation: DelegationHarness,
) -> None:
    await delegation.issue_grant()

    with pytest.raises(AuthorizationDenied, match="grantee"):
        await delegation.create_delegated_work(
            "work:wrong-grantee",
            actor=delegation.other_delegate,
        )


@pytest.mark.asyncio
async def test_ended_membership_invalidates_grant(
    delegation: DelegationHarness,
) -> None:
    await delegation.issue_grant()
    await delegation.perform(
        delegation.command(
            CommandKind.END_MEMBERSHIP,
            delegation.coordinator,
            EndMembershipPayload(principal=delegation.delegate),
            group_id="group:root",
            coordinator_epoch=1,
        )
    )

    with pytest.raises(AuthorizationDenied, match="active work_delegate"):
        await delegation.create_delegated_work("work:ended-membership")


@pytest.mark.asyncio
async def test_reactivated_membership_does_not_revive_old_grant(
    delegation: DelegationHarness,
) -> None:
    await delegation.issue_grant()
    await delegation.perform(
        delegation.command(
            CommandKind.END_MEMBERSHIP,
            delegation.coordinator,
            EndMembershipPayload(principal=delegation.delegate),
            group_id="group:root",
            coordinator_epoch=1,
        )
    )
    await delegation.add_member(delegation.delegate, (Role.WORK_DELEGATE,))

    with pytest.raises(StaleMembershipEpoch):
        await delegation.create_delegated_work("work:stale-membership")


@pytest.mark.asyncio
async def test_grant_issuance_rejects_terminal_target(
    delegation: DelegationHarness,
) -> None:
    await delegation.perform(
        delegation.command(
            CommandKind.CANCEL_WORK_ITEM,
            delegation.coordinator,
            CancelWorkItemPayload(work_item_id="work:root", reason="scope closed"),
            group_id="group:root",
            coordinator_epoch=1,
        )
    )

    with pytest.raises(InvalidTransition, match="terminal"):
        await delegation.issue_grant()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "terminal_status",
    [WorkItemStatus.VERIFIED, WorkItemStatus.FAILED, WorkItemStatus.CANCELLED],
)
async def test_target_becoming_terminal_invalidates_grant_at_every_use(
    delegation: DelegationHarness,
    terminal_status: WorkItemStatus,
) -> None:
    await delegation.issue_grant()

    def terminalize_target(state: Any) -> None:
        state.work_items["work:root"].status = terminal_status

    await delegation.store.transact(terminalize_target)

    with pytest.raises(AuthorizationDenied, match="target WorkItem is terminal"):
        await delegation.create_delegated_work(f"work:after-{terminal_status.value}")


@pytest.mark.asyncio
async def test_authorizing_proposal_must_preserve_parent_scope(
    delegation: DelegationHarness,
) -> None:
    await delegation.issue_grant(max_descendant_depth=2)
    await delegation.create_delegated_work("work:first-child")
    contract = delegation.contract(goal="Proposal with a stable parent")
    await delegation.perform(
        delegation.command(
            CommandKind.PROPOSE_WORK_ITEM,
            delegation.delegate,
            ProposeWorkItemPayload(
                proposal_id="proposal:scoped",
                contract=contract,
                parent_work_item_id="work:root",
            ),
            group_id="group:root",
        )
    )

    with pytest.raises(RevisionConflict, match=r"preserve proposed.*scope"):
        await delegation.create_delegated_work(
            "work:proposal-mismatch",
            parent_work_item_id="work:first-child",
            contract=contract,
            proposal_id="proposal:scoped",
        )


def test_delegation_budget_requires_currency_and_all_six_ceilings() -> None:
    with pytest.raises(PydanticValidationError):
        DelegationBudget(
            currency="usd",
            financial_microunits=0,
            model_tokens=1,
            tool_calls=1,
            compute_seconds=1,
            wall_clock_seconds=1,
            external_actions=1,
        )

    incomplete = DelegationBudget(currency="USD", model_tokens=1)
    with pytest.raises(PydanticValidationError, match="all six budget ceilings"):
        GrantDelegationPayload(
            grant_id="grant:incomplete",
            grantee_agent_id="agent:delegate",
            target_work_item_id="work:root",
            allowed_capabilities=(CapabilityRequirement(id="software.python"),),
            budget=incomplete,
            max_descendant_depth=1,
            expires_at=datetime(2026, 7, 15, 9, 0, tzinfo=UTC),
        )


def test_membership_schema_models_authoritative_work_delegate_grant() -> None:
    document = {
        "membershipId": "urn:missionweaveprotocol:membership:delegate",
        "missionId": "urn:missionweaveprotocol:mission:root",
        "groupId": "urn:missionweaveprotocol:group:root",
        "member": {"type": "agent", "id": "urn:missionweaveprotocol:agent:delegate"},
        "role": "work_delegate",
        "state": "active",
        "membershipEpoch": 3,
        "scopes": ["work.authorize", "work.offer"],
        "delegationGrants": [
            {
                "grantId": "urn:missionweaveprotocol:grant:scoped",
                "granteeAgentId": "urn:missionweaveprotocol:agent:delegate",
                "missionId": "urn:missionweaveprotocol:mission:root",
                "groupId": "urn:missionweaveprotocol:group:root",
                "targetWorkItemId": "urn:missionweaveprotocol:work:root",
                "allowedCapabilities": [{"id": "software.python", "version": "2.0.0"}],
                "budget": {
                    "currency": "USD",
                    "financialLimit": 0,
                    "modelTokenLimit": 100,
                    "toolCallLimit": 10,
                    "computeSecondsLimit": 0,
                    "wallClockSecondsLimit": 0,
                    "externalSideEffectLimit": 0,
                },
                "maxDescendantDepth": 2,
                "granteeMembershipEpoch": 3,
                "coordinatorEpoch": 4,
                "grantedBy": {"type": "agent", "id": "urn:missionweaveprotocol:agent:coordinator"},
                "grantedAt": "2026-07-15T08:00:00Z",
                "expiresAt": "2026-07-15T09:00:00Z",
            }
        ],
        "visibilityStartSequence": 1,
        "grantedAt": "2026-07-15T08:00:00Z",
        "activatedAt": "2026-07-15T08:00:00Z",
    }
    catalog = SchemaCatalog()

    catalog.validate("membership.schema.json", document)
    invalid = dict(document)
    invalid_grant = dict(document["delegationGrants"][0])
    invalid_budget = dict(invalid_grant["budget"])
    del invalid_budget["currency"]
    invalid_grant["budget"] = invalid_budget
    invalid["delegationGrants"] = [invalid_grant]
    with pytest.raises(JSONSchemaValidationError):
        catalog.validate("membership.schema.json", invalid)
