from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import asyncpg  # type: ignore[import-untyped]
import pytest

from missionweaveprotocol.canonical import canonical_hash, canonical_json
from missionweaveprotocol.context import PolicyLogEntry, SnapshotArchive
from missionweaveprotocol.control import HumanControl, HumanIdentity
from missionweaveprotocol.core import (
    ActionIdCollision,
    AlreadyExists,
    AuthorizationDenied,
    Core,
    InvalidCommand,
    InvalidTransition,
    NotFound,
    PolicyViolation,
    RevisionConflict,
    StaleMembershipEpoch,
    StaleOwnershipEpoch,
    StaleSessionEpoch,
)
from missionweaveprotocol.crypto import generate_keypair, sign_canonical, verify_canonical
from missionweaveprotocol.lease import ExecutionLease
from missionweaveprotocol.models import (
    AcceptWorkOfferPayload,
    ActorType,
    AddMembershipPayload,
    AgentCard,
    Approval,
    ApproveMissionPayload,
    ArchiveGroupPayload,
    Artifact,
    CancelMissionPayload,
    Capability,
    CapabilityRequirement,
    ChildFailurePolicy,
    Command,
    CommandKind,
    CooperationOverrideGrant,
    CooperationPolicyName,
    CorrectMessagePayload,
    CreateChildMissionPayload,
    CreateMissionPayload,
    CreateWorkItemPayload,
    Event,
    EventKind,
    Evidence,
    ExecutionApproval,
    FailMissionPayload,
    GrantCooperationOverridePayload,
    Group,
    GroupSnapshot,
    Message,
    MessageAmendment,
    MessageAmendmentKind,
    Mission,
    MissionStatus,
    OfferWorkItemPayload,
    OpenAgentSessionPayload,
    PostMessagePayload,
    Principal,
    ProposeWorkItemPayload,
    PublishArtifactPayload,
    Query,
    QueryKind,
    RedactMessagePayload,
    RegisterAgentCardPayload,
    RequestMissionChangesPayload,
    ResourceBudget,
    RetractMessagePayload,
    Role,
    SelectionBasis,
    StartWorkItemPayload,
    SubmitMissionPayload,
    SubmitWorkItemPayload,
    VerifyWorkItemPayload,
    WorkContract,
    WorkItem,
    WorkItemStatus,
    WorkProposal,
    WorkProposalStatus,
)
from missionweaveprotocol.policy import (
    AuthorizationService,
    CooperationLimits,
    ExecutionAuthorization,
)
from missionweaveprotocol.store import (
    AuthoritativeStore,
    InMemoryStore,
    PostgreSQLStore,
    SQLiteStore,
)


@dataclass
class MutableClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value

    def advance(self, *, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


class Scenario:
    def __init__(self, core: Core, clock: MutableClock) -> None:
        self.core = core
        self.clock = clock
        self.system = Principal.system()
        self.owner = Principal.human("human:owner")
        self.epochs: dict[str, int] = {}
        self.private_keys: dict[str, str] = {}
        self.action_number = 0

    def command(
        self,
        kind: CommandKind,
        actor: Principal,
        payload: Any,
        *,
        group_id: str | None = None,
        coordinator_epoch: int | None = None,
        session_epoch: int | None = None,
        membership_epoch: int | None = None,
        cooperation_override_grant_id: str | None = None,
        action_id: str | None = None,
        expected_revision: int | None = None,
    ) -> Command:
        self.action_number += 1
        if session_epoch is None and actor.type is ActorType.AGENT:
            session_epoch = self.epochs[actor.id]
        return Command(
            action_id=action_id or f"action:{self.action_number}",
            kind=kind,
            actor=actor,
            group_id=group_id,
            session_epoch=session_epoch,
            membership_epoch=membership_epoch,
            coordinator_epoch=coordinator_epoch,
            cooperation_override_grant_id=cooperation_override_grant_id,
            expected_revision=expected_revision,
            issued_at=self.clock(),
            payload=payload,
            signature="test-signature",
        )

    async def register(self, agent_id: str, *capabilities: str) -> None:
        private_key, public_key = generate_keypair()
        self.private_keys[agent_id] = private_key
        card = AgentCard(
            agent_id=agent_id,
            version=1,
            display_name=agent_id,
            owner="test-developer",
            public_key=public_key,
            capabilities=tuple(Capability(id=capability, version=1) for capability in capabilities),
            issued_at=self.clock(),
            signature="organization-signature",
        )
        await self.core.perform(
            self.command(
                CommandKind.REGISTER_AGENT_CARD,
                self.system,
                RegisterAgentCardPayload(card=card),
            )
        )
        event = await self.core.perform(
            self.command(
                CommandKind.OPEN_AGENT_SESSION,
                self.system,
                OpenAgentSessionPayload(agent_id=agent_id),
            )
        )
        self.epochs[agent_id] = int(event.payload["sessionEpoch"])

    def sign_artifact(self, artifact: Artifact) -> Artifact:
        return artifact.model_copy(
            update={
                "signature": sign_canonical(
                    artifact.signing_payload(),
                    self.private_keys[artifact.producing_agent_id],
                )
            }
        )

    async def reopen(self, agent_id: str) -> int:
        event = await self.core.perform(
            self.command(
                CommandKind.OPEN_AGENT_SESSION,
                self.system,
                OpenAgentSessionPayload(agent_id=agent_id),
            )
        )
        self.epochs[agent_id] = int(event.payload["sessionEpoch"])
        return self.epochs[agent_id]

    async def create_root(
        self, *, mission_id: str = "mission:root", group_id: str = "group:root"
    ) -> None:
        await self.core.perform(
            self.command(
                CommandKind.CREATE_MISSION,
                self.owner,
                CreateMissionPayload(
                    mission_id=mission_id,
                    group_id=group_id,
                    coordinator_id="agent:coordinator",
                    title="Ship a feature",
                    objective="Produce an accepted implementation",
                    definition_of_done=("tests pass", "human approves"),
                    budget=ResourceBudget(model_tokens=1_000, external_actions=10),
                    deadline=self.clock() + timedelta(hours=4),
                    permissions=("production.deploy",),
                    coordinator_lease_seconds=7_200,
                ),
                group_id=group_id,
            )
        )

    async def add_worker(self, agent_id: str, *, group_id: str = "group:root") -> None:
        await self.core.perform(
            self.command(
                CommandKind.ADD_MEMBERSHIP,
                Principal.agent("agent:coordinator"),
                AddMembershipPayload(
                    principal=Principal.agent(agent_id),
                    roles=(Role.WORKER,),
                    provisional=True,
                ),
                group_id=group_id,
                coordinator_epoch=1,
            )
        )

    def contract(self) -> WorkContract:
        return WorkContract(
            goal="Implement a focused change",
            deliverables=("source", "tests"),
            acceptance_criteria=("test suite passes",),
            required_capabilities=(CapabilityRequirement(id="software.python"),),
            deadline=self.clock() + timedelta(hours=2),
            estimated_duration_seconds=300,
        )

    async def create_work(self, work_item_id: str = "work:implementation") -> None:
        await self.core.perform(
            self.command(
                CommandKind.CREATE_WORK_ITEM,
                Principal.agent("agent:coordinator"),
                CreateWorkItemPayload(work_item_id=work_item_id, contract=self.contract()),
                group_id="group:root",
                coordinator_epoch=1,
            )
        )

    async def grant_cooperation_override(
        self,
        *,
        grant_id: str,
        policy_name: CooperationPolicyName,
        beneficiary: Principal,
        target_command_kind: CommandKind,
        target_action_id: str,
        group_id: str = "group:root",
        expires_at: datetime | None = None,
        reason: str = "MissionOwner approved a one-shot threshold exception",
    ) -> Event:
        return await self.core.perform(
            self.command(
                CommandKind.GRANT_COOPERATION_OVERRIDE,
                self.owner,
                GrantCooperationOverridePayload(
                    grant_id=grant_id,
                    policy_name=policy_name,
                    beneficiary=beneficiary,
                    target_command_kind=target_command_kind,
                    target_action_id=target_action_id,
                    reason=reason,
                    expires_at=expires_at or self.clock() + timedelta(minutes=10),
                ),
                group_id=group_id,
            )
        )

    async def offer(
        self, candidates: tuple[str, ...], *, work_item_id: str = "work:implementation"
    ) -> None:
        await self.core.perform(
            self.command(
                CommandKind.OFFER_WORK_ITEM,
                Principal.agent("agent:coordinator"),
                OfferWorkItemPayload(
                    work_item_id=work_item_id,
                    candidate_agent_ids=candidates,
                    selection_basis=SelectionBasis(
                        required_capabilities=(CapabilityRequirement(id="software.python"),),
                        verified_capability_matches=("software.python",),
                    ),
                    offer_expires_in_seconds=600,
                ),
                group_id="group:root",
                coordinator_epoch=1,
            )
        )


@dataclass(frozen=True)
class ArchiveReadyScenario:
    scenario: Scenario
    snapshot: GroupSnapshot
    private_key: str
    public_key: str
    key_id: str
    events: tuple[Event, ...]


async def _archive_ready_scenario(
    store: AuthoritativeStore | None = None,
) -> ArchiveReadyScenario:
    private_key, public_key = generate_keypair()
    key_id = "key:group-snapshot-authority"
    clock = MutableClock(datetime(2026, 7, 15, 8, 0, tzinfo=UTC))
    core = Core(
        store or InMemoryStore(),
        clock=clock,
        snapshot_authority_key_id=key_id,
        snapshot_authority_public_key=public_key,
    )
    scenario = Scenario(core, clock)
    await scenario.register("agent:coordinator", "coordination")
    await scenario.create_root()
    await core.perform(
        scenario.command(
            CommandKind.CANCEL_MISSION,
            scenario.owner,
            CancelMissionPayload(reason="Owner cancelled after review"),
            group_id="group:root",
        )
    )
    mission = await core.query(Query(kind=QueryKind.MISSION, entity_id="mission:root"))
    assert isinstance(mission, Mission)
    events = await core.replay("group:root")
    archive = SnapshotArchive(
        authority=scenario.system,
        key_id=key_id,
        private_key=private_key,
        public_key=public_key,
    )
    snapshot = archive.archive(
        group_id="group:root",
        events=events,
        state={"mission": mission.model_dump(mode="json", by_alias=True)},
        policy_log=(
            PolicyLogEntry(
                entry_id="policy:archive:owner-cancellation",
                decision="verified terminal Mission cancellation before archival",
                actor=scenario.system,
                occurred_at=clock(),
            ),
        ),
        created_at=clock(),
    )
    return ArchiveReadyScenario(
        scenario=scenario,
        snapshot=snapshot,
        private_key=private_key,
        public_key=public_key,
        key_id=key_id,
        events=events,
    )


def _resign_snapshot(
    snapshot: GroupSnapshot,
    private_key: str,
    **updates: Any,
) -> GroupSnapshot:
    candidate = snapshot.model_copy(update=updates, deep=True)
    return candidate.model_copy(
        update={
            "signature": candidate.signature.model_copy(
                update={
                    "created_at": candidate.created_at,
                    "value": sign_canonical(candidate.signing_payload(), private_key),
                }
            )
        },
        deep=True,
    )


@pytest.fixture
async def archive_ready() -> ArchiveReadyScenario:
    return await _archive_ready_scenario()


@pytest.fixture
async def scenario() -> Scenario:
    clock = MutableClock(datetime(2026, 7, 15, 8, 0, tzinfo=UTC))
    value = Scenario(Core(InMemoryStore(), clock=clock), clock)
    await value.register("agent:coordinator", "coordination", "software.python")
    await value.register("agent:worker-1", "software.python")
    await value.register("agent:worker-2", "software.python")
    await value.create_root()
    return value


async def _proposal_limited_scenario(
    store: AuthoritativeStore | None = None,
) -> tuple[Scenario, Principal]:
    clock = MutableClock(datetime(2026, 7, 15, 8, 0, tzinfo=UTC))
    value = Scenario(
        Core(
            store or InMemoryStore(),
            clock=clock,
            cooperation_limits=CooperationLimits(maximum_proposal_rate_per_minute=1),
        ),
        clock,
    )
    await value.register("agent:coordinator", "coordination", "software.python")
    await value.create_root()
    coordinator = Principal.agent("agent:coordinator")
    await value.core.perform(
        value.command(
            CommandKind.PROPOSE_WORK_ITEM,
            coordinator,
            ProposeWorkItemPayload(
                proposal_id="proposal:rate-baseline",
                contract=value.contract(),
            ),
            group_id="group:root",
        )
    )
    return value, coordinator


@pytest.mark.asyncio
async def test_authorization_is_derived_from_membership_roles(scenario: Scenario) -> None:
    await scenario.add_worker("agent:worker-1")

    with pytest.raises(AuthorizationDenied):
        await scenario.core.perform(
            scenario.command(
                CommandKind.CREATE_WORK_ITEM,
                Principal.agent("agent:worker-1"),
                CreateWorkItemPayload(
                    work_item_id="work:unauthorized",
                    contract=scenario.contract(),
                ),
                group_id="group:root",
            )
        )


@pytest.mark.asyncio
async def test_authoritative_cooperation_limits_require_scoped_override_grants() -> None:
    clock = MutableClock(datetime(2026, 7, 15, 8, 0, tzinfo=UTC))
    core = Core(
        InMemoryStore(),
        clock=clock,
        cooperation_limits=CooperationLimits(
            maximum_delegation_depth=0,
            maximum_queued_work_items=1,
            maximum_active_work_items=1,
            maximum_message_rate_per_minute=1,
            maximum_proposal_rate_per_minute=1,
        ),
    )
    limited = Scenario(core, clock)
    await limited.register("agent:coordinator", "coordination", "software.python")
    await limited.register("agent:worker-1", "software.python")
    await limited.register("agent:worker-2", "software.python")
    await limited.create_root()

    coordinator = Principal.agent("agent:coordinator")
    await core.perform(
        limited.command(
            CommandKind.PROPOSE_WORK_ITEM,
            coordinator,
            ProposeWorkItemPayload(
                proposal_id="proposal:first",
                contract=limited.contract(),
            ),
            group_id="group:root",
        )
    )
    with pytest.raises(PolicyViolation, match="proposal rate"):
        await core.perform(
            limited.command(
                CommandKind.PROPOSE_WORK_ITEM,
                coordinator,
                ProposeWorkItemPayload(
                    proposal_id="proposal:limited",
                    contract=limited.contract(),
                ),
                group_id="group:root",
            )
        )
    await limited.grant_cooperation_override(
        grant_id="override:proposal",
        policy_name=CooperationPolicyName.PROPOSAL_RATE,
        beneficiary=coordinator,
        target_command_kind=CommandKind.PROPOSE_WORK_ITEM,
        target_action_id="approved-override:proposal",
    )
    await core.perform(
        limited.command(
            CommandKind.PROPOSE_WORK_ITEM,
            coordinator,
            ProposeWorkItemPayload(
                proposal_id="proposal:approved",
                contract=limited.contract(),
            ),
            group_id="group:root",
            cooperation_override_grant_id="override:proposal",
            action_id="approved-override:proposal",
        )
    )

    await limited.create_work("work:parent")
    child_payload = CreateChildMissionPayload(
        mission_id="mission:child",
        group_id="group:child",
        parent_work_item_id="work:parent",
        coordinator_id="agent:worker-2",
        title="Bounded child",
        objective="Exercise delegation policy",
        definition_of_done=("policy evidence exists",),
        budget=ResourceBudget(),
        deadline=clock() + timedelta(hours=1),
        coordinator_lease_seconds=600,
    )
    with pytest.raises(PolicyViolation, match="delegation depth"):
        await core.perform(
            limited.command(
                CommandKind.CREATE_CHILD_MISSION,
                coordinator,
                child_payload,
                group_id="group:root",
                coordinator_epoch=1,
            )
        )
    await limited.grant_cooperation_override(
        grant_id="override:delegation",
        policy_name=CooperationPolicyName.DELEGATION_DEPTH,
        beneficiary=coordinator,
        target_command_kind=CommandKind.CREATE_CHILD_MISSION,
        target_action_id="approved-override:delegation",
    )
    await core.perform(
        limited.command(
            CommandKind.CREATE_CHILD_MISSION,
            coordinator,
            child_payload,
            group_id="group:root",
            coordinator_epoch=1,
            cooperation_override_grant_id="override:delegation",
            action_id="approved-override:delegation",
        )
    )

    await limited.add_worker("agent:worker-1")
    await limited.create_work("work:first-active")
    await limited.offer(("agent:worker-1",), work_item_id="work:first-active")
    await core.perform(
        limited.command(
            CommandKind.ACCEPT_WORK_OFFER,
            Principal.agent("agent:worker-1"),
            AcceptWorkOfferPayload(work_item_id="work:first-active"),
            group_id="group:root",
        )
    )
    await core.perform(
        limited.command(
            CommandKind.START_WORK_ITEM,
            Principal.agent("agent:worker-1"),
            StartWorkItemPayload(
                work_item_id="work:first-active",
                ownership_epoch=1,
                execution_lease_seconds=300,
            ),
            group_id="group:root",
        )
    )
    await limited.create_work("work:second-active")
    await limited.offer(("agent:worker-1",), work_item_id="work:second-active")
    await core.perform(
        limited.command(
            CommandKind.ACCEPT_WORK_OFFER,
            Principal.agent("agent:worker-1"),
            AcceptWorkOfferPayload(work_item_id="work:second-active"),
            group_id="group:root",
        )
    )
    start_second = StartWorkItemPayload(
        work_item_id="work:second-active",
        ownership_epoch=1,
        execution_lease_seconds=300,
    )
    with pytest.raises(PolicyViolation, match="active-work limit"):
        await core.perform(
            limited.command(
                CommandKind.START_WORK_ITEM,
                Principal.agent("agent:worker-1"),
                start_second,
                group_id="group:root",
            )
        )
    await limited.grant_cooperation_override(
        grant_id="override:active",
        policy_name=CooperationPolicyName.ACTIVE_WORK_ITEMS,
        beneficiary=Principal.agent("agent:worker-1"),
        target_command_kind=CommandKind.START_WORK_ITEM,
        target_action_id="approved-override:active",
    )
    await core.perform(
        limited.command(
            CommandKind.START_WORK_ITEM,
            Principal.agent("agent:worker-1"),
            start_second,
            group_id="group:root",
            cooperation_override_grant_id="override:active",
            action_id="approved-override:active",
        )
    )


@pytest.mark.asyncio
async def test_cooperation_override_is_durable_audited_and_one_shot() -> None:
    limited, coordinator = await _proposal_limited_scenario()

    with pytest.raises(PolicyViolation, match="proposal rate"):
        await limited.core.perform(
            limited.command(
                CommandKind.PROPOSE_WORK_ITEM,
                coordinator,
                ProposeWorkItemPayload(
                    proposal_id="proposal:without-grant",
                    contract=limited.contract(),
                ),
                group_id="group:root",
            )
        )
    with pytest.raises(PolicyViolation, match="unknown, or forged"):
        await limited.core.perform(
            limited.command(
                CommandKind.PROPOSE_WORK_ITEM,
                coordinator,
                ProposeWorkItemPayload(
                    proposal_id="proposal:forged-grant",
                    contract=limited.contract(),
                ),
                group_id="group:root",
                cooperation_override_grant_id="override:forged",
            )
        )

    grant_event = await limited.grant_cooperation_override(
        grant_id="override:audited",
        policy_name=CooperationPolicyName.PROPOSAL_RATE,
        beneficiary=coordinator,
        target_command_kind=CommandKind.PROPOSE_WORK_ITEM,
        target_action_id="action:audited-override",
        reason="Urgent proposal is required to unblock the Mission",
    )
    target = limited.command(
        CommandKind.PROPOSE_WORK_ITEM,
        coordinator,
        ProposeWorkItemPayload(
            proposal_id="proposal:audited-override",
            contract=limited.contract(),
        ),
        group_id="group:root",
        cooperation_override_grant_id="override:audited",
        action_id="action:audited-override",
    )
    target_event = await limited.core.perform(target)

    grant = await limited.core.query(
        Query(kind=QueryKind.COOPERATION_OVERRIDE_GRANT, entity_id="override:audited")
    )
    policy_log = await limited.core.query(Query(kind=QueryKind.POLICY_LOG, entity_id="group:root"))
    assert grant_event.kind is EventKind.COOPERATION_OVERRIDE_GRANTED
    assert isinstance(grant, CooperationOverrideGrant)
    assert grant.consumed_at == limited.clock()
    assert grant.consumed_event_id == target_event.id
    assert isinstance(policy_log, tuple)
    assert [entry.decision for entry in policy_log] == [
        "cooperation override granted",
        "cooperation override consumed",
    ]
    assert policy_log[1].details["consumedEventId"] == target_event.id

    retry = await limited.core.perform(target)
    assert retry == target_event
    with pytest.raises(PolicyViolation, match="already consumed"):
        await limited.core.perform(
            limited.command(
                CommandKind.PROPOSE_WORK_ITEM,
                coordinator,
                ProposeWorkItemPayload(
                    proposal_id="proposal:reuse",
                    contract=limited.contract(),
                ),
                group_id="group:root",
                cooperation_override_grant_id="override:audited",
                action_id="action:reuse",
            )
        )


@pytest.mark.asyncio
async def test_cooperation_override_rejects_wrong_approver_actor_action_group_and_scope() -> None:
    limited, coordinator = await _proposal_limited_scenario()

    with pytest.raises(AuthorizationDenied, match="MissionOwner"):
        await limited.core.perform(
            limited.command(
                CommandKind.GRANT_COOPERATION_OVERRIDE,
                coordinator,
                GrantCooperationOverridePayload(
                    grant_id="override:unauthorized",
                    policy_name=CooperationPolicyName.PROPOSAL_RATE,
                    beneficiary=coordinator,
                    target_command_kind=CommandKind.PROPOSE_WORK_ITEM,
                    target_action_id="action:unauthorized",
                    reason="Coordinator attempted self-approval",
                    expires_at=limited.clock() + timedelta(minutes=5),
                ),
                group_id="group:root",
            )
        )
    with pytest.raises(InvalidCommand, match="does not apply"):
        await limited.grant_cooperation_override(
            grant_id="override:wrong-kind-scope",
            policy_name=CooperationPolicyName.PROPOSAL_RATE,
            beneficiary=coordinator,
            target_command_kind=CommandKind.POST_MESSAGE,
            target_action_id="action:wrong-kind-scope",
        )

    await limited.grant_cooperation_override(
        grant_id="override:wrong-actor",
        policy_name=CooperationPolicyName.PROPOSAL_RATE,
        beneficiary=limited.owner,
        target_command_kind=CommandKind.PROPOSE_WORK_ITEM,
        target_action_id="action:wrong-actor",
    )
    with pytest.raises(PolicyViolation, match="another beneficiary"):
        await limited.core.perform(
            limited.command(
                CommandKind.PROPOSE_WORK_ITEM,
                coordinator,
                ProposeWorkItemPayload(
                    proposal_id="proposal:wrong-actor",
                    contract=limited.contract(),
                ),
                group_id="group:root",
                cooperation_override_grant_id="override:wrong-actor",
                action_id="action:wrong-actor",
            )
        )

    await limited.grant_cooperation_override(
        grant_id="override:wrong-action",
        policy_name=CooperationPolicyName.PROPOSAL_RATE,
        beneficiary=coordinator,
        target_command_kind=CommandKind.PROPOSE_WORK_ITEM,
        target_action_id="action:expected",
    )
    with pytest.raises(PolicyViolation, match="another Action ID"):
        await limited.core.perform(
            limited.command(
                CommandKind.PROPOSE_WORK_ITEM,
                coordinator,
                ProposeWorkItemPayload(
                    proposal_id="proposal:wrong-action",
                    contract=limited.contract(),
                ),
                group_id="group:root",
                cooperation_override_grant_id="override:wrong-action",
                action_id="action:received",
            )
        )

    await limited.grant_cooperation_override(
        grant_id="override:wrong-group",
        policy_name=CooperationPolicyName.PROPOSAL_RATE,
        beneficiary=coordinator,
        target_command_kind=CommandKind.PROPOSE_WORK_ITEM,
        target_action_id="action:wrong-group",
    )
    await limited.create_root(mission_id="mission:other", group_id="group:other")
    await limited.core.perform(
        limited.command(
            CommandKind.PROPOSE_WORK_ITEM,
            coordinator,
            ProposeWorkItemPayload(
                proposal_id="proposal:other-baseline",
                contract=limited.contract(),
            ),
            group_id="group:other",
        )
    )
    with pytest.raises(PolicyViolation, match="another Mission or Group"):
        await limited.core.perform(
            limited.command(
                CommandKind.PROPOSE_WORK_ITEM,
                coordinator,
                ProposeWorkItemPayload(
                    proposal_id="proposal:wrong-group",
                    contract=limited.contract(),
                ),
                group_id="group:other",
                cooperation_override_grant_id="override:wrong-group",
                action_id="action:wrong-group",
            )
        )

    system_event = await limited.core.perform(
        limited.command(
            CommandKind.GRANT_COOPERATION_OVERRIDE,
            limited.system,
            GrantCooperationOverridePayload(
                grant_id="override:organization-approved",
                policy_name=CooperationPolicyName.PROPOSAL_RATE,
                beneficiary=coordinator,
                target_command_kind=CommandKind.PROPOSE_WORK_ITEM,
                target_action_id="action:organization-approved",
                reason="Organization policy actor approved the exception",
                expires_at=limited.clock() + timedelta(minutes=5),
            ),
            group_id="group:root",
        )
    )
    assert system_event.kind is EventKind.COOPERATION_OVERRIDE_GRANTED


@pytest.mark.asyncio
async def test_cooperation_override_rejects_wrong_policy() -> None:
    clock = MutableClock(datetime(2026, 7, 15, 8, 0, tzinfo=UTC))
    limited = Scenario(
        Core(
            InMemoryStore(),
            clock=clock,
            cooperation_limits=CooperationLimits(maximum_queued_work_items=1),
        ),
        clock,
    )
    await limited.register("agent:coordinator", "coordination", "software.python")
    await limited.register("agent:worker-1", "software.python")
    await limited.create_root()
    await limited.add_worker("agent:worker-1")
    worker = Principal.agent("agent:worker-1")
    for work_item_id in ("work:queued-one", "work:queued-two"):
        await limited.create_work(work_item_id)
        await limited.offer((worker.id,), work_item_id=work_item_id)
    await limited.core.perform(
        limited.command(
            CommandKind.ACCEPT_WORK_OFFER,
            worker,
            AcceptWorkOfferPayload(work_item_id="work:queued-one"),
            group_id="group:root",
        )
    )
    await limited.grant_cooperation_override(
        grant_id="override:wrong-policy",
        policy_name=CooperationPolicyName.ACTIVE_WORK_ITEMS,
        beneficiary=worker,
        target_command_kind=CommandKind.ACCEPT_WORK_OFFER,
        target_action_id="action:wrong-policy",
    )

    with pytest.raises(PolicyViolation, match="another cooperation policy"):
        await limited.core.perform(
            limited.command(
                CommandKind.ACCEPT_WORK_OFFER,
                worker,
                AcceptWorkOfferPayload(work_item_id="work:queued-two"),
                group_id="group:root",
                cooperation_override_grant_id="override:wrong-policy",
                action_id="action:wrong-policy",
            )
        )


@pytest.mark.asyncio
async def test_cooperation_override_expiry_and_failed_transition_do_not_consume_grant() -> None:
    limited, coordinator = await _proposal_limited_scenario()
    await limited.grant_cooperation_override(
        grant_id="override:expired",
        policy_name=CooperationPolicyName.PROPOSAL_RATE,
        beneficiary=coordinator,
        target_command_kind=CommandKind.PROPOSE_WORK_ITEM,
        target_action_id="action:expired",
        expires_at=limited.clock() + timedelta(seconds=1),
    )
    limited.clock.advance(seconds=2)
    with pytest.raises(PolicyViolation, match="expired"):
        await limited.core.perform(
            limited.command(
                CommandKind.PROPOSE_WORK_ITEM,
                coordinator,
                ProposeWorkItemPayload(
                    proposal_id="proposal:expired",
                    contract=limited.contract(),
                ),
                group_id="group:root",
                cooperation_override_grant_id="override:expired",
                action_id="action:expired",
            )
        )
    expired = await limited.core.query(
        Query(kind=QueryKind.COOPERATION_OVERRIDE_GRANT, entity_id="override:expired")
    )
    assert isinstance(expired, CooperationOverrideGrant)
    assert expired.consumed_at is None

    await limited.grant_cooperation_override(
        grant_id="override:atomic",
        policy_name=CooperationPolicyName.PROPOSAL_RATE,
        beneficiary=coordinator,
        target_command_kind=CommandKind.PROPOSE_WORK_ITEM,
        target_action_id="action:atomic",
    )
    with pytest.raises(AlreadyExists, match="WorkProposal"):
        await limited.core.perform(
            limited.command(
                CommandKind.PROPOSE_WORK_ITEM,
                coordinator,
                ProposeWorkItemPayload(
                    proposal_id="proposal:rate-baseline",
                    contract=limited.contract(),
                ),
                group_id="group:root",
                cooperation_override_grant_id="override:atomic",
                action_id="action:atomic",
            )
        )
    unconsumed = await limited.core.query(
        Query(kind=QueryKind.COOPERATION_OVERRIDE_GRANT, entity_id="override:atomic")
    )
    assert isinstance(unconsumed, CooperationOverrideGrant)
    assert unconsumed.consumed_at is None

    accepted = await limited.core.perform(
        limited.command(
            CommandKind.PROPOSE_WORK_ITEM,
            coordinator,
            ProposeWorkItemPayload(
                proposal_id="proposal:atomic-retry",
                contract=limited.contract(),
            ),
            group_id="group:root",
            cooperation_override_grant_id="override:atomic",
            action_id="action:atomic",
        )
    )
    consumed = await limited.core.query(
        Query(kind=QueryKind.COOPERATION_OVERRIDE_GRANT, entity_id="override:atomic")
    )
    assert isinstance(consumed, CooperationOverrideGrant)
    assert consumed.consumed_event_id == accepted.id


@pytest.mark.asyncio
async def test_cooperation_override_survives_sqlite_restart(tmp_path: Path) -> None:
    path = tmp_path / "cooperation-override.sqlite3"
    store = SQLiteStore(path)
    limited, coordinator = await _proposal_limited_scenario(store)
    await limited.grant_cooperation_override(
        grant_id="override:restart",
        policy_name=CooperationPolicyName.PROPOSAL_RATE,
        beneficiary=coordinator,
        target_command_kind=CommandKind.PROPOSE_WORK_ITEM,
        target_action_id="action:restart",
    )
    await store.close()

    restarted_store = SQLiteStore(path)
    limited.core = Core(
        restarted_store,
        clock=limited.clock,
        cooperation_limits=CooperationLimits(maximum_proposal_rate_per_minute=1),
    )
    event = await limited.core.perform(
        limited.command(
            CommandKind.PROPOSE_WORK_ITEM,
            coordinator,
            ProposeWorkItemPayload(
                proposal_id="proposal:after-restart",
                contract=limited.contract(),
            ),
            group_id="group:root",
            cooperation_override_grant_id="override:restart",
            action_id="action:restart",
        )
    )
    grant = await limited.core.query(
        Query(kind=QueryKind.COOPERATION_OVERRIDE_GRANT, entity_id="override:restart")
    )
    policy_log = await limited.core.query(Query(kind=QueryKind.POLICY_LOG, entity_id="group:root"))
    assert isinstance(grant, CooperationOverrideGrant)
    assert grant.consumed_event_id == event.id
    assert isinstance(policy_log, tuple)
    assert len(policy_log) == 2
    await restarted_store.close()


@pytest.mark.asyncio
async def test_worker_proposes_and_coordinator_authorizes_work(scenario: Scenario) -> None:
    worker = Principal.agent("agent:worker-1")
    await scenario.core.perform(
        scenario.command(
            CommandKind.ADD_MEMBERSHIP,
            Principal.agent("agent:coordinator"),
            AddMembershipPayload(principal=worker, roles=(Role.WORKER,)),
            group_id="group:root",
            coordinator_epoch=1,
        )
    )
    contract = scenario.contract()
    await scenario.core.perform(
        scenario.command(
            CommandKind.PROPOSE_WORK_ITEM,
            worker,
            ProposeWorkItemPayload(proposal_id="proposal:worker-help", contract=contract),
            group_id="group:root",
        )
    )

    with pytest.raises(AuthorizationDenied):
        await scenario.core.perform(
            scenario.command(
                CommandKind.CREATE_WORK_ITEM,
                worker,
                CreateWorkItemPayload(
                    work_item_id="work:worker-self-authorized",
                    contract=contract,
                    proposal_id="proposal:worker-help",
                ),
                group_id="group:root",
            )
        )

    await scenario.core.perform(
        scenario.command(
            CommandKind.CREATE_WORK_ITEM,
            Principal.agent("agent:coordinator"),
            CreateWorkItemPayload(
                work_item_id="work:authorized-help",
                contract=contract,
                proposal_id="proposal:worker-help",
            ),
            group_id="group:root",
            coordinator_epoch=1,
        )
    )
    proposal = await scenario.core.query(
        Query(kind=QueryKind.WORK_PROPOSAL, entity_id="proposal:worker-help")
    )
    work = await scenario.core.query(
        Query(kind=QueryKind.WORK_ITEM, entity_id="work:authorized-help")
    )

    assert isinstance(proposal, WorkProposal)
    assert proposal.status is WorkProposalStatus.AUTHORIZED
    assert proposal.authorized_work_item_id == "work:authorized-help"
    assert isinstance(work, WorkItem)
    assert work.created_by == worker


@pytest.mark.asyncio
async def test_membership_epoch_fences_commands_after_role_change(scenario: Scenario) -> None:
    worker = Principal.agent("agent:worker-1")
    await scenario.core.perform(
        scenario.command(
            CommandKind.ADD_MEMBERSHIP,
            Principal.agent("agent:coordinator"),
            AddMembershipPayload(principal=worker, roles=(Role.WORKER,)),
            group_id="group:root",
            coordinator_epoch=1,
        )
    )
    await scenario.core.perform(
        scenario.command(
            CommandKind.ADD_MEMBERSHIP,
            Principal.agent("agent:coordinator"),
            AddMembershipPayload(principal=worker, roles=(Role.OBSERVER, Role.WORKER)),
            group_id="group:root",
            coordinator_epoch=1,
        )
    )

    with pytest.raises(StaleMembershipEpoch):
        await scenario.core.perform(
            scenario.command(
                CommandKind.PROPOSE_WORK_ITEM,
                worker,
                ProposeWorkItemPayload(
                    proposal_id="proposal:stale-membership",
                    contract=scenario.contract(),
                ),
                group_id="group:root",
                membership_epoch=1,
            )
        )


@pytest.mark.asyncio
async def test_human_execution_approval_is_scoped_to_current_ownership(
    scenario: Scenario,
) -> None:
    await scenario.add_worker("agent:worker-1")
    contract = scenario.contract().model_copy(
        update={
            "allowed_resources": ("cluster:production",),
            "budget": ResourceBudget(model_tokens=100, external_actions=1),
            "side_effect_risk": "high_risk",
            "execution_approval": "human_required",
        }
    )
    await scenario.core.perform(
        scenario.command(
            CommandKind.CREATE_WORK_ITEM,
            Principal.agent("agent:coordinator"),
            CreateWorkItemPayload(work_item_id="work:deploy", contract=contract),
            group_id="group:root",
            coordinator_epoch=1,
        )
    )
    await scenario.offer(("agent:worker-1",), work_item_id="work:deploy")
    await scenario.core.perform(
        scenario.command(
            CommandKind.ACCEPT_WORK_OFFER,
            Principal.agent("agent:worker-1"),
            AcceptWorkOfferPayload(work_item_id="work:deploy", ownership_lease_seconds=600),
            group_id="group:root",
        )
    )
    with pytest.raises(PolicyViolation, match="Execution Approval"):
        await scenario.core.perform(
            scenario.command(
                CommandKind.START_WORK_ITEM,
                Principal.agent("agent:worker-1"),
                StartWorkItemPayload(
                    work_item_id="work:deploy",
                    ownership_epoch=1,
                    execution_lease_seconds=300,
                ),
                group_id="group:root",
            )
        )
    human_identity = HumanIdentity.generate(scenario.owner.id)
    control = HumanControl(
        scenario.core,
        human_identity,
        clock=scenario.clock,
        action_id_factory=lambda: "action:execution-approval",
    )
    receipt, approved_execution = await control.approve_execution(
        "mission:root",
        approval_id="execution-approval:deploy",
        work_item_id="work:deploy",
        ownership_epoch=1,
        operations=("production.deploy",),
        resources=("cluster:production",),
        budget=ResourceBudget(model_tokens=100, external_actions=1),
        expires_in_seconds=300,
    )
    approval = await scenario.core.query(
        Query(
            kind=QueryKind.EXECUTION_APPROVAL,
            entity_id="execution-approval:deploy",
        )
    )

    assert isinstance(approval, ExecutionApproval)
    assert approval == approved_execution
    assert approval.ownership_epoch == 1
    assert approval.signature == receipt.command.signature
    assert human_identity.verify(receipt.command)
    assert approval.operations == ("production.deploy",)
    await scenario.core.perform(
        scenario.command(
            CommandKind.START_WORK_ITEM,
            Principal.agent("agent:worker-1"),
            StartWorkItemPayload(
                work_item_id="work:deploy",
                ownership_epoch=1,
                execution_lease_seconds=300,
            ),
            group_id="group:root",
        )
    )
    authorization = AuthorizationService(b"capability-secret" * 3)
    execution = ExecutionAuthorization(
        scenario.core,
        authorization,
        approval_key_resolver=lambda principal: (
            human_identity.public_key if principal == human_identity.principal else None
        ),
        clock=scenario.clock,
    )
    issued = await execution.issue(
        worker_id="agent:worker-1",
        session_epoch=scenario.epochs["agent:worker-1"],
        work_item_id="work:deploy",
        ownership_epoch=1,
        ttl=timedelta(minutes=1),
        allowed_resources=("cluster:production",),
        allowed_operations=("production.deploy",),
        budget=ResourceBudget(model_tokens=100, external_actions=1),
        approval_id=approval.id,
    )
    assert issued.claims.approval_id == approval.id
    active_work = await scenario.core.query(
        Query(kind=QueryKind.WORK_ITEM, entity_id="work:deploy")
    )
    assert isinstance(active_work, WorkItem)
    assert active_work.execution_lease_id is not None
    execution_lease = await scenario.core.query(
        Query(
            kind=QueryKind.EXECUTION_LEASE,
            entity_id=active_work.execution_lease_id,
        )
    )
    assert isinstance(execution_lease, ExecutionLease)
    assert (
        authorization.verify(
            issued.token,
            worker_id="agent:worker-1",
            session_epoch=scenario.epochs["agent:worker-1"],
            work_item_id="work:deploy",
            ownership_epoch=1,
            execution_lease=execution_lease,
            operation="production.deploy",
            now=scenario.clock(),
        )
        == issued.claims
    )


@pytest.mark.asyncio
async def test_message_correction_retraction_and_redaction_are_append_only(
    scenario: Scenario,
) -> None:
    coordinator = Principal.agent("agent:coordinator")
    posted = await scenario.core.perform(
        scenario.command(
            CommandKind.POST_MESSAGE,
            coordinator,
            PostMessagePayload(
                message_id="message:original",
                conversation_id="group:root:mission",
                content="Initial wording",
            ),
            group_id="group:root",
            coordinator_epoch=1,
        )
    )
    await scenario.core.perform(
        scenario.command(
            CommandKind.CORRECT_MESSAGE,
            coordinator,
            CorrectMessagePayload(
                amendment_id="amendment:correction",
                message_id="message:original",
                replacement_content="Corrected wording",
                reason="fix a factual typo",
            ),
            group_id="group:root",
            coordinator_epoch=1,
        )
    )
    await scenario.add_worker("agent:worker-1")
    with pytest.raises(AuthorizationDenied):
        await scenario.core.perform(
            scenario.command(
                CommandKind.RETRACT_MESSAGE,
                Principal.agent("agent:worker-1"),
                RetractMessagePayload(
                    amendment_id="amendment:unauthorized-retraction",
                    message_id="message:original",
                    reason="not my message",
                ),
                group_id="group:root",
            )
        )
    await scenario.core.perform(
        scenario.command(
            CommandKind.REDACT_MESSAGE,
            scenario.owner,
            RedactMessagePayload(
                amendment_id="amendment:redaction",
                message_id="message:original",
                reason="organization privacy policy requires removal",
            ),
            group_id="group:root",
        )
    )

    original = await scenario.core.query(
        Query(kind=QueryKind.MESSAGE, entity_id="message:original")
    )
    correction = await scenario.core.query(
        Query(kind=QueryKind.MESSAGE_AMENDMENT, entity_id="amendment:correction")
    )
    redaction = await scenario.core.query(
        Query(kind=QueryKind.MESSAGE_AMENDMENT, entity_id="amendment:redaction")
    )
    history = await scenario.core.replay("group:root", after=posted.sequence or 0)

    assert isinstance(original, Message)
    assert original.content == "Initial wording"
    assert isinstance(correction, MessageAmendment)
    assert correction.kind is MessageAmendmentKind.CORRECTION
    assert correction.replacement_content == "Corrected wording"
    assert isinstance(redaction, MessageAmendment)
    assert redaction.kind is MessageAmendmentKind.REDACTION
    assert {event.kind for event in history} >= {
        EventKind.MESSAGE_CORRECTED,
        EventKind.MESSAGE_REDACTED,
    }


@pytest.mark.asyncio
async def test_stable_action_id_deduplicates_and_rejects_content_collision(
    scenario: Scenario,
) -> None:
    command = scenario.command(
        CommandKind.CREATE_WORK_ITEM,
        Principal.agent("agent:coordinator"),
        CreateWorkItemPayload(work_item_id="work:deduplicated", contract=scenario.contract()),
        group_id="group:root",
        coordinator_epoch=1,
        action_id="stable-action",
    )
    first = await scenario.core.perform(command)
    duplicate = await scenario.core.perform(command)

    assert duplicate == first
    assert (
        len([event for event in await scenario.core.replay("group:root") if event.id == first.id])
        == 1
    )

    changed = command.model_copy(deep=True)
    changed.payload["workItemId"] = "work:different"
    with pytest.raises(ActionIdCollision):
        await scenario.core.perform(changed)

    accepted = await scenario.core.query(Query(kind=QueryKind.COMMAND, entity_id=first.id))
    assert accepted == command


@pytest.mark.asyncio
async def test_session_and_ownership_epochs_fence_stale_workers(scenario: Scenario) -> None:
    await scenario.add_worker("agent:worker-1")
    await scenario.create_work()
    await scenario.offer(("agent:worker-1",))
    old_session = scenario.epochs["agent:worker-1"]
    await scenario.reopen("agent:worker-1")

    with pytest.raises(StaleSessionEpoch):
        await scenario.core.perform(
            scenario.command(
                CommandKind.ACCEPT_WORK_OFFER,
                Principal.agent("agent:worker-1"),
                AcceptWorkOfferPayload(
                    work_item_id="work:implementation", ownership_lease_seconds=10
                ),
                group_id="group:root",
                session_epoch=old_session,
            )
        )

    await scenario.core.perform(
        scenario.command(
            CommandKind.ACCEPT_WORK_OFFER,
            Principal.agent("agent:worker-1"),
            AcceptWorkOfferPayload(work_item_id="work:implementation", ownership_lease_seconds=10),
            group_id="group:root",
        )
    )
    scenario.clock.advance(seconds=11)
    await scenario.offer(("agent:worker-1",))
    await scenario.core.perform(
        scenario.command(
            CommandKind.ACCEPT_WORK_OFFER,
            Principal.agent("agent:worker-1"),
            AcceptWorkOfferPayload(work_item_id="work:implementation", ownership_lease_seconds=300),
            group_id="group:root",
        )
    )

    work = await scenario.core.query(
        Query(kind=QueryKind.WORK_ITEM, entity_id="work:implementation")
    )
    assert isinstance(work, WorkItem)
    assert work.ownership_epoch > 1
    with pytest.raises(StaleOwnershipEpoch):
        await scenario.core.perform(
            scenario.command(
                CommandKind.START_WORK_ITEM,
                Principal.agent("agent:worker-1"),
                StartWorkItemPayload(
                    work_item_id=work.id,
                    ownership_epoch=1,
                    execution_lease_seconds=60,
                ),
                group_id="group:root",
            )
        )


@pytest.mark.asyncio
async def test_exclusive_offer_has_one_atomic_winner(scenario: Scenario) -> None:
    await scenario.add_worker("agent:worker-1")
    await scenario.add_worker("agent:worker-2")
    await scenario.create_work()
    await scenario.offer(("agent:worker-1", "agent:worker-2"))

    commands = [
        scenario.command(
            CommandKind.ACCEPT_WORK_OFFER,
            Principal.agent(agent_id),
            AcceptWorkOfferPayload(work_item_id="work:implementation"),
            group_id="group:root",
        )
        for agent_id in ("agent:worker-1", "agent:worker-2")
    ]
    results = await asyncio.gather(
        *(scenario.core.perform(command) for command in commands), return_exceptions=True
    )

    assert sum(isinstance(result, Event) for result in results) == 1
    assert sum(isinstance(result, InvalidTransition) for result in results) == 1
    work = await scenario.core.query(
        Query(kind=QueryKind.WORK_ITEM, entity_id="work:implementation")
    )
    assert isinstance(work, WorkItem)
    assert work.assignee_id in {"agent:worker-1", "agent:worker-2"}


@pytest.mark.asyncio
async def test_invalid_work_item_transition_is_rejected(scenario: Scenario) -> None:
    await scenario.create_work()
    with pytest.raises(AuthorizationDenied):
        await scenario.core.perform(
            scenario.command(
                CommandKind.START_WORK_ITEM,
                Principal.agent("agent:worker-1"),
                StartWorkItemPayload(
                    work_item_id="work:implementation",
                    ownership_epoch=1,
                    execution_lease_seconds=60,
                ),
                group_id="group:root",
            )
        )
    with pytest.raises(InvalidTransition):
        await scenario.core.perform(
            scenario.command(
                CommandKind.VERIFY_WORK_ITEM,
                Principal.agent("agent:coordinator"),
                VerifyWorkItemPayload(
                    work_item_id="work:implementation",
                    evidence=(Evidence(kind="test", description="not submitted"),),
                ),
                group_id="group:root",
                coordinator_epoch=1,
            )
        )


@pytest.mark.asyncio
async def test_group_replay_is_monotonic_and_cursor_based(scenario: Scenario) -> None:
    await scenario.create_work("work:one")
    await scenario.create_work("work:two")
    all_events = await scenario.core.replay("group:root")

    assert [event.sequence for event in all_events] == list(range(1, len(all_events) + 1))
    tail = await scenario.core.replay("group:root", after=all_events[-2].sequence or 0)
    assert tail == (all_events[-1],)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("policy", "parent_mission_status", "parent_work_status"),
    [
        (
            ChildFailurePolicy.BLOCK_PARENT_WORK_ITEM,
            MissionStatus.ACTIVE,
            WorkItemStatus.BLOCKED,
        ),
        (
            ChildFailurePolicy.FAIL_PARENT_MISSION,
            MissionStatus.FAILED,
            WorkItemStatus.FAILED,
        ),
    ],
)
async def test_child_failure_propagates_only_as_parent_policy_declares(
    scenario: Scenario,
    policy: ChildFailurePolicy,
    parent_mission_status: MissionStatus,
    parent_work_status: WorkItemStatus,
) -> None:
    await scenario.create_work()
    await scenario.core.perform(
        scenario.command(
            CommandKind.CREATE_CHILD_MISSION,
            Principal.agent("agent:coordinator"),
            CreateChildMissionPayload(
                mission_id="mission:child",
                group_id="group:child",
                parent_work_item_id="work:implementation",
                coordinator_id="agent:worker-1",
                title="Implement subsystem",
                objective="Deliver child result",
                definition_of_done=("subsystem tests pass",),
                budget=ResourceBudget(),
                deadline=scenario.clock() + timedelta(hours=1),
                failure_policy=policy,
                coordinator_lease_seconds=3_600,
            ),
            group_id="group:root",
            coordinator_epoch=1,
        )
    )
    await scenario.core.perform(
        scenario.command(
            CommandKind.FAIL_MISSION,
            Principal.agent("agent:worker-1"),
            FailMissionPayload(reason="child implementation cannot proceed"),
            group_id="group:child",
            coordinator_epoch=1,
        )
    )

    parent = await scenario.core.query(Query(kind=QueryKind.MISSION, entity_id="mission:root"))
    work = await scenario.core.query(
        Query(kind=QueryKind.WORK_ITEM, entity_id="work:implementation")
    )
    assert isinstance(parent, Mission)
    assert isinstance(work, WorkItem)
    assert parent.status is parent_mission_status
    assert work.status is parent_work_status


async def activate_one_work_item(scenario: Scenario) -> WorkItem:
    await scenario.add_worker("agent:worker-1")
    await scenario.create_work()
    await scenario.offer(("agent:worker-1",))
    await scenario.core.perform(
        scenario.command(
            CommandKind.ACCEPT_WORK_OFFER,
            Principal.agent("agent:worker-1"),
            AcceptWorkOfferPayload(work_item_id="work:implementation"),
            group_id="group:root",
        )
    )
    await scenario.core.perform(
        scenario.command(
            CommandKind.START_WORK_ITEM,
            Principal.agent("agent:worker-1"),
            StartWorkItemPayload(
                work_item_id="work:implementation",
                ownership_epoch=1,
                execution_lease_seconds=600,
            ),
            group_id="group:root",
        )
    )
    work = await scenario.core.query(
        Query(kind=QueryKind.WORK_ITEM, entity_id="work:implementation")
    )
    assert isinstance(work, WorkItem)
    assert work.execution_lease_id is not None
    return work


@pytest.mark.asyncio
async def test_authoritative_artifact_publication_verifies_signature_and_provenance(
    scenario: Scenario,
) -> None:
    work = await activate_one_work_item(scenario)

    unsigned = Artifact(
        id="artifact:source",
        content_hash="sha256:" + "d" * 64,
        media_type="application/json",
        producing_agent_id="agent:worker-1",
        agent_card_version=1,
        mission_id=work.mission_id,
        group_id=work.group_id,
        work_item_id=work.id,
        created_at=scenario.clock(),
        data_classification="confidential",
        signature="pending",
    )
    with pytest.raises(AuthorizationDenied, match="signature"):
        await scenario.core.perform(
            scenario.command(
                CommandKind.PUBLISH_ARTIFACT,
                Principal.agent("agent:worker-1"),
                PublishArtifactPayload(
                    artifact=unsigned,
                    ownership_epoch=work.ownership_epoch,
                    execution_lease_id=work.execution_lease_id,
                ),
                group_id=work.group_id,
            )
        )

    source = scenario.sign_artifact(unsigned)
    await scenario.core.perform(
        scenario.command(
            CommandKind.PUBLISH_ARTIFACT,
            Principal.agent("agent:worker-1"),
            PublishArtifactPayload(
                artifact=source,
                ownership_epoch=work.ownership_epoch,
                execution_lease_id=work.execution_lease_id,
            ),
            group_id=work.group_id,
        )
    )

    missing_source = scenario.sign_artifact(
        unsigned.model_copy(
            update={
                "id": "artifact:missing-source",
                "content_hash": "sha256:" + "e" * 64,
                "source_artifact_hashes": ("sha256:" + "f" * 64,),
                "signature": "pending",
            }
        )
    )
    with pytest.raises(NotFound, match="provenance source"):
        await scenario.core.perform(
            scenario.command(
                CommandKind.PUBLISH_ARTIFACT,
                Principal.agent("agent:worker-1"),
                PublishArtifactPayload(
                    artifact=missing_source,
                    ownership_epoch=work.ownership_epoch,
                    execution_lease_id=work.execution_lease_id,
                ),
                group_id=work.group_id,
            )
        )

    downgraded = scenario.sign_artifact(
        unsigned.model_copy(
            update={
                "id": "artifact:downgraded",
                "content_hash": "sha256:" + "0" * 64,
                "source_artifact_hashes": (source.content_hash,),
                "data_classification": "public",
                "signature": "pending",
            }
        )
    )
    with pytest.raises(PolicyViolation, match="downgrade"):
        await scenario.core.perform(
            scenario.command(
                CommandKind.PUBLISH_ARTIFACT,
                Principal.agent("agent:worker-1"),
                PublishArtifactPayload(
                    artifact=downgraded,
                    ownership_epoch=work.ownership_epoch,
                    execution_lease_id=work.execution_lease_id,
                ),
                group_id=work.group_id,
            )
        )


async def complete_one_work_item(scenario: Scenario) -> tuple[WorkItem, Artifact]:
    active = await activate_one_work_item(scenario)
    artifact = scenario.sign_artifact(
        Artifact(
            id="artifact:implementation",
            content_hash="sha256:" + "a" * 64,
            media_type="application/zip",
            producing_agent_id="agent:worker-1",
            agent_card_version=1,
            mission_id="mission:root",
            group_id="group:root",
            work_item_id="work:implementation",
            source_artifact_hashes=(),
            tool_versions={"pytest": "8"},
            model_versions={"agent": "test"},
            created_at=scenario.clock(),
            data_classification="internal",
            signature="pending",
        )
    )
    await scenario.core.perform(
        scenario.command(
            CommandKind.PUBLISH_ARTIFACT,
            Principal.agent("agent:worker-1"),
            PublishArtifactPayload(
                artifact=artifact,
                ownership_epoch=1,
                execution_lease_id=cast(str, active.execution_lease_id),
            ),
            group_id="group:root",
        )
    )
    await scenario.core.perform(
        scenario.command(
            CommandKind.SUBMIT_WORK_ITEM,
            Principal.agent("agent:worker-1"),
            SubmitWorkItemPayload(
                work_item_id="work:implementation",
                ownership_epoch=1,
                execution_lease_id=cast(str, active.execution_lease_id),
                artifact_ids=(artifact.id,),
                evidence=(Evidence(kind="tests", description="pytest passed"),),
            ),
            group_id="group:root",
        )
    )
    await scenario.core.perform(
        scenario.command(
            CommandKind.VERIFY_WORK_ITEM,
            Principal.agent("agent:coordinator"),
            VerifyWorkItemPayload(
                work_item_id="work:implementation",
                evidence=(Evidence(kind="review", description="criteria satisfied"),),
            ),
            group_id="group:root",
            coordinator_epoch=1,
        )
    )
    work = await scenario.core.query(
        Query(kind=QueryKind.WORK_ITEM, entity_id="work:implementation")
    )
    assert isinstance(work, WorkItem)
    return work, artifact


@pytest.mark.asyncio
async def test_human_change_request_and_exact_revision_approval(scenario: Scenario) -> None:
    _, artifact = await complete_one_work_item(scenario)
    await scenario.core.perform(
        scenario.command(
            CommandKind.SUBMIT_MISSION,
            Principal.agent("agent:coordinator"),
            SubmitMissionPayload(artifact_hashes=(artifact.content_hash,)),
            group_id="group:root",
            coordinator_epoch=1,
        )
    )
    submitted = await scenario.core.query(Query(kind=QueryKind.MISSION, entity_id="mission:root"))
    assert isinstance(submitted, Mission)
    assert submitted.submitted_revision is not None

    with pytest.raises(RevisionConflict):
        await scenario.core.perform(
            scenario.command(
                CommandKind.APPROVE_MISSION,
                scenario.owner,
                ApproveMissionPayload(
                    approval_id="approval:stale",
                    mission_revision=submitted.submitted_revision - 1,
                    artifact_hashes=(artifact.content_hash,),
                    acceptance_policy_version="policy:1",
                ),
                group_id="group:root",
            )
        )

    await scenario.core.perform(
        scenario.command(
            CommandKind.REQUEST_MISSION_CHANGES,
            scenario.owner,
            RequestMissionChangesPayload(
                mission_revision=submitted.submitted_revision,
                feedback="Clarify the release note",
            ),
            group_id="group:root",
        )
    )
    reopened = await scenario.core.query(Query(kind=QueryKind.MISSION, entity_id="mission:root"))
    assert isinstance(reopened, Mission)
    assert reopened.status is MissionStatus.ACTIVE

    await scenario.core.perform(
        scenario.command(
            CommandKind.SUBMIT_MISSION,
            Principal.agent("agent:coordinator"),
            SubmitMissionPayload(artifact_hashes=(artifact.content_hash,)),
            group_id="group:root",
            coordinator_epoch=1,
        )
    )
    resubmitted = await scenario.core.query(Query(kind=QueryKind.MISSION, entity_id="mission:root"))
    assert isinstance(resubmitted, Mission)
    assert resubmitted.submitted_revision is not None
    await scenario.core.perform(
        scenario.command(
            CommandKind.APPROVE_MISSION,
            scenario.owner,
            ApproveMissionPayload(
                approval_id="approval:final",
                mission_revision=resubmitted.submitted_revision,
                artifact_hashes=(artifact.content_hash,),
                acceptance_policy_version="policy:1",
                comments="Approved",
            ),
            group_id="group:root",
        )
    )

    approved = await scenario.core.query(Query(kind=QueryKind.MISSION, entity_id="mission:root"))
    approval = await scenario.core.query(Query(kind=QueryKind.APPROVAL, entity_id="approval:final"))
    approved_group = await scenario.core.query(Query(kind=QueryKind.GROUP, entity_id="group:root"))
    assert isinstance(approved, Mission)
    assert isinstance(approval, Approval)
    assert isinstance(approved_group, Group)
    assert approved.status is MissionStatus.APPROVED
    assert approved.approved_artifact_hashes == (artifact.content_hash,)
    assert approval.signature == "test-signature"
    assert approved_group.archived_at is None
    assert approved_group.archive_snapshot_id is None

    with pytest.raises(InvalidTransition):
        await scenario.core.perform(
            scenario.command(
                CommandKind.CREATE_WORK_ITEM,
                Principal.agent("agent:coordinator"),
                CreateWorkItemPayload(
                    work_item_id="work:mutate-approved",
                    contract=scenario.contract(),
                ),
                group_id="group:root",
                coordinator_epoch=1,
            )
        )

    await scenario.core.perform(
        scenario.command(
            CommandKind.CREATE_FOLLOW_UP_MISSION,
            scenario.owner,
            CreateMissionPayload(
                mission_id="mission:follow-up",
                group_id="group:follow-up",
                coordinator_id="agent:coordinator",
                title="Correct the approved release",
                objective="Publish a linked correction without mutating the approved Mission",
                definition_of_done=("correction approved",),
                deadline=scenario.clock() + timedelta(hours=1),
                coordinator_lease_seconds=3_600,
                follow_up_of_mission_id="mission:root",
            ),
            group_id="group:follow-up",
        )
    )
    follow_up = await scenario.core.query(
        Query(kind=QueryKind.MISSION, entity_id="mission:follow-up")
    )
    assert isinstance(follow_up, Mission)
    assert follow_up.follow_up_of_mission_id == "mission:root"


@pytest.mark.asyncio
async def test_failed_mission_group_remains_active_until_snapshot_exists(
    scenario: Scenario,
) -> None:
    await scenario.core.perform(
        scenario.command(
            CommandKind.FAIL_MISSION,
            scenario.owner,
            FailMissionPayload(reason="Mission cannot meet acceptance criteria"),
            group_id="group:root",
        )
    )

    mission = await scenario.core.query(Query(kind=QueryKind.MISSION, entity_id="mission:root"))
    group = await scenario.core.query(Query(kind=QueryKind.GROUP, entity_id="group:root"))
    assert isinstance(mission, Mission)
    assert isinstance(group, Group)
    assert mission.status is MissionStatus.FAILED
    assert group.archived_at is None
    assert group.archive_snapshot_id is None


@pytest.mark.asyncio
async def test_system_archives_terminal_group_with_authority_signed_complete_snapshot() -> None:
    snapshot_private_key, snapshot_public_key = generate_keypair()
    snapshot_key_id = "key:group-snapshot-authority"
    clock = MutableClock(datetime(2026, 7, 15, 8, 0, tzinfo=UTC))
    core = Core(
        InMemoryStore(),
        clock=clock,
        snapshot_authority_key_id=snapshot_key_id,
        snapshot_authority_public_key=snapshot_public_key,
    )
    scenario = Scenario(core, clock)
    await scenario.register("agent:coordinator", "coordination")
    await scenario.create_root()
    await core.perform(
        scenario.command(
            CommandKind.CANCEL_MISSION,
            scenario.owner,
            CancelMissionPayload(reason="Owner cancelled after review"),
            group_id="group:root",
        )
    )
    terminal_group = await core.query(Query(kind=QueryKind.GROUP, entity_id="group:root"))
    terminal_mission = await core.query(Query(kind=QueryKind.MISSION, entity_id="mission:root"))
    assert isinstance(terminal_group, Group)
    assert isinstance(terminal_mission, Mission)
    assert terminal_group.archived_at is None
    assert terminal_group.archive_snapshot_id is None

    events_before_archive = await core.replay("group:root")
    archive = SnapshotArchive(
        authority=scenario.system,
        key_id=snapshot_key_id,
        private_key=snapshot_private_key,
        public_key=snapshot_public_key,
    )
    snapshot = archive.archive(
        group_id="group:root",
        events=events_before_archive,
        state={"mission": terminal_mission.model_dump(mode="json", by_alias=True)},
        policy_log=(
            PolicyLogEntry(
                entry_id="policy:archive:owner-cancellation",
                decision="verified terminal Mission cancellation before archival",
                actor=scenario.system,
                occurred_at=clock(),
            ),
        ),
        created_at=clock(),
    )

    archived_event = await core.perform(
        scenario.command(
            CommandKind.ARCHIVE_GROUP,
            scenario.system,
            ArchiveGroupPayload(snapshot=snapshot),
            group_id="group:root",
        )
    )

    archived_group = await core.query(Query(kind=QueryKind.GROUP, entity_id="group:root"))
    persisted_snapshot = await core.query(
        Query(kind=QueryKind.GROUP_SNAPSHOT, entity_id=snapshot.snapshot_id)
    )
    archived_history = await core.replay("group:root")
    assert archived_event.kind is EventKind.GROUP_ARCHIVED
    assert isinstance(archived_group, Group)
    assert archived_group.archived_at == clock()
    assert archived_group.archive_snapshot_id == snapshot.snapshot_id
    assert persisted_snapshot == snapshot
    assert [event.kind for event in archived_history[-2:]] == [
        EventKind.GROUP_SNAPSHOT_CREATED,
        EventKind.GROUP_ARCHIVED,
    ]
    assert snapshot.event_ids == tuple(
        snapshot.protocol_event_id(event.id) for event in events_before_archive
    )


@pytest.mark.asyncio
async def test_group_archive_requires_system_command_and_snapshot(
    archive_ready: ArchiveReadyScenario,
) -> None:
    scenario = archive_ready.scenario

    with pytest.raises(AuthorizationDenied, match="organization authority"):
        await scenario.core.perform(
            scenario.command(
                CommandKind.ARCHIVE_GROUP,
                scenario.owner,
                ArchiveGroupPayload(snapshot=archive_ready.snapshot),
                group_id="group:root",
            )
        )
    with pytest.raises(InvalidCommand, match="payload"):
        await scenario.core.perform(
            scenario.command(
                CommandKind.ARCHIVE_GROUP,
                scenario.system,
                {},
                group_id="group:root",
            )
        )


@pytest.mark.asyncio
async def test_group_archive_rejects_untrusted_key_or_forged_signature(
    archive_ready: ArchiveReadyScenario,
) -> None:
    scenario = archive_ready.scenario
    wrong_key = archive_ready.snapshot.model_copy(
        update={
            "signature": archive_ready.snapshot.signature.model_copy(
                update={"key_id": "key:untrusted-snapshot-authority"}
            )
        },
        deep=True,
    )
    forged = archive_ready.snapshot.model_copy(
        update={"signature": archive_ready.snapshot.signature.model_copy(update={"value": "AA"})},
        deep=True,
    )

    for action_id, snapshot in (("archive:wrong-key", wrong_key), ("archive:forged", forged)):
        with pytest.raises(AuthorizationDenied):
            await scenario.core.perform(
                scenario.command(
                    CommandKind.ARCHIVE_GROUP,
                    scenario.system,
                    ArchiveGroupPayload(snapshot=snapshot),
                    group_id="group:root",
                    action_id=action_id,
                )
            )


@pytest.mark.asyncio
async def test_group_archive_rejects_wrong_group_stale_or_noncontiguous_history(
    archive_ready: ArchiveReadyScenario,
) -> None:
    scenario = archive_ready.scenario
    snapshot = archive_ready.snapshot
    wrong_group = _resign_snapshot(
        snapshot,
        archive_ready.private_key,
        group_id="group:other",
    )
    stale = _resign_snapshot(
        snapshot,
        archive_ready.private_key,
        through_sequence=snapshot.through_sequence - 1,
        event_ids=snapshot.event_ids[:-1],
    )
    wrong_event_ids = _resign_snapshot(
        snapshot,
        archive_ready.private_key,
        event_ids=(*snapshot.event_ids[:-1], "event:forged"),
    )

    with pytest.raises(InvalidCommand, match="another Group"):
        await scenario.core.perform(
            scenario.command(
                CommandKind.ARCHIVE_GROUP,
                scenario.system,
                ArchiveGroupPayload(snapshot=wrong_group),
                group_id="group:root",
                action_id="archive:wrong-group",
            )
        )
    with pytest.raises(RevisionConflict, match="current Group sequence"):
        await scenario.core.perform(
            scenario.command(
                CommandKind.ARCHIVE_GROUP,
                scenario.system,
                ArchiveGroupPayload(snapshot=stale),
                group_id="group:root",
                action_id="archive:stale",
            )
        )
    with pytest.raises(InvalidCommand, match="contiguous authoritative history"):
        await scenario.core.perform(
            scenario.command(
                CommandKind.ARCHIVE_GROUP,
                scenario.system,
                ArchiveGroupPayload(snapshot=wrong_event_ids),
                group_id="group:root",
                action_id="archive:wrong-events",
            )
        )


@pytest.mark.asyncio
async def test_group_archive_rejects_non_system_creator_empty_policy_and_invalid_time(
    archive_ready: ArchiveReadyScenario,
) -> None:
    scenario = archive_ready.scenario
    snapshot = archive_ready.snapshot
    non_system_creator = _resign_snapshot(
        snapshot,
        archive_ready.private_key,
        created_by=Principal.agent("agent:snapshot-forger"),
    )
    empty_policy = snapshot.model_copy(update={"policy_log": ()}, deep=True)
    predating = _resign_snapshot(
        snapshot,
        archive_ready.private_key,
        created_at=archive_ready.events[-1].occurred_at - timedelta(seconds=1),
    )
    future = _resign_snapshot(
        snapshot,
        archive_ready.private_key,
        created_at=scenario.clock() + timedelta(seconds=1),
    )

    with pytest.raises(AuthorizationDenied, match="system authority"):
        await scenario.core.perform(
            scenario.command(
                CommandKind.ARCHIVE_GROUP,
                scenario.system,
                ArchiveGroupPayload(snapshot=non_system_creator),
                group_id="group:root",
                action_id="archive:non-system-creator",
            )
        )
    with pytest.raises(InvalidCommand, match="payload"):
        await scenario.core.perform(
            scenario.command(
                CommandKind.ARCHIVE_GROUP,
                scenario.system,
                ArchiveGroupPayload(snapshot=empty_policy),
                group_id="group:root",
                action_id="archive:empty-policy",
            )
        )
    with pytest.raises(InvalidCommand, match="predates"):
        await scenario.core.perform(
            scenario.command(
                CommandKind.ARCHIVE_GROUP,
                scenario.system,
                ArchiveGroupPayload(snapshot=predating),
                group_id="group:root",
                action_id="archive:predating",
            )
        )
    with pytest.raises(InvalidCommand, match="after the archive Command"):
        await scenario.core.perform(
            scenario.command(
                CommandKind.ARCHIVE_GROUP,
                scenario.system,
                ArchiveGroupPayload(snapshot=future),
                group_id="group:root",
                action_id="archive:future",
            )
        )


@pytest.mark.asyncio
async def test_group_archive_rejects_double_archival(
    archive_ready: ArchiveReadyScenario,
) -> None:
    scenario = archive_ready.scenario
    await scenario.core.perform(
        scenario.command(
            CommandKind.ARCHIVE_GROUP,
            scenario.system,
            ArchiveGroupPayload(snapshot=archive_ready.snapshot),
            group_id="group:root",
            action_id="archive:first",
        )
    )

    with pytest.raises(InvalidTransition, match="already archived"):
        await scenario.core.perform(
            scenario.command(
                CommandKind.ARCHIVE_GROUP,
                scenario.system,
                ArchiveGroupPayload(snapshot=archive_ready.snapshot),
                group_id="group:root",
                action_id="archive:second",
            )
        )


@pytest.mark.asyncio
async def test_sqlite_store_persists_authoritative_state_and_replay(tmp_path: Path) -> None:
    path = tmp_path / "missionweaveprotocol.sqlite3"
    clock = MutableClock(datetime(2026, 7, 15, 8, 0, tzinfo=UTC))
    first_store = SQLiteStore(path)
    first = Scenario(Core(first_store, clock=clock), clock)
    await first.register("agent:coordinator", "coordination")
    await first.create_root()
    await first_store.close()

    second_store = SQLiteStore(path)
    second_core = Core(second_store, clock=clock)
    mission = await second_core.query(Query(kind=QueryKind.MISSION, entity_id="mission:root"))
    events = await second_core.replay("group:root")
    await second_store.close()

    assert isinstance(mission, Mission)
    assert mission.id == "mission:root"
    assert [event.sequence for event in events] == [1]


@pytest.mark.asyncio
async def test_sqlite_restart_preserves_archived_group_and_complete_snapshot(
    tmp_path: Path,
) -> None:
    path = tmp_path / "missionweaveprotocol-archive.sqlite3"
    first_store = SQLiteStore(path)
    ready = await _archive_ready_scenario(first_store)
    await ready.scenario.core.perform(
        ready.scenario.command(
            CommandKind.ARCHIVE_GROUP,
            ready.scenario.system,
            ArchiveGroupPayload(snapshot=ready.snapshot),
            group_id="group:root",
        )
    )
    await first_store.close()

    second_store = SQLiteStore(path)
    second_core = Core(
        second_store,
        clock=ready.scenario.clock,
        snapshot_authority_key_id=ready.key_id,
        snapshot_authority_public_key=ready.public_key,
    )
    group = await second_core.query(Query(kind=QueryKind.GROUP, entity_id="group:root"))
    snapshot = await second_core.query(
        Query(kind=QueryKind.GROUP_SNAPSHOT, entity_id=ready.snapshot.snapshot_id)
    )
    events = await second_core.replay("group:root")
    await second_store.close()

    assert isinstance(group, Group)
    assert group.archive_snapshot_id == ready.snapshot.snapshot_id
    assert group.archived_at == ready.scenario.clock()
    assert snapshot == ready.snapshot
    assert snapshot.policy_log == ready.snapshot.policy_log
    assert [event.kind for event in events[-2:]] == [
        EventKind.GROUP_SNAPSHOT_CREATED,
        EventKind.GROUP_ARCHIVED,
    ]


@pytest.mark.asyncio
async def test_postgresql_store_persists_state_and_replay_when_test_database_is_available() -> None:
    url = os.getenv("MISSIONWEAVEPROTOCOL_TEST_POSTGRES_URL")
    if not url:
        pytest.skip(
            "set MISSIONWEAVEPROTOCOL_TEST_POSTGRES_URL to run the PostgreSQL Store "
            "integration test"
        )
    connection = await asyncpg.connect(url)
    await connection.execute("DROP TABLE IF EXISTS missionweaveprotocol_authoritative_state")
    await connection.close()

    first_store = PostgreSQLStore(url)
    ready = await _archive_ready_scenario(first_store)
    await ready.scenario.core.perform(
        ready.scenario.command(
            CommandKind.ARCHIVE_GROUP,
            ready.scenario.system,
            ArchiveGroupPayload(snapshot=ready.snapshot),
            group_id="group:root",
        )
    )
    assert first_store.dialect_name == "postgresql"
    await first_store.close()

    second_store = PostgreSQLStore(url)
    second_core = Core(
        second_store,
        clock=ready.scenario.clock,
        snapshot_authority_key_id=ready.key_id,
        snapshot_authority_public_key=ready.public_key,
    )
    mission = await second_core.query(Query(kind=QueryKind.MISSION, entity_id="mission:root"))
    group = await second_core.query(Query(kind=QueryKind.GROUP, entity_id="group:root"))
    snapshot = await second_core.query(
        Query(kind=QueryKind.GROUP_SNAPSHOT, entity_id=ready.snapshot.snapshot_id)
    )
    events = await second_core.replay("group:root")
    await second_store.close()

    assert isinstance(mission, Mission)
    assert isinstance(group, Group)
    assert mission.id == "mission:root"
    assert group.archive_snapshot_id == ready.snapshot.snapshot_id
    assert snapshot == ready.snapshot
    assert [event.kind for event in events[-2:]] == [
        EventKind.GROUP_SNAPSHOT_CREATED,
        EventKind.GROUP_ARCHIVED,
    ]


def test_canonical_hashing_and_ed25519_signatures_are_stable() -> None:
    left = {"z": 2, "a": {"name": "MissionWeaveProtocol", "enabled": True}}
    right = {"a": {"enabled": True, "name": "MissionWeaveProtocol"}, "z": 2}
    private_key, public_key = generate_keypair()

    assert canonical_json(left) == canonical_json(right)
    assert canonical_hash(left) == canonical_hash(right)
    signature = sign_canonical(left, private_key)
    assert verify_canonical(right, signature, public_key)
    assert not verify_canonical({"z": 3, "a": left["a"]}, signature, public_key)


def test_canonical_json_uses_rfc8785_number_rendering() -> None:
    assert (
        canonical_json({"numbers": (333333333.33333329, 1e30, 4.50, 2e-3, 1e-27)})
        == '{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}'
    )
