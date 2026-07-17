from __future__ import annotations

from datetime import UTC, datetime, timedelta
from itertools import count
from typing import Any, cast

import pytest

from missionweaveprotocol.control import HumanControl, HumanIdentity
from missionweaveprotocol.core import Core
from missionweaveprotocol.crypto import generate_keypair, sign_canonical
from missionweaveprotocol.models import (
    AcceptWorkOfferPayload,
    AddMembershipPayload,
    AgentCard,
    Artifact,
    Capability,
    CapabilityRequirement,
    Command,
    CommandKind,
    CreateWorkItemPayload,
    Evidence,
    Mission,
    MissionStatus,
    OfferWorkItemPayload,
    OpenAgentSessionPayload,
    Principal,
    PublishArtifactPayload,
    Query,
    QueryKind,
    RegisterAgentCardPayload,
    Role,
    SelectionBasis,
    StartWorkItemPayload,
    SubmitMissionPayload,
    SubmitWorkItemPayload,
    VerifyWorkItemPayload,
    WorkContract,
    WorkItem,
)
from missionweaveprotocol.store import InMemoryStore

NOW = datetime(2026, 7, 15, 8, 0, tzinfo=UTC)


class AgentCommands:
    def __init__(self, core: Core) -> None:
        self.core = core
        self.epochs: dict[str, int] = {}
        self.private_keys: dict[str, str] = {}
        self._ids = count(1)

    def command(
        self,
        kind: CommandKind,
        actor: Principal,
        payload: Any,
        *,
        group_id: str | None = None,
        coordinator_epoch: int | None = None,
    ) -> Command:
        return Command(
            action_id=f"test-action:{next(self._ids)}",
            kind=kind,
            actor=actor,
            group_id=group_id,
            session_epoch=self.epochs.get(actor.id),
            coordinator_epoch=coordinator_epoch,
            issued_at=NOW,
            payload=payload,
            signature="test-agent-signature",
        )

    async def register(self, agent_id: str, *capabilities: str) -> None:
        private_key, public_key = generate_keypair()
        self.private_keys[agent_id] = private_key
        card = AgentCard(
            agent_id=agent_id,
            version=1,
            display_name=agent_id,
            owner="organization:test",
            public_key=public_key,
            capabilities=tuple(Capability(id=value, version=1) for value in capabilities),
            issued_at=NOW,
            signature="organization-signature",
        )
        await self.core.perform(
            self.command(
                CommandKind.REGISTER_AGENT_CARD,
                Principal.system(),
                RegisterAgentCardPayload(card=card),
            )
        )
        opened = await self.core.perform(
            self.command(
                CommandKind.OPEN_AGENT_SESSION,
                Principal.system(),
                OpenAgentSessionPayload(agent_id=agent_id),
            )
        )
        self.epochs[agent_id] = cast(int, opened.payload["sessionEpoch"])

    def sign_artifact(self, artifact: Artifact) -> Artifact:
        return artifact.model_copy(
            update={
                "signature": sign_canonical(
                    artifact.signing_payload(),
                    self.private_keys[artifact.producing_agent_id],
                )
            }
        )


@pytest.fixture
async def control_setup() -> tuple[Core, HumanControl, AgentCommands]:
    core = Core(InMemoryStore(), clock=lambda: NOW)
    agents = AgentCommands(core)
    await agents.register("agent:coordinator-a", "coordination", "software.python")
    await agents.register("agent:coordinator-b", "coordination")
    await agents.register("agent:worker", "software.python")
    identity = HumanIdentity.generate("human:owner")
    action_ids = count(1)
    control = HumanControl(
        core,
        identity,
        clock=lambda: NOW,
        action_id_factory=lambda: f"human-action:{next(action_ids)}",
    )
    return core, control, agents


@pytest.mark.asyncio
async def test_human_interface_can_create_inspect_direct_replace_and_cancel(
    control_setup: tuple[Core, HumanControl, AgentCommands],
) -> None:
    core, control, _ = control_setup
    created = await control.create(
        mission_id="mission:control",
        group_id="group:control",
        coordinator_id="agent:coordinator-a",
        title="Control a Mission",
        objective="Exercise every human control",
        definition_of_done=("human can inspect",),
        deadline=NOW + timedelta(hours=1),
    )
    directed = await control.direct("mission:control", "Prioritize deterministic evidence.")
    replaced = await control.replace_coordinator(
        "mission:control", "agent:coordinator-b", lease_seconds=900
    )

    inspection = await control.inspect("mission:control")
    accepted = await control.accepted_command(created.event.id)

    assert control.identity.verify(created.command)
    assert accepted == created.command
    assert directed.event.group_id == "group:control"
    assert inspection.mission.coordinator_id == "agent:coordinator-b"
    assert inspection.mission.coordinator_epoch == 2
    assert replaced.event.payload["coordinatorEpoch"] == 2

    await control.cancel("mission:control", "demonstrated owner cancellation")
    cancelled = await core.query(Query(kind=QueryKind.MISSION, entity_id="mission:control"))
    assert isinstance(cancelled, Mission)
    assert cancelled.status is MissionStatus.CANCELLED


@pytest.mark.asyncio
async def test_human_change_request_and_approval_are_signed_and_durable(
    control_setup: tuple[Core, HumanControl, AgentCommands],
) -> None:
    core, control, agents = control_setup
    await control.create(
        mission_id="mission:approval",
        group_id="group:approval",
        coordinator_id="agent:coordinator-a",
        title="Approve a Mission",
        objective="Persist a signed exact-revision decision",
        definition_of_done=("verified Artifact", "signed approval"),
        deadline=NOW + timedelta(hours=2),
        coordinator_lease_seconds=7_200,
    )
    coordinator = Principal.agent("agent:coordinator-a")
    worker = Principal.agent("agent:worker")
    await core.perform(
        agents.command(
            CommandKind.ADD_MEMBERSHIP,
            coordinator,
            AddMembershipPayload(principal=worker, roles=(Role.WORKER,), provisional=True),
            group_id="group:approval",
            coordinator_epoch=1,
        )
    )
    contract = WorkContract(
        goal="Produce an approved deliverable",
        deliverables=("source",),
        acceptance_criteria=("review passes",),
        deadline=NOW + timedelta(hours=1),
        required_capabilities=(CapabilityRequirement(id="software.python"),),
    )
    await core.perform(
        agents.command(
            CommandKind.CREATE_WORK_ITEM,
            coordinator,
            CreateWorkItemPayload(work_item_id="work:approval", contract=contract),
            group_id="group:approval",
            coordinator_epoch=1,
        )
    )
    await core.perform(
        agents.command(
            CommandKind.OFFER_WORK_ITEM,
            coordinator,
            OfferWorkItemPayload(
                work_item_id="work:approval",
                candidate_agent_ids=(worker.id,),
                selection_basis=SelectionBasis(
                    required_capabilities=(CapabilityRequirement(id="software.python"),),
                    verified_capability_matches=("software.python",),
                ),
            ),
            group_id="group:approval",
            coordinator_epoch=1,
        )
    )
    await core.perform(
        agents.command(
            CommandKind.ACCEPT_WORK_OFFER,
            worker,
            AcceptWorkOfferPayload(work_item_id="work:approval"),
            group_id="group:approval",
        )
    )
    await core.perform(
        agents.command(
            CommandKind.START_WORK_ITEM,
            worker,
            StartWorkItemPayload(
                work_item_id="work:approval",
                ownership_epoch=1,
                execution_lease_seconds=600,
            ),
            group_id="group:approval",
        )
    )
    active = await core.query(Query(kind=QueryKind.WORK_ITEM, entity_id="work:approval"))
    assert isinstance(active, WorkItem)
    assert active.execution_lease_id is not None
    artifact = agents.sign_artifact(
        Artifact(
            id="artifact:approval",
            content_hash="sha256:" + "c" * 64,
            media_type="application/zip",
            producing_agent_id=worker.id,
            agent_card_version=1,
            mission_id="mission:approval",
            group_id="group:approval",
            work_item_id="work:approval",
            created_at=NOW,
            data_classification="internal",
            signature="pending",
        )
    )
    await core.perform(
        agents.command(
            CommandKind.PUBLISH_ARTIFACT,
            worker,
            PublishArtifactPayload(
                artifact=artifact,
                ownership_epoch=1,
                execution_lease_id=active.execution_lease_id,
            ),
            group_id="group:approval",
        )
    )
    await core.perform(
        agents.command(
            CommandKind.SUBMIT_WORK_ITEM,
            worker,
            SubmitWorkItemPayload(
                work_item_id="work:approval",
                ownership_epoch=1,
                execution_lease_id=active.execution_lease_id,
                artifact_ids=(artifact.id,),
                evidence=(Evidence(kind="tests", description="tests passed"),),
            ),
            group_id="group:approval",
        )
    )
    await core.perform(
        agents.command(
            CommandKind.VERIFY_WORK_ITEM,
            coordinator,
            VerifyWorkItemPayload(
                work_item_id="work:approval",
                evidence=(Evidence(kind="review", description="review passed"),),
            ),
            group_id="group:approval",
            coordinator_epoch=1,
        )
    )
    await core.perform(
        agents.command(
            CommandKind.SUBMIT_MISSION,
            coordinator,
            SubmitMissionPayload(artifact_hashes=(artifact.content_hash,)),
            group_id="group:approval",
            coordinator_epoch=1,
        )
    )

    await control.request_changes("mission:approval", "Add a clearer release note.")
    await core.perform(
        agents.command(
            CommandKind.SUBMIT_MISSION,
            coordinator,
            SubmitMissionPayload(artifact_hashes=(artifact.content_hash,)),
            group_id="group:approval",
            coordinator_epoch=1,
        )
    )
    receipt, approval = await control.approve(
        "mission:approval",
        approval_id="approval:final",
        comments="Verified and approved",
    )
    stored_command = await control.accepted_command(receipt.event.id)

    assert control.identity.verify(stored_command)
    assert approval.signature == stored_command.signature
    assert approval.mission_revision > 1
    approved = await core.query(Query(kind=QueryKind.MISSION, entity_id="mission:approval"))
    assert isinstance(approved, Mission)
    assert approved.status is MissionStatus.APPROVED
