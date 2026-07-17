from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from missionweaveprotocol.conformance import SchemaCatalog
from missionweaveprotocol.crypto import generate_keypair
from missionweaveprotocol.documents import (
    ArtifactLocation,
    DocumentMappingError,
    DocumentSigner,
    ProtocolDocumentAdapter,
    ProtocolDocumentConfig,
)
from missionweaveprotocol.models import (
    AgentCard,
    Approval,
    Artifact,
    Capability,
    CapabilityRequirement,
    Checkpoint,
    Conversation,
    Evidence,
    ExecutionApproval,
    Group,
    Membership,
    MembershipStatus,
    Message,
    Mission,
    MissionStatus,
    Principal,
    ResourceBudget,
    RetryPolicy,
    Role,
    SelectionBasis,
    WorkContract,
    WorkItem,
    WorkItemStatus,
)

NOW = datetime(2026, 7, 15, 8, 0, tzinfo=UTC)
ARTIFACT_HASH = "sha256:" + "a" * 64
INPUT_HASH = "sha256:" + "b" * 64


@dataclass(slots=True)
class ProjectionFixture:
    adapter: ProtocolDocumentAdapter
    registry_signer: DocumentSigner
    agent_signer: DocumentSigner
    human_signer: DocumentSigner
    card: AgentCard
    mission: Mission
    group: Group
    membership: Membership
    contract: WorkContract
    work: WorkItem
    conversation: Conversation
    message: Message
    artifact: Artifact
    approval: Approval
    execution_approval: ExecutionApproval


@pytest.fixture
def projections() -> ProjectionFixture:
    registry_private, _ = generate_keypair()
    agent_private, agent_public = generate_keypair()
    human_private, _ = generate_keypair()
    registry_signer = DocumentSigner(
        principal_id="organization",
        key_id="key:registry",
        private_key=registry_private,
    )
    agent_signer = DocumentSigner(
        principal_id="developer",
        key_id="key:developer",
        private_key=agent_private,
    )
    human_signer = DocumentSigner(
        principal_id="human:owner",
        key_id="key:owner",
        private_key=human_private,
    )
    adapter = ProtocolDocumentAdapter(
        ProtocolDocumentConfig(
            organization_id="acme",
            endpoints=("wss://agents.example.test/missionweaveprotocol",),
            max_concurrency=2,
            registry_signer=registry_signer,
            principal_signers=(agent_signer, human_signer),
        )
    )
    capability = Capability(
        id="software.python",
        version=2,
        input_schema="https://schemas.example.test/python-input.json",
        output_schema="https://schemas.example.test/python-output.json",
        constraints={
            "inputSchemaHash": "sha256:" + "1" * 64,
            "outputSchemaHash": "sha256:" + "2" * 64,
            "python": ">=3.12",
        },
        verified_evidence=("capability-evidence",),
    )
    card = AgentCard(
        agent_id="developer",
        version=2,
        display_name="Developer Agent",
        owner="human:platform-owner",
        public_key=agent_public,
        capabilities=(capability,),
        issued_at=NOW,
        signature="internal-registry-projection-signature",
    )
    mission = Mission(
        id="mission-one",
        group_id="group-one",
        title="Ship pagination",
        objective="Implement and verify cursor pagination",
        definition_of_done=("integration tests pass", "review evidence accepted"),
        owner=Principal.human("human:owner"),
        coordinator_id=card.agent_id,
        coordinator_epoch=2,
        coordinator_lease_expires_at=NOW + timedelta(hours=2),
        budget=ResourceBudget(
            model_tokens=100_000,
            tool_calls=500,
            wall_clock_seconds=86_400,
            external_actions=1,
        ),
        deadline=NOW + timedelta(days=1),
        permissions=("repository.read", "repository.write"),
        status=MissionStatus.APPROVED,
        revision=4,
        created_at=NOW,
        updated_at=NOW + timedelta(hours=4),
    )
    group = Group(
        id=mission.group_id,
        mission_id=mission.id,
        main_conversation_id="conversation-main",
        created_at=mission.created_at,
    )
    membership = Membership(
        group_id=mission.group_id,
        principal=Principal.agent(card.agent_id),
        roles=(Role.WORKER,),
        status=MembershipStatus.ACTIVE,
        epoch=3,
        visibility_after_sequence=12,
        joined_at=NOW + timedelta(minutes=5),
    )
    contract = WorkContract(
        goal="Implement cursor pagination",
        deliverables=("source and test changes",),
        acceptance_criteria=("integration tests pass",),
        inputs=(INPUT_HASH,),
        allowed_tools=("python",),
        allowed_resources=("repository",),
        deadline=NOW + timedelta(hours=8),
        requested_priority=80,
        estimated_duration_seconds=7_200,
        required_capabilities=(CapabilityRequirement(id="software.python", minimum_version=2),),
        budget=ResourceBudget(
            model_tokens=30_000,
            tool_calls=100,
            wall_clock_seconds=14_400,
            external_actions=1,
        ),
        retry_policy=RetryPolicy(
            max_attempts=3,
            initial_backoff_seconds=1,
            maximum_backoff_seconds=8,
        ),
        exclusive=True,
    )
    submission_evidence = Evidence(
        kind="deterministic-tests",
        description="Run the pinned integration test suite",
        artifact_hash=ARTIFACT_HASH,
        data={"toolVersion": "pytest 8.4.1", "passed": 24},
    )
    work = WorkItem(
        id="implementation",
        mission_id=mission.id,
        group_id=mission.group_id,
        conversation_id="conversation-implementation",
        created_by=Principal.agent(card.agent_id),
        contract=contract,
        status=WorkItemStatus.VERIFIED,
        revision=5,
        dependency_ids=("requirements",),
        assignee_id=card.agent_id,
        assigned_agent_card_version=card.version,
        assigned_capability_versions={"software.python": 2},
        selection_basis=SelectionBasis(
            required_capabilities=contract.required_capabilities,
            verified_capability_matches=("software.python",),
            authorization_eligible=True,
            expected_cost_microunits=2_500_000,
            reliability_evidence=("python-performance",),
            policy_rules_applied=("capability-match", "within-budget"),
        ),
        ownership_epoch=2,
        ownership_lease_expires_at=NOW + timedelta(hours=2),
        execution_lease_expires_at=NOW + timedelta(hours=1),
        checkpoints=(
            Checkpoint(
                phase="review",
                completed_milestones=("implementation", "tests"),
                next_step="publish result",
                state_artifact_hash=ARTIFACT_HASH,
                created_at=NOW + timedelta(hours=2),
            ),
        ),
        artifact_ids=("artifact-one",),
        submission_evidence=(submission_evidence,),
        verification_evidence=(
            Evidence(kind="review", description="Coordinator accepted the evidence"),
        ),
        created_at=NOW + timedelta(minutes=10),
        updated_at=NOW + timedelta(hours=3),
    )
    conversation = Conversation(
        id=work.conversation_id,
        group_id=mission.group_id,
        work_item_id=work.id,
        title="Implementation WorkItem",
        created_at=work.created_at,
    )
    message = Message(
        id="message-one",
        group_id=mission.group_id,
        conversation_id=conversation.id,
        author=Principal.agent(card.agent_id),
        content="Implementation is ready for review.",
        mentions=(mission.owner,),
        created_at=NOW + timedelta(hours=1),
    )
    artifact = Artifact(
        id="artifact-one",
        content_hash=ARTIFACT_HASH,
        media_type="application/vnd.git.patch",
        schema_uri="urn:missionweaveprotocol:schema:opaque",
        producing_agent_id=card.agent_id,
        agent_card_version=card.version,
        mission_id=mission.id,
        group_id=mission.group_id,
        work_item_id=work.id,
        source_artifact_hashes=(INPUT_HASH,),
        tool_versions={"git": "2.50.0", "pytest": "8.4.1"},
        model_versions={"openai/gpt-5": "2026-07-01"},
        created_at=NOW + timedelta(hours=2),
        data_classification="internal",
        signature="internal-artifact-projection-signature",
    )
    approval = Approval(
        id="approval-one",
        mission_id=mission.id,
        mission_revision=mission.revision,
        artifact_hashes=(artifact.content_hash,),
        acceptance_policy_version="1.2.0",
        approver=mission.owner,
        approved_at=NOW + timedelta(hours=4),
        comments="Acceptance criteria and evidence reviewed.",
        signature="internal-human-projection-signature",
    )
    execution_approval = ExecutionApproval(
        id="execution-approval-one",
        mission_id=mission.id,
        group_id=mission.group_id,
        work_item_id=work.id,
        ownership_epoch=work.ownership_epoch,
        operations=("production.deploy",),
        resources=("cluster:production",),
        budget=ResourceBudget(tool_calls=2, external_actions=1),
        approver=mission.owner,
        approved_at=NOW + timedelta(hours=2),
        expires_at=NOW + timedelta(hours=3),
        comments="Approve the production release gate.",
        signature="internal-execution-approval-signature",
    )
    return ProjectionFixture(
        adapter=adapter,
        registry_signer=registry_signer,
        agent_signer=agent_signer,
        human_signer=human_signer,
        card=card,
        mission=mission,
        group=group,
        membership=membership,
        contract=contract,
        work=work,
        conversation=conversation,
        message=message,
        artifact=artifact,
        approval=approval,
        execution_approval=execution_approval,
    )


def test_all_required_projection_documents_validate_normative_schemas(
    projections: ProjectionFixture,
) -> None:
    adapter = projections.adapter
    evidence = adapter.evidence(
        projections.work.submission_evidence[0],
        projections.work,
        generated_by=Principal.agent(projections.card.agent_id),
        created_at=projections.work.updated_at,
    )
    documents = {
        "agent-card.schema.json": adapter.agent_card(projections.card),
        "membership.schema.json": adapter.membership(
            projections.membership,
            projections.mission,
        ),
        "mission.schema.json": adapter.mission(projections.mission, projections.card),
        "group.schema.json": adapter.group(projections.group),
        "conversation.schema.json": adapter.conversation(
            projections.conversation,
            projections.mission,
            work_item=projections.work,
        ),
        "message.schema.json": adapter.message(projections.message, projections.mission),
        "work-contract.schema.json": adapter.work_contract(
            projections.contract,
            dependency_ids=projections.work.dependency_ids,
        ),
        "work-item.schema.json": adapter.work_item(
            projections.work,
            artifacts=(projections.artifact,),
        ),
        "artifact.schema.json": adapter.artifact(
            projections.artifact,
            projections.card,
            ArtifactLocation(
                uri="https://artifacts.example.test/sha256/" + "a" * 64,
                size_bytes=4096,
            ),
        ),
        "evidence.schema.json": evidence,
        "approval.schema.json": adapter.approval(
            projections.approval,
            projections.mission,
        ),
    }

    catalog = SchemaCatalog()
    for schema_name, document in documents.items():
        catalog.validate(schema_name, document)

    agent_id = str(documents["agent-card.schema.json"]["agentId"])
    mission_id = str(documents["mission.schema.json"]["missionId"])
    assert agent_id.startswith("urn:missionweaveprotocol:agent:")
    assert mission_id.startswith("urn:missionweaveprotocol:mission:")
    assert documents["group.schema.json"]["state"] == "active"
    assert documents["mission.schema.json"]["state"] == "approved"
    assert documents["work-item.schema.json"]["state"] == "verified"
    assert documents["membership.schema.json"]["visibilityStartSequence"] == 13
    assert documents["work-item.schema.json"]["submission"]["evidenceIds"] == [
        evidence["evidenceId"]
    ]


@pytest.mark.parametrize("status", tuple(MissionStatus))
def test_mission_projection_preserves_the_authoritative_state_name(
    projections: ProjectionFixture,
    status: MissionStatus,
) -> None:
    document = projections.adapter.mission(
        projections.mission.model_copy(update={"status": status}),
        projections.card,
    )

    assert document["state"] == status.value


@pytest.mark.parametrize("status", tuple(WorkItemStatus))
def test_work_item_projection_preserves_the_authoritative_state_name(
    projections: ProjectionFixture,
    status: WorkItemStatus,
) -> None:
    document = projections.adapter.work_item(
        projections.work.model_copy(update={"status": status}),
        artifacts=(projections.artifact,),
    )

    assert document["state"] == status.value


@pytest.mark.parametrize(
    ("name", "public_key", "field", "replacement"),
    (
        ("agent", "registry", "displayName", "Tampered Agent"),
        ("artifact", "agent", "sizeBytes", 9999),
        ("evidence", "agent", "method", "Tampered evidence"),
        ("approval", "human", "comments", "Tampered approval"),
    ),
)
def test_schema_required_signatures_verify_and_tampering_fails(
    projections: ProjectionFixture,
    name: str,
    public_key: str,
    field: str,
    replacement: object,
) -> None:
    documents = {
        "agent": projections.adapter.agent_card(projections.card),
        "artifact": projections.adapter.artifact(
            projections.artifact,
            projections.card,
            ArtifactLocation(uri="https://artifacts.example.test/a", size_bytes=4096),
        ),
        "evidence": projections.adapter.evidence(
            projections.work.submission_evidence[0],
            projections.work,
            generated_by=Principal.agent(projections.card.agent_id),
            created_at=projections.work.updated_at,
        ),
        "approval": projections.adapter.approval(
            projections.approval,
            projections.mission,
        ),
    }
    keys = {
        "registry": projections.registry_signer.public_key,
        "agent": projections.agent_signer.public_key,
        "human": projections.human_signer.public_key,
    }
    document = documents[name]

    assert projections.adapter.verify_signature(document, keys[public_key])

    tampered: dict[str, Any] = deepcopy(document)
    tampered[field] = replacement
    assert not projections.adapter.verify_signature(tampered, keys[public_key])


def test_execution_approval_maps_to_normative_work_execution_decision(
    projections: ProjectionFixture,
) -> None:
    document = projections.adapter.approval(
        projections.execution_approval,
        projections.mission,
    )

    SchemaCatalog().validate("approval.schema.json", document)
    assert document["kind"] == "work_execution"
    assert document["workItemId"].startswith("urn:missionweaveprotocol:work-item:")
    assert "operation:production.deploy" in document["conditions"]
    assert projections.adapter.verify_signature(document, projections.human_signer.public_key)


def test_adapter_rejects_projection_that_would_require_invented_capability_metadata(
    projections: ProjectionFixture,
) -> None:
    incomplete = projections.card.model_copy(
        update={"capabilities": (Capability(id="software.python", version=2),)}
    )

    with pytest.raises(DocumentMappingError, match="schema URIs"):
        projections.adapter.agent_card(incomplete)


def test_archived_group_requires_and_validates_real_snapshot_reference(
    projections: ProjectionFixture,
) -> None:
    archived = projections.group.model_copy(update={"archived_at": NOW + timedelta(hours=5)})

    with pytest.raises(DocumentMappingError, match="archive snapshot ID"):
        projections.adapter.group(archived)

    document = projections.adapter.group(
        archived.model_copy(update={"archive_snapshot_id": "snapshot-one"}),
    )
    SchemaCatalog().validate("group.schema.json", document)
    assert document["state"] == "archived"
    assert document["archiveSnapshotId"].startswith("urn:missionweaveprotocol:group-snapshot:")
