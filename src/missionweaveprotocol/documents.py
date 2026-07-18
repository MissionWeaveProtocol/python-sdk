"""Signed normative-document Adapter for reference Core projections.

The classes in :mod:`missionweaveprotocol.models` are intentionally compact, internal state
projections. They are not wire documents and MUST NOT be serialized directly as normative
MissionWeaveProtocol durable objects.
``ProtocolDocumentAdapter`` is the explicit seam that supplies deployment metadata, joins
related projections, normalizes identifiers, maps states, signs required documents, and validates
the result against the normative JSON Schemas.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.hazmat.primitives import serialization
from jsonschema import ValidationError as JSONSchemaValidationError

from .canonical import canonical_hash
from .conformance import SchemaCatalog
from .crypto import (
    PrivateKeyLike,
    encode_public_key,
    load_private_key,
)
from .models import (
    ActorType,
    AgentCard,
    Approval,
    Artifact,
    Capability,
    CapabilityRequirement,
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
from .signed_documents import (
    SignedDocumentCodec,
    SignedDocumentKind,
    SignedDocumentSigningError,
)

type ProtocolDocument = dict[str, Any]

_ABSOLUTE_ID = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")


class DocumentMappingError(ValueError):
    """An internal projection lacks information required by a normative document."""


@dataclass(frozen=True, slots=True)
class DocumentSigner:
    """One Ed25519 signing identity available to the Adapter."""

    principal_id: str
    key_id: str
    private_key: PrivateKeyLike

    @property
    def algorithm(self) -> str:
        return "Ed25519"

    @property
    def public_key_bytes(self) -> bytes:
        return (
            load_private_key(self.private_key)
            .public_key()
            .public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        )

    def sign(self, message: bytes) -> bytes:
        return load_private_key(self.private_key).sign(message)

    @property
    def public_key(self) -> str:
        return encode_public_key(load_private_key(self.private_key).public_key())


@dataclass(frozen=True, slots=True)
class ProtocolDocumentConfig:
    """Deployment metadata absent from compact Core projections."""

    organization_id: str
    endpoints: tuple[str, ...]
    max_concurrency: int
    registry_signer: DocumentSigner
    principal_signers: tuple[DocumentSigner, ...]

    def __post_init__(self) -> None:
        if not self.endpoints or any(
            not endpoint.startswith("wss://") for endpoint in self.endpoints
        ):
            raise ValueError("Agent endpoints must contain at least one wss:// URI")
        if self.max_concurrency <= 0:
            raise ValueError("max_concurrency must be positive")
        principals = [signer.principal_id for signer in self.principal_signers]
        if len(principals) != len(set(principals)):
            raise ValueError("principal_signers contains duplicate principal IDs")


@dataclass(frozen=True, slots=True)
class ArtifactLocation:
    """Deployment location metadata not retained by the authoritative Artifact projection."""

    uri: str
    size_bytes: int

    def __post_init__(self) -> None:
        if ":" not in self.uri:
            raise ValueError("Artifact URI must be absolute")
        if self.size_bytes < 0:
            raise ValueError("Artifact size cannot be negative")


class ProtocolDocumentAdapter:
    """Map internal projections to validated normative durable documents."""

    def __init__(
        self,
        config: ProtocolDocumentConfig,
        *,
        schemas: SchemaCatalog | None = None,
        codec: SignedDocumentCodec | None = None,
    ) -> None:
        self._config = config
        self._schemas = schemas or SchemaCatalog()
        self._codec = codec or SignedDocumentCodec()
        self._signers = {signer.principal_id: signer for signer in config.principal_signers}

    def agent_card(self, card: AgentCard) -> ProtocolDocument:
        capabilities = [self._capability(capability) for capability in card.capabilities]
        if not capabilities:
            raise DocumentMappingError("normative Agent Cards require at least one capability")
        agent_signer = self._signers.get(card.agent_id)
        if agent_signer is not None and agent_signer.public_key != card.public_key:
            raise DocumentMappingError(
                "configured Agent signer does not match the Agent Card public key"
            )
        public_key_id = (
            agent_signer.key_id
            if agent_signer is not None
            else self._id(f"{card.agent_id}:key:{card.version}", "key")
        )
        document: ProtocolDocument = {
            "agentId": self._id(card.agent_id, "agent"),
            "organizationId": self._id(self._config.organization_id, "organization"),
            "cardVersion": card.version,
            "displayName": card.display_name,
            "owner": self._owner_actor(card.owner),
            "status": "active",
            "protocolVersions": ["0.1"],
            "endpoints": [
                {"transport": "wss", "uri": endpoint} for endpoint in self._config.endpoints
            ],
            "publicKeys": [
                {
                    "keyId": self._id(public_key_id, "key"),
                    "algorithm": "Ed25519",
                    "publicKey": card.public_key,
                    "validFrom": self._timestamp(card.issued_at),
                }
            ],
            "capabilities": capabilities,
            "maxConcurrency": self._config.max_concurrency,
            "issuedAt": self._timestamp(card.issued_at),
        }
        return self._sign(
            SignedDocumentKind.AGENT_CARD,
            document,
            self._config.registry_signer,
        )

    def membership(self, membership: Membership, mission: Mission) -> ProtocolDocument:
        self._same_group(membership.group_id, mission.group_id, "Membership")
        if len(membership.roles) != 1:
            raise DocumentMappingError(
                "normative Membership has one role; the projection must contain exactly one"
            )
        role = self._membership_role(membership.roles[0])
        document: ProtocolDocument = {
            "membershipId": self._id(
                f"{membership.group_id}:{membership.principal.type.value}:"
                f"{membership.principal.id}:{membership.epoch}",
                "membership",
            ),
            "missionId": self._id(mission.id, "mission"),
            "groupId": self._id(membership.group_id, "group"),
            "member": self._actor(membership.principal),
            "role": role,
            "state": membership.status.value,
            "membershipEpoch": membership.epoch,
            "scopes": self._membership_scopes(membership.roles[0]),
            "visibilityStartSequence": membership.visibility_after_sequence + 1,
            "grantedAt": self._timestamp(membership.joined_at),
        }
        if membership.status is MembershipStatus.PROVISIONAL:
            document["contextPackageId"] = self._id(
                f"{membership.group_id}:{membership.principal.id}:{membership.epoch}",
                "context-package",
            )
            document["provisionalExpiresAt"] = self._timestamp(mission.deadline)
        elif membership.status is MembershipStatus.ACTIVE:
            document["activatedAt"] = self._timestamp(membership.joined_at)
        else:
            if membership.ended_at is None:
                raise DocumentMappingError("ended Membership requires ended_at")
            document["endedAt"] = self._timestamp(membership.ended_at)
        return self._validated("membership.schema.json", document)

    def mission(self, mission: Mission, coordinator_card: AgentCard) -> ProtocolDocument:
        if coordinator_card.agent_id != mission.coordinator_id:
            raise DocumentMappingError("Coordinator Agent Card does not match Mission coordinator")
        budget = self._budget(
            mission.budget,
            fallback_wall_seconds=max(
                1, int((mission.deadline - mission.created_at).total_seconds())
            ),
        )
        document: ProtocolDocument = {
            "missionId": self._id(mission.id, "mission"),
            "groupId": self._id(mission.group_id, "group"),
            "revision": mission.revision,
            "objective": mission.objective,
            "definitionOfDone": self._criteria(mission.definition_of_done),
            "missionOwner": self._actor(mission.owner),
            "coordinator": {
                "agentId": self._id(mission.coordinator_id, "agent"),
                "agentCardVersion": coordinator_card.version,
                "coordinatorEpoch": mission.coordinator_epoch,
                "leaseId": self._id(
                    f"{mission.id}:coordinator:{mission.coordinator_epoch}",
                    "lease",
                ),
            },
            "state": self._mission_state(mission.status),
            "budget": budget,
            "deadline": self._timestamp(mission.deadline),
            "approvalPolicy": {
                "finalHumanApproval": mission.parent_mission_id is None,
                "highRiskExecutionApproval": bool(mission.permissions),
                "policyVersion": "1.0.0",
            },
            "createdAt": self._timestamp(mission.created_at),
        }
        if mission.parent_mission_id is not None:
            if mission.parent_work_item_id is None:
                raise DocumentMappingError("child Mission requires parent_work_item_id")
            document["parent"] = {
                "missionId": self._id(mission.parent_mission_id, "mission"),
                "workItemId": self._id(mission.parent_work_item_id, "work-item"),
                "depth": 1,
            }
        if mission.follow_up_of_mission_id is not None:
            document["followUpToMissionId"] = self._id(
                mission.follow_up_of_mission_id,
                "mission",
            )
        return self._validated("mission.schema.json", document)

    def group(self, group: Group) -> ProtocolDocument:
        """Map one Group, requiring its real snapshot reference once archived."""

        document: ProtocolDocument = {
            "groupId": self._id(group.id, "group"),
            "missionId": self._id(group.mission_id, "mission"),
            "state": "archived" if group.archived_at is not None else "active",
            "mainConversationId": self._id(
                group.main_conversation_id,
                "conversation",
            ),
            "createdAt": self._timestamp(group.created_at),
        }
        if group.archived_at is not None:
            if group.archive_snapshot_id is None:
                raise DocumentMappingError(
                    "archived Group requires its authoritative archive snapshot ID"
                )
            document["archivedAt"] = self._timestamp(group.archived_at)
            document["archiveSnapshotId"] = self._id(
                group.archive_snapshot_id,
                "group-snapshot",
            )
        elif group.archive_snapshot_id is not None:
            raise DocumentMappingError("active Group cannot reference an archive snapshot")
        return self._validated("group.schema.json", document)

    def conversation(
        self,
        conversation: Conversation,
        mission: Mission,
        *,
        work_item: WorkItem | None = None,
    ) -> ProtocolDocument:
        self._same_group(conversation.group_id, mission.group_id, "Conversation")
        if conversation.work_item_id is None:
            conversation_type = "group"
            created_by = mission.owner
        else:
            if work_item is None or work_item.id != conversation.work_item_id:
                raise DocumentMappingError(
                    "WorkItem Conversation requires its related WorkItem projection"
                )
            conversation_type = "work_item"
            created_by = work_item.created_by
        document: ProtocolDocument = {
            "conversationId": self._id(conversation.id, "conversation"),
            "missionId": self._id(mission.id, "mission"),
            "groupId": self._id(conversation.group_id, "group"),
            "type": conversation_type,
            "title": conversation.title,
            "access": {"mode": "group"},
            "createdBy": self._actor(created_by),
            "createdAt": self._timestamp(conversation.created_at),
            "state": "active",
            "revision": 1,
        }
        if conversation.work_item_id is not None:
            document["primaryWorkItemId"] = self._id(
                conversation.work_item_id,
                "work-item",
            )
        return self._validated("conversation.schema.json", document)

    def message(self, message: Message, mission: Mission) -> ProtocolDocument:
        self._same_group(message.group_id, mission.group_id, "Message")
        document: ProtocolDocument = {
            "messageId": self._id(message.id, "message"),
            "missionId": self._id(mission.id, "mission"),
            "groupId": self._id(message.group_id, "group"),
            "conversationId": self._id(message.conversation_id, "conversation"),
            "author": self._actor(message.author),
            "kind": "message",
            "authority": False,
            "content": [{"type": "text", "text": message.content}],
            "mentions": [self._actor(principal) for principal in message.mentions],
            "committedAt": self._timestamp(message.created_at),
        }
        return self._validated("message.schema.json", document)

    def work_contract(
        self,
        contract: WorkContract,
        *,
        dependency_ids: Sequence[str] = (),
    ) -> ProtocolDocument:
        if not contract.required_capabilities:
            raise DocumentMappingError(
                "normative Work Contracts require at least one capability requirement"
            )
        input_hashes = list(contract.inputs)
        invalid_input = next(
            (value for value in input_hashes if not _SHA256.fullmatch(value)), None
        )
        if invalid_input is not None:
            raise DocumentMappingError(
                f"Work Contract input is not a content hash: {invalid_input}"
            )
        allowed_resources = [
            {"resource": self._id(resource, "resource"), "operations": ["read"]}
            for resource in contract.allowed_resources
        ]
        allowed_resources.extend(
            {
                "resource": self._id(tool, "tool"),
                "operations": ["execute"],
            }
            for tool in contract.allowed_tools
        )
        fallback = contract.estimated_duration_seconds
        budget = self._budget(contract.budget, fallback_wall_seconds=fallback)
        document: ProtocolDocument = {
            "contractVersion": 1,
            "goal": contract.goal,
            "requiredDeliverables": [
                {
                    "deliverableId": f"deliverable-{index}",
                    "description": description,
                    "mediaType": "application/octet-stream",
                    "schema": "urn:missionweaveprotocol:schema:opaque",
                }
                for index, description in enumerate(contract.deliverables, start=1)
            ],
            "acceptanceCriteria": self._criteria(contract.acceptance_criteria),
            "inputArtifacts": input_hashes,
            "dependencyWorkItemIds": [self._id(item, "work-item") for item in dependency_ids],
            "allowedResources": allowed_resources,
            "requiredCapabilities": [
                self._capability_requirement(requirement)
                for requirement in contract.required_capabilities
            ],
            "deadline": self._timestamp(contract.deadline),
            "requestedUrgency": self._urgency(contract.requested_priority),
            "businessImpact": contract.goal,
            "retryPolicy": self._retry_policy(contract.retry_policy),
            "budget": budget,
            "sideEffectRisk": self._side_effect_risk(contract),
            "executionApproval": self._execution_approval(contract),
            "constraints": {
                "exclusive": contract.exclusive,
                **(
                    {"estimatedDurationSeconds": contract.estimated_duration_seconds}
                    if contract.estimated_duration_seconds is not None
                    else {}
                ),
            },
        }
        return self._validated("work-contract.schema.json", document)

    def work_item(
        self,
        work: WorkItem,
        *,
        artifacts: Sequence[Artifact] = (),
    ) -> ProtocolDocument:
        state = self._work_state(work.status)
        document: ProtocolDocument = {
            "workItemId": self._id(work.id, "work-item"),
            "missionId": self._id(work.mission_id, "mission"),
            "groupId": self._id(work.group_id, "group"),
            "conversationId": self._id(work.conversation_id, "conversation"),
            "revision": work.revision,
            "state": state,
            "exclusive": work.contract.exclusive,
            "contract": self.work_contract(
                work.contract,
                dependency_ids=work.dependency_ids,
            ),
            "createdBy": self._actor(work.created_by),
            "authorizedBy": self._actor(work.created_by),
            "createdAt": self._timestamp(work.created_at),
            "updatedAt": self._timestamp(work.updated_at),
        }
        if work.assignee_id is not None:
            document["owner"] = self._owner(work)
            document["selectionBasis"] = self._selection_basis(work)
        elif state in {
            "queued",
            "active",
            "blocked",
            "submitted",
            "verified",
        }:
            raise DocumentMappingError(f"WorkItem state {state} requires an owner")
        if work.checkpoints:
            checkpoint = work.checkpoints[-1]
            document["progress"] = {
                "currentPhase": checkpoint.phase,
                "completedMilestones": list(checkpoint.completed_milestones),
                "nextCheckpoint": checkpoint.next_step or checkpoint.phase,
                "blockers": [work.blocker] if work.blocker else [],
                "updatedCompletionEstimate": self._timestamp(
                    work.execution_lease_expires_at or work.contract.deadline
                ),
                "evidenceIds": [],
            }
        if state in {"submitted", "verified"}:
            document["submission"] = self._submission(work, artifacts)
        return self._validated("work-item.schema.json", document)

    def artifact(
        self,
        artifact: Artifact,
        producer_card: AgentCard,
        location: ArtifactLocation,
    ) -> ProtocolDocument:
        if producer_card.agent_id != artifact.producing_agent_id:
            raise DocumentMappingError("producer Agent Card does not match Artifact producer")
        if producer_card.version != artifact.agent_card_version:
            raise DocumentMappingError("Artifact producer Agent Card version does not match")
        capabilities = [
            {
                "id": self._capability_id(capability.id),
                "version": self._version(capability.version),
            }
            for capability in producer_card.capabilities
        ]
        if not capabilities:
            raise DocumentMappingError("Artifact producer must pin at least one capability")
        classification = artifact.data_classification
        if classification not in {"public", "internal", "confidential", "restricted"}:
            raise DocumentMappingError(f"unsupported Artifact classification: {classification}")
        document: ProtocolDocument = {
            "artifactId": self._id(artifact.id, "artifact"),
            "contentHash": artifact.content_hash,
            "uri": location.uri,
            "sizeBytes": location.size_bytes,
            "mediaType": artifact.media_type,
            "schemaUri": artifact.schema_uri or "urn:missionweaveprotocol:schema:opaque",
            "producer": {
                "agentId": self._id(artifact.producing_agent_id, "agent"),
                "agentCardVersion": artifact.agent_card_version,
                "capabilities": capabilities,
            },
            "missionId": self._id(artifact.mission_id, "mission"),
            "groupId": self._id(artifact.group_id, "group"),
            "workItemId": self._id(artifact.work_item_id, "work-item"),
            "sourceArtifactHashes": list(artifact.source_artifact_hashes),
            "toolVersions": [
                {"name": name, "version": version}
                for name, version in sorted(artifact.tool_versions.items())
            ],
            "modelVersions": [
                self._model_version(name, version)
                for name, version in sorted(artifact.model_versions.items())
            ],
            "classification": classification,
            "createdAt": self._timestamp(artifact.created_at),
        }
        return self._sign(
            SignedDocumentKind.ARTIFACT,
            document,
            self._signer_for(artifact.producing_agent_id),
        )

    def evidence(
        self,
        evidence: Evidence,
        work: WorkItem,
        *,
        generated_by: Principal,
        created_at: datetime,
        phase: str = "submission",
        index: int = 0,
    ) -> ProtocolDocument:
        artifact_hashes = self._evidence_artifact_hashes(evidence)
        subject: ProtocolDocument
        if artifact_hashes:
            subject = {"type": "artifact", "id": artifact_hashes[0]}
        else:
            subject = {"type": "work_item", "id": self._id(work.id, "work-item")}
        document: ProtocolDocument = {
            "evidenceId": self._evidence_id(evidence, work, phase=phase, index=index),
            "missionId": self._id(work.mission_id, "mission"),
            "groupId": self._id(work.group_id, "group"),
            "workItemId": self._id(work.id, "work-item"),
            "type": self._evidence_type(evidence.kind),
            "subject": subject,
            "criterionIds": [
                criterion["criterionId"]
                for criterion in self._criteria(work.contract.acceptance_criteria)
            ],
            "method": evidence.description,
            "result": "passed" if evidence.success else "failed",
            "details": evidence.data,
            "artifactHashes": artifact_hashes,
            "generatedBy": self._actor(generated_by),
            "createdAt": self._timestamp(created_at),
        }
        tool_version = evidence.data.get("toolVersion")
        if isinstance(tool_version, str):
            document["toolVersion"] = tool_version
        model_version = evidence.data.get("modelVersion")
        if isinstance(model_version, str):
            document["modelVersion"] = model_version
        return self._sign(
            SignedDocumentKind.EVIDENCE,
            document,
            self._signer_for(generated_by.id),
        )

    def approval(
        self,
        approval: Approval | ExecutionApproval,
        mission: Mission,
    ) -> ProtocolDocument:
        if approval.mission_id != mission.id:
            raise DocumentMappingError("Approval does not belong to the supplied Mission")
        if isinstance(approval, ExecutionApproval):
            self._same_group(approval.group_id, mission.group_id, "Execution Approval")
            conditions = [
                *(f"operation:{operation}" for operation in approval.operations),
                *(f"resource:{resource}" for resource in approval.resources),
                f"ownershipEpoch:{approval.ownership_epoch}",
                f"expiresAt:{self._timestamp(approval.expires_at)}",
                f"budgetHash:{canonical_hash(approval.budget)}",
            ]
            execution_document: ProtocolDocument = {
                "approvalId": self._id(approval.id, "approval"),
                "kind": "work_execution",
                "decision": "approved",
                "missionId": self._id(approval.mission_id, "mission"),
                "groupId": self._id(approval.group_id, "group"),
                "workItemId": self._id(approval.work_item_id, "work-item"),
                "missionRevision": mission.revision,
                "artifactHashes": [],
                "acceptancePolicyVersion": "1.0.0",
                "approver": self._actor(approval.approver),
                "comments": approval.comments or "",
                "conditions": conditions,
                "occurredAt": self._timestamp(approval.approved_at),
            }
            return self._sign(
                SignedDocumentKind.APPROVAL,
                execution_document,
                self._signer_for(approval.approver.id),
            )
        if not _SEMVER.fullmatch(approval.acceptance_policy_version):
            raise DocumentMappingError(
                "Approval acceptance_policy_version must be semantic version"
            )
        kind = "mission_final" if mission.parent_mission_id is None else "child_mission"
        document: ProtocolDocument = {
            "approvalId": self._id(approval.id, "approval"),
            "kind": kind,
            "decision": "approved",
            "missionId": self._id(approval.mission_id, "mission"),
            "groupId": self._id(mission.group_id, "group"),
            "missionRevision": approval.mission_revision,
            "artifactHashes": list(approval.artifact_hashes),
            "acceptancePolicyVersion": approval.acceptance_policy_version,
            "approver": self._actor(approval.approver),
            "comments": approval.comments or "",
            "conditions": [],
            "occurredAt": self._timestamp(approval.approved_at),
        }
        return self._sign(
            SignedDocumentKind.APPROVAL,
            document,
            self._signer_for(approval.approver.id),
        )

    def _capability(self, capability: Capability) -> ProtocolDocument:
        if capability.input_schema is None or capability.output_schema is None:
            raise DocumentMappingError(
                f"Capability {capability.id} requires input and output schema URIs"
            )
        input_hash = capability.constraints.get("inputSchemaHash")
        output_hash = capability.constraints.get("outputSchemaHash")
        if not isinstance(input_hash, str) or not _SHA256.fullmatch(input_hash):
            raise DocumentMappingError(f"Capability {capability.id} lacks inputSchemaHash")
        if not isinstance(output_hash, str) or not _SHA256.fullmatch(output_hash):
            raise DocumentMappingError(f"Capability {capability.id} lacks outputSchemaHash")
        if not capability.verified_evidence:
            raise DocumentMappingError(f"Capability {capability.id} lacks verified evidence")
        constraints = dict(capability.constraints)
        constraints.pop("inputSchemaHash", None)
        constraints.pop("outputSchemaHash", None)
        return {
            "id": self._capability_id(capability.id),
            "version": self._version(capability.version),
            "inputSchema": capability.input_schema,
            "inputSchemaHash": input_hash,
            "outputSchema": capability.output_schema,
            "outputSchemaHash": output_hash,
            "constraints": constraints,
            "verifiedEvidence": [
                self._id(item, "evidence") for item in capability.verified_evidence
            ],
        }

    def _owner(self, work: WorkItem) -> ProtocolDocument:
        if work.assignee_id is None or work.assigned_agent_card_version is None:
            raise DocumentMappingError("owned WorkItem requires assignee and Agent Card version")
        pins = [
            {"id": self._capability_id(identifier), "version": self._version(version)}
            for identifier, version in sorted(work.assigned_capability_versions.items())
        ]
        if not pins:
            pins = [
                self._capability_requirement(requirement)
                for requirement in work.contract.required_capabilities
            ]
        if not pins or work.ownership_epoch <= 0:
            raise DocumentMappingError(
                "owned WorkItem requires capability pins and ownership epoch"
            )
        return {
            "agentId": self._id(work.assignee_id, "agent"),
            "agentCardVersion": work.assigned_agent_card_version,
            "capabilityPins": pins,
            "ownershipEpoch": work.ownership_epoch,
            "ownershipLeaseId": self._id(
                f"{work.id}:ownership:{work.ownership_epoch}",
                "lease",
            ),
            "acceptedAt": self._timestamp(work.updated_at),
        }

    def _selection_basis(self, work: WorkItem) -> ProtocolDocument:
        selection = work.selection_basis or SelectionBasis(
            required_capabilities=work.contract.required_capabilities,
            verified_capability_matches=tuple(
                requirement.id for requirement in work.contract.required_capabilities
            ),
            policy_rules_applied=("reference-core-selection",),
        )
        required = selection.required_capabilities or work.contract.required_capabilities
        if not required:
            raise DocumentMappingError("owned WorkItem requires selection capability evidence")
        versions = {requirement.id: requirement.minimum_version for requirement in required}
        verified = [
            {
                "id": self._capability_id(identifier),
                "version": self._version(
                    work.assigned_capability_versions.get(identifier, versions.get(identifier, 1))
                ),
            }
            for identifier in selection.verified_capability_matches
        ]
        if not verified:
            verified = [self._capability_requirement(requirement) for requirement in required]
        return {
            "requiredCapabilities": [
                self._capability_requirement(requirement) for requirement in required
            ],
            "verifiedMatches": verified,
            "authorizationEligible": selection.authorization_eligible,
            "availabilityEstimate": self._timestamp(work.updated_at),
            "expectedCost": (selection.expected_cost_microunits or 0) / 1_000_000,
            "reliabilityEvidence": [
                self._id(item, "evidence") for item in selection.reliability_evidence
            ],
            "policyRulesApplied": list(
                selection.policy_rules_applied or ("reference-core-selection",)
            ),
        }

    def _submission(
        self,
        work: WorkItem,
        artifacts: Sequence[Artifact],
    ) -> ProtocolDocument:
        by_id = {artifact.id: artifact for artifact in artifacts}
        missing = [artifact_id for artifact_id in work.artifact_ids if artifact_id not in by_id]
        if missing:
            raise DocumentMappingError(
                f"WorkItem submission lacks Artifact projections: {', '.join(missing)}"
            )
        hashes = [by_id[artifact_id].content_hash for artifact_id in work.artifact_ids]
        evidence_ids = [
            self._evidence_id(item, work, phase="submission", index=index)
            for index, item in enumerate(work.submission_evidence)
        ]
        if not hashes or not evidence_ids:
            raise DocumentMappingError(
                "submitted WorkItem requires Artifacts and submission Evidence"
            )
        return {
            "artifactHashes": hashes,
            "evidenceIds": evidence_ids,
            "submittedAt": self._timestamp(work.updated_at),
        }

    def _evidence_id(
        self,
        evidence: Evidence,
        work: WorkItem,
        *,
        phase: str,
        index: int,
    ) -> str:
        fingerprint = canonical_hash(
            {
                "evidence": evidence,
                "index": index,
                "phase": phase,
                "workItemId": work.id,
            }
        ).removeprefix("sha256:")
        return f"urn:missionweaveprotocol:evidence:{fingerprint}"

    @staticmethod
    def _evidence_artifact_hashes(evidence: Evidence) -> list[str]:
        values: list[str] = []
        if evidence.artifact_hash is not None and _SHA256.fullmatch(evidence.artifact_hash):
            values.append(evidence.artifact_hash)
        data_hash = evidence.data.get("artifactHash")
        if isinstance(data_hash, str) and _SHA256.fullmatch(data_hash) and data_hash not in values:
            values.append(data_hash)
        return values

    def _sign(
        self,
        kind: SignedDocumentKind,
        document: ProtocolDocument,
        signer: DocumentSigner,
    ) -> ProtocolDocument:
        selected_signer = DocumentSigner(
            principal_id=signer.principal_id,
            key_id=self._id(signer.key_id, "key"),
            private_key=signer.private_key,
        )
        try:
            signed = self._codec.sign(kind, document, selected_signer)
        except SignedDocumentSigningError as error:
            raise DocumentMappingError(
                f"{kind.value} document cannot be signed: {error}"
            ) from error
        value = json.loads(signed.canonical_document_bytes)
        if not isinstance(value, dict):
            raise DocumentMappingError(f"{kind.value} signed document is not an object")
        return value

    def _validated(
        self,
        schema_name: str,
        document: ProtocolDocument,
    ) -> ProtocolDocument:
        try:
            self._schemas.validate(schema_name, document)
        except JSONSchemaValidationError as error:
            path = "/".join(str(item) for item in error.absolute_path)
            raise DocumentMappingError(
                f"{schema_name} rejected mapped projection at {path or '<root>'}: {error.message}"
            ) from error
        return document

    def _signer_for(self, principal_id: str) -> DocumentSigner:
        try:
            return self._signers[principal_id]
        except KeyError as error:
            raise DocumentMappingError(
                f"no document signer configured for principal {principal_id}"
            ) from error

    @staticmethod
    def _timestamp(value: datetime) -> str:
        if value.tzinfo is None or value.utcoffset() is None:
            raise DocumentMappingError("normative timestamps must be timezone-aware")
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")

    @staticmethod
    def _id(value: str, namespace: str) -> str:
        if _ABSOLUTE_ID.fullmatch(value):
            return value
        fingerprint = canonical_hash(value).removeprefix("sha256:")
        return f"urn:missionweaveprotocol:{namespace}:{fingerprint}"

    def _actor(self, principal: Principal) -> ProtocolDocument:
        actor_type = "service" if principal.type is ActorType.SYSTEM else principal.type.value
        namespace = "service" if principal.type is ActorType.SYSTEM else principal.type.value
        return {"type": actor_type, "id": self._id(principal.id, namespace)}

    def _owner_actor(self, owner: str) -> ProtocolDocument:
        if owner.startswith("human:") or owner.startswith("urn:missionweaveprotocol:human:"):
            return {"type": "human", "id": self._id(owner, "human")}
        if owner.startswith("agent:") or owner.startswith("urn:missionweaveprotocol:agent:"):
            return {"type": "agent", "id": self._id(owner, "agent")}
        return {"type": "service", "id": self._id(owner, "service")}

    @staticmethod
    def _same_group(actual: str, expected: str, name: str) -> None:
        if actual != expected:
            raise DocumentMappingError(f"{name} and Mission Group IDs do not match")

    @staticmethod
    def _version(version: int) -> str:
        return f"{version}.0.0"

    @staticmethod
    def _capability_id(identifier: str) -> str:
        if re.fullmatch(r"^[a-z0-9]+(?:[.-][a-z0-9]+)+$", identifier):
            return identifier
        normalized = re.sub(r"[^a-z0-9]+", "-", identifier.lower()).strip("-") or "capability"
        return f"missionweaveprotocol.{normalized}"

    def _capability_requirement(
        self,
        requirement: CapabilityRequirement,
    ) -> ProtocolDocument:
        return {
            "id": self._capability_id(requirement.id),
            "version": self._version(requirement.minimum_version),
        }

    @staticmethod
    def _criteria(values: Sequence[str]) -> list[ProtocolDocument]:
        return [
            {
                "criterionId": f"criterion-{index}",
                "description": description,
                "evidenceRequired": ["business_rule"],
            }
            for index, description in enumerate(values, start=1)
        ]

    @staticmethod
    def _budget(
        budget: ResourceBudget,
        *,
        fallback_wall_seconds: int | None,
    ) -> ProtocolDocument:
        document: ProtocolDocument = {}
        if budget.financial_microunits is not None:
            document["currency"] = "USD"
            document["financialLimit"] = budget.financial_microunits / 1_000_000
        mappings = {
            "model_tokens": "modelTokenLimit",
            "tool_calls": "toolCallLimit",
            "compute_seconds": "computeSecondsLimit",
            "wall_clock_seconds": "wallClockSecondsLimit",
            "external_actions": "externalSideEffectLimit",
        }
        for source, target in mappings.items():
            value = getattr(budget, source)
            if value is not None:
                document[target] = value
        if not document and fallback_wall_seconds is not None:
            document["wallClockSecondsLimit"] = max(1, fallback_wall_seconds)
        if not document:
            raise DocumentMappingError("normative budget requires at least one resource limit")
        return document

    @staticmethod
    def _retry_policy(policy: RetryPolicy) -> ProtocolDocument:
        if policy.maximum_backoff_seconds == 0:
            backoff = "none"
        elif policy.initial_backoff_seconds == policy.maximum_backoff_seconds:
            backoff = "fixed"
        else:
            backoff = "exponential"
        return {
            "maxAttempts": policy.max_attempts,
            "backoff": backoff,
            "maxDelay": f"PT{policy.maximum_backoff_seconds}S",
            "retryableFailures": [],
        }

    @staticmethod
    def _urgency(priority: int) -> str:
        if priority >= 90:
            return "critical"
        if priority >= 70:
            return "high"
        if priority >= 30:
            return "normal"
        return "routine"

    @staticmethod
    def _side_effect_risk(contract: WorkContract) -> str:
        if contract.budget.external_actions:
            return "external"
        if contract.allowed_tools or contract.allowed_resources:
            return "reversible"
        return "none"

    @staticmethod
    def _execution_approval(contract: WorkContract) -> str:
        if contract.budget.external_actions:
            return "human_required"
        if contract.allowed_tools or contract.allowed_resources:
            return "policy_required"
        return "not_required"

    @staticmethod
    def _mission_state(status: MissionStatus) -> str:
        return status.value

    @staticmethod
    def _work_state(status: WorkItemStatus) -> str:
        return status.value

    @staticmethod
    def _membership_role(role: Role) -> str:
        return {
            Role.MISSION_OWNER: "mission_owner",
            Role.COORDINATOR: "coordinator",
            Role.WORKER: "worker",
            Role.REVIEWER: "reviewer",
            Role.OBSERVER: "observer",
            Role.WORK_DELEGATE: "work_delegate",
        }[role]

    @staticmethod
    def _membership_scopes(role: Role) -> list[str]:
        return {
            Role.MISSION_OWNER: [
                "mission.inspect",
                "mission.direct",
                "mission.approve",
                "mission.cancel",
            ],
            Role.COORDINATOR: [
                "message.post",
                "work.authorize",
                "work.offer",
                "work.verify",
                "mission.submit",
            ],
            Role.WORKER: ["message.post", "work.accept_offer", "work.execute"],
            Role.REVIEWER: ["message.post", "work.accept_offer", "work.review"],
            Role.OBSERVER: ["message.read"],
            Role.WORK_DELEGATE: ["work.propose", "work.delegate"],
        }[role]

    @staticmethod
    def _evidence_type(kind: str) -> str:
        lowered = kind.lower()
        if "artifact" in lowered or "integrity" in lowered:
            return "artifact_integrity"
        if "schema" in lowered:
            return "schema_validation"
        if "test" in lowered:
            return "deterministic_test"
        if "review" in lowered or "verif" in lowered:
            return "reviewer_assessment"
        if "human" in lowered:
            return "human_review"
        if "policy" in lowered:
            return "policy_check"
        if "fail" in lowered:
            return "failure_report"
        return "business_rule"

    @staticmethod
    def _model_version(name: str, version: str) -> ProtocolDocument:
        separator = "/" if "/" in name else ":" if ":" in name else None
        if separator is None:
            provider, model = "reference", name
        else:
            provider, model = name.split(separator, 1)
        return {"provider": provider, "model": model, "version": version}
