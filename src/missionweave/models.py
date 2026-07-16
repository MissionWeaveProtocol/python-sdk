"""Typed domain and wire models for the MissionWeave authoritative core.

The models in this module deliberately contain no transport or persistence behavior.  They are
the stable vocabulary shared by the core Module, Store adapters, and protocol bindings.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    field_validator,
    model_validator,
)


def _to_camel(name: str) -> str:
    head, *tail = name.split("_")
    return head + "".join(part.capitalize() for part in tail)


class ProtocolModel(BaseModel):
    """Base model with one strict, alias-aware protocol representation."""

    model_config = ConfigDict(
        alias_generator=_to_camel,
        extra="forbid",
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_assignment=True,
    )


Identifier = Annotated[str, Field(min_length=1, max_length=512)]
ContentHash = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
SemanticVersion = Annotated[
    str,
    Field(
        pattern=(
            r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
            r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
        ),
        max_length=128,
    ),
]
PositiveSeconds = Annotated[int, Field(gt=0, le=31_536_000)]
NonNegativeInt = Annotated[int, Field(ge=0)]


class ActorType(StrEnum):
    AGENT = "agent"
    HUMAN = "human"
    SYSTEM = "system"


class Role(StrEnum):
    MISSION_OWNER = "mission_owner"
    COORDINATOR = "coordinator"
    WORKER = "worker"
    REVIEWER = "reviewer"
    OBSERVER = "observer"
    WORK_DELEGATE = "work_delegate"


class MembershipStatus(StrEnum):
    PROVISIONAL = "provisional"
    ACTIVE = "active"
    ENDED = "ended"


class MessageAmendmentKind(StrEnum):
    CORRECTION = "correction"
    RETRACTION = "retraction"
    REDACTION = "redaction"


class MissionStatus(StrEnum):
    ACTIVE = "active"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    FAILED = "failed"
    CANCELLED = "cancelled"


class WorkItemStatus(StrEnum):
    OPEN = "open"
    OFFERED = "offered"
    QUEUED = "queued"
    ACTIVE = "active"
    BLOCKED = "blocked"
    SUBMITTED = "submitted"
    VERIFIED = "verified"
    FAILED = "failed"
    CANCELLED = "cancelled"


class WorkProposalStatus(StrEnum):
    OPEN = "open"
    AUTHORIZED = "authorized"
    WITHDRAWN = "withdrawn"


class ChildFailurePolicy(StrEnum):
    BLOCK_PARENT_WORK_ITEM = "block_parent_work_item"
    FAIL_PARENT_WORK_ITEM = "fail_parent_work_item"
    FAIL_PARENT_MISSION = "fail_parent_mission"


class CooperationPolicyName(StrEnum):
    MESSAGE_RATE = "message_rate"
    PROPOSAL_RATE = "proposal_rate"
    DELEGATION_DEPTH = "delegation_depth"
    QUEUED_WORK_ITEMS = "queued_work_items"
    ACTIVE_WORK_ITEMS = "active_work_items"


class CommandKind(StrEnum):
    REGISTER_AGENT_CARD = "ext.missionweave.registry.agent_card_register"
    OPEN_AGENT_SESSION = "ext.missionweave.identity.session_open"
    CREATE_MISSION = "mission.create"
    CREATE_FOLLOW_UP_MISSION = "mission.create_follow_up"
    CREATE_CHILD_MISSION = "mission.create_child"
    ADD_MEMBERSHIP = "membership.change"
    END_MEMBERSHIP = "membership.end"
    GRANT_DELEGATION = "membership.grant_delegation"
    REPLACE_COORDINATOR = "mission.assign_coordinator"
    RENEW_COORDINATOR_LEASE = "mission.renew_coordinator"
    POST_MESSAGE = "message.post"
    CORRECT_MESSAGE = "message.correct"
    RETRACT_MESSAGE = "message.retract"
    REDACT_MESSAGE = "message.redact"
    PROPOSE_WORK_ITEM = "work.propose"
    CREATE_WORK_ITEM = "work.authorize"
    ADD_WORK_ITEM_DEPENDENCY = "ext.missionweave.core.work_dependency_add"
    OFFER_WORK_ITEM = "work.offer"
    ACCEPT_WORK_OFFER = "work.accept_offer"
    START_WORK_ITEM = "work.start"
    RENEW_EXECUTION_LEASE = "ext.missionweave.core.work_execution_lease_renew"
    RECORD_RESOURCE_USAGE = "ext.missionweave.core.resource_usage_record"
    CHECKPOINT_WORK_ITEM = "work.checkpoint"
    BLOCK_WORK_ITEM = "work.block"
    UNBLOCK_WORK_ITEM = "work.unblock"
    PUBLISH_ARTIFACT = "artifact.publish"
    SUBMIT_WORK_ITEM = "work.submit"
    VERIFY_WORK_ITEM = "work.accept_result"
    FAIL_WORK_ITEM = "work.fail"
    CANCEL_WORK_ITEM = "work.cancel"
    SUBMIT_MISSION = "mission.submit_for_approval"
    APPROVE_MISSION = "mission.approve"
    GRANT_EXECUTION_APPROVAL = "approval.grant_execution"
    GRANT_COOPERATION_OVERRIDE = "policy.grant_cooperation_override"
    REQUEST_MISSION_CHANGES = "mission.request_changes"
    FAIL_MISSION = "mission.terminate"
    CANCEL_MISSION = "mission.cancel"
    ARCHIVE_GROUP = "ext.missionweave.core.group_archive"


class EventKind(StrEnum):
    AGENT_CARD_REGISTERED = "ext.missionweave.registry.agent_card_registered"
    AGENT_SESSION_OPENED = "ext.missionweave.identity.session_opened"
    MISSION_CREATED = "mission.created"
    FOLLOW_UP_MISSION_CREATED = "mission.follow_up.created"
    CHILD_MISSION_CREATED = "mission.child.created"
    MISSION_SUBMITTED = "mission.submitted_for_approval"
    MISSION_APPROVED = "mission.approved"
    EXECUTION_APPROVAL_GRANTED = "approval.execution.granted"
    COOPERATION_OVERRIDE_GRANTED = "policy.cooperation_override.granted"
    MISSION_CHANGES_REQUESTED = "mission.changes_requested"
    MISSION_FAILED = "mission.terminated"
    MISSION_CANCELLED = "mission.cancelled"
    MEMBERSHIP_ADDED = "membership.changed"
    MEMBERSHIP_ENDED = "membership.ended"
    DELEGATION_GRANTED = "membership.delegation.granted"
    COORDINATOR_REPLACED = "mission.coordinator.assigned"
    COORDINATOR_LEASE_RENEWED = "mission.coordinator.renewed"
    MESSAGE_POSTED = "message.posted"
    MESSAGE_CORRECTED = "message.corrected"
    MESSAGE_RETRACTED = "message.retracted"
    MESSAGE_REDACTED = "message.redacted"
    WORK_ITEM_PROPOSED = "work.proposed"
    WORK_ITEM_CREATED = "work.authorized"
    WORK_ITEM_DEPENDENCY_ADDED = "work.contract.revised"
    WORK_ITEM_OFFERED = "work.offer.created"
    WORK_OFFER_ACCEPTED = "work.offer.accepted"
    WORK_ITEM_STARTED = "work.started"
    EXECUTION_LEASE_RENEWED = "work.progressed"
    EXECUTION_LEASE_REVOKED = "ext.missionweave.core.work_execution_lease_revoked"
    RESOURCE_USAGE_RECORDED = "ext.missionweave.core.resource_usage_recorded"
    WORK_ITEM_CHECKPOINTED = "work.checkpointed"
    WORK_ITEM_BLOCKED = "work.blocked"
    WORK_ITEM_UNBLOCKED = "work.unblocked"
    ARTIFACT_PUBLISHED = "artifact.published"
    WORK_ITEM_SUBMITTED = "work.submitted"
    WORK_ITEM_VERIFIED = "work.result.accepted"
    WORK_ITEM_FAILED = "work.failed"
    WORK_ITEM_CANCELLED = "work.cancelled"
    GROUP_SNAPSHOT_CREATED = "group.snapshot.created"
    GROUP_ARCHIVED = "group.archived"


class QueryKind(StrEnum):
    COMMAND = "command"
    AGENT_CARD = "agent_card"
    SESSION_EPOCH = "session_epoch"
    MISSION = "mission"
    GROUP = "group"
    MEMBERSHIP = "membership"
    CONVERSATION = "conversation"
    MESSAGE = "message"
    MESSAGE_AMENDMENT = "message_amendment"
    WORK_PROPOSAL = "work_proposal"
    WORK_ITEM = "work_item"
    MISSION_WORK_ITEMS = "mission_work_items"
    ARTIFACT = "artifact"
    APPROVAL = "approval"
    EXECUTION_APPROVAL = "execution_approval"
    COOPERATION_OVERRIDE_GRANT = "cooperation_override_grant"
    POLICY_LOG = "policy_log"
    GROUP_SNAPSHOT = "group_snapshot"
    DELEGATION_GRANT = "delegation_grant"
    EXECUTION_LEASE = "execution_lease"
    BUDGET_REMAINING = "budget_remaining"


class Principal(ProtocolModel):
    model_config = ConfigDict(
        alias_generator=_to_camel,
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )

    type: ActorType
    id: Identifier

    @classmethod
    def agent(cls, agent_id: str) -> Principal:
        return cls(type=ActorType.AGENT, id=agent_id)

    @classmethod
    def human(cls, human_id: str) -> Principal:
        return cls(type=ActorType.HUMAN, id=human_id)

    @classmethod
    def system(cls, system_id: str = "organization") -> Principal:
        return cls(type=ActorType.SYSTEM, id=system_id)


class SignatureEnvelope(ProtocolModel):
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: Identifier
    created_at: AwareDatetime
    value: Identifier


class PolicyLogEntry(ProtocolModel):
    entry_id: Identifier
    decision: Annotated[str, Field(min_length=1, max_length=4000)]
    actor: Principal
    details: dict[str, JsonValue] = Field(default_factory=dict)
    occurred_at: AwareDatetime


def _snapshot_uri(value: str, namespace: str) -> str:
    if ":" in value:
        return value
    try:
        return f"urn:uuid:{UUID(value)}"
    except ValueError:
        return f"urn:missionweave:{namespace}:{value}"


def _snapshot_actor_document(actor: Principal) -> dict[str, str]:
    actor_type = "service" if actor.type is ActorType.SYSTEM else actor.type.value
    return {"type": actor_type, "id": _snapshot_uri(actor.id, "actor")}


class GroupSnapshot(ProtocolModel):
    snapshot_id: Identifier
    group_id: Identifier
    through_sequence: Annotated[int, Field(gt=0)]
    event_ids: Annotated[tuple[Identifier, ...], Field(min_length=1)]
    state_hash: ContentHash
    policy_log: Annotated[tuple[PolicyLogEntry, ...], Field(min_length=1)]
    created_by: Principal
    created_at: AwareDatetime
    signature: SignatureEnvelope

    @field_validator("event_ids")
    @classmethod
    def event_ids_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("Group snapshot Event IDs must be unique")
        return value

    @model_validator(mode="after")
    def event_count_matches_sequence(self) -> GroupSnapshot:
        if len(self.event_ids) != self.through_sequence:
            raise ValueError("Group snapshot Event IDs must cover every sequence from one")
        return self

    @staticmethod
    def protocol_group_id(group_id: str) -> str:
        return _snapshot_uri(group_id, "group")

    @staticmethod
    def protocol_event_id(event_id: str) -> str:
        return _snapshot_uri(event_id, "event")

    def signing_payload(self) -> dict[str, Any]:
        document = self.protocol_document()
        del document["signature"]
        return document

    def protocol_document(self) -> dict[str, Any]:
        document = self.model_dump(mode="json", by_alias=True)
        document["createdBy"] = _snapshot_actor_document(self.created_by)
        policy_log = document["policyLog"]
        if not isinstance(policy_log, list):
            raise TypeError("Group snapshot policy log must serialize as an array")
        for raw, entry in zip(policy_log, self.policy_log, strict=True):
            if not isinstance(raw, dict):
                raise TypeError("Group snapshot policy entry must serialize as an object")
            raw["actor"] = _snapshot_actor_document(entry.actor)
        return document


class Capability(ProtocolModel):
    id: Identifier
    version: Annotated[int, Field(gt=0)]
    input_schema: str | None = None
    output_schema: str | None = None
    constraints: dict[str, JsonValue] = Field(default_factory=dict)
    verified_evidence: tuple[str, ...] = ()


class CapabilityRequirement(ProtocolModel):
    id: Identifier
    minimum_version: Annotated[int, Field(gt=0)] = 1


class AgentCard(ProtocolModel):
    agent_id: Identifier
    version: Annotated[int, Field(gt=0)]
    display_name: Identifier
    owner: Identifier
    public_key: Identifier
    capabilities: tuple[Capability, ...]
    issued_at: AwareDatetime
    signature: Identifier

    @field_validator("capabilities")
    @classmethod
    def capabilities_are_unique(cls, value: tuple[Capability, ...]) -> tuple[Capability, ...]:
        ids = [capability.id for capability in value]
        if len(ids) != len(set(ids)):
            raise ValueError("capability identifiers must be unique")
        return value

    def supports(self, requirements: tuple[CapabilityRequirement, ...]) -> bool:
        available = {capability.id: capability.version for capability in self.capabilities}
        return all(available.get(item.id, 0) >= item.minimum_version for item in requirements)


class PresenceRecord(ProtocolModel):
    agent_id: Identifier
    online: bool
    available_capacity: NonNegativeInt
    available_capabilities: tuple[Identifier, ...] = ()
    estimated_response_seconds: NonNegativeInt | None = None
    last_heartbeat_at: AwareDatetime


class ResourceBudget(ProtocolModel):
    financial_microunits: NonNegativeInt | None = None
    model_tokens: NonNegativeInt | None = None
    tool_calls: NonNegativeInt | None = None
    compute_seconds: NonNegativeInt | None = None
    wall_clock_seconds: NonNegativeInt | None = None
    external_actions: NonNegativeInt | None = None

    def contains(self, child: ResourceBudget) -> bool:
        for field_name in type(self).model_fields:
            parent_limit = getattr(self, field_name)
            child_limit = getattr(child, field_name)
            if child_limit is not None and (parent_limit is None or child_limit > parent_limit):
                return False
        return True


class ResourceUsage(ProtocolModel):
    """A six-dimensional nonnegative resource-usage quantity."""

    financial_microunits: NonNegativeInt = 0
    model_tokens: NonNegativeInt = 0
    tool_calls: NonNegativeInt = 0
    compute_seconds: NonNegativeInt = 0
    wall_clock_seconds: NonNegativeInt = 0
    external_actions: NonNegativeInt = 0


class DelegationBudget(ResourceBudget):
    """A fully bounded Resource Budget with an explicit financial currency."""

    currency: Annotated[str, Field(pattern=r"^[A-Z]{3}$")]


class RetryPolicy(ProtocolModel):
    max_attempts: Annotated[int, Field(ge=1)] = 1
    initial_backoff_seconds: NonNegativeInt = 0
    maximum_backoff_seconds: NonNegativeInt = 0

    @model_validator(mode="after")
    def validate_backoff(self) -> RetryPolicy:
        if self.maximum_backoff_seconds < self.initial_backoff_seconds:
            raise ValueError("maximum_backoff_seconds must be at least initial_backoff_seconds")
        return self


class WorkContract(ProtocolModel):
    goal: Identifier
    deliverables: tuple[Identifier, ...]
    acceptance_criteria: tuple[Identifier, ...]
    inputs: tuple[str, ...] = ()
    allowed_tools: tuple[Identifier, ...] = ()
    allowed_resources: tuple[Identifier, ...] = ()
    deadline: AwareDatetime
    requested_priority: Annotated[int, Field(ge=0, le=100)] = 50
    estimated_duration_seconds: PositiveSeconds | None = None
    required_capabilities: tuple[CapabilityRequirement, ...] = ()
    budget: ResourceBudget = Field(default_factory=ResourceBudget)
    retry_policy: RetryPolicy = Field(default_factory=RetryPolicy)
    exclusive: bool = True
    side_effect_risk: Literal["none", "reversible", "external", "high_risk", "destructive"] = "none"
    execution_approval: Literal["not_required", "policy_required", "human_required"] = (
        "not_required"
    )

    @field_validator("deliverables", "acceptance_criteria")
    @classmethod
    def contract_sections_are_not_empty(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("a Work Contract requires deliverables and acceptance criteria")
        return value

    @field_validator("required_capabilities")
    @classmethod
    def requirements_are_unique(
        cls, value: tuple[CapabilityRequirement, ...]
    ) -> tuple[CapabilityRequirement, ...]:
        ids = [requirement.id for requirement in value]
        if len(ids) != len(set(ids)):
            raise ValueError("required capability identifiers must be unique")
        return value

    @model_validator(mode="after")
    def high_risk_requires_execution_approval(self) -> WorkContract:
        if (
            self.side_effect_risk in {"high_risk", "destructive"}
            and self.execution_approval != "human_required"
        ):
            raise ValueError("high-risk side effects require human Execution Approval")
        return self


class SelectionBasis(ProtocolModel):
    required_capabilities: tuple[CapabilityRequirement, ...] = ()
    verified_capability_matches: tuple[Identifier, ...] = ()
    authorization_eligible: bool = True
    availability_estimate: str | None = None
    expected_cost_microunits: NonNegativeInt | None = None
    reliability_evidence: tuple[str, ...] = ()
    policy_rules_applied: tuple[str, ...] = ()


class Evidence(ProtocolModel):
    kind: Identifier
    description: Identifier
    success: bool = True
    artifact_hash: str | None = None
    data: dict[str, JsonValue] = Field(default_factory=dict)


class Checkpoint(ProtocolModel):
    phase: Identifier
    completed_milestones: tuple[str, ...] = ()
    next_step: str | None = None
    state_artifact_hash: str | None = None
    created_at: AwareDatetime


class Mission(ProtocolModel):
    id: Identifier
    group_id: Identifier
    title: Identifier
    objective: Identifier
    definition_of_done: tuple[Identifier, ...]
    owner: Principal
    coordinator_id: Identifier
    coordinator_epoch: Annotated[int, Field(gt=0)]
    coordinator_lease_expires_at: AwareDatetime
    budget: ResourceBudget
    deadline: AwareDatetime
    permissions: tuple[Identifier, ...] = ()
    status: MissionStatus = MissionStatus.ACTIVE
    revision: Annotated[int, Field(gt=0)] = 1
    parent_mission_id: Identifier | None = None
    parent_work_item_id: Identifier | None = None
    follow_up_of_mission_id: Identifier | None = None
    child_failure_policy: ChildFailurePolicy = ChildFailurePolicy.BLOCK_PARENT_WORK_ITEM
    submitted_revision: int | None = None
    submitted_artifact_hashes: tuple[str, ...] = ()
    approved_artifact_hashes: tuple[str, ...] = ()
    failure_reason: str | None = None
    created_at: AwareDatetime
    updated_at: AwareDatetime

    @field_validator("definition_of_done")
    @classmethod
    def definition_is_not_empty(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("a Mission requires a definition of done")
        return value


class Group(ProtocolModel):
    id: Identifier
    mission_id: Identifier
    main_conversation_id: Identifier
    created_at: AwareDatetime
    archived_at: AwareDatetime | None = None
    archive_snapshot_id: Identifier | None = None

    @model_validator(mode="after")
    def archive_link_is_complete(self) -> Group:
        if (self.archived_at is None) != (self.archive_snapshot_id is None):
            raise ValueError("archived Group requires both archived_at and archive_snapshot_id")
        return self


class Membership(ProtocolModel):
    group_id: Identifier
    principal: Principal
    roles: tuple[Role, ...]
    status: MembershipStatus
    epoch: Annotated[int, Field(gt=0)] = 1
    visibility_after_sequence: NonNegativeInt = 0
    joined_at: AwareDatetime
    ended_at: AwareDatetime | None = None

    @field_validator("roles")
    @classmethod
    def roles_are_nonempty_and_unique(cls, value: tuple[Role, ...]) -> tuple[Role, ...]:
        if not value:
            raise ValueError("membership requires at least one role")
        if len(value) != len(set(value)):
            raise ValueError("membership roles must be unique")
        return tuple(sorted(value, key=lambda role: role.value))


class DelegationGrant(ProtocolModel):
    id: Identifier
    grantee_agent_id: Identifier
    mission_id: Identifier
    group_id: Identifier
    target_work_item_id: Identifier
    allowed_capabilities: tuple[CapabilityRequirement, ...]
    budget: DelegationBudget
    max_descendant_depth: NonNegativeInt
    grantee_membership_epoch: Annotated[int, Field(gt=0)]
    coordinator_epoch: Annotated[int, Field(gt=0)]
    granted_by: Principal
    granted_at: AwareDatetime
    expires_at: AwareDatetime

    @model_validator(mode="after")
    def validate_grant(self) -> DelegationGrant:
        if self.granted_by.type is not ActorType.AGENT:
            raise ValueError("Delegation Grant issuer must be an Agent")
        if not self.allowed_capabilities:
            raise ValueError("Delegation Grant requires at least one allowed capability")
        capability_ids = [item.id for item in self.allowed_capabilities]
        if len(capability_ids) != len(set(capability_ids)):
            raise ValueError("Delegation Grant capability identifiers must be unique")
        missing_budget = [
            field_name
            for field_name in ResourceBudget.model_fields
            if getattr(self.budget, field_name) is None
        ]
        if missing_budget:
            raise ValueError(
                "Delegation Grant requires all six budget ceilings: " + ", ".join(missing_budget)
            )
        if self.expires_at <= self.granted_at:
            raise ValueError("Delegation Grant expiry must follow its grant time")
        return self


class CooperationOverrideGrant(ProtocolModel):
    id: Identifier
    mission_id: Identifier
    group_id: Identifier
    policy_name: CooperationPolicyName
    beneficiary: Principal
    target_command_kind: CommandKind
    target_action_id: Identifier
    approver: Principal
    reason: Identifier
    granted_at: AwareDatetime
    expires_at: AwareDatetime
    signature: Identifier
    consumed_at: AwareDatetime | None = None
    consumed_event_id: Identifier | None = None

    @model_validator(mode="after")
    def validate_lifetime(self) -> CooperationOverrideGrant:
        if self.expires_at <= self.granted_at:
            raise ValueError("Cooperation Override Grant expiry must follow its grant time")
        if (self.consumed_at is None) != (self.consumed_event_id is None):
            raise ValueError(
                "Cooperation Override Grant consumption requires both time and Event ID"
            )
        if self.consumed_at is not None and self.consumed_at < self.granted_at:
            raise ValueError("Cooperation Override Grant cannot be consumed before it is granted")
        return self


class Conversation(ProtocolModel):
    id: Identifier
    group_id: Identifier
    work_item_id: Identifier | None = None
    title: Identifier
    created_at: AwareDatetime


class Message(ProtocolModel):
    id: Identifier
    group_id: Identifier
    conversation_id: Identifier
    author: Principal
    content: Identifier
    mentions: tuple[Principal, ...] = ()
    created_at: AwareDatetime


class MessageAmendment(ProtocolModel):
    id: Identifier
    group_id: Identifier
    message_id: Identifier
    kind: MessageAmendmentKind
    actor: Principal
    replacement_content: str | None = None
    reason: Identifier
    created_at: AwareDatetime


class WorkProposal(ProtocolModel):
    id: Identifier
    mission_id: Identifier
    group_id: Identifier
    proposed_by: Principal
    contract: WorkContract
    dependency_ids: tuple[Identifier, ...] = ()
    parent_work_item_id: Identifier | None = None
    status: WorkProposalStatus = WorkProposalStatus.OPEN
    authorized_work_item_id: Identifier | None = None
    created_at: AwareDatetime
    updated_at: AwareDatetime


class WorkItem(ProtocolModel):
    id: Identifier
    mission_id: Identifier
    group_id: Identifier
    conversation_id: Identifier
    created_by: Principal
    contract: WorkContract
    status: WorkItemStatus
    revision: Annotated[int, Field(gt=0)] = 1
    dependency_ids: tuple[Identifier, ...] = ()
    offered_agent_ids: tuple[Identifier, ...] = ()
    offer_expires_at: AwareDatetime | None = None
    assignee_id: Identifier | None = None
    assigned_agent_card_version: int | None = None
    assigned_capability_versions: dict[str, int] = Field(default_factory=dict)
    selection_basis: SelectionBasis | None = None
    ownership_epoch: NonNegativeInt = 0
    ownership_lease_expires_at: AwareDatetime | None = None
    execution_lease_id: Identifier | None = None
    execution_lease_expires_at: AwareDatetime | None = None
    checkpoints: tuple[Checkpoint, ...] = ()
    blocker: str | None = None
    artifact_ids: tuple[Identifier, ...] = ()
    submission_evidence: tuple[Evidence, ...] = ()
    verification_evidence: tuple[Evidence, ...] = ()
    child_mission_id: Identifier | None = None
    parent_work_item_id: Identifier | None = None
    delegation_grant_id: Identifier | None = None
    delegation_depth: NonNegativeInt = 0
    failure_reason: str | None = None
    created_at: AwareDatetime
    updated_at: AwareDatetime


class Artifact(ProtocolModel):
    id: Identifier
    content_hash: ContentHash
    media_type: Identifier
    schema_uri: str | None = None
    producing_agent_id: Identifier
    agent_card_version: Annotated[int, Field(gt=0)]
    mission_id: Identifier
    group_id: Identifier
    work_item_id: Identifier
    source_artifact_hashes: tuple[ContentHash, ...] = ()
    tool_versions: dict[str, str] = Field(default_factory=dict)
    model_versions: dict[str, str] = Field(default_factory=dict)
    created_at: AwareDatetime
    data_classification: Literal["public", "internal", "confidential", "restricted"]
    signature: Identifier

    @field_validator("source_artifact_hashes")
    @classmethod
    def source_hashes_are_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(value) != len(set(value)):
            raise ValueError("Artifact source hashes must be unique")
        return value

    @model_validator(mode="after")
    def artifact_does_not_source_itself(self) -> Artifact:
        if self.content_hash in self.source_artifact_hashes:
            raise ValueError("Artifact cannot cite its own content hash as provenance")
        return self

    def signing_payload(self) -> dict[str, Any]:
        """Canonical authoritative manifest fields covered by the producer signature."""

        return self.model_dump(mode="json", by_alias=True, exclude={"signature"})


class Approval(ProtocolModel):
    id: Identifier
    mission_id: Identifier
    mission_revision: Annotated[int, Field(gt=0)]
    artifact_hashes: tuple[str, ...]
    acceptance_policy_version: Identifier
    approver: Principal
    approved_at: AwareDatetime
    comments: str | None = None
    signature: Identifier


class ExecutionApproval(ProtocolModel):
    id: Identifier
    mission_id: Identifier
    group_id: Identifier
    work_item_id: Identifier
    ownership_epoch: Annotated[int, Field(gt=0)]
    operations: tuple[Identifier, ...]
    resources: tuple[Identifier, ...] = ()
    budget: ResourceBudget = Field(default_factory=ResourceBudget)
    approver: Principal
    approved_at: AwareDatetime
    expires_at: AwareDatetime
    comments: str | None = None
    signature: Identifier


class ExtensionEnvelope(ProtocolModel):
    model_config = ConfigDict(str_strip_whitespace=False)

    version: SemanticVersion
    critical: bool
    data: JsonValue


class Command(ProtocolModel):
    protocol_version: Literal["0.1"] = "0.1"
    action_id: Identifier
    kind: CommandKind
    actor: Principal
    group_id: Identifier | None = None
    session_epoch: Annotated[int, Field(gt=0)] | None = None
    membership_epoch: Annotated[int, Field(gt=0)] | None = None
    coordinator_epoch: Annotated[int, Field(gt=0)] | None = None
    cooperation_override_grant_id: Identifier | None = None
    expected_revision: Annotated[int, Field(gt=0)] | None = None
    issued_at: AwareDatetime
    payload: dict[str, JsonValue] = Field(default_factory=dict)
    extensions: dict[str, ExtensionEnvelope] = Field(default_factory=dict)
    signature: str | None = None

    @field_validator("payload", mode="before")
    @classmethod
    def serialize_payload_model(cls, value: Any) -> Any:
        if isinstance(value, BaseModel):
            return value.model_dump(mode="json", by_alias=True)
        return value

    def signing_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="python", by_alias=True, exclude={"signature"})


class Event(ProtocolModel):
    model_config = ConfigDict(
        alias_generator=_to_camel,
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        str_strip_whitespace=True,
    )

    protocol_version: Literal["0.1"] = "0.1"
    id: Identifier
    kind: EventKind
    group_id: Identifier | None = None
    sequence: Annotated[int, Field(gt=0)] | None = None
    actor: Principal
    action_id: Identifier
    command_hash: Identifier
    payload: dict[str, JsonValue]
    extensions: dict[str, ExtensionEnvelope] = Field(default_factory=dict)
    occurred_at: AwareDatetime


class Query(ProtocolModel):
    kind: QueryKind
    entity_id: Identifier
    group_id: Identifier | None = None
    actor_type: ActorType | None = None


class RegisterAgentCardPayload(ProtocolModel):
    card: AgentCard


class OpenAgentSessionPayload(ProtocolModel):
    agent_id: Identifier


class CreateMissionPayload(ProtocolModel):
    mission_id: Identifier
    group_id: Identifier
    coordinator_id: Identifier
    title: Identifier
    objective: Identifier
    definition_of_done: tuple[Identifier, ...]
    budget: ResourceBudget = Field(default_factory=ResourceBudget)
    deadline: AwareDatetime
    permissions: tuple[Identifier, ...] = ()
    coordinator_lease_seconds: PositiveSeconds = 300
    follow_up_of_mission_id: Identifier | None = None


class CreateChildMissionPayload(ProtocolModel):
    mission_id: Identifier
    group_id: Identifier
    parent_work_item_id: Identifier
    coordinator_id: Identifier
    title: Identifier
    objective: Identifier
    definition_of_done: tuple[Identifier, ...]
    budget: ResourceBudget = Field(default_factory=ResourceBudget)
    deadline: AwareDatetime
    permissions: tuple[Identifier, ...] = ()
    failure_policy: ChildFailurePolicy = ChildFailurePolicy.BLOCK_PARENT_WORK_ITEM
    coordinator_lease_seconds: PositiveSeconds = 300


class AddMembershipPayload(ProtocolModel):
    principal: Principal
    roles: tuple[Role, ...]
    provisional: bool = False
    visibility_after_sequence: NonNegativeInt | None = None


class EndMembershipPayload(ProtocolModel):
    principal: Principal


class ReplaceCoordinatorPayload(ProtocolModel):
    coordinator_id: Identifier
    lease_seconds: PositiveSeconds = 300


class RenewCoordinatorLeasePayload(ProtocolModel):
    lease_seconds: PositiveSeconds = 300


class PostMessagePayload(ProtocolModel):
    message_id: Identifier
    conversation_id: Identifier
    content: Identifier
    mentions: tuple[Principal, ...] = ()


class CorrectMessagePayload(ProtocolModel):
    amendment_id: Identifier
    message_id: Identifier
    replacement_content: Identifier
    reason: Identifier


class RetractMessagePayload(ProtocolModel):
    amendment_id: Identifier
    message_id: Identifier
    reason: Identifier


class RedactMessagePayload(ProtocolModel):
    amendment_id: Identifier
    message_id: Identifier
    reason: Identifier


class ProposeWorkItemPayload(ProtocolModel):
    proposal_id: Identifier
    contract: WorkContract
    dependency_ids: tuple[Identifier, ...] = ()
    parent_work_item_id: Identifier | None = None


class CreateWorkItemPayload(ProtocolModel):
    work_item_id: Identifier
    contract: WorkContract
    dependency_ids: tuple[Identifier, ...] = ()
    proposal_id: Identifier | None = None
    parent_work_item_id: Identifier | None = None
    delegation_grant_id: Identifier | None = None


class AddWorkItemDependencyPayload(ProtocolModel):
    work_item_id: Identifier
    dependency_id: Identifier


class OfferWorkItemPayload(ProtocolModel):
    work_item_id: Identifier
    candidate_agent_ids: tuple[Identifier, ...]
    selection_basis: SelectionBasis
    offer_expires_in_seconds: PositiveSeconds = 300
    delegation_grant_id: Identifier | None = None

    @field_validator("candidate_agent_ids")
    @classmethod
    def candidates_are_nonempty_and_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("at least one candidate is required")
        if len(value) != len(set(value)):
            raise ValueError("candidate Agent identifiers must be unique")
        return value


class AcceptWorkOfferPayload(ProtocolModel):
    work_item_id: Identifier
    ownership_lease_seconds: PositiveSeconds = 900


class StartWorkItemPayload(ProtocolModel):
    work_item_id: Identifier
    ownership_epoch: Annotated[int, Field(gt=0)]
    execution_lease_seconds: PositiveSeconds = 300


class RenewExecutionLeasePayload(ProtocolModel):
    work_item_id: Identifier
    ownership_epoch: Annotated[int, Field(gt=0)]
    execution_lease_id: Identifier
    lease_seconds: PositiveSeconds = 300


class RecordResourceUsagePayload(ProtocolModel):
    work_item_id: Identifier
    ownership_epoch: Annotated[int, Field(gt=0)]
    execution_lease_id: Identifier
    usage_delta: ResourceUsage

    @model_validator(mode="after")
    def delta_is_not_empty(self) -> RecordResourceUsagePayload:
        if not any(
            getattr(self.usage_delta, field_name)
            for field_name in type(self.usage_delta).model_fields
        ):
            raise ValueError("resource usage delta must consume at least one dimension")
        return self


class CheckpointWorkItemPayload(ProtocolModel):
    work_item_id: Identifier
    ownership_epoch: Annotated[int, Field(gt=0)]
    execution_lease_id: Identifier
    checkpoint: Checkpoint
    resume_within_seconds: PositiveSeconds = 900


class BlockWorkItemPayload(ProtocolModel):
    work_item_id: Identifier
    ownership_epoch: Annotated[int, Field(gt=0)]
    execution_lease_id: Identifier
    reason: Identifier
    checkpoint: Checkpoint
    blocked_lease_seconds: PositiveSeconds = 900


class UnblockWorkItemPayload(ProtocolModel):
    work_item_id: Identifier


class PublishArtifactPayload(ProtocolModel):
    artifact: Artifact
    ownership_epoch: Annotated[int, Field(gt=0)]
    execution_lease_id: Identifier


class SubmitWorkItemPayload(ProtocolModel):
    work_item_id: Identifier
    ownership_epoch: Annotated[int, Field(gt=0)]
    execution_lease_id: Identifier
    artifact_ids: tuple[Identifier, ...]
    evidence: tuple[Evidence, ...]

    @field_validator("artifact_ids", "evidence")
    @classmethod
    def submission_is_not_empty(cls, value: tuple[Any, ...]) -> tuple[Any, ...]:
        if not value:
            raise ValueError("submission requires Artifacts and Evidence")
        return value


class VerifyWorkItemPayload(ProtocolModel):
    work_item_id: Identifier
    evidence: tuple[Evidence, ...]

    @field_validator("evidence")
    @classmethod
    def evidence_is_not_empty(cls, value: tuple[Evidence, ...]) -> tuple[Evidence, ...]:
        if not value:
            raise ValueError("verification requires Evidence")
        return value


class FailWorkItemPayload(ProtocolModel):
    work_item_id: Identifier
    reason: Identifier
    ownership_epoch: Annotated[int, Field(gt=0)] | None = None
    execution_lease_id: Identifier | None = None

    @model_validator(mode="after")
    def execution_scope_is_paired(self) -> FailWorkItemPayload:
        if (self.ownership_epoch is None) != (self.execution_lease_id is None):
            raise ValueError("Worker failure requires both ownership epoch and Execution Lease ID")
        return self


class CancelWorkItemPayload(ProtocolModel):
    work_item_id: Identifier
    reason: Identifier


class SubmitMissionPayload(ProtocolModel):
    artifact_hashes: tuple[str, ...]

    @field_validator("artifact_hashes")
    @classmethod
    def artifacts_are_not_empty(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("Mission submission requires at least one Artifact")
        return value


class ApproveMissionPayload(ProtocolModel):
    approval_id: Identifier
    mission_revision: Annotated[int, Field(gt=0)]
    artifact_hashes: tuple[str, ...]
    acceptance_policy_version: Identifier
    comments: str | None = None


class GrantExecutionApprovalPayload(ProtocolModel):
    approval_id: Identifier
    work_item_id: Identifier
    ownership_epoch: Annotated[int, Field(gt=0)]
    operations: tuple[Identifier, ...]
    resources: tuple[Identifier, ...] = ()
    budget: ResourceBudget = Field(default_factory=ResourceBudget)
    expires_in_seconds: PositiveSeconds = 300
    comments: str | None = None

    @field_validator("operations")
    @classmethod
    def operations_are_nonempty_and_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("Execution Approval operations must be nonempty and unique")
        return value


class GrantCooperationOverridePayload(ProtocolModel):
    grant_id: Identifier
    policy_name: CooperationPolicyName
    beneficiary: Principal
    target_command_kind: CommandKind
    target_action_id: Identifier
    reason: Identifier
    expires_at: AwareDatetime


class GrantDelegationPayload(ProtocolModel):
    grant_id: Identifier
    grantee_agent_id: Identifier
    target_work_item_id: Identifier
    allowed_capabilities: tuple[CapabilityRequirement, ...]
    budget: DelegationBudget
    max_descendant_depth: NonNegativeInt
    expires_at: AwareDatetime

    @field_validator("allowed_capabilities")
    @classmethod
    def capabilities_are_nonempty_and_unique(
        cls,
        value: tuple[CapabilityRequirement, ...],
    ) -> tuple[CapabilityRequirement, ...]:
        identifiers = [item.id for item in value]
        if not identifiers or len(identifiers) != len(set(identifiers)):
            raise ValueError("allowed capabilities must be nonempty and unique")
        return value

    @model_validator(mode="after")
    def budget_has_all_six_ceilings(self) -> GrantDelegationPayload:
        missing = [
            field_name
            for field_name in ResourceBudget.model_fields
            if getattr(self.budget, field_name) is None
        ]
        if missing:
            raise ValueError(
                "Delegation Grant requires all six budget ceilings: " + ", ".join(missing)
            )
        return self


class RequestMissionChangesPayload(ProtocolModel):
    mission_revision: Annotated[int, Field(gt=0)]
    feedback: Identifier


class FailMissionPayload(ProtocolModel):
    reason: Identifier


class CancelMissionPayload(ProtocolModel):
    reason: Identifier


class ArchiveGroupPayload(ProtocolModel):
    snapshot: GroupSnapshot


type CommandPayload = (
    RegisterAgentCardPayload
    | OpenAgentSessionPayload
    | CreateMissionPayload
    | CreateChildMissionPayload
    | AddMembershipPayload
    | EndMembershipPayload
    | GrantDelegationPayload
    | ReplaceCoordinatorPayload
    | RenewCoordinatorLeasePayload
    | PostMessagePayload
    | CorrectMessagePayload
    | RetractMessagePayload
    | RedactMessagePayload
    | ProposeWorkItemPayload
    | CreateWorkItemPayload
    | AddWorkItemDependencyPayload
    | OfferWorkItemPayload
    | AcceptWorkOfferPayload
    | StartWorkItemPayload
    | RenewExecutionLeasePayload
    | RecordResourceUsagePayload
    | CheckpointWorkItemPayload
    | BlockWorkItemPayload
    | UnblockWorkItemPayload
    | PublishArtifactPayload
    | SubmitWorkItemPayload
    | VerifyWorkItemPayload
    | FailWorkItemPayload
    | CancelWorkItemPayload
    | SubmitMissionPayload
    | ApproveMissionPayload
    | GrantExecutionApprovalPayload
    | GrantCooperationOverridePayload
    | RequestMissionChangesPayload
    | FailMissionPayload
    | CancelMissionPayload
    | ArchiveGroupPayload
)


type QueryResult = (
    Command
    | AgentCard
    | Mission
    | Group
    | Membership
    | Conversation
    | Message
    | MessageAmendment
    | WorkProposal
    | WorkItem
    | Artifact
    | Approval
    | ExecutionApproval
    | CooperationOverrideGrant
    | PolicyLogEntry
    | GroupSnapshot
    | DelegationGrant
    | ResourceBudget
    | tuple[WorkItem, ...]
    | tuple[PolicyLogEntry, ...]
    | int
    | None
)
