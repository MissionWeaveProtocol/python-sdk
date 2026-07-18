"""Authoritative MissionWeaveProtocol state-transition Module.

Callers need to learn only three operations: ``perform`` a Command, ``query`` current state, and
``replay`` a Group history.  Authorization, idempotency, state machines, leases, dependency
validation, parent/child propagation, and Event ordering remain inside this implementation.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Never, cast
from uuid import uuid4

from jsonschema import ValidationError as JSONSchemaValidationError
from pydantic import ValidationError as PydanticValidationError

from .budget import BudgetLedger, BudgetLedgerError
from .canonical import canonical_hash, canonical_json
from .conformance import SchemaCatalog
from .crypto import PublicKeyLike, verify_canonical
from .delegation import (
    DelegationAuthority,
    DelegationViolation,
    DelegationViolationKind,
    budget_within_ceiling,
)
from .ingress import CommandIngress
from .lease import ExecutionLease, LeaseState
from .models import (
    AcceptWorkOfferPayload,
    ActorType,
    AddMembershipPayload,
    AddWorkItemDependencyPayload,
    AgentCard,
    Approval,
    ApproveMissionPayload,
    ArchiveGroupPayload,
    BlockWorkItemPayload,
    CancelMissionPayload,
    CancelWorkItemPayload,
    CheckpointWorkItemPayload,
    ChildFailurePolicy,
    Command,
    CommandKind,
    CommandPayload,
    Conversation,
    CooperationOverrideGrant,
    CooperationPolicyName,
    CorrectMessagePayload,
    CreateChildMissionPayload,
    CreateMissionPayload,
    CreateWorkItemPayload,
    DelegationGrant,
    EndMembershipPayload,
    Event,
    EventKind,
    ExecutionApproval,
    FailMissionPayload,
    FailWorkItemPayload,
    GrantCooperationOverridePayload,
    GrantDelegationPayload,
    GrantExecutionApprovalPayload,
    Group,
    GroupSnapshot,
    Membership,
    MembershipStatus,
    Message,
    MessageAmendment,
    MessageAmendmentKind,
    Mission,
    MissionStatus,
    OfferWorkItemPayload,
    OpenAgentSessionPayload,
    PolicyLogEntry,
    PostMessagePayload,
    Principal,
    ProposeWorkItemPayload,
    ProtocolModel,
    PublishArtifactPayload,
    Query,
    QueryKind,
    QueryResult,
    RecordResourceUsagePayload,
    RedactMessagePayload,
    RegisterAgentCardPayload,
    RenewCoordinatorLeasePayload,
    RenewExecutionLeasePayload,
    ReplaceCoordinatorPayload,
    RequestMissionChangesPayload,
    RetractMessagePayload,
    Role,
    SignatureEnvelope,
    StartWorkItemPayload,
    SubmitMissionPayload,
    SubmitWorkItemPayload,
    UnblockWorkItemPayload,
    VerifyWorkItemPayload,
    WorkItem,
    WorkItemStatus,
    WorkProposal,
    WorkProposalStatus,
)
from .offline import (
    OFFLINE_EXECUTION_EXTENSION,
    OFFLINE_EXECUTION_EXTENSION_VERSION,
    OfflineProgressBinding,
)
from .policy import CooperationLimits
from .store import (
    AuthoritativeState,
    AuthoritativeStore,
    DedupRecord,
    deduplication_key,
    membership_key,
)


class ErrorCode(StrEnum):
    INVALID_COMMAND = "invalid_command"
    NOT_FOUND = "not_found"
    ALREADY_EXISTS = "already_exists"
    AUTHORIZATION_DENIED = "authorization_denied"
    ACTION_ID_COLLISION = "action_id_collision"
    STALE_SESSION_EPOCH = "stale_session_epoch"
    STALE_MEMBERSHIP_EPOCH = "stale_membership_epoch"
    STALE_COORDINATOR_EPOCH = "stale_coordinator_epoch"
    STALE_OWNERSHIP_EPOCH = "stale_ownership_epoch"
    LEASE_EXPIRED = "lease_expired"
    INVALID_TRANSITION = "invalid_transition"
    REVISION_CONFLICT = "revision_conflict"
    DEPENDENCY_ERROR = "dependency_error"
    POLICY_VIOLATION = "policy_violation"
    BUDGET_EXCEEDED = "budget_exceeded"


class MissionWeaveProtocolError(Exception):
    """Base error with stable protocol code and structured details."""

    code = ErrorCode.INVALID_COMMAND

    def __init__(self, message: str, **details: Any) -> None:
        super().__init__(message)
        self.message = message
        self.details = details

    def as_dict(self) -> dict[str, Any]:
        return {"code": self.code.value, "message": self.message, "details": self.details}


class InvalidCommand(MissionWeaveProtocolError):
    code = ErrorCode.INVALID_COMMAND


class NotFound(MissionWeaveProtocolError):
    code = ErrorCode.NOT_FOUND


class AlreadyExists(MissionWeaveProtocolError):
    code = ErrorCode.ALREADY_EXISTS


class AuthorizationDenied(MissionWeaveProtocolError):
    code = ErrorCode.AUTHORIZATION_DENIED


class ActionIdCollision(MissionWeaveProtocolError):
    code = ErrorCode.ACTION_ID_COLLISION


class StaleSessionEpoch(MissionWeaveProtocolError):
    code = ErrorCode.STALE_SESSION_EPOCH


class StaleMembershipEpoch(MissionWeaveProtocolError):
    code = ErrorCode.STALE_MEMBERSHIP_EPOCH


class StaleCoordinatorEpoch(MissionWeaveProtocolError):
    code = ErrorCode.STALE_COORDINATOR_EPOCH


class StaleOwnershipEpoch(MissionWeaveProtocolError):
    code = ErrorCode.STALE_OWNERSHIP_EPOCH


class LeaseExpired(MissionWeaveProtocolError):
    code = ErrorCode.LEASE_EXPIRED


class InvalidTransition(MissionWeaveProtocolError):
    code = ErrorCode.INVALID_TRANSITION


class RevisionConflict(MissionWeaveProtocolError):
    code = ErrorCode.REVISION_CONFLICT


class DependencyError(MissionWeaveProtocolError):
    code = ErrorCode.DEPENDENCY_ERROR


class PolicyViolation(MissionWeaveProtocolError):
    code = ErrorCode.POLICY_VIOLATION


class BudgetExceeded(MissionWeaveProtocolError):
    code = ErrorCode.BUDGET_EXCEEDED


Clock = Callable[[], datetime]


_COOPERATION_POLICY_TARGETS: dict[CooperationPolicyName, frozenset[CommandKind]] = {
    CooperationPolicyName.MESSAGE_RATE: frozenset({CommandKind.POST_MESSAGE}),
    CooperationPolicyName.PROPOSAL_RATE: frozenset({CommandKind.PROPOSE_WORK_ITEM}),
    CooperationPolicyName.DELEGATION_DEPTH: frozenset(
        {
            CommandKind.CREATE_CHILD_MISSION,
            CommandKind.CREATE_WORK_ITEM,
            CommandKind.GRANT_DELEGATION,
        }
    ),
    CooperationPolicyName.QUEUED_WORK_ITEMS: frozenset({CommandKind.ACCEPT_WORK_OFFER}),
    CooperationPolicyName.ACTIVE_WORK_ITEMS: frozenset(
        {CommandKind.ACCEPT_WORK_OFFER, CommandKind.START_WORK_ITEM}
    ),
}


_PAYLOAD_TYPES: dict[CommandKind, type[ProtocolModel]] = {
    CommandKind.REGISTER_AGENT_CARD: RegisterAgentCardPayload,
    CommandKind.OPEN_AGENT_SESSION: OpenAgentSessionPayload,
    CommandKind.CREATE_MISSION: CreateMissionPayload,
    CommandKind.CREATE_FOLLOW_UP_MISSION: CreateMissionPayload,
    CommandKind.CREATE_CHILD_MISSION: CreateChildMissionPayload,
    CommandKind.ADD_MEMBERSHIP: AddMembershipPayload,
    CommandKind.END_MEMBERSHIP: EndMembershipPayload,
    CommandKind.GRANT_DELEGATION: GrantDelegationPayload,
    CommandKind.REPLACE_COORDINATOR: ReplaceCoordinatorPayload,
    CommandKind.RENEW_COORDINATOR_LEASE: RenewCoordinatorLeasePayload,
    CommandKind.POST_MESSAGE: PostMessagePayload,
    CommandKind.CORRECT_MESSAGE: CorrectMessagePayload,
    CommandKind.RETRACT_MESSAGE: RetractMessagePayload,
    CommandKind.REDACT_MESSAGE: RedactMessagePayload,
    CommandKind.PROPOSE_WORK_ITEM: ProposeWorkItemPayload,
    CommandKind.CREATE_WORK_ITEM: CreateWorkItemPayload,
    CommandKind.ADD_WORK_ITEM_DEPENDENCY: AddWorkItemDependencyPayload,
    CommandKind.OFFER_WORK_ITEM: OfferWorkItemPayload,
    CommandKind.ACCEPT_WORK_OFFER: AcceptWorkOfferPayload,
    CommandKind.START_WORK_ITEM: StartWorkItemPayload,
    CommandKind.RENEW_EXECUTION_LEASE: RenewExecutionLeasePayload,
    CommandKind.RECORD_RESOURCE_USAGE: RecordResourceUsagePayload,
    CommandKind.CHECKPOINT_WORK_ITEM: CheckpointWorkItemPayload,
    CommandKind.BLOCK_WORK_ITEM: BlockWorkItemPayload,
    CommandKind.UNBLOCK_WORK_ITEM: UnblockWorkItemPayload,
    CommandKind.PUBLISH_ARTIFACT: PublishArtifactPayload,
    CommandKind.SUBMIT_WORK_ITEM: SubmitWorkItemPayload,
    CommandKind.VERIFY_WORK_ITEM: VerifyWorkItemPayload,
    CommandKind.FAIL_WORK_ITEM: FailWorkItemPayload,
    CommandKind.CANCEL_WORK_ITEM: CancelWorkItemPayload,
    CommandKind.SUBMIT_MISSION: SubmitMissionPayload,
    CommandKind.APPROVE_MISSION: ApproveMissionPayload,
    CommandKind.GRANT_EXECUTION_APPROVAL: GrantExecutionApprovalPayload,
    CommandKind.GRANT_COOPERATION_OVERRIDE: GrantCooperationOverridePayload,
    CommandKind.REQUEST_MISSION_CHANGES: RequestMissionChangesPayload,
    CommandKind.FAIL_MISSION: FailMissionPayload,
    CommandKind.CANCEL_MISSION: CancelMissionPayload,
    CommandKind.ARCHIVE_GROUP: ArchiveGroupPayload,
}


class Core:
    """Deep authoritative Module for one organization."""

    def __init__(
        self,
        store: AuthoritativeStore,
        *,
        clock: Clock | None = None,
        cooperation_limits: CooperationLimits | None = None,
        snapshot_authority_key_id: str | None = None,
        snapshot_authority_public_key: PublicKeyLike | None = None,
    ) -> None:
        if (snapshot_authority_key_id is None) != (snapshot_authority_public_key is None):
            raise ValueError("snapshot authority key ID and public key must be configured together")
        self._store = store
        self._clock = clock or (lambda: datetime.now(UTC))
        self._cooperation_limits = cooperation_limits or CooperationLimits()
        self._snapshot_authority_key_id = snapshot_authority_key_id
        self._snapshot_authority_public_key = snapshot_authority_public_key
        self._schemas = SchemaCatalog()

    async def perform(self, command: Command) -> Event:
        """Validate and atomically apply one signed, idempotent Command."""

        now = self._now()
        command_hash = command.verified_signing_hash or canonical_hash(command.signing_payload())

        def apply(state: AuthoritativeState) -> Event:
            dedup_key = deduplication_key(
                command.actor.type.value, command.actor.id, command.action_id
            )
            previous = state.deduplication.get(dedup_key)
            if previous is not None:
                if previous.command_hash != command_hash:
                    raise ActionIdCollision(
                        "the action ID was already used for different Command content",
                        action_id=command.action_id,
                    )
                return previous.event

            payload = self._validate_payload(command)
            self._authenticate(state, command)
            self._ensure_budget_ledger(state)
            cooperation_override = self._enforce_cooperation_policy(state, command, payload, now)
            self._reconcile_offline_progress(
                state,
                command,
                payload,
                command_hash,
                now,
            )
            event = self._dispatch(state, command, payload, command_hash, now)
            if cooperation_override is not None:
                self._consume_cooperation_override(
                    state,
                    cooperation_override,
                    command,
                    event,
                    now,
                )
            state.accepted_commands[event.id] = command.model_copy(deep=True)
            state.deduplication[dedup_key] = DedupRecord(
                command_hash=command_hash,
                event=event,
            )
            return event

        return await self._store.transact(apply)

    async def query(self, query: Query) -> QueryResult:
        """Read one current authoritative projection."""

        def inspect(state: AuthoritativeState) -> QueryResult:
            if query.kind is QueryKind.COMMAND:
                return state.accepted_commands.get(query.entity_id)
            if query.kind is QueryKind.AGENT_CARD:
                return state.agent_cards.get(query.entity_id)
            if query.kind is QueryKind.SESSION_EPOCH:
                return state.sessions.get(query.entity_id)
            if query.kind is QueryKind.MISSION:
                return state.missions.get(query.entity_id)
            if query.kind is QueryKind.GROUP:
                return state.groups.get(query.entity_id)
            if query.kind is QueryKind.GROUP_SNAPSHOT:
                return state.group_snapshots.get(query.entity_id)
            if query.kind is QueryKind.CONVERSATION:
                return state.conversations.get(query.entity_id)
            if query.kind is QueryKind.MESSAGE:
                return state.messages.get(query.entity_id)
            if query.kind is QueryKind.MESSAGE_AMENDMENT:
                return state.message_amendments.get(query.entity_id)
            if query.kind is QueryKind.WORK_PROPOSAL:
                return state.work_proposals.get(query.entity_id)
            if query.kind is QueryKind.WORK_ITEM:
                return state.work_items.get(query.entity_id)
            if query.kind is QueryKind.ARTIFACT:
                return state.artifacts.get(query.entity_id)
            if query.kind is QueryKind.APPROVAL:
                return state.approvals.get(query.entity_id)
            if query.kind is QueryKind.EXECUTION_APPROVAL:
                return state.execution_approvals.get(query.entity_id)
            if query.kind is QueryKind.COOPERATION_OVERRIDE_GRANT:
                return state.cooperation_override_grants.get(query.entity_id)
            if query.kind is QueryKind.POLICY_LOG:
                return tuple(state.policy_log.get(query.entity_id, ()))
            if query.kind is QueryKind.DELEGATION_GRANT:
                return state.delegation_grants.get(query.entity_id)
            if query.kind is QueryKind.EXECUTION_LEASE:
                lease = state.execution_leases.get(query.entity_id)
                if lease is None:
                    return None
                if lease.state is LeaseState.ACTIVE and lease.expires_at <= self._now():
                    lease = lease.close(
                        LeaseState.EXPIRED,
                        at=lease.expires_at,
                        reason="Execution Lease reached its expiry",
                    )
                return cast(QueryResult, lease)
            if query.kind is QueryKind.BUDGET_REMAINING:
                try:
                    candidate = state.model_copy(deep=True)
                    self._ensure_budget_ledger(candidate)
                    return self._budget_ledger(candidate).remaining(query.entity_id)
                except BudgetLedgerError as error:
                    raise NotFound(str(error), account_id=query.entity_id) from error
            if query.kind is QueryKind.MISSION_WORK_ITEMS:
                return tuple(
                    sorted(
                        (
                            work
                            for work in state.work_items.values()
                            if work.mission_id == query.entity_id
                        ),
                        key=lambda work: work.id,
                    )
                )
            if query.kind is QueryKind.MEMBERSHIP:
                if query.group_id is None or query.actor_type is None:
                    raise InvalidCommand("membership queries require group_id and actor_type")
                return state.memberships.get(
                    membership_key(query.group_id, query.actor_type.value, query.entity_id)
                )
            raise InvalidCommand("unsupported query kind", kind=query.kind.value)

        return await self._store.inspect(inspect)

    async def replay(
        self, group_id: str, *, after: int = 0, limit: int = 1_000
    ) -> tuple[Event, ...]:
        """Replay ordered Group Events strictly after a Cursor."""

        if after < 0:
            raise InvalidCommand("replay cursor cannot be negative", after=after)
        if limit <= 0 or limit > 10_000:
            raise InvalidCommand("replay limit must be between 1 and 10000", limit=limit)

        def inspect(state: AuthoritativeState) -> tuple[Event, ...]:
            if group_id not in state.groups:
                raise NotFound("Group does not exist", group_id=group_id)
            events = state.events.get(group_id, [])
            return tuple(event for event in events if cast(int, event.sequence) > after)[:limit]

        return await self._store.inspect(inspect)

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise RuntimeError("Core clock must return a timezone-aware datetime")
        return now.astimezone(UTC)

    def _validate_payload(self, command: Command) -> CommandPayload:
        payload_type = _PAYLOAD_TYPES.get(command.kind)
        if payload_type is None:
            raise InvalidCommand("unsupported Command kind", kind=command.kind.value)
        try:
            return cast(
                CommandPayload,
                payload_type.model_validate(
                    CommandIngress.execution_payload(
                        command,
                        payload_fields=payload_type.model_fields,
                    )
                ),
            )
        except PydanticValidationError as exc:
            raise InvalidCommand(
                "Command payload does not match its schema",
                kind=command.kind.value,
                errors=exc.errors(include_url=False),
            ) from exc

    def _authenticate(self, state: AuthoritativeState, command: Command) -> None:
        if command.signature is None:
            raise InvalidCommand("durable Commands require a canonical signature")
        if command.actor.type is ActorType.AGENT:
            current = state.sessions.get(command.actor.id)
            if current is None or command.session_epoch != current:
                raise StaleSessionEpoch(
                    "Command was not sent by the current Agent runtime",
                    agent_id=command.actor.id,
                    expected=current,
                    received=command.session_epoch,
                )
        elif command.session_epoch is not None:
            raise InvalidCommand("only Agent Commands carry a session epoch")

        membership_exempt = command.kind in {
            CommandKind.CREATE_MISSION,
            CommandKind.CREATE_FOLLOW_UP_MISSION,
        }
        if (
            command.actor.type in {ActorType.AGENT, ActorType.HUMAN}
            and not membership_exempt
            and command.group_id is not None
            and command.group_id in state.groups
        ):
            membership = self._membership(state, command.group_id, command.actor)
            if membership is None:
                raise AuthorizationDenied(
                    "Command actor lacks a Group Membership",
                    group_id=command.group_id,
                    actor_id=command.actor.id,
                )
            if command.membership_epoch != membership.epoch:
                raise StaleMembershipEpoch(
                    "Command requires the current Membership epoch",
                    expected=membership.epoch,
                    received=command.membership_epoch,
                )

    def _enforce_cooperation_policy(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: CommandPayload,
        now: datetime,
    ) -> CooperationOverrideGrant | None:
        """Enforce bounded cooperation on the authoritative pre-transition state."""

        limits = self._cooperation_limits
        group_id = command.group_id
        resolved: CooperationOverrideGrant | None = None

        def authorize(
            policy_name: CooperationPolicyName,
            message: str,
            **details: Any,
        ) -> None:
            nonlocal resolved
            if command.cooperation_override_grant_id is None:
                raise PolicyViolation(message, **details)
            candidate = self._resolve_cooperation_override(
                state,
                command,
                policy_name,
                now,
            )
            if resolved is not None and resolved.id != candidate.id:
                raise InvalidCommand(
                    "one Command cannot consume multiple Cooperation Override Grants"
                )
            resolved = candidate

        if command.kind in {CommandKind.POST_MESSAGE, CommandKind.PROPOSE_WORK_ITEM}:
            if group_id is None:
                raise InvalidCommand("rate-limited Commands require a Group")
            event_kind = (
                EventKind.MESSAGE_POSTED
                if command.kind is CommandKind.POST_MESSAGE
                else EventKind.WORK_ITEM_PROPOSED
            )
            limit = (
                limits.maximum_message_rate_per_minute
                if command.kind is CommandKind.POST_MESSAGE
                else limits.maximum_proposal_rate_per_minute
            )
            cutoff = now - timedelta(minutes=1)
            recent = sum(
                1
                for event in state.events.get(group_id, ())
                if event.kind is event_kind
                and event.actor == command.actor
                and event.occurred_at > cutoff
            )
            policy_name = (
                CooperationPolicyName.MESSAGE_RATE
                if command.kind is CommandKind.POST_MESSAGE
                else CooperationPolicyName.PROPOSAL_RATE
            )
            if recent >= limit:
                authorize(
                    policy_name,
                    f"{policy_name.value.replace('_', ' ')} limit requires approved escalation",
                    limit=limit,
                )

        if command.kind is CommandKind.CREATE_CHILD_MISSION:
            parent = self._mission_for_command(state, command)
            depth = self._mission_depth(state, parent) + 1
            if depth > limits.maximum_delegation_depth:
                authorize(
                    CooperationPolicyName.DELEGATION_DEPTH,
                    "delegation depth requires approved escalation",
                    depth=depth,
                    limit=limits.maximum_delegation_depth,
                )

        if (
            command.kind is CommandKind.CREATE_WORK_ITEM
            and isinstance(payload, CreateWorkItemPayload)
            and payload.parent_work_item_id is not None
        ):
            mission = self._mission_for_command(state, command)
            parent_work = self._work_item(
                state,
                payload.parent_work_item_id,
                mission.group_id,
            )
            depth = parent_work.delegation_depth + 1
            if depth > limits.maximum_delegation_depth:
                authorize(
                    CooperationPolicyName.DELEGATION_DEPTH,
                    "delegation depth requires approved escalation",
                    depth=depth,
                    limit=limits.maximum_delegation_depth,
                )

        if (
            command.kind is CommandKind.GRANT_DELEGATION
            and isinstance(payload, GrantDelegationPayload)
            and payload.max_descendant_depth > limits.maximum_delegation_depth
        ):
            authorize(
                CooperationPolicyName.DELEGATION_DEPTH,
                "Delegation Grant depth requires approved escalation",
                depth=payload.max_descendant_depth,
                limit=limits.maximum_delegation_depth,
            )

        if command.kind is CommandKind.ACCEPT_WORK_OFFER:
            queued = sum(
                1
                for work in state.work_items.values()
                if work.assignee_id == command.actor.id and work.status is WorkItemStatus.QUEUED
            )
            active = sum(
                1
                for work in state.work_items.values()
                if work.assignee_id == command.actor.id and work.status is WorkItemStatus.ACTIVE
            )
            if queued + 1 > limits.maximum_queued_work_items:
                authorize(
                    CooperationPolicyName.QUEUED_WORK_ITEMS,
                    "Worker queue limit requires approved escalation",
                    queued=queued + 1,
                    limit=limits.maximum_queued_work_items,
                )
            if active > limits.maximum_active_work_items:
                authorize(
                    CooperationPolicyName.ACTIVE_WORK_ITEMS,
                    "Worker active-work limit requires approved escalation",
                    active=active,
                    limit=limits.maximum_active_work_items,
                )

        if command.kind is CommandKind.START_WORK_ITEM:
            active = sum(
                1
                for work in state.work_items.values()
                if work.assignee_id == command.actor.id and work.status is WorkItemStatus.ACTIVE
            )
            if active + 1 > limits.maximum_active_work_items:
                authorize(
                    CooperationPolicyName.ACTIVE_WORK_ITEMS,
                    "Worker active-work limit requires approved escalation",
                    active=active + 1,
                    limit=limits.maximum_active_work_items,
                )

        if resolved is None and command.cooperation_override_grant_id is not None:
            raise InvalidCommand(
                "Command cites a Cooperation Override Grant but no cooperation limit is exceeded",
                cooperation_override_grant_id=command.cooperation_override_grant_id,
            )
        return resolved

    def _resolve_cooperation_override(
        self,
        state: AuthoritativeState,
        command: Command,
        policy_name: CooperationPolicyName,
        now: datetime,
    ) -> CooperationOverrideGrant:
        grant_id = command.cooperation_override_grant_id
        if grant_id is None:
            raise PolicyViolation("cooperation limit requires an explicit override grant")
        grant = state.cooperation_override_grants.get(grant_id)
        if grant is None:
            raise PolicyViolation(
                "Cooperation Override Grant is missing, unknown, or forged",
                cooperation_override_grant_id=grant_id,
            )
        if grant.consumed_at is not None or grant.consumed_event_id is not None:
            raise PolicyViolation(
                "Cooperation Override Grant was already consumed",
                cooperation_override_grant_id=grant.id,
                consumed_event_id=grant.consumed_event_id,
            )
        if grant.expires_at <= now:
            raise PolicyViolation(
                "Cooperation Override Grant has expired",
                cooperation_override_grant_id=grant.id,
                expires_at=grant.expires_at,
            )
        mission = self._mission_for_command(state, command)
        if grant.group_id != mission.group_id or grant.mission_id != mission.id:
            raise PolicyViolation(
                "Cooperation Override Grant belongs to another Mission or Group",
                cooperation_override_grant_id=grant.id,
            )
        if grant.beneficiary != command.actor:
            raise PolicyViolation(
                "Cooperation Override Grant belongs to another beneficiary",
                cooperation_override_grant_id=grant.id,
            )
        if grant.target_command_kind is not command.kind:
            raise PolicyViolation(
                "Cooperation Override Grant targets another Command kind",
                cooperation_override_grant_id=grant.id,
                expected=grant.target_command_kind.value,
                received=command.kind.value,
            )
        if grant.target_action_id != command.action_id:
            raise PolicyViolation(
                "Cooperation Override Grant targets another Action ID",
                cooperation_override_grant_id=grant.id,
                expected=grant.target_action_id,
                received=command.action_id,
            )
        if grant.policy_name is not policy_name:
            raise PolicyViolation(
                "Cooperation Override Grant targets another cooperation policy",
                cooperation_override_grant_id=grant.id,
                expected=grant.policy_name.value,
                received=policy_name.value,
            )
        if command.kind not in _COOPERATION_POLICY_TARGETS[grant.policy_name]:
            raise PolicyViolation(
                "Cooperation Override Grant has an invalid policy and Command scope",
                cooperation_override_grant_id=grant.id,
            )
        if grant.approver.type is not ActorType.SYSTEM and grant.approver != mission.owner:
            raise PolicyViolation(
                "Cooperation Override Grant lacks a current authorized approver",
                cooperation_override_grant_id=grant.id,
            )
        return grant

    @staticmethod
    def _consume_cooperation_override(
        state: AuthoritativeState,
        grant: CooperationOverrideGrant,
        command: Command,
        event: Event,
        now: datetime,
    ) -> None:
        document = grant.model_dump(mode="python")
        document.update(consumed_at=now, consumed_event_id=event.id)
        consumed = CooperationOverrideGrant.model_validate(document)
        state.cooperation_override_grants[grant.id] = consumed
        state.policy_log.setdefault(grant.group_id, []).append(
            PolicyLogEntry(
                entry_id=f"policy-log:cooperation-override:{uuid4()}",
                decision="cooperation override consumed",
                actor=command.actor,
                details={
                    "grantId": grant.id,
                    "missionId": grant.mission_id,
                    "groupId": grant.group_id,
                    "policyName": grant.policy_name.value,
                    "targetCommandKind": grant.target_command_kind.value,
                    "targetActionId": grant.target_action_id,
                    "consumedEventId": event.id,
                },
                occurred_at=now,
            )
        )

    def _reconcile_offline_progress(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: CommandPayload,
        command_hash: str,
        now: datetime,
    ) -> None:
        """Validate disconnected progress and atomically charge its authoritative budget."""

        envelope = command.extensions.get(OFFLINE_EXECUTION_EXTENSION)
        if envelope is None:
            return
        if command.kind not in {CommandKind.POST_MESSAGE, CommandKind.CHECKPOINT_WORK_ITEM}:
            raise InvalidCommand(
                "offline execution binding is valid only for reversible progress Commands"
            )
        if envelope.version != OFFLINE_EXECUTION_EXTENSION_VERSION or not envelope.critical:
            raise InvalidCommand("offline execution binding version or criticality is invalid")
        try:
            binding = OfflineProgressBinding.model_validate(envelope.data)
        except PydanticValidationError as error:
            raise InvalidCommand(
                "offline execution binding is invalid",
                errors=error.errors(include_url=False),
            ) from error
        if command.actor.type is not ActorType.AGENT or command.actor.id != binding.agent_id:
            raise AuthorizationDenied("offline progress Agent binding does not match the Command")
        if command.group_id != binding.group_id:
            raise AuthorizationDenied("offline progress Group binding does not match the Command")
        if command.issued_at < binding.buffered_at or command.issued_at > now:
            raise InvalidCommand("offline reconciliation timestamp is outside its valid window")

        work = self._work_item(state, binding.work_item_id, binding.group_id)
        if work.status not in {WorkItemStatus.ACTIVE, WorkItemStatus.QUEUED}:
            raise InvalidTransition(
                "offline progress must reconcile before submission or another state transition",
                work_item_id=work.id,
                status=work.status.value,
            )
        self._require_work_owner(work, command, binding.ownership_epoch, now)
        if command.kind is CommandKind.POST_MESSAGE:
            if (
                not isinstance(payload, PostMessagePayload)
                or payload.conversation_id != work.conversation_id
            ):
                raise AuthorizationDenied(
                    "offline Message is outside the bound WorkItem Conversation"
                )
        elif (
            not isinstance(payload, CheckpointWorkItemPayload)
            or payload.work_item_id != work.id
            or payload.ownership_epoch != binding.ownership_epoch
        ):
            raise AuthorizationDenied("offline checkpoint is outside the bound WorkItem")

        lease = self._execution_lease(state, binding.execution_lease_id)
        mission = state.missions[work.mission_id]
        self._require_lease_scope(
            lease,
            mission=mission,
            work=work,
            ownership_epoch=binding.ownership_epoch,
        )
        if lease.holder_agent_id != binding.agent_id:
            raise AuthorizationDenied("offline progress Agent did not hold the Execution Lease")
        if lease.session_epoch != binding.session_epoch:
            raise StaleSessionEpoch(
                "offline progress Session Epoch does not match its Execution Lease",
                expected=lease.session_epoch,
                received=binding.session_epoch,
            )
        if binding.execution_lease_expires_at != lease.expires_at:
            raise LeaseExpired("offline progress carries an inconsistent Execution Lease expiry")
        if not (lease.starts_at <= binding.disconnected_at < lease.expires_at):
            raise LeaseExpired("offline disconnection occurred outside the Execution Lease")
        if binding.buffered_at >= lease.expires_at:
            raise LeaseExpired("offline progress was buffered after the Execution Lease expired")
        if lease.closed_at is not None and binding.buffered_at > lease.closed_at:
            raise LeaseExpired("offline progress was buffered after the Execution Lease closed")

        usage = binding.resource_usage_delta
        if not any(getattr(usage, field_name) for field_name in type(usage).model_fields):
            return
        ledger = self._budget_ledger(state)
        try:
            cumulative = ledger.consume(work.id, usage)
            remaining = ledger.remaining(work.id)
        except BudgetLedgerError as error:
            raise BudgetExceeded(str(error), work_item_id=work.id) from error
        state.budget_ledger = ledger.snapshot()
        self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.RESOURCE_USAGE_RECORDED,
            {
                "workItemId": work.id,
                "executionLeaseId": lease.lease_id,
                "ownershipEpoch": binding.ownership_epoch,
                "usageDelta": usage,
                "cumulativeUsage": cumulative,
                "remainingBudget": remaining,
                "offlineReconciliation": {
                    "disconnectedAt": binding.disconnected_at,
                    "bufferedAt": binding.buffered_at,
                    "graceDeadline": binding.grace_deadline,
                    "executionSessionEpoch": binding.session_epoch,
                    "reconciliationSessionEpoch": command.session_epoch,
                    "reconciledAt": now,
                    "progressActionId": command.action_id,
                },
            },
            group_id=work.group_id,
        )

    def _dispatch(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: CommandPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        kind = command.kind
        if kind is CommandKind.REGISTER_AGENT_CARD:
            return self._register_agent_card(
                state, command, cast(RegisterAgentCardPayload, payload), command_hash, now
            )
        if kind is CommandKind.OPEN_AGENT_SESSION:
            return self._open_agent_session(
                state, command, cast(OpenAgentSessionPayload, payload), command_hash, now
            )
        if kind in {CommandKind.CREATE_MISSION, CommandKind.CREATE_FOLLOW_UP_MISSION}:
            return self._create_mission(
                state, command, cast(CreateMissionPayload, payload), command_hash, now
            )
        if kind is CommandKind.CREATE_CHILD_MISSION:
            return self._create_child_mission(
                state, command, cast(CreateChildMissionPayload, payload), command_hash, now
            )
        if kind is CommandKind.ADD_MEMBERSHIP:
            return self._add_membership(
                state, command, cast(AddMembershipPayload, payload), command_hash, now
            )
        if kind is CommandKind.END_MEMBERSHIP:
            return self._end_membership(
                state, command, cast(EndMembershipPayload, payload), command_hash, now
            )
        if kind is CommandKind.GRANT_DELEGATION:
            return self._grant_delegation(
                state,
                command,
                cast(GrantDelegationPayload, payload),
                command_hash,
                now,
            )
        if kind is CommandKind.GRANT_COOPERATION_OVERRIDE:
            return self._grant_cooperation_override(
                state,
                command,
                cast(GrantCooperationOverridePayload, payload),
                command_hash,
                now,
            )
        if kind is CommandKind.REPLACE_COORDINATOR:
            return self._replace_coordinator(
                state, command, cast(ReplaceCoordinatorPayload, payload), command_hash, now
            )
        if kind is CommandKind.RENEW_COORDINATOR_LEASE:
            return self._renew_coordinator_lease(
                state,
                command,
                cast(RenewCoordinatorLeasePayload, payload),
                command_hash,
                now,
            )
        if kind is CommandKind.POST_MESSAGE:
            return self._post_message(
                state, command, cast(PostMessagePayload, payload), command_hash, now
            )
        if kind is CommandKind.CORRECT_MESSAGE:
            return self._amend_message(
                state,
                command,
                cast(CorrectMessagePayload, payload),
                command_hash,
                now,
                MessageAmendmentKind.CORRECTION,
            )
        if kind is CommandKind.RETRACT_MESSAGE:
            return self._amend_message(
                state,
                command,
                cast(RetractMessagePayload, payload),
                command_hash,
                now,
                MessageAmendmentKind.RETRACTION,
            )
        if kind is CommandKind.REDACT_MESSAGE:
            return self._amend_message(
                state,
                command,
                cast(RedactMessagePayload, payload),
                command_hash,
                now,
                MessageAmendmentKind.REDACTION,
            )
        if kind is CommandKind.PROPOSE_WORK_ITEM:
            return self._propose_work_item(
                state,
                command,
                cast(ProposeWorkItemPayload, payload),
                command_hash,
                now,
            )
        if kind is CommandKind.CREATE_WORK_ITEM:
            return self._create_work_item(
                state, command, cast(CreateWorkItemPayload, payload), command_hash, now
            )
        if kind is CommandKind.ADD_WORK_ITEM_DEPENDENCY:
            return self._add_work_item_dependency(
                state,
                command,
                cast(AddWorkItemDependencyPayload, payload),
                command_hash,
                now,
            )
        if kind is CommandKind.OFFER_WORK_ITEM:
            return self._offer_work_item(
                state, command, cast(OfferWorkItemPayload, payload), command_hash, now
            )
        if kind is CommandKind.ACCEPT_WORK_OFFER:
            return self._accept_work_offer(
                state, command, cast(AcceptWorkOfferPayload, payload), command_hash, now
            )
        if kind is CommandKind.START_WORK_ITEM:
            return self._start_work_item(
                state, command, cast(StartWorkItemPayload, payload), command_hash, now
            )
        if kind is CommandKind.RENEW_EXECUTION_LEASE:
            return self._renew_execution_lease(
                state,
                command,
                cast(RenewExecutionLeasePayload, payload),
                command_hash,
                now,
            )
        if kind is CommandKind.RECORD_RESOURCE_USAGE:
            return self._record_resource_usage(
                state,
                command,
                cast(RecordResourceUsagePayload, payload),
                command_hash,
                now,
            )
        if kind is CommandKind.CHECKPOINT_WORK_ITEM:
            return self._checkpoint_work_item(
                state,
                command,
                cast(CheckpointWorkItemPayload, payload),
                command_hash,
                now,
            )
        if kind is CommandKind.BLOCK_WORK_ITEM:
            return self._block_work_item(
                state, command, cast(BlockWorkItemPayload, payload), command_hash, now
            )
        if kind is CommandKind.UNBLOCK_WORK_ITEM:
            return self._unblock_work_item(
                state, command, cast(UnblockWorkItemPayload, payload), command_hash, now
            )
        if kind is CommandKind.PUBLISH_ARTIFACT:
            return self._publish_artifact(
                state, command, cast(PublishArtifactPayload, payload), command_hash, now
            )
        if kind is CommandKind.SUBMIT_WORK_ITEM:
            return self._submit_work_item(
                state, command, cast(SubmitWorkItemPayload, payload), command_hash, now
            )
        if kind is CommandKind.VERIFY_WORK_ITEM:
            return self._verify_work_item(
                state, command, cast(VerifyWorkItemPayload, payload), command_hash, now
            )
        if kind is CommandKind.FAIL_WORK_ITEM:
            return self._fail_work_item(
                state, command, cast(FailWorkItemPayload, payload), command_hash, now
            )
        if kind is CommandKind.CANCEL_WORK_ITEM:
            return self._cancel_work_item(
                state, command, cast(CancelWorkItemPayload, payload), command_hash, now
            )
        if kind is CommandKind.SUBMIT_MISSION:
            return self._submit_mission(
                state, command, cast(SubmitMissionPayload, payload), command_hash, now
            )
        if kind is CommandKind.APPROVE_MISSION:
            return self._approve_mission(
                state, command, cast(ApproveMissionPayload, payload), command_hash, now
            )
        if kind is CommandKind.REQUEST_MISSION_CHANGES:
            return self._request_mission_changes(
                state,
                command,
                cast(RequestMissionChangesPayload, payload),
                command_hash,
                now,
            )
        if kind is CommandKind.GRANT_EXECUTION_APPROVAL:
            return self._grant_execution_approval(
                state,
                command,
                cast(GrantExecutionApprovalPayload, payload),
                command_hash,
                now,
            )
        if kind is CommandKind.FAIL_MISSION:
            return self._fail_mission_command(
                state, command, cast(FailMissionPayload, payload), command_hash, now
            )
        if kind is CommandKind.CANCEL_MISSION:
            return self._cancel_mission(
                state, command, cast(CancelMissionPayload, payload), command_hash, now
            )
        if kind is CommandKind.ARCHIVE_GROUP:
            return self._archive_group(
                state, command, cast(ArchiveGroupPayload, payload), command_hash, now
            )
        raise InvalidCommand("unsupported Command kind", kind=kind.value)

    def _register_agent_card(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: RegisterAgentCardPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        self._require_system(command)
        previous = state.agent_cards.get(payload.card.agent_id)
        if previous is not None and payload.card.version <= previous.version:
            raise RevisionConflict(
                "Agent Card version must increase",
                agent_id=payload.card.agent_id,
                current=previous.version,
                received=payload.card.version,
            )
        state.agent_cards[payload.card.agent_id] = payload.card
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.AGENT_CARD_REGISTERED,
            {"agentId": payload.card.agent_id, "version": payload.card.version},
        )

    def _open_agent_session(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: OpenAgentSessionPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        self._require_system(command)
        self._require_agent_card(state, payload.agent_id)
        epoch = state.sessions.get(payload.agent_id, 0) + 1
        state.sessions[payload.agent_id] = epoch
        for work in sorted(state.work_items.values(), key=lambda item: item.id):
            if (
                work.assignee_id != payload.agent_id
                or work.status is not WorkItemStatus.ACTIVE
                or work.execution_lease_id is None
            ):
                continue
            old_lease_id = work.execution_lease_id
            self._close_execution_lease(
                state,
                work,
                now,
                state_if_live=LeaseState.REVOKED,
                reason="Agent Session Epoch was replaced",
            )
            work.status = WorkItemStatus.QUEUED
            self._touch_work(work, now)
            self._emit(
                state,
                command,
                command_hash,
                now,
                EventKind.EXECUTION_LEASE_REVOKED,
                {
                    "workItemId": work.id,
                    "executionLeaseId": old_lease_id,
                    "reason": "session_replaced",
                    "status": work.status.value,
                    "sessionEpoch": epoch,
                },
                group_id=work.group_id,
            )
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.AGENT_SESSION_OPENED,
            {"agentId": payload.agent_id, "sessionEpoch": epoch},
        )

    def _create_mission(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: CreateMissionPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        if command.actor.type is not ActorType.HUMAN:
            raise AuthorizationDenied("a root Mission must be created by its human MissionOwner")
        self._require_command_group(command, payload.group_id)
        self._require_new_ids(state, payload.mission_id, payload.group_id)
        self._require_agent_card(state, payload.coordinator_id)
        previous: Mission | None = None
        if command.kind is CommandKind.CREATE_FOLLOW_UP_MISSION:
            if payload.follow_up_of_mission_id is None:
                raise InvalidCommand("a follow-up Mission must reference an approved Mission")
            previous = state.missions.get(payload.follow_up_of_mission_id)
            if previous is None:
                raise NotFound("follow-up source Mission does not exist")
            if previous.status is not MissionStatus.APPROVED:
                raise InvalidTransition("only an approved Mission may have a follow-up")
            if previous.owner != command.actor:
                raise AuthorizationDenied("follow-up Mission must retain the accountable owner")
        elif payload.follow_up_of_mission_id is not None:
            raise InvalidCommand("mission.create cannot carry a follow-up source")
        if payload.deadline <= now:
            raise PolicyViolation("Mission deadline must be in the future")

        ledger = self._budget_ledger(state)
        try:
            ledger.register_mission(payload.mission_id, payload.budget)
        except BudgetLedgerError as error:
            raise BudgetExceeded(str(error), mission_id=payload.mission_id) from error
        state.budget_ledger = ledger.snapshot()

        mission = Mission(
            id=payload.mission_id,
            group_id=payload.group_id,
            title=payload.title,
            objective=payload.objective,
            definition_of_done=payload.definition_of_done,
            owner=command.actor,
            coordinator_id=payload.coordinator_id,
            coordinator_epoch=1,
            coordinator_lease_expires_at=now + timedelta(seconds=payload.coordinator_lease_seconds),
            budget=payload.budget,
            deadline=payload.deadline,
            permissions=payload.permissions,
            follow_up_of_mission_id=(previous.id if previous is not None else None),
            created_at=now,
            updated_at=now,
        )
        group = Group(
            id=payload.group_id,
            mission_id=payload.mission_id,
            main_conversation_id=f"{payload.group_id}:mission",
            created_at=now,
        )
        state.missions[mission.id] = mission
        state.groups[group.id] = group
        state.group_sequences[group.id] = 0
        state.events[group.id] = []
        state.conversations[group.main_conversation_id] = Conversation(
            id=group.main_conversation_id,
            group_id=group.id,
            title="Mission",
            created_at=now,
        )
        self._upsert_membership(
            state, group.id, command.actor, (Role.MISSION_OWNER,), MembershipStatus.ACTIVE, now
        )
        self._upsert_membership(
            state,
            group.id,
            Principal.agent(payload.coordinator_id),
            (Role.COORDINATOR,),
            MembershipStatus.ACTIVE,
            now,
        )
        return self._emit(
            state,
            command,
            command_hash,
            now,
            (
                EventKind.FOLLOW_UP_MISSION_CREATED
                if previous is not None
                else EventKind.MISSION_CREATED
            ),
            {
                "mission": mission,
                "group": group,
                "followUpOfMissionId": previous.id if previous is not None else None,
            },
            group_id=group.id,
        )

    def _create_child_mission(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: CreateChildMissionPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        parent = self._mission_for_command(state, command)
        self._require_coordinator(state, parent, command, now)
        self._require_active_mission(parent)
        self._require_new_ids(state, payload.mission_id, payload.group_id)
        self._require_agent_card(state, payload.coordinator_id)
        parent_work = self._work_item(state, payload.parent_work_item_id, parent.group_id)
        if parent_work.child_mission_id is not None:
            raise AlreadyExists(
                "WorkItem already owns a child Mission", work_item_id=parent_work.id
            )
        if parent_work.status in {
            WorkItemStatus.SUBMITTED,
            WorkItemStatus.VERIFIED,
            WorkItemStatus.FAILED,
            WorkItemStatus.CANCELLED,
        }:
            self._invalid_transition("promote to child Mission", parent_work)
        if payload.deadline <= now or payload.deadline > parent.deadline:
            raise PolicyViolation("child Mission deadline must fit within its parent deadline")
        if payload.deadline > parent_work.contract.deadline:
            raise PolicyViolation("child Mission deadline must fit within the parent Work Contract")
        if not parent.budget.contains(payload.budget) or not parent_work.contract.budget.contains(
            payload.budget
        ):
            raise PolicyViolation("child Mission budget must be a subset of its ancestors")
        if not set(payload.permissions).issubset(parent.permissions):
            raise PolicyViolation("child Mission permissions must be a subset of its parent")

        ledger = self._budget_ledger(state)
        try:
            ledger.register_mission(
                payload.mission_id,
                payload.budget,
                parent_mission_id=parent.id,
                parent_work_item_id=parent_work.id,
            )
        except BudgetLedgerError as error:
            raise BudgetExceeded(str(error), mission_id=payload.mission_id) from error
        state.budget_ledger = ledger.snapshot()

        owner = command.actor
        child = Mission(
            id=payload.mission_id,
            group_id=payload.group_id,
            title=payload.title,
            objective=payload.objective,
            definition_of_done=payload.definition_of_done,
            owner=owner,
            coordinator_id=payload.coordinator_id,
            coordinator_epoch=1,
            coordinator_lease_expires_at=now + timedelta(seconds=payload.coordinator_lease_seconds),
            budget=payload.budget,
            deadline=payload.deadline,
            permissions=payload.permissions,
            parent_mission_id=parent.id,
            parent_work_item_id=parent_work.id,
            child_failure_policy=payload.failure_policy,
            created_at=now,
            updated_at=now,
        )
        child_group = Group(
            id=payload.group_id,
            mission_id=child.id,
            main_conversation_id=f"{payload.group_id}:mission",
            created_at=now,
        )
        state.missions[child.id] = child
        state.groups[child_group.id] = child_group
        state.group_sequences[child_group.id] = 0
        state.events[child_group.id] = []
        state.conversations[child_group.main_conversation_id] = Conversation(
            id=child_group.main_conversation_id,
            group_id=child_group.id,
            title="Mission",
            created_at=now,
        )
        self._upsert_membership(
            state,
            child_group.id,
            owner,
            (Role.MISSION_OWNER,),
            MembershipStatus.ACTIVE,
            now,
        )
        self._upsert_membership(
            state,
            child_group.id,
            Principal.agent(payload.coordinator_id),
            (Role.COORDINATOR,),
            MembershipStatus.ACTIVE,
            now,
        )

        parent_work.child_mission_id = child.id
        parent_work.status = WorkItemStatus.BLOCKED
        parent_work.blocker = f"awaiting child Mission {child.id}"
        self._fence_work_owner(state, parent_work, now)
        self._touch_work(parent_work, now)
        self._touch_mission(parent, now)

        primary = self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.CHILD_MISSION_CREATED,
            {
                "parentMissionId": parent.id,
                "parentWorkItemId": parent_work.id,
                "childMissionId": child.id,
                "childGroupId": child.group_id,
            },
            group_id=parent.group_id,
        )
        self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.MISSION_CREATED,
            {"mission": child, "group": child_group, "parentEventId": primary.id},
            group_id=child.group_id,
        )
        return primary

    def _add_membership(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: AddMembershipPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        self._require_owner_or_coordinator(state, mission, command, now)
        self._require_not_terminal_mission(mission)
        if payload.principal.type is ActorType.AGENT:
            self._require_agent_card(state, payload.principal.id)
        if Role.MISSION_OWNER in payload.roles and payload.principal != mission.owner:
            raise AuthorizationDenied("only the recorded MissionOwner may hold that role")
        if Role.COORDINATOR in payload.roles and payload.principal != Principal.agent(
            mission.coordinator_id
        ):
            raise AuthorizationDenied("only the current Coordinator may hold that role")
        status = MembershipStatus.PROVISIONAL if payload.provisional else MembershipStatus.ACTIVE
        visibility = (
            state.group_sequences.get(mission.group_id, 0)
            if payload.visibility_after_sequence is None
            else payload.visibility_after_sequence
        )
        membership = self._upsert_membership(
            state,
            mission.group_id,
            payload.principal,
            payload.roles,
            status,
            now,
            visibility_after_sequence=visibility,
        )
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.MEMBERSHIP_ADDED,
            {"membership": membership},
            group_id=mission.group_id,
        )

    def _end_membership(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: EndMembershipPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        self._require_owner_or_coordinator(state, mission, command, now)
        self._require_not_terminal_mission(mission)
        if payload.principal == mission.owner or payload.principal == Principal.agent(
            mission.coordinator_id
        ):
            raise PolicyViolation("MissionOwner and current Coordinator memberships cannot end")
        membership = self._membership(state, mission.group_id, payload.principal)
        if membership is None or membership.status is MembershipStatus.ENDED:
            raise NotFound("active Membership does not exist", principal_id=payload.principal.id)
        membership.status = MembershipStatus.ENDED
        membership.epoch += 1
        membership.ended_at = now
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.MEMBERSHIP_ENDED,
            {"principal": payload.principal},
            group_id=mission.group_id,
        )

    def _grant_cooperation_override(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: GrantCooperationOverridePayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        if command.actor.type is not ActorType.SYSTEM:
            self._require_mission_owner(state, mission, command)
        self._require_not_terminal_mission(mission)
        if payload.grant_id in state.cooperation_override_grants:
            raise AlreadyExists(
                "Cooperation Override Grant ID already exists",
                grant_id=payload.grant_id,
            )
        permitted_targets = _COOPERATION_POLICY_TARGETS[payload.policy_name]
        if payload.target_command_kind not in permitted_targets:
            raise InvalidCommand(
                "cooperation policy does not apply to the target Command kind",
                policy_name=payload.policy_name.value,
                target_command_kind=payload.target_command_kind.value,
            )
        if payload.expires_at <= now or payload.expires_at > mission.deadline:
            raise PolicyViolation(
                "Cooperation Override Grant expiry must fit within the Mission",
                expires_at=payload.expires_at,
                mission_deadline=mission.deadline,
            )
        beneficiary_membership = self._membership(
            state,
            mission.group_id,
            payload.beneficiary,
        )
        if (
            beneficiary_membership is None
            or beneficiary_membership.status is MembershipStatus.ENDED
        ):
            raise AuthorizationDenied(
                "Cooperation Override Grant beneficiary requires a current Group Membership",
                beneficiary_id=payload.beneficiary.id,
            )
        target_dedup_key = deduplication_key(
            payload.beneficiary.type.value,
            payload.beneficiary.id,
            payload.target_action_id,
        )
        if target_dedup_key in state.deduplication:
            raise InvalidTransition(
                "Cooperation Override Grant cannot target an already accepted Action ID",
                target_action_id=payload.target_action_id,
            )
        grant = CooperationOverrideGrant(
            id=payload.grant_id,
            mission_id=mission.id,
            group_id=mission.group_id,
            policy_name=payload.policy_name,
            beneficiary=payload.beneficiary,
            target_command_kind=payload.target_command_kind,
            target_action_id=payload.target_action_id,
            approver=command.actor,
            reason=payload.reason,
            granted_at=now,
            expires_at=payload.expires_at,
            signature=cast(SignatureEnvelope, command.signature).value,
        )
        state.cooperation_override_grants[grant.id] = grant
        event = self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.COOPERATION_OVERRIDE_GRANTED,
            {"cooperationOverrideGrant": grant},
            group_id=mission.group_id,
        )
        state.policy_log.setdefault(mission.group_id, []).append(
            PolicyLogEntry(
                entry_id=f"policy-log:cooperation-override:{uuid4()}",
                decision="cooperation override granted",
                actor=command.actor,
                details={
                    "grantId": grant.id,
                    "missionId": grant.mission_id,
                    "groupId": grant.group_id,
                    "policyName": grant.policy_name.value,
                    "beneficiaryType": grant.beneficiary.type.value,
                    "beneficiaryId": grant.beneficiary.id,
                    "targetCommandKind": grant.target_command_kind.value,
                    "targetActionId": grant.target_action_id,
                    "reason": grant.reason,
                    "expiresAt": grant.expires_at.isoformat(),
                    "grantedEventId": event.id,
                },
                occurred_at=now,
            )
        )
        return event

    def _grant_delegation(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: GrantDelegationPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        self._require_coordinator(state, mission, command, now)
        self._require_active_mission(mission)
        if payload.grant_id in state.delegation_grants:
            raise AlreadyExists(
                "Delegation Grant ID already exists",
                grant_id=payload.grant_id,
            )
        grantee = Principal.agent(payload.grantee_agent_id)
        membership = self._membership(state, mission.group_id, grantee)
        if (
            membership is None
            or membership.status is not MembershipStatus.ACTIVE
            or Role.WORK_DELEGATE not in membership.roles
        ):
            raise AuthorizationDenied(
                "Delegation grantee requires an active work_delegate Membership",
                grantee_agent_id=payload.grantee_agent_id,
            )
        target = self._work_item(state, payload.target_work_item_id, mission.group_id)
        if target.mission_id != mission.id:
            raise AuthorizationDenied("Delegation target belongs to another Mission")
        if target.status in {
            WorkItemStatus.VERIFIED,
            WorkItemStatus.FAILED,
            WorkItemStatus.CANCELLED,
        }:
            raise InvalidTransition(
                "Delegation Grant target WorkItem is terminal",
                work_item_id=target.id,
                status=target.status.value,
            )
        if payload.expires_at <= now or payload.expires_at > mission.deadline:
            raise PolicyViolation("Delegation Grant expiry must fit within the active Mission")
        if not budget_within_ceiling(payload.budget, mission.budget):
            raise PolicyViolation("Delegation Grant budget exceeds the Mission budget")
        grant = DelegationGrant(
            id=payload.grant_id,
            grantee_agent_id=payload.grantee_agent_id,
            mission_id=mission.id,
            group_id=mission.group_id,
            target_work_item_id=target.id,
            allowed_capabilities=payload.allowed_capabilities,
            budget=payload.budget,
            max_descendant_depth=payload.max_descendant_depth,
            grantee_membership_epoch=membership.epoch,
            coordinator_epoch=mission.coordinator_epoch,
            granted_by=command.actor,
            granted_at=now,
            expires_at=payload.expires_at,
        )
        state.delegation_grants[grant.id] = grant
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.DELEGATION_GRANTED,
            {"delegationGrant": grant},
            group_id=mission.group_id,
        )

    def _replace_coordinator(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: ReplaceCoordinatorPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        self._require_mission_owner(state, mission, command)
        self._require_not_terminal_mission(mission)
        self._require_agent_card(state, payload.coordinator_id)
        old_id = mission.coordinator_id
        if old_id == payload.coordinator_id:
            raise InvalidTransition("replacement Coordinator must be a different Agent")

        self._remove_membership_role(
            state, mission.group_id, Principal.agent(old_id), Role.COORDINATOR, now
        )
        self._upsert_membership(
            state,
            mission.group_id,
            Principal.agent(payload.coordinator_id),
            (Role.COORDINATOR,),
            MembershipStatus.ACTIVE,
            now,
        )
        mission.coordinator_id = payload.coordinator_id
        mission.coordinator_epoch += 1
        mission.coordinator_lease_expires_at = now + timedelta(seconds=payload.lease_seconds)
        mission.updated_at = now

        old_owner = Principal.agent(old_id)
        new_owner = Principal.agent(payload.coordinator_id)
        for child in state.missions.values():
            if child.parent_mission_id == mission.id and child.owner == old_owner:
                self._remove_membership_role(
                    state, child.group_id, old_owner, Role.MISSION_OWNER, now
                )
                self._upsert_membership(
                    state,
                    child.group_id,
                    new_owner,
                    (Role.MISSION_OWNER,),
                    MembershipStatus.ACTIVE,
                    now,
                )
                child.owner = new_owner
                child.updated_at = now

        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.COORDINATOR_REPLACED,
            {
                "previousCoordinatorId": old_id,
                "coordinatorId": payload.coordinator_id,
                "coordinatorEpoch": mission.coordinator_epoch,
                "leaseExpiresAt": mission.coordinator_lease_expires_at,
            },
            group_id=mission.group_id,
        )

    def _renew_coordinator_lease(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: RenewCoordinatorLeasePayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        self._require_coordinator(state, mission, command, now)
        self._require_not_terminal_mission(mission)
        mission.coordinator_lease_expires_at = now + timedelta(seconds=payload.lease_seconds)
        mission.updated_at = now
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.COORDINATOR_LEASE_RENEWED,
            {
                "coordinatorEpoch": mission.coordinator_epoch,
                "leaseExpiresAt": mission.coordinator_lease_expires_at,
            },
            group_id=mission.group_id,
        )

    def _post_message(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: PostMessagePayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        self._require_not_terminal_mission(mission)
        self._require_active_membership(state, mission.group_id, command.actor)
        conversation = state.conversations.get(payload.conversation_id)
        if conversation is None or conversation.group_id != mission.group_id:
            raise NotFound("Conversation does not exist in this Group")
        if payload.message_id in state.messages:
            raise AlreadyExists("Message ID already exists", message_id=payload.message_id)
        message = Message(
            id=payload.message_id,
            group_id=mission.group_id,
            conversation_id=conversation.id,
            author=command.actor,
            content=payload.content,
            mentions=payload.mentions,
            created_at=now,
        )
        state.messages[message.id] = message
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.MESSAGE_POSTED,
            {"message": message},
            group_id=mission.group_id,
        )

    def _amend_message(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: CorrectMessagePayload | RetractMessagePayload | RedactMessagePayload,
        command_hash: str,
        now: datetime,
        kind: MessageAmendmentKind,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        self._require_not_terminal_mission(mission)
        self._require_active_membership(state, mission.group_id, command.actor)
        message = state.messages.get(payload.message_id)
        if message is None or message.group_id != mission.group_id:
            raise NotFound("Message does not exist in this Group")
        if payload.amendment_id in state.message_amendments:
            raise AlreadyExists(
                "Message amendment ID already exists", amendment_id=payload.amendment_id
            )
        if kind is MessageAmendmentKind.REDACTION:
            self._require_owner_or_coordinator(state, mission, command, now)
        elif command.actor != message.author:
            raise AuthorizationDenied("only the Message author may correct or retract it")
        replacement = (
            payload.replacement_content if isinstance(payload, CorrectMessagePayload) else None
        )
        amendment = MessageAmendment(
            id=payload.amendment_id,
            group_id=mission.group_id,
            message_id=message.id,
            kind=kind,
            actor=command.actor,
            replacement_content=replacement,
            reason=payload.reason,
            created_at=now,
        )
        state.message_amendments[amendment.id] = amendment
        event_kind = {
            MessageAmendmentKind.CORRECTION: EventKind.MESSAGE_CORRECTED,
            MessageAmendmentKind.RETRACTION: EventKind.MESSAGE_RETRACTED,
            MessageAmendmentKind.REDACTION: EventKind.MESSAGE_REDACTED,
        }[kind]
        return self._emit(
            state,
            command,
            command_hash,
            now,
            event_kind,
            {"amendment": amendment},
            group_id=mission.group_id,
        )

    def _propose_work_item(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: ProposeWorkItemPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        self._require_active_membership(state, mission.group_id, command.actor)
        self._require_active_mission(mission)
        if payload.proposal_id in state.work_proposals:
            raise AlreadyExists("WorkProposal ID already exists", proposal_id=payload.proposal_id)
        if payload.contract.deadline > mission.deadline:
            raise PolicyViolation("proposed WorkItem deadline must fit within its Mission")
        if not mission.budget.contains(payload.contract.budget):
            raise PolicyViolation("proposed WorkItem budget must fit within its Mission")
        dependencies = tuple(sorted(set(payload.dependency_ids)))
        for dependency_id in dependencies:
            dependency = self._work_item(state, dependency_id, mission.group_id)
            if dependency.mission_id != mission.id:
                raise DependencyError("dependencies must belong to the same Mission")
        if payload.parent_work_item_id is not None:
            parent = self._work_item(state, payload.parent_work_item_id, mission.group_id)
            if parent.mission_id != mission.id:
                raise AuthorizationDenied("proposal parent WorkItem belongs to another Mission")
        proposal = WorkProposal(
            id=payload.proposal_id,
            mission_id=mission.id,
            group_id=mission.group_id,
            proposed_by=command.actor,
            contract=payload.contract,
            dependency_ids=dependencies,
            parent_work_item_id=payload.parent_work_item_id,
            created_at=now,
            updated_at=now,
        )
        state.work_proposals[proposal.id] = proposal
        self._touch_mission(mission, now)
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.WORK_ITEM_PROPOSED,
            {"proposal": proposal},
            group_id=mission.group_id,
        )

    def _create_work_item(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: CreateWorkItemPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        delegation = self._require_work_author(
            state,
            mission,
            command,
            now,
            payload.delegation_grant_id,
        )
        self._require_active_mission(mission)
        if payload.work_item_id in state.work_items:
            raise AlreadyExists("WorkItem ID already exists", work_item_id=payload.work_item_id)
        if payload.contract.deadline > mission.deadline:
            raise PolicyViolation("WorkItem deadline must fit within its Mission")
        if not mission.budget.contains(payload.contract.budget):
            raise PolicyViolation("WorkItem budget must fit within its Mission")
        for dependency_id in payload.dependency_ids:
            dependency = self._work_item(state, dependency_id, mission.group_id)
            if dependency.mission_id != mission.id:
                raise DependencyError("dependencies must belong to the same Mission")
        parent_work: WorkItem | None = None
        delegation_depth = 0
        if payload.parent_work_item_id is not None:
            parent_work = self._work_item(
                state,
                payload.parent_work_item_id,
                mission.group_id,
            )
            if parent_work.mission_id != mission.id:
                raise AuthorizationDenied("parent WorkItem belongs to another Mission")
            delegation_depth = parent_work.delegation_depth + 1
        if delegation is not None:
            if parent_work is None:
                raise AuthorizationDenied(
                    "delegated WorkItem authorization requires a parent WorkItem"
                )
            try:
                delegation_depth = delegation.authorize_descendant(
                    parent_work,
                    payload.contract,
                )
            except DelegationViolation as error:
                self._raise_delegation_violation(error)
        proposal: WorkProposal | None = None
        if payload.proposal_id is not None:
            proposal = state.work_proposals.get(payload.proposal_id)
            if proposal is None or proposal.group_id != mission.group_id:
                raise NotFound("WorkProposal does not exist in this Group")
            if proposal.status is not WorkProposalStatus.OPEN:
                raise InvalidTransition("WorkProposal is no longer open")
            if (
                proposal.contract != payload.contract
                or proposal.dependency_ids != tuple(sorted(set(payload.dependency_ids)))
                or proposal.parent_work_item_id != payload.parent_work_item_id
            ):
                raise RevisionConflict(
                    "authorized WorkItem must preserve proposed contract, dependencies, and scope"
                )
        ledger = self._budget_ledger(state)
        try:
            ledger.register_work_item(
                payload.work_item_id,
                mission.id,
                payload.contract.budget,
                parent_work_item_id=parent_work.id if parent_work is not None else None,
            )
        except BudgetLedgerError as error:
            raise BudgetExceeded(str(error), work_item_id=payload.work_item_id) from error
        state.budget_ledger = ledger.snapshot()
        conversation_id = f"{mission.group_id}:work:{payload.work_item_id}"
        work = WorkItem(
            id=payload.work_item_id,
            mission_id=mission.id,
            group_id=mission.group_id,
            conversation_id=conversation_id,
            created_by=proposal.proposed_by if proposal is not None else command.actor,
            contract=payload.contract,
            status=WorkItemStatus.OPEN,
            dependency_ids=tuple(sorted(set(payload.dependency_ids))),
            parent_work_item_id=parent_work.id if parent_work is not None else None,
            delegation_grant_id=(delegation.grant.id if delegation is not None else None),
            delegation_depth=delegation_depth,
            created_at=now,
            updated_at=now,
        )
        state.work_items[work.id] = work
        if proposal is not None:
            proposal.status = WorkProposalStatus.AUTHORIZED
            proposal.authorized_work_item_id = work.id
            proposal.updated_at = now
        state.conversations[conversation_id] = Conversation(
            id=conversation_id,
            group_id=mission.group_id,
            work_item_id=work.id,
            title=work.contract.goal,
            created_at=now,
        )
        self._touch_mission(mission, now)
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.WORK_ITEM_CREATED,
            {"workItem": work, "proposalId": payload.proposal_id},
            group_id=mission.group_id,
        )

    def _add_work_item_dependency(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: AddWorkItemDependencyPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        self._require_coordinator(state, mission, command, now)
        self._require_active_mission(mission)
        work = self._work_item(state, payload.work_item_id, mission.group_id)
        dependency = self._work_item(state, payload.dependency_id, mission.group_id)
        self._check_revision(work.revision, command)
        if work.status not in {
            WorkItemStatus.OPEN,
            WorkItemStatus.OFFERED,
            WorkItemStatus.QUEUED,
            WorkItemStatus.BLOCKED,
        }:
            self._invalid_transition("add dependency", work)
        if work.id == dependency.id:
            raise DependencyError("a WorkItem cannot depend on itself")
        if dependency.id in work.dependency_ids:
            raise AlreadyExists("dependency already exists", dependency_id=dependency.id)
        if self._dependency_reaches(state, dependency.id, work.id):
            raise DependencyError(
                "dependency would create a cycle",
                work_item_id=work.id,
                dependency_id=dependency.id,
            )
        work.dependency_ids = tuple(sorted((*work.dependency_ids, dependency.id)))
        self._touch_work(work, now)
        self._touch_mission(mission, now)
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.WORK_ITEM_DEPENDENCY_ADDED,
            {"workItemId": work.id, "dependencyId": dependency.id, "revision": work.revision},
            group_id=mission.group_id,
        )

    def _offer_work_item(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: OfferWorkItemPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        delegation = self._require_work_author(
            state,
            mission,
            command,
            now,
            payload.delegation_grant_id,
        )
        self._require_active_mission(mission)
        work = self._work_item(state, payload.work_item_id, mission.group_id)
        self._check_revision(work.revision, command)
        if delegation is not None:
            try:
                delegation.authorize_existing(work)
            except DelegationViolation as error:
                self._raise_delegation_violation(error)
            work.delegation_grant_id = delegation.grant.id
        if work.status in {
            WorkItemStatus.VERIFIED,
            WorkItemStatus.SUBMITTED,
            WorkItemStatus.CANCELLED,
        }:
            self._invalid_transition("offer", work)
        if work.assignee_id is not None:
            expiry = work.ownership_lease_expires_at
            if expiry is not None and expiry > now:
                raise InvalidTransition(
                    "exclusive WorkItem already has a live owner",
                    work_item_id=work.id,
                    assignee_id=work.assignee_id,
                )
            self._fence_work_owner(state, work, now)
        if work.status is WorkItemStatus.OFFERED and work.offer_expires_at is not None:
            candidates = set(work.offered_agent_ids) if work.offer_expires_at > now else set()
        else:
            candidates = set()
        for agent_id in payload.candidate_agent_ids:
            membership = self._membership(state, mission.group_id, Principal.agent(agent_id))
            if membership is None or membership.status is MembershipStatus.ENDED:
                raise AuthorizationDenied("candidate is not a Group member", agent_id=agent_id)
            if Role.WORKER not in membership.roles:
                raise AuthorizationDenied("candidate lacks the Worker role", agent_id=agent_id)
            card = self._require_agent_card(state, agent_id)
            if not card.supports(work.contract.required_capabilities):
                raise PolicyViolation(
                    "candidate does not satisfy Work Contract capabilities", agent_id=agent_id
                )
            candidates.add(agent_id)
        work.status = WorkItemStatus.OFFERED
        work.offered_agent_ids = tuple(sorted(candidates))
        work.offer_expires_at = now + timedelta(seconds=payload.offer_expires_in_seconds)
        work.selection_basis = payload.selection_basis
        work.failure_reason = None
        self._touch_work(work, now)
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.WORK_ITEM_OFFERED,
            {
                "workItemId": work.id,
                "candidateAgentIds": work.offered_agent_ids,
                "offerExpiresAt": work.offer_expires_at,
                "selectionBasis": payload.selection_basis,
            },
            group_id=mission.group_id,
        )

    def _accept_work_offer(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: AcceptWorkOfferPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        if command.actor.type is not ActorType.AGENT:
            raise AuthorizationDenied("only a Worker Agent may accept an offer")
        mission = self._mission_for_command(state, command)
        self._require_active_mission(mission)
        work = self._work_item(state, payload.work_item_id, mission.group_id)
        self._check_revision(work.revision, command)
        if work.status is not WorkItemStatus.OFFERED:
            self._invalid_transition("accept offer", work)
        if work.offer_expires_at is None or work.offer_expires_at <= now:
            raise LeaseExpired("WorkItem offer has expired", work_item_id=work.id)
        if command.actor.id not in work.offered_agent_ids:
            raise AuthorizationDenied("Agent was not offered this WorkItem")
        membership = self._membership(state, mission.group_id, command.actor)
        if membership is None or Role.WORKER not in membership.roles:
            raise AuthorizationDenied("Agent lacks a Worker Membership")
        if membership.status is MembershipStatus.ENDED:
            raise AuthorizationDenied("Agent Membership has ended")
        card = self._require_agent_card(state, command.actor.id)
        if not card.supports(work.contract.required_capabilities):
            raise PolicyViolation("Agent Card no longer satisfies the Work Contract")
        if membership.status is not MembershipStatus.ACTIVE:
            membership.status = MembershipStatus.ACTIVE
            membership.epoch += 1
        membership.ended_at = None
        work.status = WorkItemStatus.QUEUED
        work.assignee_id = command.actor.id
        work.ownership_epoch += 1
        work.ownership_lease_expires_at = now + timedelta(seconds=payload.ownership_lease_seconds)
        work.execution_lease_id = None
        work.execution_lease_expires_at = None
        work.assigned_agent_card_version = card.version
        work.assigned_capability_versions = {
            requirement.id: next(
                capability.version
                for capability in card.capabilities
                if capability.id == requirement.id
            )
            for requirement in work.contract.required_capabilities
        }
        work.offered_agent_ids = ()
        work.offer_expires_at = None
        self._touch_work(work, now)
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.WORK_OFFER_ACCEPTED,
            {
                "workItemId": work.id,
                "assigneeId": work.assignee_id,
                "ownershipEpoch": work.ownership_epoch,
                "ownershipLeaseExpiresAt": work.ownership_lease_expires_at,
                "agentCardVersion": card.version,
            },
            group_id=mission.group_id,
        )

    def _start_work_item(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: StartWorkItemPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        self._require_active_mission(mission)
        work = self._work_item(state, payload.work_item_id, mission.group_id)
        self._check_revision(work.revision, command)
        self._require_work_owner(work, command, payload.ownership_epoch, now)
        if work.status is not WorkItemStatus.QUEUED:
            self._invalid_transition("start", work)
        if work.execution_lease_id is not None or work.execution_lease_expires_at is not None:
            raise InvalidTransition(
                "queued WorkItem already projects an Execution Lease",
                work_item_id=work.id,
            )
        unfinished = [
            dependency_id
            for dependency_id in work.dependency_ids
            if state.work_items[dependency_id].status is not WorkItemStatus.VERIFIED
        ]
        if unfinished:
            raise DependencyError("WorkItem dependencies are not verified", dependencies=unfinished)
        if work.contract.execution_approval != "not_required":
            matching_approvals = [
                approval
                for approval in state.execution_approvals.values()
                if approval.work_item_id == work.id
                and approval.ownership_epoch == work.ownership_epoch
                and approval.expires_at > now
            ]
            if not matching_approvals:
                raise PolicyViolation("WorkItem requires a current Execution Approval")
        session_epoch = command.session_epoch
        if session_epoch is None:
            raise InvalidCommand("work.start requires an Agent Session Epoch")
        lease = ExecutionLease(
            lease_id=f"lease:execution:{uuid4()}",
            mission_id=mission.id,
            group_id=mission.group_id,
            work_item_id=work.id,
            holder_agent_id=command.actor.id,
            session_epoch=session_epoch,
            ownership_epoch=work.ownership_epoch,
            issued_at=now,
            starts_at=now,
            expires_at=now + timedelta(seconds=payload.execution_lease_seconds),
        )
        self._validate_execution_lease(lease)
        state.execution_leases[lease.lease_id] = lease
        work.status = WorkItemStatus.ACTIVE
        work.execution_lease_id = lease.lease_id
        work.execution_lease_expires_at = lease.expires_at
        if cast(datetime, work.ownership_lease_expires_at) < work.execution_lease_expires_at:
            work.ownership_lease_expires_at = work.execution_lease_expires_at
        self._touch_work(work, now)
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.WORK_ITEM_STARTED,
            {
                "workItemId": work.id,
                "ownershipEpoch": work.ownership_epoch,
                "executionLease": lease,
                "executionLeaseExpiresAt": work.execution_lease_expires_at,
            },
            group_id=mission.group_id,
        )

    def _grant_execution_approval(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: GrantExecutionApprovalPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        if command.actor.type is not ActorType.HUMAN:
            raise AuthorizationDenied("Execution Approval requires a human MissionOwner")
        self._require_mission_owner(state, mission, command)
        self._require_active_mission(mission)
        work = self._work_item(state, payload.work_item_id, mission.group_id)
        if work.status is not WorkItemStatus.QUEUED:
            self._invalid_transition("grant execution approval for", work)
        if work.assignee_id is None or work.ownership_lease_expires_at is None:
            raise InvalidTransition("Execution Approval requires a current WorkItem owner")
        if payload.ownership_epoch != work.ownership_epoch:
            raise StaleOwnershipEpoch(
                "Execution Approval targets a stale ownership epoch",
                expected=work.ownership_epoch,
                received=payload.ownership_epoch,
            )
        if payload.approval_id in state.execution_approvals:
            raise AlreadyExists(
                "Execution Approval ID already exists", approval_id=payload.approval_id
            )
        if not set(payload.operations).issubset(mission.permissions):
            raise PolicyViolation("Execution Approval operations exceed Mission permissions")
        if not set(payload.resources).issubset(work.contract.allowed_resources):
            raise PolicyViolation("Execution Approval resources exceed the Work Contract")
        if not work.contract.budget.contains(payload.budget):
            raise PolicyViolation("Execution Approval budget exceeds the Work Contract")
        expires_at = now + timedelta(seconds=payload.expires_in_seconds)
        if expires_at > work.ownership_lease_expires_at:
            raise PolicyViolation("Execution Approval cannot outlive WorkItem ownership")
        approval = ExecutionApproval(
            id=payload.approval_id,
            mission_id=mission.id,
            group_id=mission.group_id,
            work_item_id=work.id,
            ownership_epoch=work.ownership_epoch,
            operations=tuple(sorted(set(payload.operations))),
            resources=tuple(sorted(set(payload.resources))),
            budget=payload.budget,
            approver=command.actor,
            approved_at=now,
            expires_at=expires_at,
            comments=payload.comments,
            signature=cast(SignatureEnvelope, command.signature).value,
        )
        state.execution_approvals[approval.id] = approval
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.EXECUTION_APPROVAL_GRANTED,
            {"approval": approval},
            group_id=mission.group_id,
        )

    def _renew_execution_lease(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: RenewExecutionLeasePayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        work = self._work_item(state, payload.work_item_id, mission.group_id)
        self._check_revision(work.revision, command)
        self._require_work_owner(work, command, payload.ownership_epoch, now)
        if work.status is not WorkItemStatus.ACTIVE:
            self._invalid_transition("renew execution lease", work)
        lease = self._require_execution_lease(
            state,
            work,
            command,
            payload.execution_lease_id,
            now,
        )
        expiry = now + timedelta(seconds=payload.lease_seconds)
        try:
            renewed = lease.renew(at=now, expires_at=expiry)
        except ValueError as error:
            raise LeaseExpired(str(error), execution_lease_id=lease.lease_id) from error
        self._validate_execution_lease(renewed)
        state.execution_leases[renewed.lease_id] = renewed
        work.execution_lease_expires_at = renewed.expires_at
        work.ownership_lease_expires_at = expiry
        self._touch_work(work, now)
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.EXECUTION_LEASE_RENEWED,
            {
                "workItemId": work.id,
                "ownershipEpoch": work.ownership_epoch,
                "executionLease": renewed,
                "executionLeaseExpiresAt": renewed.expires_at,
            },
            group_id=mission.group_id,
        )

    def _record_resource_usage(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: RecordResourceUsagePayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        work = self._work_item(state, payload.work_item_id, mission.group_id)
        lease = self._execution_lease(state, payload.execution_lease_id)
        self._require_lease_scope(
            lease,
            mission=mission,
            work=work,
            ownership_epoch=payload.ownership_epoch,
        )
        if command.actor.type is ActorType.AGENT:
            self._require_work_owner(work, command, payload.ownership_epoch, now)
            if work.status is not WorkItemStatus.ACTIVE:
                self._invalid_transition("record resource usage for", work)
            self._require_execution_lease(
                state,
                work,
                command,
                payload.execution_lease_id,
                now,
            )
        else:
            self._require_system(command)

        ledger = self._budget_ledger(state)
        try:
            cumulative = ledger.consume(work.id, payload.usage_delta)
            remaining = ledger.remaining(work.id)
        except BudgetLedgerError as error:
            raise BudgetExceeded(str(error), work_item_id=work.id) from error
        state.budget_ledger = ledger.snapshot()
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.RESOURCE_USAGE_RECORDED,
            {
                "workItemId": work.id,
                "executionLeaseId": lease.lease_id,
                "ownershipEpoch": lease.ownership_epoch,
                "usageDelta": payload.usage_delta,
                "cumulativeUsage": cumulative,
                "remainingBudget": remaining,
            },
            group_id=mission.group_id,
        )

    def _checkpoint_work_item(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: CheckpointWorkItemPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        work = self._work_item(state, payload.work_item_id, mission.group_id)
        self._check_revision(work.revision, command)
        self._require_work_owner(work, command, payload.ownership_epoch, now)
        if work.status is not WorkItemStatus.ACTIVE:
            self._invalid_transition("checkpoint", work)
        self._require_execution_lease(
            state,
            work,
            command,
            payload.execution_lease_id,
            now,
        )
        work.checkpoints = (*work.checkpoints, payload.checkpoint)
        work.status = WorkItemStatus.QUEUED
        self._close_execution_lease(
            state,
            work,
            now,
            state_if_live=LeaseState.RELEASED,
            reason="Worker checkpointed and released its execution slot",
        )
        work.ownership_lease_expires_at = now + timedelta(seconds=payload.resume_within_seconds)
        self._touch_work(work, now)
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.WORK_ITEM_CHECKPOINTED,
            {
                "workItemId": work.id,
                "checkpoint": payload.checkpoint,
                "ownershipLeaseExpiresAt": work.ownership_lease_expires_at,
            },
            group_id=mission.group_id,
        )

    def _block_work_item(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: BlockWorkItemPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        work = self._work_item(state, payload.work_item_id, mission.group_id)
        self._check_revision(work.revision, command)
        self._require_work_owner(work, command, payload.ownership_epoch, now)
        if work.status is not WorkItemStatus.ACTIVE:
            self._invalid_transition("block", work)
        self._require_execution_lease(
            state,
            work,
            command,
            payload.execution_lease_id,
            now,
        )
        work.checkpoints = (*work.checkpoints, payload.checkpoint)
        work.status = WorkItemStatus.BLOCKED
        work.blocker = payload.reason
        self._close_execution_lease(
            state,
            work,
            now,
            state_if_live=LeaseState.RELEASED,
            reason="Worker blocked and released its execution slot",
        )
        work.ownership_lease_expires_at = now + timedelta(seconds=payload.blocked_lease_seconds)
        self._touch_work(work, now)
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.WORK_ITEM_BLOCKED,
            {
                "workItemId": work.id,
                "reason": payload.reason,
                "ownershipLeaseExpiresAt": work.ownership_lease_expires_at,
            },
            group_id=mission.group_id,
        )

    def _unblock_work_item(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: UnblockWorkItemPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        self._require_coordinator(state, mission, command, now)
        self._require_active_mission(mission)
        work = self._work_item(state, payload.work_item_id, mission.group_id)
        self._check_revision(work.revision, command)
        if work.status is not WorkItemStatus.BLOCKED:
            self._invalid_transition("unblock", work)
        if work.child_mission_id is not None:
            child = state.missions[work.child_mission_id]
            if child.status is not MissionStatus.APPROVED:
                raise InvalidTransition("a WorkItem cannot bypass its active child Mission")
        if (
            work.assignee_id is not None
            and work.ownership_lease_expires_at is not None
            and work.ownership_lease_expires_at > now
        ):
            work.status = WorkItemStatus.QUEUED
        else:
            self._fence_work_owner(state, work, now)
            work.status = WorkItemStatus.OPEN
        work.blocker = None
        self._touch_work(work, now)
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.WORK_ITEM_UNBLOCKED,
            {"workItemId": work.id, "status": work.status.value},
            group_id=mission.group_id,
        )

    def _publish_artifact(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: PublishArtifactPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        artifact = payload.artifact
        mission = self._mission_for_command(state, command)
        work = self._work_item(state, artifact.work_item_id, mission.group_id)
        self._require_work_owner(work, command, payload.ownership_epoch, now)
        if work.status is not WorkItemStatus.ACTIVE:
            self._invalid_transition("publish Artifact", work)
        self._require_execution_lease(
            state,
            work,
            command,
            payload.execution_lease_id,
            now,
        )
        if artifact.id in state.artifacts:
            raise AlreadyExists("Artifact ID already exists", artifact_id=artifact.id)
        if artifact.group_id != mission.group_id or artifact.mission_id != mission.id:
            raise InvalidCommand("Artifact provenance does not match the Command Group")
        if artifact.producing_agent_id != command.actor.id:
            raise AuthorizationDenied("Artifact producer must be the current WorkItem owner")
        if artifact.agent_card_version != work.assigned_agent_card_version:
            raise RevisionConflict(
                "Artifact Agent Card version differs from the pinned assignment version"
            )
        producer_card = self._require_agent_card(state, artifact.producing_agent_id)
        if not verify_canonical(
            artifact.signing_payload(),
            artifact.signature,
            producer_card.public_key,
        ):
            raise AuthorizationDenied("Artifact manifest signature is invalid")
        if artifact.created_at > now:
            raise InvalidCommand("Artifact creation time cannot be in the future")

        classification_rank = {
            "public": 0,
            "internal": 1,
            "confidential": 2,
            "restricted": 3,
        }
        for source_hash in artifact.source_artifact_hashes:
            sources = [
                source for source in state.artifacts.values() if source.content_hash == source_hash
            ]
            if not sources:
                raise NotFound(
                    "Artifact provenance source is not present in authoritative state",
                    source_artifact_hash=source_hash,
                )
            related_sources = []
            for source in sources:
                source_mission = state.missions.get(source.mission_id)
                if source_mission is None:
                    continue
                if (
                    source_mission.id == mission.id
                    or self._is_descendant(state, mission, source_mission.id)
                    or self._is_descendant(state, source_mission, mission.id)
                ):
                    related_sources.append(source)
            if not related_sources:
                raise AuthorizationDenied(
                    "Artifact provenance cannot cross unrelated Mission boundaries without "
                    "publication",
                    source_artifact_hash=source_hash,
                )
            required_rank = max(
                classification_rank[source.data_classification] for source in related_sources
            )
            if classification_rank[artifact.data_classification] < required_rank:
                raise PolicyViolation(
                    "derived Artifact cannot downgrade its source classification",
                    source_artifact_hash=source_hash,
                )
        state.artifacts[artifact.id] = artifact
        work.artifact_ids = tuple(sorted((*work.artifact_ids, artifact.id)))
        self._touch_work(work, now)
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.ARTIFACT_PUBLISHED,
            {"artifact": artifact},
            group_id=mission.group_id,
        )

    def _submit_work_item(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: SubmitWorkItemPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        work = self._work_item(state, payload.work_item_id, mission.group_id)
        self._check_revision(work.revision, command)
        self._require_work_owner(work, command, payload.ownership_epoch, now)
        if work.status is not WorkItemStatus.ACTIVE:
            self._invalid_transition("submit", work)
        self._require_execution_lease(
            state,
            work,
            command,
            payload.execution_lease_id,
            now,
        )
        for artifact_id in payload.artifact_ids:
            artifact = state.artifacts.get(artifact_id)
            if artifact is None or artifact.work_item_id != work.id:
                raise NotFound("submitted Artifact does not belong to the WorkItem")
        work.status = WorkItemStatus.SUBMITTED
        work.artifact_ids = tuple(sorted(set(payload.artifact_ids)))
        work.submission_evidence = payload.evidence
        self._close_execution_lease(
            state,
            work,
            now,
            state_if_live=LeaseState.RELEASED,
            reason="Worker submitted its result and released execution",
        )
        self._touch_work(work, now)
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.WORK_ITEM_SUBMITTED,
            {
                "workItemId": work.id,
                "artifactIds": work.artifact_ids,
                "evidence": payload.evidence,
            },
            group_id=mission.group_id,
        )

    def _verify_work_item(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: VerifyWorkItemPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        self._require_coordinator(state, mission, command, now)
        self._require_active_mission(mission)
        work = self._work_item(state, payload.work_item_id, mission.group_id)
        self._check_revision(work.revision, command)
        if work.status is not WorkItemStatus.SUBMITTED:
            self._invalid_transition("verify", work)
        if not all(evidence.success for evidence in payload.evidence):
            raise PolicyViolation("verification Evidence must be successful")
        work.status = WorkItemStatus.VERIFIED
        work.verification_evidence = payload.evidence
        work.ownership_lease_expires_at = None
        self._touch_work(work, now)
        self._touch_mission(mission, now)
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.WORK_ITEM_VERIFIED,
            {"workItemId": work.id, "evidence": payload.evidence},
            group_id=mission.group_id,
        )

    def _fail_work_item(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: FailWorkItemPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        work = self._work_item(state, payload.work_item_id, mission.group_id)
        if command.actor == Principal.agent(mission.coordinator_id):
            self._require_coordinator(state, mission, command, now)
        else:
            if payload.ownership_epoch is None or payload.execution_lease_id is None:
                raise InvalidCommand(
                    "Worker failure requires an ownership epoch and Execution Lease ID"
                )
            self._require_work_owner(work, command, payload.ownership_epoch, now)
            if work.status is not WorkItemStatus.ACTIVE:
                self._invalid_transition("fail", work)
            self._require_execution_lease(
                state,
                work,
                command,
                payload.execution_lease_id,
                now,
            )
        if work.status in {
            WorkItemStatus.VERIFIED,
            WorkItemStatus.FAILED,
            WorkItemStatus.CANCELLED,
        }:
            self._invalid_transition("fail", work)
        work.status = WorkItemStatus.FAILED
        work.failure_reason = payload.reason
        if work.execution_lease_id is not None:
            self._close_execution_lease(
                state,
                work,
                now,
                state_if_live=LeaseState.REVOKED,
                reason="WorkItem failed",
            )
        work.ownership_lease_expires_at = None
        self._touch_work(work, now)
        self._touch_mission(mission, now)
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.WORK_ITEM_FAILED,
            {"workItemId": work.id, "reason": payload.reason},
            group_id=mission.group_id,
        )

    def _cancel_work_item(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: CancelWorkItemPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        self._require_owner_or_coordinator(state, mission, command, now)
        work = self._work_item(state, payload.work_item_id, mission.group_id)
        if work.status in {
            WorkItemStatus.VERIFIED,
            WorkItemStatus.FAILED,
            WorkItemStatus.CANCELLED,
        }:
            self._invalid_transition("cancel", work)
        work.status = WorkItemStatus.CANCELLED
        work.failure_reason = payload.reason
        self._fence_work_owner(state, work, now)
        self._touch_work(work, now)
        self._touch_mission(mission, now)
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.WORK_ITEM_CANCELLED,
            {"workItemId": work.id, "reason": payload.reason},
            group_id=mission.group_id,
        )

    def _submit_mission(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: SubmitMissionPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        self._require_coordinator(state, mission, command, now)
        self._require_active_mission(mission)
        self._check_revision(mission.revision, command)
        work_items = [work for work in state.work_items.values() if work.mission_id == mission.id]
        if not work_items or any(
            work.status not in {WorkItemStatus.VERIFIED, WorkItemStatus.CANCELLED}
            for work in work_items
        ):
            raise InvalidTransition("all Mission WorkItems must be verified or cancelled")
        artifacts_by_hash = {
            artifact.content_hash: artifact
            for artifact in state.artifacts.values()
            if artifact.mission_id == mission.id
        }
        if any(value not in artifacts_by_hash for value in payload.artifact_hashes):
            raise NotFound("Mission submission references an unknown Artifact hash")
        mission.status = MissionStatus.AWAITING_APPROVAL
        mission.submitted_revision = mission.revision
        mission.submitted_artifact_hashes = tuple(sorted(set(payload.artifact_hashes)))
        mission.updated_at = now
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.MISSION_SUBMITTED,
            {
                "missionId": mission.id,
                "missionRevision": mission.submitted_revision,
                "artifactHashes": mission.submitted_artifact_hashes,
            },
            group_id=mission.group_id,
        )

    def _approve_mission(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: ApproveMissionPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        self._require_mission_owner(state, mission, command)
        if mission.status is not MissionStatus.AWAITING_APPROVAL:
            raise InvalidTransition("only a submitted Mission may be approved")
        if payload.mission_revision != mission.submitted_revision:
            raise RevisionConflict(
                "approval targets a different Mission revision",
                expected=mission.submitted_revision,
                received=payload.mission_revision,
            )
        if set(payload.artifact_hashes) != set(mission.submitted_artifact_hashes):
            raise RevisionConflict("approval must reference the exact submitted Artifact set")
        if payload.approval_id in state.approvals:
            raise AlreadyExists("Approval ID already exists", approval_id=payload.approval_id)
        approval = Approval(
            id=payload.approval_id,
            mission_id=mission.id,
            mission_revision=payload.mission_revision,
            artifact_hashes=tuple(sorted(set(payload.artifact_hashes))),
            acceptance_policy_version=payload.acceptance_policy_version,
            approver=command.actor,
            approved_at=now,
            comments=payload.comments,
            signature=cast(SignatureEnvelope, command.signature).value,
        )
        state.approvals[approval.id] = approval
        mission.status = MissionStatus.APPROVED
        mission.approved_artifact_hashes = approval.artifact_hashes
        mission.updated_at = now
        primary = self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.MISSION_APPROVED,
            {"approval": approval},
            group_id=mission.group_id,
        )
        if mission.parent_mission_id is not None and mission.parent_work_item_id is not None:
            parent = state.missions[mission.parent_mission_id]
            parent_work = state.work_items[mission.parent_work_item_id]
            parent_work.status = WorkItemStatus.VERIFIED
            parent_work.blocker = None
            parent_work.artifact_ids = tuple(
                sorted(
                    artifact.id
                    for artifact in state.artifacts.values()
                    if artifact.mission_id == mission.id
                    and artifact.content_hash in mission.approved_artifact_hashes
                )
            )
            parent_work.verification_evidence = (self._child_approval_evidence(mission, approval),)
            self._touch_work(parent_work, now)
            self._touch_mission(parent, now)
            self._emit(
                state,
                command,
                command_hash,
                now,
                EventKind.WORK_ITEM_VERIFIED,
                {
                    "workItemId": parent_work.id,
                    "childMissionId": mission.id,
                    "childApprovalId": approval.id,
                    "sourceEventId": primary.id,
                },
                group_id=parent.group_id,
            )
        return primary

    def _request_mission_changes(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: RequestMissionChangesPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        self._require_mission_owner(state, mission, command)
        if mission.status is not MissionStatus.AWAITING_APPROVAL:
            raise InvalidTransition("changes may only be requested for a submitted Mission")
        if payload.mission_revision != mission.submitted_revision:
            raise RevisionConflict("change request targets a different Mission revision")
        mission.status = MissionStatus.ACTIVE
        mission.revision += 1
        mission.submitted_revision = None
        mission.submitted_artifact_hashes = ()
        mission.updated_at = now
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.MISSION_CHANGES_REQUESTED,
            {
                "missionId": mission.id,
                "feedback": payload.feedback,
                "newRevision": mission.revision,
            },
            group_id=mission.group_id,
        )

    def _fail_mission_command(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: FailMissionPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        self._require_owner_or_coordinator(state, mission, command, now)
        self._require_not_terminal_mission(mission)
        self._mark_mission_failed(state, mission, payload.reason, now)
        primary = self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.MISSION_FAILED,
            {"missionId": mission.id, "reason": payload.reason},
            group_id=mission.group_id,
        )
        self._propagate_child_failure(state, mission, command, command_hash, now, primary.id)
        return primary

    def _cancel_mission(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: CancelMissionPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        mission = self._mission_for_command(state, command)
        if command.actor.type is not ActorType.SYSTEM:
            self._require_mission_owner(state, mission, command)
        self._require_not_terminal_mission(mission)
        self._mark_mission_cancelled(state, mission, payload.reason, now)
        primary = self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.MISSION_CANCELLED,
            {"missionId": mission.id, "reason": payload.reason},
            group_id=mission.group_id,
        )
        descendants = sorted(
            (
                child
                for child in state.missions.values()
                if self._is_descendant(state, child, mission.id)
                and child.status not in self._terminal_mission_statuses()
            ),
            key=lambda item: self._mission_depth(state, item),
            reverse=True,
        )
        for child in descendants:
            self._mark_mission_cancelled(
                state, child, f"parent Mission {mission.id} cancelled", now
            )
            self._emit(
                state,
                command,
                command_hash,
                now,
                EventKind.MISSION_CANCELLED,
                {
                    "missionId": child.id,
                    "reason": f"parent Mission {mission.id} cancelled",
                    "sourceEventId": primary.id,
                },
                group_id=child.group_id,
            )
        return primary

    def _archive_group(
        self,
        state: AuthoritativeState,
        command: Command,
        payload: ArchiveGroupPayload,
        command_hash: str,
        now: datetime,
    ) -> Event:
        self._require_system(command)
        if command.group_id is None:
            raise InvalidCommand("Group archival requires a Group")
        group = state.groups.get(command.group_id)
        if group is None:
            raise NotFound("Group does not exist", group_id=command.group_id)
        if group.archived_at is not None or group.archive_snapshot_id is not None:
            raise InvalidTransition("Group is already archived", group_id=group.id)
        mission = state.missions.get(group.mission_id)
        if mission is None:
            raise NotFound("Group Mission does not exist", mission_id=group.mission_id)
        if mission.status not in self._terminal_mission_statuses():
            raise InvalidTransition(
                "only a terminal Mission Group may be archived",
                mission_id=mission.id,
                status=mission.status.value,
            )

        snapshot = payload.snapshot
        self._validate_group_snapshot(state, group, snapshot, command.issued_at)
        if snapshot.snapshot_id in state.group_snapshots:
            raise AlreadyExists(
                "Group snapshot ID already exists", snapshot_id=snapshot.snapshot_id
            )
        state.group_snapshots[snapshot.snapshot_id] = snapshot.model_copy(deep=True)
        archived_group = group.model_copy(
            update={"archive_snapshot_id": snapshot.snapshot_id, "archived_at": now},
            deep=True,
        )
        state.groups[group.id] = archived_group
        self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.GROUP_SNAPSHOT_CREATED,
            {
                "snapshotId": snapshot.snapshot_id,
                "throughSequence": snapshot.through_sequence,
                "stateHash": snapshot.state_hash,
            },
            group_id=group.id,
        )
        return self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.GROUP_ARCHIVED,
            {
                "snapshotId": snapshot.snapshot_id,
                "archivedAt": now,
            },
            group_id=group.id,
        )

    def _validate_group_snapshot(
        self,
        state: AuthoritativeState,
        group: Group,
        snapshot: GroupSnapshot,
        command_time: datetime,
    ) -> None:
        if snapshot.created_by.type is not ActorType.SYSTEM:
            raise AuthorizationDenied("Group snapshot must be created by a system authority")
        try:
            self._schemas.validate("group-snapshot.schema.json", snapshot.protocol_document())
        except JSONSchemaValidationError as error:
            raise InvalidCommand(
                "Group snapshot does not conform to group-snapshot.schema.json",
                reason=error.message,
            ) from error
        if self._snapshot_authority_key_id is None or self._snapshot_authority_public_key is None:
            raise AuthorizationDenied("Group snapshot authority is not configured")
        if snapshot.signature.key_id != self._snapshot_authority_key_id:
            raise AuthorizationDenied(
                "Group snapshot signature key ID is not trusted",
                expected=self._snapshot_authority_key_id,
                received=snapshot.signature.key_id,
            )
        if not verify_canonical(
            snapshot.signing_payload(),
            snapshot.signature.value,
            self._snapshot_authority_public_key,
        ):
            raise AuthorizationDenied("Group snapshot signature is invalid")
        expected_group_id = GroupSnapshot.protocol_group_id(group.id)
        if snapshot.group_id != expected_group_id:
            raise InvalidCommand(
                "Group snapshot belongs to another Group",
                expected=expected_group_id,
                received=snapshot.group_id,
            )
        through_sequence = state.group_sequences.get(group.id, 0)
        if snapshot.through_sequence != through_sequence:
            raise RevisionConflict(
                "Group snapshot does not cover the current Group sequence",
                expected=through_sequence,
                received=snapshot.through_sequence,
            )
        ordered = tuple(
            sorted(state.events.get(group.id, ()), key=lambda event: int(event.sequence or 0))
        )
        expected_sequences = tuple(range(1, through_sequence + 1))
        actual_sequences = tuple(int(event.sequence or 0) for event in ordered)
        expected_event_ids = tuple(GroupSnapshot.protocol_event_id(event.id) for event in ordered)
        if actual_sequences != expected_sequences or snapshot.event_ids != expected_event_ids:
            raise InvalidCommand(
                "Group snapshot Event IDs do not match the contiguous authoritative history"
            )
        if snapshot.created_at < ordered[-1].occurred_at:
            raise InvalidCommand("Group snapshot predates its last covered Event")
        if snapshot.created_at > command_time:
            raise InvalidCommand("Group snapshot was created after the archive Command")
        if not snapshot.policy_log:
            raise InvalidCommand("Group snapshot requires a nonempty policy log")

    def _emit(
        self,
        state: AuthoritativeState,
        command: Command,
        command_hash: str,
        now: datetime,
        kind: EventKind,
        payload: Any,
        *,
        group_id: str | None = None,
    ) -> Event:
        sequence: int | None = None
        if group_id is not None:
            sequence = state.group_sequences.get(group_id, 0) + 1
            state.group_sequences[group_id] = sequence
        normalized_payload = cast(dict[str, Any], json.loads(canonical_json(payload)))
        event = Event(
            id=str(uuid4()),
            kind=kind,
            group_id=group_id,
            sequence=sequence,
            actor=command.actor,
            action_id=command.action_id,
            correlation_id=command.correlation_id,
            caused_by_event_id=command.caused_by_event_id,
            command_hash=command_hash,
            payload=normalized_payload,
            extensions=command.extensions,
            occurred_at=now,
        )
        if group_id is not None:
            state.events.setdefault(group_id, []).append(event)
        return event

    @staticmethod
    def _require_system(command: Command) -> None:
        if command.actor.type is not ActorType.SYSTEM:
            raise AuthorizationDenied("Command requires organization authority")

    @staticmethod
    def _require_command_group(command: Command, expected: str) -> None:
        if command.group_id != expected:
            raise InvalidCommand(
                "Command Group does not match payload Group",
                expected=expected,
                received=command.group_id,
            )

    @staticmethod
    def _require_new_ids(state: AuthoritativeState, mission_id: str, group_id: str) -> None:
        if mission_id in state.missions:
            raise AlreadyExists("Mission ID already exists", mission_id=mission_id)
        if group_id in state.groups:
            raise AlreadyExists("Group ID already exists", group_id=group_id)

    @staticmethod
    def _require_agent_card(state: AuthoritativeState, agent_id: str) -> AgentCard:
        card = state.agent_cards.get(agent_id)
        if card is None:
            raise NotFound("Agent is not registered", agent_id=agent_id)
        return card

    @staticmethod
    def _mission_for_command(state: AuthoritativeState, command: Command) -> Mission:
        if command.group_id is None:
            raise InvalidCommand("Command requires a Group")
        group = state.groups.get(command.group_id)
        if group is None:
            raise NotFound("Group does not exist", group_id=command.group_id)
        return state.missions[group.mission_id]

    @staticmethod
    def _work_item(state: AuthoritativeState, work_item_id: str, group_id: str) -> WorkItem:
        work = state.work_items.get(work_item_id)
        if work is None or work.group_id != group_id:
            raise NotFound("WorkItem does not exist in this Group", work_item_id=work_item_id)
        return work

    @staticmethod
    def _membership(
        state: AuthoritativeState, group_id: str, principal: Principal
    ) -> Membership | None:
        return state.memberships.get(membership_key(group_id, principal.type.value, principal.id))

    def _require_active_membership(
        self, state: AuthoritativeState, group_id: str, principal: Principal
    ) -> Membership:
        membership = self._membership(state, group_id, principal)
        if membership is None or membership.status is not MembershipStatus.ACTIVE:
            raise AuthorizationDenied(
                "actor lacks an active Group Membership", principal_id=principal.id
            )
        return membership

    def _require_role(
        self,
        state: AuthoritativeState,
        group_id: str,
        principal: Principal,
        roles: set[Role],
    ) -> Membership:
        membership = self._require_active_membership(state, group_id, principal)
        if not roles.intersection(membership.roles):
            raise AuthorizationDenied(
                "Membership lacks a required role",
                principal_id=principal.id,
                required=sorted(role.value for role in roles),
            )
        return membership

    def _require_mission_owner(
        self, state: AuthoritativeState, mission: Mission, command: Command
    ) -> None:
        if command.actor != mission.owner:
            raise AuthorizationDenied("Command requires the MissionOwner")
        self._require_role(state, mission.group_id, command.actor, {Role.MISSION_OWNER})

    def _require_coordinator(
        self,
        state: AuthoritativeState,
        mission: Mission,
        command: Command,
        now: datetime,
    ) -> None:
        if command.actor != Principal.agent(mission.coordinator_id):
            raise AuthorizationDenied("Command requires the current Coordinator")
        self._require_role(state, mission.group_id, command.actor, {Role.COORDINATOR})
        if command.coordinator_epoch != mission.coordinator_epoch:
            raise StaleCoordinatorEpoch(
                "Command carries a stale Coordinator epoch",
                expected=mission.coordinator_epoch,
                received=command.coordinator_epoch,
            )
        if mission.coordinator_lease_expires_at <= now:
            raise LeaseExpired("Coordinator lease has expired", mission_id=mission.id)

    def _require_owner_or_coordinator(
        self,
        state: AuthoritativeState,
        mission: Mission,
        command: Command,
        now: datetime,
    ) -> None:
        if command.actor == mission.owner:
            self._require_mission_owner(state, mission, command)
            return
        self._require_coordinator(state, mission, command, now)

    def _require_work_author(
        self,
        state: AuthoritativeState,
        mission: Mission,
        command: Command,
        now: datetime,
        delegation_grant_id: str | None,
    ) -> DelegationAuthority | None:
        if command.actor == Principal.agent(mission.coordinator_id):
            self._require_coordinator(state, mission, command, now)
            if delegation_grant_id is not None:
                raise InvalidCommand("Coordinator Commands must omit delegation_grant_id")
            return None
        if delegation_grant_id is None:
            raise AuthorizationDenied("work_delegate role requires an explicit Delegation Grant ID")
        grant = state.delegation_grants.get(delegation_grant_id)
        if grant is None:
            raise AuthorizationDenied(
                "Delegation Grant is missing, unknown, or forged",
                delegation_grant_id=delegation_grant_id,
            )
        membership = self._membership(state, mission.group_id, command.actor)
        try:
            return DelegationAuthority(
                grant,
                actor=command.actor,
                mission=mission,
                membership=membership,
                work_items=state.work_items,
                now=now,
            )
        except DelegationViolation as error:
            self._raise_delegation_violation(error)

    @staticmethod
    def _raise_delegation_violation(error: DelegationViolation) -> Never:
        if error.kind is DelegationViolationKind.COORDINATOR_EPOCH:
            raise StaleCoordinatorEpoch(str(error)) from error
        if error.kind is DelegationViolationKind.MEMBERSHIP_EPOCH:
            raise StaleMembershipEpoch(str(error)) from error
        if error.kind is DelegationViolationKind.EXPIRED:
            raise LeaseExpired(str(error)) from error
        if error.kind in {
            DelegationViolationKind.CAPABILITY,
            DelegationViolationKind.BUDGET,
            DelegationViolationKind.DEPTH,
        }:
            raise PolicyViolation(str(error)) from error
        raise AuthorizationDenied(str(error)) from error

    @staticmethod
    def _require_active_mission(mission: Mission) -> None:
        if mission.status is not MissionStatus.ACTIVE:
            raise InvalidTransition(
                "Mission must be active", mission_id=mission.id, status=mission.status.value
            )

    @classmethod
    def _require_not_terminal_mission(cls, mission: Mission) -> None:
        if mission.status in cls._terminal_mission_statuses():
            raise InvalidTransition(
                "Mission is terminal", mission_id=mission.id, status=mission.status.value
            )

    @staticmethod
    def _terminal_mission_statuses() -> set[MissionStatus]:
        return {MissionStatus.APPROVED, MissionStatus.FAILED, MissionStatus.CANCELLED}

    @staticmethod
    def _check_revision(current: int, command: Command) -> None:
        if command.expected_revision is not None and command.expected_revision != current:
            raise RevisionConflict(
                "Command targets a stale entity revision",
                expected=current,
                received=command.expected_revision,
            )

    @staticmethod
    def _invalid_transition(action: str, work: WorkItem) -> None:
        raise InvalidTransition(
            f"cannot {action} WorkItem in {work.status.value} state",
            work_item_id=work.id,
            status=work.status.value,
        )

    @staticmethod
    def _touch_work(work: WorkItem, now: datetime) -> None:
        work.revision += 1
        work.updated_at = now

    @staticmethod
    def _touch_mission(mission: Mission, now: datetime) -> None:
        mission.revision += 1
        mission.updated_at = now

    def _upsert_membership(
        self,
        state: AuthoritativeState,
        group_id: str,
        principal: Principal,
        roles: tuple[Role, ...],
        status: MembershipStatus,
        now: datetime,
        *,
        visibility_after_sequence: int = 0,
    ) -> Membership:
        key = membership_key(group_id, principal.type.value, principal.id)
        existing = state.memberships.get(key)
        if existing is None:
            existing = Membership(
                group_id=group_id,
                principal=principal,
                roles=roles,
                status=status,
                visibility_after_sequence=visibility_after_sequence,
                joined_at=now,
            )
            state.memberships[key] = existing
            return existing
        existing.roles = tuple(sorted(set((*existing.roles, *roles)), key=lambda role: role.value))
        existing.epoch += 1
        existing.status = status
        existing.visibility_after_sequence = visibility_after_sequence
        existing.ended_at = None
        return existing

    def _remove_membership_role(
        self,
        state: AuthoritativeState,
        group_id: str,
        principal: Principal,
        role: Role,
        now: datetime,
    ) -> None:
        membership = self._membership(state, group_id, principal)
        if membership is None:
            return
        remaining = tuple(item for item in membership.roles if item is not role)
        if remaining:
            membership.roles = remaining
            membership.epoch += 1
        else:
            # Retain the historical role on an ended Membership. The domain requires every
            # Membership record to describe at least one role, including its audit tombstone.
            membership.status = MembershipStatus.ENDED
            membership.epoch += 1
            membership.ended_at = now

    @staticmethod
    def _dependency_reaches(state: AuthoritativeState, start_id: str, target_id: str) -> bool:
        pending = [start_id]
        visited: set[str] = set()
        while pending:
            current = pending.pop()
            if current == target_id:
                return True
            if current in visited:
                continue
            visited.add(current)
            work = state.work_items.get(current)
            if work is not None:
                pending.extend(work.dependency_ids)
        return False

    @staticmethod
    def _budget_ledger(state: AuthoritativeState) -> BudgetLedger:
        return BudgetLedger.rebuild(state.budget_ledger)

    def _ensure_budget_ledger(self, state: AuthoritativeState) -> None:
        snapshot = state.budget_ledger
        mission_ids = {account.mission_id for account in snapshot.missions}
        work_item_ids = {account.work_item_id for account in snapshot.work_items}
        expected_missions = set(state.missions)
        expected_work_items = set(state.work_items)
        if mission_ids == expected_missions and work_item_ids == expected_work_items:
            try:
                ledger = BudgetLedger.rebuild(snapshot)
            except BudgetLedgerError as error:
                raise BudgetExceeded("authoritative budget ledger is invalid") from error
            state.budget_ledger = ledger.snapshot()
            return
        if mission_ids or work_item_ids:
            raise BudgetExceeded(
                "authoritative budget ledger coverage does not match durable state",
                missing_missions=sorted(expected_missions - mission_ids),
                missing_work_items=sorted(expected_work_items - work_item_ids),
            )

        ledger = BudgetLedger()
        pending_missions = dict(state.missions)
        pending_work_items = dict(state.work_items)
        registered_missions: set[str] = set()
        registered_work_items: set[str] = set()
        while pending_missions or pending_work_items:
            progressed = False
            for mission_id in sorted(tuple(pending_missions)):
                mission = pending_missions[mission_id]
                if (
                    mission.parent_mission_id is not None
                    and mission.parent_mission_id not in registered_missions
                ):
                    continue
                if (
                    mission.parent_work_item_id is not None
                    and mission.parent_work_item_id not in registered_work_items
                ):
                    continue
                try:
                    ledger.register_mission(
                        mission.id,
                        mission.budget,
                        parent_mission_id=mission.parent_mission_id,
                        parent_work_item_id=mission.parent_work_item_id,
                    )
                except BudgetLedgerError as error:
                    raise BudgetExceeded(
                        "legacy authoritative state cannot be backfilled into the budget ledger",
                        mission_id=mission.id,
                    ) from error
                registered_missions.add(mission.id)
                del pending_missions[mission_id]
                progressed = True
            for work_item_id in sorted(tuple(pending_work_items)):
                work = pending_work_items[work_item_id]
                if work.mission_id not in registered_missions:
                    continue
                if (
                    work.parent_work_item_id is not None
                    and work.parent_work_item_id not in registered_work_items
                ):
                    continue
                try:
                    ledger.register_work_item(
                        work.id,
                        work.mission_id,
                        work.contract.budget,
                        parent_work_item_id=work.parent_work_item_id,
                    )
                except BudgetLedgerError as error:
                    raise BudgetExceeded(
                        "legacy authoritative state cannot be backfilled into the budget ledger",
                        work_item_id=work.id,
                    ) from error
                registered_work_items.add(work.id)
                del pending_work_items[work_item_id]
                progressed = True
            if not progressed:
                raise BudgetExceeded(
                    "legacy authoritative budget hierarchy contains missing references or a cycle"
                )
        state.budget_ledger = ledger.snapshot()

    @staticmethod
    def _require_work_owner(
        work: WorkItem, command: Command, ownership_epoch: int, now: datetime
    ) -> None:
        if command.actor.type is not ActorType.AGENT or command.actor.id != work.assignee_id:
            raise AuthorizationDenied("Command requires the current WorkItem owner")
        if ownership_epoch != work.ownership_epoch:
            raise StaleOwnershipEpoch(
                "Command carries a stale ownership epoch",
                expected=work.ownership_epoch,
                received=ownership_epoch,
            )
        if work.ownership_lease_expires_at is None or work.ownership_lease_expires_at <= now:
            raise LeaseExpired("WorkItem ownership lease has expired", work_item_id=work.id)

    @staticmethod
    def _execution_lease(state: AuthoritativeState, lease_id: str) -> ExecutionLease:
        lease = state.execution_leases.get(lease_id)
        if lease is None:
            raise LeaseExpired("Execution Lease does not exist", execution_lease_id=lease_id)
        return lease

    @staticmethod
    def _require_lease_scope(
        lease: ExecutionLease,
        *,
        mission: Mission,
        work: WorkItem,
        ownership_epoch: int,
    ) -> None:
        if (
            lease.mission_id != mission.id
            or lease.group_id != mission.group_id
            or lease.work_item_id != work.id
        ):
            raise AuthorizationDenied("Execution Lease belongs to another scope")
        if lease.ownership_epoch != ownership_epoch:
            raise StaleOwnershipEpoch(
                "Execution Lease carries a stale ownership epoch",
                expected=work.ownership_epoch,
                received=lease.ownership_epoch,
            )

    def _require_execution_lease(
        self,
        state: AuthoritativeState,
        work: WorkItem,
        command: Command,
        lease_id: str,
        now: datetime,
    ) -> ExecutionLease:
        if work.execution_lease_id != lease_id:
            raise LeaseExpired(
                "Command carries a stale Execution Lease ID",
                expected=work.execution_lease_id,
                received=lease_id,
            )
        lease = self._execution_lease(state, lease_id)
        mission = state.missions[work.mission_id]
        self._require_lease_scope(
            lease,
            mission=mission,
            work=work,
            ownership_epoch=work.ownership_epoch,
        )
        if command.actor.type is not ActorType.AGENT or command.actor.id != lease.holder_agent_id:
            raise AuthorizationDenied("Command actor does not hold the Execution Lease")
        if command.session_epoch != lease.session_epoch:
            raise StaleSessionEpoch(
                "Execution Lease belongs to a replaced Agent Session",
                expected=lease.session_epoch,
                received=command.session_epoch,
            )
        if lease.state is not LeaseState.ACTIVE:
            raise LeaseExpired(
                "Execution Lease is no longer active",
                execution_lease_id=lease.lease_id,
                state=lease.state.value,
            )
        if lease.expires_at <= now:
            raise LeaseExpired(
                "WorkItem execution lease has expired",
                work_item_id=work.id,
                execution_lease_id=lease.lease_id,
            )
        if work.execution_lease_expires_at != lease.expires_at:
            raise LeaseExpired("WorkItem Execution Lease projection is inconsistent")
        return lease

    def _validate_execution_lease(self, lease: ExecutionLease) -> None:
        try:
            self._schemas.validate(
                "lease.schema.json",
                lease.model_dump(mode="json", by_alias=True, exclude_none=True),
            )
        except JSONSchemaValidationError as error:
            raise InvalidCommand("Execution Lease does not match lease.schema.json") from error

    def _close_execution_lease(
        self,
        state: AuthoritativeState,
        work: WorkItem,
        now: datetime,
        *,
        state_if_live: LeaseState,
        reason: str,
    ) -> ExecutionLease | None:
        lease_id = work.execution_lease_id
        if lease_id is None:
            work.execution_lease_expires_at = None
            return None
        lease = self._execution_lease(state, lease_id)
        if lease.state is LeaseState.ACTIVE:
            if lease.expires_at <= now:
                terminal = LeaseState.EXPIRED
                closed_at = lease.expires_at
                closure_reason = f"{reason}; lease had reached its expiry"
            else:
                terminal = state_if_live
                closed_at = now
                closure_reason = reason
            lease = lease.close(terminal, at=closed_at, reason=closure_reason)
            self._validate_execution_lease(lease)
            state.execution_leases[lease.lease_id] = lease
        work.execution_lease_id = None
        work.execution_lease_expires_at = None
        return lease

    def _fence_work_owner(
        self,
        state: AuthoritativeState,
        work: WorkItem,
        now: datetime,
    ) -> None:
        self._close_execution_lease(
            state,
            work,
            now,
            state_if_live=LeaseState.REVOKED,
            reason="WorkItem ownership was fenced",
        )
        if work.assignee_id is not None:
            work.ownership_epoch += 1
        work.assignee_id = None
        work.assigned_agent_card_version = None
        work.assigned_capability_versions = {}
        work.ownership_lease_expires_at = None
        work.offered_agent_ids = ()
        work.offer_expires_at = None
        work.updated_at = now

    @staticmethod
    def _child_approval_evidence(mission: Mission, approval: Approval) -> Any:
        from .models import Evidence

        return Evidence(
            kind="child_mission_approval",
            description=f"Child Mission {mission.id} approved as {approval.id}",
            success=True,
            data={"childMissionId": mission.id, "approvalId": approval.id},
        )

    def _mark_mission_failed(
        self, state: AuthoritativeState, mission: Mission, reason: str, now: datetime
    ) -> None:
        mission.status = MissionStatus.FAILED
        mission.failure_reason = reason
        mission.updated_at = now
        for work in state.work_items.values():
            if work.mission_id == mission.id and work.status not in {
                WorkItemStatus.VERIFIED,
                WorkItemStatus.FAILED,
                WorkItemStatus.CANCELLED,
            }:
                work.status = WorkItemStatus.FAILED
                work.failure_reason = reason
                self._fence_work_owner(state, work, now)
                self._touch_work(work, now)

    def _mark_mission_cancelled(
        self, state: AuthoritativeState, mission: Mission, reason: str, now: datetime
    ) -> None:
        mission.status = MissionStatus.CANCELLED
        mission.failure_reason = reason
        mission.updated_at = now
        for work in state.work_items.values():
            if work.mission_id == mission.id and work.status not in {
                WorkItemStatus.VERIFIED,
                WorkItemStatus.FAILED,
                WorkItemStatus.CANCELLED,
            }:
                work.status = WorkItemStatus.CANCELLED
                work.failure_reason = reason
                self._fence_work_owner(state, work, now)
                self._touch_work(work, now)

    def _propagate_child_failure(
        self,
        state: AuthoritativeState,
        child: Mission,
        command: Command,
        command_hash: str,
        now: datetime,
        source_event_id: str,
    ) -> None:
        if child.parent_mission_id is None or child.parent_work_item_id is None:
            return
        parent = state.missions[child.parent_mission_id]
        parent_work = state.work_items[child.parent_work_item_id]
        reason = f"child Mission {child.id} failed: {child.failure_reason}"
        if child.child_failure_policy is ChildFailurePolicy.BLOCK_PARENT_WORK_ITEM:
            parent_work.status = WorkItemStatus.BLOCKED
            parent_work.blocker = reason
            self._fence_work_owner(state, parent_work, now)
            self._touch_work(parent_work, now)
            self._touch_mission(parent, now)
            self._emit(
                state,
                command,
                command_hash,
                now,
                EventKind.WORK_ITEM_BLOCKED,
                {
                    "workItemId": parent_work.id,
                    "reason": reason,
                    "sourceEventId": source_event_id,
                },
                group_id=parent.group_id,
            )
            return
        parent_work.status = WorkItemStatus.FAILED
        parent_work.failure_reason = reason
        self._fence_work_owner(state, parent_work, now)
        self._touch_work(parent_work, now)
        self._touch_mission(parent, now)
        failed_work_event = self._emit(
            state,
            command,
            command_hash,
            now,
            EventKind.WORK_ITEM_FAILED,
            {
                "workItemId": parent_work.id,
                "reason": reason,
                "sourceEventId": source_event_id,
            },
            group_id=parent.group_id,
        )
        if child.child_failure_policy is ChildFailurePolicy.FAIL_PARENT_MISSION:
            self._mark_mission_failed(state, parent, reason, now)
            parent_event = self._emit(
                state,
                command,
                command_hash,
                now,
                EventKind.MISSION_FAILED,
                {
                    "missionId": parent.id,
                    "reason": reason,
                    "sourceEventId": failed_work_event.id,
                },
                group_id=parent.group_id,
            )
            self._propagate_child_failure(
                state, parent, command, command_hash, now, parent_event.id
            )

    @staticmethod
    def _is_descendant(state: AuthoritativeState, candidate: Mission, ancestor_id: str) -> bool:
        parent_id = candidate.parent_mission_id
        while parent_id is not None:
            if parent_id == ancestor_id:
                return True
            parent_id = state.missions[parent_id].parent_mission_id
        return False

    @staticmethod
    def _mission_depth(state: AuthoritativeState, mission: Mission) -> int:
        depth = 0
        parent_id = mission.parent_mission_id
        while parent_id is not None:
            depth += 1
            parent_id = state.missions[parent_id].parent_mission_id
        return depth
