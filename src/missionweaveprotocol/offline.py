"""Bounded reversible progress for one disconnected active WorkItem."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, cast

from pydantic import AwareDatetime, Field, JsonValue, ValidationError, model_validator

from .auth import AgentIdentity, default_agent_key_id
from .canonical import canonical_bytes
from .local_store import LocalStoreError, SQLiteAgentStore
from .models import (
    CheckpointWorkItemPayload,
    Command,
    CommandKind,
    ExtensionEnvelope,
    Identifier,
    PostMessagePayload,
    Principal,
    ProtocolModel,
    ResourceUsage,
    WorkItem,
    WorkItemStatus,
)

Clock = Callable[[], datetime]

OFFLINE_EXECUTION_EXTENSION = "urn:missionweaveprotocol:extension:bounded-offline-execution"
OFFLINE_EXECUTION_EXTENSION_VERSION = "0.1.0"
_REVERSIBLE_KINDS = frozenset(
    {
        CommandKind.POST_MESSAGE,
        CommandKind.CHECKPOINT_WORK_ITEM,
    }
)


class OfflinePolicyError(ValueError):
    """Disconnected progress violates the active lease, binding, or resource policy."""


class OfflineProgressBinding(ProtocolModel):
    """Authoritative evidence binding one buffered action to its disconnected lease window."""

    agent_id: Identifier
    group_id: Identifier
    work_item_id: Identifier
    session_epoch: Annotated[int, Field(gt=0)]
    ownership_epoch: Annotated[int, Field(gt=0)]
    execution_lease_id: Identifier
    disconnected_at: AwareDatetime
    buffered_at: AwareDatetime
    grace_deadline: AwareDatetime
    execution_lease_expires_at: AwareDatetime
    resource_usage_delta: ResourceUsage = Field(default_factory=ResourceUsage)

    @model_validator(mode="after")
    def window_is_ordered(self) -> OfflineProgressBinding:
        if self.disconnected_at > self.buffered_at:
            raise ValueError("offline progress cannot predate disconnection")
        if self.buffered_at >= self.grace_deadline:
            raise ValueError("offline progress must precede its grace deadline")
        if self.grace_deadline > self.execution_lease_expires_at:
            raise ValueError("offline grace cannot exceed the Execution Lease")
        if self.resource_usage_delta.external_actions:
            raise ValueError("offline progress cannot consume external actions")
        return self


@dataclass(frozen=True, slots=True)
class OfflineLimits:
    """Organization-selected bounds for one disconnected execution window."""

    max_disconnect_grace: timedelta
    max_actions: int
    max_usage: ResourceUsage

    def __post_init__(self) -> None:
        if self.max_disconnect_grace <= timedelta(0):
            raise ValueError("offline disconnect grace must be positive")
        if self.max_actions < 1:
            raise ValueError("offline action limit must be positive")


class OfflineExecutionPolicy:
    """Validate, sign, and durably buffer reversible progress for one active assignment."""

    def __init__(
        self,
        store: SQLiteAgentStore,
        identity: AgentIdentity,
        work_item: WorkItem,
        *,
        disconnected_at: datetime,
        limits: OfflineLimits,
        clock: Clock | None = None,
    ) -> None:
        self._store = store
        self._identity = identity
        self._clock = clock or (lambda: datetime.now(UTC))
        self._disconnected_at = _aware_utc(disconnected_at, "disconnect time")
        self._max_actions = limits.max_actions
        self._max_usage = limits.max_usage.model_copy(deep=True)
        self._usage = ResourceUsage()
        self._buffered: dict[str, tuple[Command, ResourceUsage]] = {}

        if work_item.status is not WorkItemStatus.ACTIVE:
            raise OfflinePolicyError("offline execution requires an already-active WorkItem")
        if work_item.assignee_id != identity.agent_id:
            raise OfflinePolicyError("offline WorkItem is not assigned to the signing Agent")
        if work_item.ownership_epoch < 1:
            raise OfflinePolicyError("offline WorkItem requires a current Ownership Epoch")
        if work_item.execution_lease_id is None or work_item.execution_lease_expires_at is None:
            raise OfflinePolicyError("offline WorkItem requires a current execution lease")

        self._agent_id = identity.agent_id
        self._group_id = work_item.group_id
        self._work_item_id = work_item.id
        self._conversation_id = work_item.conversation_id
        self._ownership_epoch = work_item.ownership_epoch
        self._execution_lease_id = work_item.execution_lease_id
        self._execution_lease_expires_at = _aware_utc(
            work_item.execution_lease_expires_at,
            "execution lease expiry",
        )
        self._grace_deadline = min(
            self._disconnected_at + limits.max_disconnect_grace,
            self._execution_lease_expires_at,
        )

        now = self._now()
        if self._disconnected_at > now:
            raise OfflinePolicyError("disconnect time cannot be in the future")
        self._require_current_window(now)

    @property
    def grace_deadline(self) -> datetime:
        return self._grace_deadline

    @property
    def buffered_actions(self) -> int:
        return len(self._buffered)

    @property
    def cumulative_usage(self) -> ResourceUsage:
        return self._usage.model_copy(deep=True)

    def buffer(
        self,
        command: Command,
        *,
        usage: ResourceUsage | None = None,
    ) -> Command:
        """Enqueue one canonically signed reversible Command within the current window."""

        now = self._now()
        self._require_current_window(now)
        delta = (usage or ResourceUsage()).model_copy(deep=True)
        if delta.external_actions:
            raise OfflinePolicyError("external actions are forbidden during offline execution")
        self._validate_command(command, now)
        signed = self._sign_bound_command(command, delta, buffered_at=now)

        previous = self._buffered.get(command.action_id)
        if previous is not None:
            previous_command, previous_usage = previous
            if previous_command != signed or previous_usage != delta:
                raise OfflinePolicyError("offline action ID collision")
            return previous_command
        if self.buffered_actions >= self._max_actions:
            raise OfflinePolicyError("offline action limit exceeded")

        next_usage = _add_usage(self._usage, delta)
        _require_within_usage_limit(next_usage, self._max_usage)
        try:
            self._store.enqueue_action(
                self._agent_id,
                signed.action_id,
                signed.model_dump(mode="json", by_alias=True),
            )
        except LocalStoreError as error:
            raise OfflinePolicyError(str(error)) from error
        self._buffered[signed.action_id] = (signed, delta)
        self._usage = next_usage
        return signed

    def _validate_command(self, command: Command, now: datetime) -> None:
        if command.kind not in _REVERSIBLE_KINDS:
            raise OfflinePolicyError(f"{command.kind.value} is not reversible offline progress")
        if command.actor != Principal.agent(self._agent_id):
            raise OfflinePolicyError("offline Command Agent does not match the active assignment")
        if command.session_epoch is None:
            raise OfflinePolicyError("offline Command requires its active Session Epoch")
        if command.group_id != self._group_id:
            raise OfflinePolicyError("offline Command Group does not match the active assignment")
        issued_at = _aware_utc(command.issued_at, "offline Command issue time")
        if issued_at < self._disconnected_at or issued_at > now:
            raise OfflinePolicyError("offline Command was not issued during the disconnect window")
        if OFFLINE_EXECUTION_EXTENSION in command.extensions:
            raise OfflinePolicyError("offline execution extension is reserved for the policy")

        try:
            if command.kind is CommandKind.POST_MESSAGE:
                message_payload = PostMessagePayload.model_validate(command.payload)
                if message_payload.conversation_id != self._conversation_id:
                    raise OfflinePolicyError(
                        "offline progress Message is outside the active WorkItem Conversation"
                    )
                return
            checkpoint_payload = CheckpointWorkItemPayload.model_validate(command.payload)
        except ValidationError as error:
            raise OfflinePolicyError("offline reversible Command payload is invalid") from error
        if checkpoint_payload.work_item_id != self._work_item_id:
            raise OfflinePolicyError(
                "offline Command WorkItem does not match the active assignment"
            )
        if checkpoint_payload.ownership_epoch != self._ownership_epoch:
            raise OfflinePolicyError("offline Command carries a stale Ownership Epoch")
        if checkpoint_payload.execution_lease_id != self._execution_lease_id:
            raise OfflinePolicyError("offline Command carries a stale Execution Lease ID")
        checkpoint_time = _aware_utc(
            checkpoint_payload.checkpoint.created_at,
            "offline checkpoint time",
        )
        if checkpoint_time < self._disconnected_at or checkpoint_time > now:
            raise OfflinePolicyError(
                "offline checkpoint was not created during the disconnect window"
            )

    def _sign_bound_command(
        self,
        command: Command,
        usage: ResourceUsage,
        *,
        buffered_at: datetime,
    ) -> Command:
        binding = OfflineProgressBinding(
            agent_id=self._agent_id,
            group_id=self._group_id,
            work_item_id=self._work_item_id,
            session_epoch=cast(int, command.session_epoch),
            ownership_epoch=self._ownership_epoch,
            execution_lease_id=self._execution_lease_id,
            disconnected_at=self._disconnected_at,
            buffered_at=buffered_at,
            grace_deadline=self._grace_deadline,
            execution_lease_expires_at=self._execution_lease_expires_at,
            resource_usage_delta=usage,
        )
        extensions = dict(command.extensions)
        extensions[OFFLINE_EXECUTION_EXTENSION] = ExtensionEnvelope(
            version=OFFLINE_EXECUTION_EXTENSION_VERSION,
            critical=True,
            data=cast(
                JsonValue,
                binding.model_dump(mode="json", by_alias=True),
            ),
        )
        unsigned = command.model_copy(update={"extensions": extensions, "signature": None})
        signature = self._identity.sign(canonical_bytes(unsigned.signing_payload()))
        return unsigned.model_copy(update={"signature": signature})

    def _require_current_window(self, now: datetime) -> None:
        if now >= self._execution_lease_expires_at:
            raise OfflinePolicyError("offline execution lease has expired")
        if now >= self._grace_deadline:
            raise OfflinePolicyError("offline disconnect grace has expired")

    def _now(self) -> datetime:
        return _aware_utc(self._clock(), "offline policy clock")


def rebase_offline_command(
    command: Command,
    identity: AgentIdentity,
    *,
    session_epoch: int,
    membership_epoch: int,
    issued_at: datetime | None = None,
    execution_lease_id: str | None = None,
) -> Command:
    """Bind buffered progress to a current session without rewriting its offline evidence."""

    if command.kind not in _REVERSIBLE_KINDS:
        raise OfflinePolicyError(f"{command.kind.value} is not an offline wire Command")
    if command.actor != Principal.agent(identity.agent_id) or command.group_id is None:
        raise OfflinePolicyError("offline Command identity or Group does not match")
    if session_epoch < 1:
        raise OfflinePolicyError("offline Command requires a current Session epoch")
    if membership_epoch < 1:
        raise OfflinePolicyError("offline Command requires a current Membership epoch")
    envelope = command.extensions.get(OFFLINE_EXECUTION_EXTENSION)
    if envelope is None:
        raise OfflinePolicyError("offline Command is missing its execution binding")
    if envelope.version != OFFLINE_EXECUTION_EXTENSION_VERSION or not envelope.critical:
        raise OfflinePolicyError("offline Command execution binding is unsupported")
    try:
        binding = OfflineProgressBinding.model_validate(envelope.data)
    except ValidationError as error:
        raise OfflinePolicyError("offline Command execution binding is invalid") from error

    reconciliation_time = _aware_utc(
        issued_at or datetime.now(UTC),
        "offline reconciliation time",
    )
    if reconciliation_time < binding.buffered_at:
        raise OfflinePolicyError("offline reconciliation cannot predate buffered progress")

    payload = dict(command.payload)
    if command.kind is CommandKind.CHECKPOINT_WORK_ITEM:
        if execution_lease_id is None:
            buffered_lease_id = payload.get("executionLeaseId")
            if isinstance(buffered_lease_id, str):
                execution_lease_id = buffered_lease_id
        if not isinstance(execution_lease_id, str) or not execution_lease_id:
            raise OfflinePolicyError("offline checkpoint requires a current Execution Lease ID")
        payload["executionLeaseId"] = execution_lease_id

    unsigned = command.model_copy(
        update={
            "session_epoch": session_epoch,
            "membership_epoch": membership_epoch,
            "issued_at": reconciliation_time,
            "payload": payload,
            "signature": None,
        }
    )
    signature = identity.sign(canonical_bytes(unsigned.signing_payload()))
    return unsigned.model_copy(update={"signature": signature})


def offline_command_to_wire(
    command: Command,
    identity: AgentIdentity,
    *,
    session_epoch: int,
    membership_epoch: int,
    issued_at: datetime | None = None,
    execution_lease_id: str | None = None,
    key_id: str | None = None,
) -> dict[str, JsonValue]:
    """Serialize freshly rebased offline progress for authenticated gateway reconciliation."""

    rebased = rebase_offline_command(
        command,
        identity,
        session_epoch=session_epoch,
        membership_epoch=membership_epoch,
        issued_at=issued_at,
        execution_lease_id=execution_lease_id,
    )
    payload = cast(dict[str, JsonValue], dict(rebased.payload))
    reconciled_at = _timestamp(rebased.issued_at)
    document: dict[str, JsonValue] = {
        "protocolVersion": rebased.protocol_version,
        "actionId": rebased.action_id,
        "actor": {"type": "agent", "id": identity.agent_id},
        "sessionEpoch": session_epoch,
        "membershipEpoch": membership_epoch,
        "groupId": cast(str, rebased.group_id),
        "kind": rebased.kind.value,
        "correlationId": f"{rebased.action_id}:reconciliation",
        "issuedAt": reconciled_at,
        "payload": payload,
    }
    conversation_id = payload.get("conversationId")
    if isinstance(conversation_id, str):
        document["conversationId"] = conversation_id
        payload.pop("conversationId")
    work_item_id = payload.get("workItemId")
    if isinstance(work_item_id, str):
        document["workItemId"] = work_item_id
    if rebased.expected_revision is not None:
        document["expectedRevision"] = rebased.expected_revision
    if rebased.extensions:
        serialized = rebased.model_dump(mode="json", by_alias=True, include={"extensions"})
        extensions = serialized.get("extensions")
        if isinstance(extensions, dict):
            document["extensions"] = cast(dict[str, JsonValue], extensions)
    signature = identity.sign(canonical_bytes(document))
    document["signature"] = {
        "algorithm": "Ed25519",
        "keyId": key_id or default_agent_key_id(identity.agent_id),
        "createdAt": reconciled_at,
        "value": signature,
    }
    return document


def _add_usage(current: ResourceUsage, delta: ResourceUsage) -> ResourceUsage:
    return ResourceUsage(
        financial_microunits=(current.financial_microunits + delta.financial_microunits),
        model_tokens=current.model_tokens + delta.model_tokens,
        tool_calls=current.tool_calls + delta.tool_calls,
        compute_seconds=current.compute_seconds + delta.compute_seconds,
        wall_clock_seconds=current.wall_clock_seconds + delta.wall_clock_seconds,
        external_actions=current.external_actions + delta.external_actions,
    )


def _require_within_usage_limit(usage: ResourceUsage, limit: ResourceUsage) -> None:
    for field_name in ResourceUsage.model_fields:
        if getattr(usage, field_name) > getattr(limit, field_name):
            raise OfflinePolicyError(f"offline resource limit exceeded: {field_name}")


def _aware_utc(value: datetime, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise OfflinePolicyError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


__all__ = [
    "OFFLINE_EXECUTION_EXTENSION",
    "OFFLINE_EXECUTION_EXTENSION_VERSION",
    "OfflineExecutionPolicy",
    "OfflineLimits",
    "OfflinePolicyError",
    "OfflineProgressBinding",
    "offline_command_to_wire",
    "rebase_offline_command",
]
