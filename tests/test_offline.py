from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from missionweaveprotocol.auth import AgentIdentity
from missionweaveprotocol.crypto import verify_canonical
from missionweaveprotocol.local_store import SQLiteAgentStore
from missionweaveprotocol.models import (
    Checkpoint,
    CheckpointWorkItemPayload,
    Command,
    CommandKind,
    PostMessagePayload,
    Principal,
    ResourceBudget,
    WorkContract,
    WorkItem,
    WorkItemStatus,
)
from missionweaveprotocol.offline import (
    OFFLINE_EXECUTION_EXTENSION,
    OfflineExecutionPolicy,
    OfflineLimits,
    OfflinePolicyError,
)
from missionweaveprotocol.policy import ResourceUsage

NOW = datetime(2026, 7, 16, 9, 0, tzinfo=UTC)
AGENT_ID = "agent://acme/worker"
GROUP_ID = "group:offline"
WORK_ID = "work:offline"
CONVERSATION_ID = "conversation:offline-work"
OWNERSHIP_EPOCH = 4
EXECUTION_LEASE_ID = "lease:offline-execution"


@dataclass
class Clock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value


def _work(identity: AgentIdentity, **changes: object) -> WorkItem:
    work = WorkItem(
        id=WORK_ID,
        mission_id="mission:offline",
        group_id=GROUP_ID,
        conversation_id=CONVERSATION_ID,
        created_by=Principal.agent("agent://acme/coordinator"),
        contract=WorkContract(
            goal="Continue reversible local analysis",
            deliverables=("checkpoint",),
            acceptance_criteria=("progress is reconciled",),
            deadline=NOW + timedelta(hours=1),
            budget=ResourceBudget(model_tokens=100, compute_seconds=60),
            side_effect_risk="reversible",
        ),
        status=WorkItemStatus.ACTIVE,
        assignee_id=identity.agent_id,
        ownership_epoch=OWNERSHIP_EPOCH,
        ownership_lease_expires_at=NOW + timedelta(minutes=5),
        execution_lease_id=EXECUTION_LEASE_ID,
        execution_lease_expires_at=NOW + timedelta(minutes=2),
        created_at=NOW - timedelta(minutes=5),
        updated_at=NOW,
    )
    return work.model_copy(update=changes)


def _limits(*, max_actions: int = 2, model_tokens: int = 10) -> OfflineLimits:
    return OfflineLimits(
        max_disconnect_grace=timedelta(seconds=30),
        max_actions=max_actions,
        max_usage=ResourceUsage(
            model_tokens=model_tokens,
            tool_calls=2,
            compute_seconds=20,
            wall_clock_seconds=30,
        ),
    )


def _message(
    identity: AgentIdentity,
    *,
    action_id: str = "offline:message:1",
    group_id: str = GROUP_ID,
    conversation_id: str = CONVERSATION_ID,
    actor_id: str | None = None,
    issued_at: datetime = NOW,
) -> Command:
    return Command(
        action_id=action_id,
        kind=CommandKind.POST_MESSAGE,
        actor=Principal.agent(actor_id or identity.agent_id),
        group_id=group_id,
        session_epoch=1,
        issued_at=issued_at,
        payload=PostMessagePayload(
            message_id=f"message:{action_id}",
            conversation_id=conversation_id,
            content="Reversible progress while disconnected.",
        ),
        signature="signature-to-replace",
    )


def _checkpoint(
    identity: AgentIdentity,
    *,
    action_id: str = "offline:checkpoint:1",
    work_item_id: str = WORK_ID,
    ownership_epoch: int = OWNERSHIP_EPOCH,
    execution_lease_id: str = EXECUTION_LEASE_ID,
) -> Command:
    return Command(
        action_id=action_id,
        kind=CommandKind.CHECKPOINT_WORK_ITEM,
        actor=Principal.agent(identity.agent_id),
        group_id=GROUP_ID,
        session_epoch=1,
        issued_at=NOW,
        payload=CheckpointWorkItemPayload(
            work_item_id=work_item_id,
            ownership_epoch=ownership_epoch,
            execution_lease_id=execution_lease_id,
            checkpoint=Checkpoint(
                phase="offline-analysis",
                completed_milestones=("parsed inputs",),
                next_step="reconcile",
                created_at=NOW,
            ),
        ),
        signature=None,
    )


def _policy(
    tmp_path,
    identity: AgentIdentity,
    *,
    work: WorkItem | None = None,
    clock: Clock | None = None,
    disconnected_at: datetime = NOW,
    limits: OfflineLimits | None = None,
) -> tuple[OfflineExecutionPolicy, SQLiteAgentStore]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    store = SQLiteAgentStore(tmp_path / "agent.sqlite3")
    policy = OfflineExecutionPolicy(
        store,
        identity,
        work or _work(identity),
        disconnected_at=disconnected_at,
        limits=limits or _limits(),
        clock=clock or Clock(NOW),
    )
    return policy, store


def test_reversible_progress_is_bound_signed_and_queued_canonically(tmp_path) -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    policy, store = _policy(tmp_path, identity)

    signed_message = policy.buffer(
        _message(identity),
        usage=ResourceUsage(model_tokens=3, compute_seconds=2, wall_clock_seconds=5),
    )
    signed_checkpoint = policy.buffer(
        _checkpoint(identity),
        usage=ResourceUsage(model_tokens=4, compute_seconds=3, wall_clock_seconds=5),
    )

    assert signed_message.signature is not None
    assert verify_canonical(
        signed_message.signing_payload(), signed_message.signature.value, identity.public_key
    )
    binding = signed_message.extensions[OFFLINE_EXECUTION_EXTENSION].data
    assert isinstance(binding, dict)
    assert binding["agentId"] == AGENT_ID
    assert binding["groupId"] == GROUP_ID
    assert binding["workItemId"] == WORK_ID
    assert binding["ownershipEpoch"] == OWNERSHIP_EPOCH
    assert binding["executionLeaseId"] == EXECUTION_LEASE_ID
    assert binding["resourceUsageDelta"]["modelTokens"] == 3
    assert signed_checkpoint.payload["executionLeaseId"] == EXECUTION_LEASE_ID
    checkpoint_binding = signed_checkpoint.extensions[OFFLINE_EXECUTION_EXTENSION].data
    assert isinstance(checkpoint_binding, dict)
    assert checkpoint_binding["executionLeaseId"] == EXECUTION_LEASE_ID
    assert signed_checkpoint.signature is not None
    assert verify_canonical(
        signed_checkpoint.signing_payload(),
        signed_checkpoint.signature.value,
        identity.public_key,
    )
    expected_actions = [
        signed_message.model_dump(mode="json", by_alias=True),
        signed_checkpoint.model_dump(mode="json", by_alias=True),
    ]
    assert store.pending_actions(AGENT_ID) == expected_actions
    assert policy.buffered_actions == 2
    assert policy.cumulative_usage == ResourceUsage(
        model_tokens=7,
        compute_seconds=5,
        wall_clock_seconds=10,
    )
    store.close()
    reopened = SQLiteAgentStore(tmp_path / "agent.sqlite3")
    assert reopened.pending_actions(AGENT_ID) == expected_actions


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"status": WorkItemStatus.QUEUED}, "already-active"),
        ({"assignee_id": "agent://acme/other"}, "not assigned"),
        ({"ownership_epoch": 0}, "Ownership Epoch"),
        ({"execution_lease_id": None}, "execution lease"),
        ({"execution_lease_expires_at": None}, "execution lease"),
        ({"execution_lease_expires_at": NOW}, "execution lease has expired"),
    ],
)
def test_policy_requires_an_active_owned_work_item_with_current_execution_lease(
    tmp_path,
    change: dict[str, object],
    message: str,
) -> None:
    identity = AgentIdentity.generate(AGENT_ID)

    with pytest.raises(OfflinePolicyError, match=message):
        _policy(tmp_path, identity, work=_work(identity, **change))


def test_policy_rejects_expired_disconnect_grace_and_rechecks_each_buffer(tmp_path) -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    with pytest.raises(OfflinePolicyError, match="disconnect grace"):
        _policy(
            tmp_path,
            identity,
            disconnected_at=NOW - timedelta(seconds=31),
        )

    clock = Clock(NOW)
    policy, store = _policy(tmp_path / "live", identity, clock=clock)
    assert policy.grace_deadline == NOW + timedelta(seconds=30)
    clock.value = policy.grace_deadline
    with pytest.raises(OfflinePolicyError, match="disconnect grace"):
        policy.buffer(_message(identity))
    assert store.pending_actions(AGENT_ID) == []

    lease_clock = Clock(NOW)
    lease_expiry = NOW + timedelta(seconds=10)
    lease_policy, lease_store = _policy(
        tmp_path / "lease",
        identity,
        work=_work(identity, execution_lease_expires_at=lease_expiry),
        clock=lease_clock,
    )
    assert lease_policy.grace_deadline == lease_expiry
    lease_clock.value = lease_expiry
    with pytest.raises(OfflinePolicyError, match="execution lease"):
        lease_policy.buffer(_message(identity))
    assert lease_store.pending_actions(AGENT_ID) == []


@pytest.mark.parametrize(
    "command",
    [
        lambda identity: _message(identity, actor_id="agent://acme/other"),
        lambda identity: _message(identity, group_id="group:other"),
        lambda identity: _message(identity, conversation_id="conversation:other"),
        lambda identity: _checkpoint(identity, work_item_id="work:other"),
        lambda identity: _checkpoint(identity, ownership_epoch=OWNERSHIP_EPOCH - 1),
        lambda identity: _checkpoint(identity, execution_lease_id="lease:other"),
    ],
)
def test_policy_rejects_commands_outside_the_bound_assignment(tmp_path, command) -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    policy, store = _policy(tmp_path, identity)

    with pytest.raises(OfflinePolicyError):
        policy.buffer(command(identity))
    assert store.pending_actions(AGENT_ID) == []


@pytest.mark.parametrize(
    "kind",
    [
        CommandKind.START_WORK_ITEM,
        CommandKind.SUBMIT_WORK_ITEM,
        CommandKind.GRANT_EXECUTION_APPROVAL,
        CommandKind.PUBLISH_ARTIFACT,
    ],
)
def test_policy_rejects_new_starts_submission_and_high_risk_or_external_commands(
    tmp_path,
    kind: CommandKind,
) -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    policy, store = _policy(tmp_path, identity)
    command = _message(identity).model_copy(update={"kind": kind})

    with pytest.raises(OfflinePolicyError, match="not reversible"):
        policy.buffer(command)
    assert store.pending_actions(AGENT_ID) == []


def test_policy_rejects_external_usage_and_secret_payload_fields(tmp_path) -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    policy, store = _policy(tmp_path, identity)

    with pytest.raises(OfflinePolicyError, match="external actions"):
        policy.buffer(_message(identity), usage=ResourceUsage(external_actions=1))

    secret_payload = dict(_message(identity).payload)
    secret_payload["capabilityToken"] = "must-not-be-buffered"
    with pytest.raises(OfflinePolicyError, match="payload is invalid"):
        policy.buffer(_message(identity).model_copy(update={"payload": secret_payload}))
    assert store.pending_actions(AGENT_ID) == []


def test_action_and_cumulative_resource_limits_are_atomic(tmp_path) -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    action_policy, action_store = _policy(
        tmp_path / "actions",
        identity,
        limits=_limits(max_actions=1),
    )
    first = _message(identity)
    signed = action_policy.buffer(first, usage=ResourceUsage(model_tokens=2))
    assert action_policy.buffer(first, usage=ResourceUsage(model_tokens=2)) == signed
    with pytest.raises(OfflinePolicyError, match="action limit"):
        action_policy.buffer(_message(identity, action_id="offline:message:2"))
    assert len(action_store.pending_actions(AGENT_ID)) == 1
    assert action_policy.cumulative_usage.model_tokens == 2

    resource_policy, resource_store = _policy(
        tmp_path / "resources",
        identity,
        limits=_limits(max_actions=2, model_tokens=5),
    )
    resource_policy.buffer(first, usage=ResourceUsage(model_tokens=3))
    with pytest.raises(OfflinePolicyError, match="model_tokens"):
        resource_policy.buffer(
            _message(identity, action_id="offline:message:2"),
            usage=ResourceUsage(model_tokens=3),
        )
    assert len(resource_store.pending_actions(AGENT_ID)) == 1
    assert resource_policy.buffered_actions == 1
    assert resource_policy.cumulative_usage.model_tokens == 3
