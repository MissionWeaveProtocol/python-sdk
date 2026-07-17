"""Signed human control interface for Mission lifecycle operations.

The human-facing seam deliberately exposes Mission concepts rather than raw state tables or
transport frames. Every mutation is emitted as a canonical, Ed25519-signed durable Command and
can be correlated with the accepted Event retained by the authoritative Core.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from .core import Core, NotFound
from .crypto import generate_keypair, sign_canonical, verify_canonical
from .models import (
    Approval,
    ApproveMissionPayload,
    CancelMissionPayload,
    Command,
    CommandKind,
    CreateMissionPayload,
    Event,
    ExecutionApproval,
    GrantExecutionApprovalPayload,
    Group,
    Mission,
    PostMessagePayload,
    Principal,
    ProtocolModel,
    Query,
    QueryKind,
    ReplaceCoordinatorPayload,
    RequestMissionChangesPayload,
    ResourceBudget,
    WorkItem,
)

Clock = Callable[[], datetime]
IdFactory = Callable[[], str]


@dataclass(frozen=True, slots=True)
class HumanIdentity:
    """A MissionOwner signing identity used by the reference control interface."""

    human_id: str
    private_key: str
    public_key: str
    key_id: str

    @classmethod
    def generate(cls, human_id: str, *, key_id: str | None = None) -> HumanIdentity:
        private_key, public_key = generate_keypair()
        return cls(
            human_id=human_id,
            private_key=private_key,
            public_key=public_key,
            key_id=key_id or f"{human_id}:signing-key",
        )

    @property
    def principal(self) -> Principal:
        return Principal.human(self.human_id)

    def sign(self, command: Command) -> Command:
        return command.model_copy(
            update={"signature": sign_canonical(command.signing_payload(), self.private_key)}
        )

    def verify(self, command: Command) -> bool:
        signature = command.signature
        return isinstance(signature, str) and verify_canonical(
            command.signing_payload(), signature, self.public_key
        )


@dataclass(frozen=True, slots=True)
class ControlReceipt:
    """The signed request and the authoritative fact accepted for it."""

    command: Command
    event: Event


@dataclass(frozen=True, slots=True)
class MissionInspection:
    """One consistent human-readable Mission view built through the Core interface."""

    mission: Mission
    group: Group
    work_items: tuple[WorkItem, ...]
    events: tuple[Event, ...]


class HumanControl:
    """Create, inspect, direct, review, cancel, and re-coordinate Missions."""

    def __init__(
        self,
        core: Core,
        identity: HumanIdentity,
        *,
        clock: Clock | None = None,
        action_id_factory: IdFactory | None = None,
    ) -> None:
        self._core = core
        self.identity = identity
        self._clock = clock or (lambda: datetime.now(UTC))
        self._action_id_factory = action_id_factory or (lambda: f"human-action:{uuid4()}")

    async def create(
        self,
        *,
        mission_id: str,
        group_id: str,
        coordinator_id: str,
        title: str,
        objective: str,
        definition_of_done: tuple[str, ...],
        deadline: datetime,
        budget: ResourceBudget | None = None,
        permissions: tuple[str, ...] = (),
        coordinator_lease_seconds: int = 300,
    ) -> ControlReceipt:
        return await self._perform(
            CommandKind.CREATE_MISSION,
            CreateMissionPayload(
                mission_id=mission_id,
                group_id=group_id,
                coordinator_id=coordinator_id,
                title=title,
                objective=objective,
                definition_of_done=definition_of_done,
                budget=budget or ResourceBudget(),
                deadline=deadline,
                permissions=permissions,
                coordinator_lease_seconds=coordinator_lease_seconds,
            ),
            group_id=group_id,
        )

    async def inspect(self, mission_id: str) -> MissionInspection:
        mission = await self._mission(mission_id)
        group = await self._core.query(Query(kind=QueryKind.GROUP, entity_id=mission.group_id))
        work_items = await self._core.query(
            Query(kind=QueryKind.MISSION_WORK_ITEMS, entity_id=mission.id)
        )
        if (
            not isinstance(group, Group)
            or not isinstance(work_items, tuple)
            or not all(isinstance(item, WorkItem) for item in work_items)
        ):
            raise RuntimeError("authoritative Core returned an inconsistent Mission projection")
        typed_work_items = tuple(item for item in work_items if isinstance(item, WorkItem))
        return MissionInspection(
            mission=mission,
            group=group,
            work_items=typed_work_items,
            events=await self._core.replay(mission.group_id),
        )

    async def direct(
        self,
        mission_id: str,
        content: str,
        *,
        conversation_id: str | None = None,
        message_id: str | None = None,
        mentions: tuple[Principal, ...] = (),
    ) -> ControlReceipt:
        inspection = await self.inspect(mission_id)
        return await self._perform(
            CommandKind.POST_MESSAGE,
            PostMessagePayload(
                message_id=message_id or f"human-message:{uuid4()}",
                conversation_id=conversation_id or inspection.group.main_conversation_id,
                content=content,
                mentions=mentions,
            ),
            group_id=inspection.group.id,
        )

    async def request_changes(
        self,
        mission_id: str,
        feedback: str,
        *,
        mission_revision: int | None = None,
    ) -> ControlReceipt:
        mission = await self._mission(mission_id)
        revision = mission_revision or mission.submitted_revision
        if revision is None:
            raise ValueError("Mission has no submitted revision to change")
        return await self._perform(
            CommandKind.REQUEST_MISSION_CHANGES,
            RequestMissionChangesPayload(mission_revision=revision, feedback=feedback),
            group_id=mission.group_id,
            expected_revision=mission.revision,
        )

    async def approve(
        self,
        mission_id: str,
        *,
        approval_id: str | None = None,
        mission_revision: int | None = None,
        artifact_hashes: tuple[str, ...] | None = None,
        acceptance_policy_version: str = "1.0.0",
        comments: str | None = None,
    ) -> tuple[ControlReceipt, Approval]:
        mission = await self._mission(mission_id)
        revision = mission_revision or mission.submitted_revision
        if revision is None:
            raise ValueError("Mission has no submitted revision to approve")
        hashes = artifact_hashes or mission.submitted_artifact_hashes
        receipt = await self._perform(
            CommandKind.APPROVE_MISSION,
            ApproveMissionPayload(
                approval_id=approval_id or f"approval:{uuid4()}",
                mission_revision=revision,
                artifact_hashes=hashes,
                acceptance_policy_version=acceptance_policy_version,
                comments=comments,
            ),
            group_id=mission.group_id,
            expected_revision=mission.revision,
        )
        approval_value = receipt.event.payload.get("approval")
        if not isinstance(approval_value, dict):
            raise RuntimeError("Mission approval Event did not contain an Approval")
        approval = Approval.model_validate(approval_value)
        return receipt, approval

    async def approve_execution(
        self,
        mission_id: str,
        *,
        work_item_id: str,
        ownership_epoch: int,
        operations: tuple[str, ...],
        resources: tuple[str, ...] = (),
        budget: ResourceBudget | None = None,
        expires_in_seconds: int = 300,
        approval_id: str | None = None,
        comments: str | None = None,
    ) -> tuple[ControlReceipt, ExecutionApproval]:
        mission = await self._mission(mission_id)
        receipt = await self._perform(
            CommandKind.GRANT_EXECUTION_APPROVAL,
            GrantExecutionApprovalPayload(
                approval_id=approval_id or f"execution-approval:{uuid4()}",
                work_item_id=work_item_id,
                ownership_epoch=ownership_epoch,
                operations=operations,
                resources=resources,
                budget=budget or ResourceBudget(),
                expires_in_seconds=expires_in_seconds,
                comments=comments,
            ),
            group_id=mission.group_id,
            expected_revision=mission.revision,
        )
        approval_value = receipt.event.payload.get("approval")
        if not isinstance(approval_value, dict):
            raise RuntimeError("Execution Approval Event did not contain an Approval")
        return receipt, ExecutionApproval.model_validate(approval_value)

    async def cancel(self, mission_id: str, reason: str) -> ControlReceipt:
        mission = await self._mission(mission_id)
        return await self._perform(
            CommandKind.CANCEL_MISSION,
            CancelMissionPayload(reason=reason),
            group_id=mission.group_id,
            expected_revision=mission.revision,
        )

    async def replace_coordinator(
        self,
        mission_id: str,
        coordinator_id: str,
        *,
        lease_seconds: int = 300,
    ) -> ControlReceipt:
        mission = await self._mission(mission_id)
        return await self._perform(
            CommandKind.REPLACE_COORDINATOR,
            ReplaceCoordinatorPayload(
                coordinator_id=coordinator_id,
                lease_seconds=lease_seconds,
            ),
            group_id=mission.group_id,
            expected_revision=mission.revision,
        )

    async def accepted_command(self, event_id: str) -> Command:
        command = await self._core.query(Query(kind=QueryKind.COMMAND, entity_id=event_id))
        if not isinstance(command, Command):
            raise NotFound("accepted Command does not exist", event_id=event_id)
        return command

    async def _mission(self, mission_id: str) -> Mission:
        mission = await self._core.query(Query(kind=QueryKind.MISSION, entity_id=mission_id))
        if not isinstance(mission, Mission):
            raise NotFound("Mission does not exist", mission_id=mission_id)
        return mission

    async def _perform(
        self,
        kind: CommandKind,
        payload: ProtocolModel,
        *,
        group_id: str,
        expected_revision: int | None = None,
    ) -> ControlReceipt:
        unsigned = Command(
            action_id=self._action_id_factory(),
            kind=kind,
            actor=self.identity.principal,
            group_id=group_id,
            expected_revision=expected_revision,
            issued_at=self._now(),
            payload=payload.model_dump(mode="json", by_alias=True),
        )
        command = self.identity.sign(unsigned)
        event = await self._core.perform(command)
        return ControlReceipt(command=command, event=event)

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise RuntimeError("HumanControl clock must return a timezone-aware datetime")
        return now.astimezone(UTC)


__all__ = [
    "ControlReceipt",
    "HumanControl",
    "HumanIdentity",
    "MissionInspection",
]
