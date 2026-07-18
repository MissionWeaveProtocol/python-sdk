"""Executable deterministic MissionWeaveProtocol 0.1 proof of concept.

The public Interface is intentionally small: ``run_poc`` for async callers,
``run_poc_sync`` for command-line callers, and a structured ``POCReport``.  The
Implementation drives the authoritative Core and the Worker-local Scheduler/Agent
Modules through their published Interfaces; it does not special-case their state.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import socket
from collections.abc import Awaitable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import TypeVar, cast

import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from websockets.asyncio.client import ClientConnection, connect

from missionweaveprotocol.agent import AgentRuntime
from missionweaveprotocol.artifacts import ArtifactManifest, LocalArtifactStore
from missionweaveprotocol.auth import (
    AgentIdentity,
    AgentKeyRegistry,
    SessionAuthority,
    default_agent_key_id,
)
from missionweaveprotocol.canonical import canonical_bytes, canonical_hash
from missionweaveprotocol.context import (
    ContextPackage,
    ContextPackageService,
    GroupSnapshot,
    KnowledgePublication,
    KnowledgePublisher,
    PolicyLogEntry,
    SnapshotArchive,
)
from missionweaveprotocol.control import HumanControl, HumanIdentity
from missionweaveprotocol.core import (
    ActionIdCollision,
    AuthorizationDenied,
    Core,
    LeaseExpired,
    StaleCoordinatorEpoch,
    StaleOwnershipEpoch,
    StaleSessionEpoch,
)
from missionweaveprotocol.crypto import encode_private_key, encode_public_key, verify_canonical
from missionweaveprotocol.gateway import CoreGatewayAdapter, GroupGateway
from missionweaveprotocol.local_store import SQLiteAgentStore
from missionweaveprotocol.models import (
    AcceptWorkOfferPayload,
    ActorType,
    AddMembershipPayload,
    AddWorkItemDependencyPayload,
    AgentCard,
    Approval,
    ApproveMissionPayload,
    ArchiveGroupPayload,
    Artifact,
    BlockWorkItemPayload,
    Capability,
    CapabilityRequirement,
    Checkpoint,
    CheckpointWorkItemPayload,
    ChildFailurePolicy,
    Command,
    CommandKind,
    CreateChildMissionPayload,
    CreateWorkItemPayload,
    Event,
    EventKind,
    Evidence,
    Group,
    Membership,
    MembershipStatus,
    Mission,
    MissionStatus,
    OfferWorkItemPayload,
    OpenAgentSessionPayload,
    PostMessagePayload,
    Principal,
    ProposeWorkItemPayload,
    ProtocolModel,
    PublishArtifactPayload,
    Query,
    QueryKind,
    RegisterAgentCardPayload,
    RenewExecutionLeasePayload,
    ResourceBudget,
    Role,
    SelectionBasis,
    SignatureEnvelope,
    StartWorkItemPayload,
    SubmitMissionPayload,
    SubmitWorkItemPayload,
    UnblockWorkItemPayload,
    VerifyWorkItemPayload,
    WorkContract,
    WorkItem,
    WorkItemStatus,
    WorkProposal,
    WorkProposalStatus,
)
from missionweaveprotocol.offline import (
    OFFLINE_EXECUTION_EXTENSION,
    OfflineExecutionPolicy,
    OfflineLimits,
    OfflinePolicyError,
    offline_command_to_wire,
)
from missionweaveprotocol.policy import ResourceUsage
from missionweaveprotocol.replay import AgentReplay, EventProjection, EventProjector
from missionweaveprotocol.scheduler import (
    CheckpointRef,
    Dispatch,
    EstimateBand,
    GroupSchedulingPolicy,
    Preempt,
    Scheduler,
    SchedulerPolicy,
    SchedulingEstimate,
    TransitionKind,
    WorkOffer,
    WorkTransition,
)
from missionweaveprotocol.store import InMemoryStore
from missionweaveprotocol.wire import (
    AuthFrame,
    ChallengeFrame,
    CommandFrame,
    ErrorFrame,
    EventFrame,
    GroupCursor,
    HelloFrame,
    SubscribeFrame,
    WelcomeFrame,
    encode_frame,
    parse_frame,
)

SYSTEM_ID = "organization"
OWNER_ID = "human://acme/owner"
COORD_AUTH = "agent://acme/coordinator-auth"
COORD_CLI = "agent://acme/coordinator-cli"
COORD_CLI_REPLACEMENT = "agent://acme/coordinator-cli-v2"
ANALYST = "agent://acme/analyst"
CODER = "agent://acme/coder"
REVIEWER = "agent://acme/reviewer"
SECURITY_COORDINATOR = "agent://acme/security-coordinator"
SECURITY_WORKER = "agent://acme/security-worker"

MISSION_AUTH = "mission:authentication"
GROUP_AUTH = "group:authentication"
MISSION_CLI = "mission:cli"
GROUP_CLI = "group:cli"
MISSION_SECURITY = "mission:authentication:security"
GROUP_SECURITY = "group:authentication:security"
SNAPSHOT_AUTHORITY_KEY_ID = "urn:missionweaveprotocol:key:system:snapshot-archive"


@dataclass(slots=True)
class _MutableClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        if seconds < 0:
            raise ValueError("the deterministic POC clock cannot move backwards")
        self.value += timedelta(seconds=seconds)


@dataclass(frozen=True, slots=True)
class MissionResult:
    mission_id: str
    group_id: str
    status: str
    revision: int
    approval_id: str
    artifact_hashes: tuple[str, ...]
    event_count: int

    def to_dict(self) -> dict[str, object]:
        return {
            "approvalId": self.approval_id,
            "artifactHashes": list(self.artifact_hashes),
            "eventCount": self.event_count,
            "groupId": self.group_id,
            "missionId": self.mission_id,
            "revision": self.revision,
            "status": self.status,
        }


@dataclass(frozen=True, slots=True)
class POCReport:
    """Stable, JSON-ready result of the executable POC."""

    passed: bool
    checks: tuple[tuple[str, bool], ...]
    missions: tuple[MissionResult, ...]
    scheduler_dispatch_order: tuple[str, ...]
    event_counts: tuple[tuple[str, int], ...]
    final_cursors: tuple[tuple[str, int], ...]
    failure_injections: tuple[str, ...]
    artifact_provenance_edges: int
    worker_message_count: int
    context_package_count: int
    knowledge_publication_count: int
    group_snapshot_count: int
    policy_log_entry_count: int

    def require_success(self) -> None:
        failures = [name for name, passed in self.checks if not passed]
        if not self.passed or failures:
            raise AssertionError(f"MissionWeaveProtocol POC failed checks: {failures}")

    def to_dict(self) -> dict[str, object]:
        return {
            "artifactProvenanceEdges": self.artifact_provenance_edges,
            "checks": {name: passed for name, passed in self.checks},
            "contextPackageCount": self.context_package_count,
            "eventCounts": dict(self.event_counts),
            "failureInjections": list(self.failure_injections),
            "finalCursors": dict(self.final_cursors),
            "missions": [mission.to_dict() for mission in self.missions],
            "passed": self.passed,
            "groupSnapshotCount": self.group_snapshot_count,
            "knowledgePublicationCount": self.knowledge_publication_count,
            "policyLogEntryCount": self.policy_log_entry_count,
            "schedulerDispatchOrder": list(self.scheduler_dispatch_order),
            "workerMessageCount": self.worker_message_count,
        }


ErrorT = TypeVar("ErrorT", bound=BaseException)


def _decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class _LiveGateway:
    """Real loopback WebSocket binding over the scenario's authoritative Core."""

    def __init__(self, scenario: _Scenario) -> None:
        keys = AgentKeyRegistry()
        keys.register(REVIEWER, scenario.identities[REVIEWER].public_key)
        adapter = CoreGatewayAdapter(
            scenario.core,
            keys,
            authority_private_key=hashlib.sha256(
                b"missionweaveprotocol-poc-gateway-authority"
            ).digest(),
            clock=scenario.clock,
        )
        sessions = SessionAuthority(
            keys,
            secret=b"missionweaveprotocol-poc-session-secret-fixed!!",
            clock=scenario.clock,
        )
        self._gateway = GroupGateway(adapter, sessions, clock=scenario.clock)
        self._port = self._available_port()
        self._server = uvicorn.Server(
            uvicorn.Config(
                self._gateway.app,
                host="127.0.0.1",
                port=self._port,
                log_level="error",
                access_log=False,
                lifespan="off",
            )
        )
        self._server_task: asyncio.Task[None] | None = None

    @staticmethod
    def _available_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as value:
            value.bind(("127.0.0.1", 0))
            return int(value.getsockname()[1])

    async def start(self) -> None:
        self._server_task = asyncio.create_task(self._server.serve())
        for _ in range(200):
            if self._server.started:
                return
            if self._server_task.done():
                await self._server_task
                raise RuntimeError("GroupGateway server stopped during startup")
            await asyncio.sleep(0.01)
        raise RuntimeError("GroupGateway server did not start")

    async def stop(self) -> None:
        self._server.should_exit = True
        if self._server_task is not None:
            await self._server_task
            self._server_task = None

    async def connect(self) -> tuple[ClientConnection, WelcomeFrame]:
        connection = await connect(f"ws://127.0.0.1:{self._port}/ws")
        identity = self._gateway_identity
        await connection.send(
            encode_frame(
                HelloFrame(
                    agent_id=identity.agent_id,
                    key_id="urn:missionweaveprotocol:key:reviewer",
                    client_nonce="cG9jLWNsaWVudC1ub25jZQ",
                )
            )
        )
        challenge = parse_frame(await connection.recv())
        if not isinstance(challenge, ChallengeFrame):
            raise AssertionError("GroupGateway did not issue an authentication challenge")
        await connection.send(
            encode_frame(
                AuthFrame(
                    agent_id=identity.agent_id,
                    key_id="urn:missionweaveprotocol:key:reviewer",
                    client_nonce=challenge.client_nonce,
                    server_nonce=challenge.server_nonce,
                    challenge_signature=identity.sign(_decode_base64url(challenge.challenge)),
                )
            )
        )
        welcome = parse_frame(await connection.recv())
        if not isinstance(welcome, WelcomeFrame):
            raise AssertionError("GroupGateway did not accept the authenticated Worker")
        return connection, welcome

    @property
    def _gateway_identity(self) -> AgentIdentity:
        # The Adapter registry and this deterministic identity use the same key material.
        return _deterministic_identity(REVIEWER)

    async def subscribe(
        self,
        connection: ClientConnection,
        cursors: Mapping[str, int],
        *,
        subscription_id: str,
    ) -> None:
        await connection.send(
            encode_frame(
                SubscribeFrame(
                    subscription_id=subscription_id,
                    groups=tuple(
                        GroupCursor(group_id=group_id, after_sequence=sequence)
                        for group_id, sequence in sorted(cursors.items())
                    ),
                )
            )
        )


def _deterministic_identity(principal_id: str) -> AgentIdentity:
    seed = hashlib.sha256(f"missionweaveprotocol-poc:{principal_id}".encode()).digest()
    return AgentIdentity(principal_id, Ed25519PrivateKey.from_private_bytes(seed))


def _deterministic_human_identity(human_id: str) -> HumanIdentity:
    seed = hashlib.sha256(f"missionweaveprotocol-poc:{human_id}".encode()).digest()
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    return HumanIdentity(
        human_id=human_id,
        private_key=encode_private_key(private_key),
        public_key=encode_public_key(private_key.public_key()),
        key_id=f"{human_id}:deterministic-poc-key",
    )


class _Scenario:
    def __init__(self, root: Path) -> None:
        self.clock = _MutableClock(datetime(2026, 7, 15, 8, 0, tzinfo=UTC))
        self.authoritative_store = InMemoryStore()
        snapshot_authority = _deterministic_identity(SYSTEM_ID)
        self.core = Core(
            self.authoritative_store,
            clock=self.clock,
            snapshot_authority_key_id=SNAPSHOT_AUTHORITY_KEY_ID,
            snapshot_authority_public_key=snapshot_authority.public_key,
        )
        self.artifact_store = LocalArtifactStore(root / "artifacts")
        principal_ids = (
            SYSTEM_ID,
            OWNER_ID,
            COORD_AUTH,
            COORD_CLI,
            COORD_CLI_REPLACEMENT,
            ANALYST,
            CODER,
            REVIEWER,
            SECURITY_COORDINATOR,
            SECURITY_WORKER,
        )
        self.identities = {
            principal_id: _deterministic_identity(principal_id) for principal_id in principal_ids
        }
        self.system = Principal.system(SYSTEM_ID)
        self.human_identity = _deterministic_human_identity(OWNER_ID)
        self.owner = self.human_identity.principal
        self.human_action_number = 0
        self.human_control = HumanControl(
            self.core,
            self.human_identity,
            clock=self.clock,
            action_id_factory=self._next_human_action_id,
        )
        self.epochs: dict[str, int] = {}
        self.membership_epochs: dict[tuple[str, ActorType, str], int] = {}
        self.action_number = 0
        self.checks: dict[str, bool] = {}
        self.manifests: dict[str, ArtifactManifest] = {}
        self.messages: list[str] = []
        self.failure_injections: list[str] = []

    def _next_human_action_id(self) -> str:
        self.human_action_number += 1
        return f"poc:human-action:{self.human_action_number:04d}"

    def prove(self, name: str, condition: bool) -> None:
        if not condition:
            raise AssertionError(f"POC check failed: {name}")
        self.checks[name] = True

    async def expect(
        self,
        name: str,
        error_type: type[ErrorT],
        operation: Awaitable[object],
    ) -> ErrorT:
        try:
            await operation
        except error_type as error:
            self.checks[name] = True
            self.failure_injections.append(name)
            return error
        raise AssertionError(f"POC check failed: {name} did not raise {error_type.__name__}")

    def command(
        self,
        kind: CommandKind,
        actor: Principal,
        payload: ProtocolModel,
        *,
        group_id: str | None = None,
        coordinator_epoch: int | None = None,
        session_epoch: int | None = None,
        membership_epoch: int | None = None,
        action_id: str | None = None,
        expected_revision: int | None = None,
    ) -> Command:
        self.action_number += 1
        if actor.type is ActorType.AGENT and session_epoch is None:
            session_epoch = self.epochs[actor.id]
        if (
            membership_epoch is None
            and group_id is not None
            and actor.type in {ActorType.AGENT, ActorType.HUMAN}
            and kind not in {CommandKind.CREATE_MISSION, CommandKind.CREATE_FOLLOW_UP_MISSION}
        ):
            try:
                membership_epoch = self.membership_epochs[(group_id, actor.type, actor.id)]
            except KeyError as error:
                raise AssertionError(
                    f"POC command issuer lacks Membership epoch for {actor.id} in {group_id}"
                ) from error
        resolved_action_id = action_id or f"poc:action:{self.action_number:04d}"
        unsigned = Command(
            action_id=resolved_action_id,
            kind=kind,
            actor=actor,
            group_id=group_id,
            session_epoch=session_epoch,
            membership_epoch=membership_epoch,
            coordinator_epoch=coordinator_epoch,
            correlation_id=resolved_action_id,
            conversation_id=getattr(payload, "conversation_id", None),
            work_item_id=getattr(payload, "work_item_id", None),
            expected_revision=expected_revision,
            issued_at=self.clock(),
            payload=payload.model_dump(mode="json", by_alias=True),
            signature=None,
        )
        identity = self.identities[actor.id]
        signature = SignatureEnvelope(
            key_id=default_agent_key_id(actor.id),
            created_at=unsigned.issued_at,
            value=identity.sign(canonical_bytes(unsigned.signing_payload())),
        )
        return unsigned.model_copy(update={"signature": signature})

    def resign(self, command: Command) -> Command:
        unsigned = command.model_copy(update={"signature": None})
        identity = self.identities[command.actor.id]
        signature = SignatureEnvelope(
            key_id=default_agent_key_id(command.actor.id),
            created_at=unsigned.issued_at,
            value=identity.sign(canonical_bytes(unsigned.signing_payload())),
        )
        return unsigned.model_copy(update={"signature": signature})

    async def perform(self, command: Command) -> Event:
        signature = command.signature
        if signature is None or not verify_canonical(
            command.signing_payload(),
            signature.value,
            self.identities[command.actor.id].public_key,
        ):
            raise AssertionError(f"invalid POC Command signature: {command.action_id}")
        event = await self.core.perform(command)
        await self._refresh_memberships(command, event)
        return event

    async def observe_control_receipt(self, command: Command, event: Event) -> None:
        """Refresh issuer fencing state after HumanControl mutates authoritative Memberships."""

        await self._refresh_memberships(command, event)

    async def _refresh_memberships(self, command: Command, event: Event) -> None:
        candidates: set[tuple[str, Principal]] = set()
        if command.group_id is not None and command.actor.type is not ActorType.SYSTEM:
            candidates.add((command.group_id, command.actor))
        if command.kind in {CommandKind.CREATE_MISSION, CommandKind.CREATE_FOLLOW_UP_MISSION}:
            payload = command.payload
            group_id = payload.get("groupId")
            coordinator_id = payload.get("coordinatorId")
            if isinstance(group_id, str) and isinstance(coordinator_id, str):
                candidates.add((group_id, command.actor))
                candidates.add((group_id, Principal.agent(coordinator_id)))
        elif command.kind is CommandKind.CREATE_CHILD_MISSION:
            child_group_id = command.payload.get("groupId")
            coordinator_id = command.payload.get("coordinatorId")
            if isinstance(child_group_id, str) and isinstance(coordinator_id, str):
                candidates.add((child_group_id, command.actor))
                candidates.add((child_group_id, Principal.agent(coordinator_id)))
        elif command.kind in {CommandKind.ADD_MEMBERSHIP, CommandKind.END_MEMBERSHIP}:
            principal = command.payload.get("principal")
            if command.group_id is not None and isinstance(principal, dict):
                candidates.add((command.group_id, Principal.model_validate(principal)))
        elif command.kind is CommandKind.REPLACE_COORDINATOR:
            previous = event.payload.get("previousCoordinatorId")
            replacement = event.payload.get("coordinatorId")
            if command.group_id is not None:
                if isinstance(previous, str):
                    candidates.add((command.group_id, Principal.agent(previous)))
                if isinstance(replacement, str):
                    candidates.add((command.group_id, Principal.agent(replacement)))

        for group_id, membership_principal in candidates:
            membership = await self.core.query(
                Query(
                    kind=QueryKind.MEMBERSHIP,
                    entity_id=membership_principal.id,
                    group_id=group_id,
                    actor_type=membership_principal.type,
                )
            )
            if isinstance(membership, Membership):
                self.membership_epochs[
                    (group_id, membership_principal.type, membership_principal.id)
                ] = membership.epoch

    async def register(self, agent_id: str, capabilities: tuple[str, ...]) -> None:
        identity = self.identities[agent_id]
        unsigned_card = AgentCard(
            agent_id=agent_id,
            version=1,
            display_name=agent_id.rsplit("/", 1)[-1],
            owner="acme-engineering",
            public_key=identity.public_key,
            capabilities=tuple(Capability(id=value, version=1) for value in capabilities),
            issued_at=self.clock(),
            signature="pending",
        )
        card_payload = unsigned_card.model_dump(mode="python", exclude={"signature"})
        card = unsigned_card.model_copy(
            update={"signature": self.identities[SYSTEM_ID].sign(canonical_bytes(card_payload))}
        )
        await self.perform(
            self.command(
                CommandKind.REGISTER_AGENT_CARD,
                self.system,
                RegisterAgentCardPayload(card=card),
            )
        )
        await self.reopen(agent_id)

    async def reopen(self, agent_id: str) -> int:
        event = await self.perform(
            self.command(
                CommandKind.OPEN_AGENT_SESSION,
                self.system,
                OpenAgentSessionPayload(agent_id=agent_id),
            )
        )
        epoch_value = event.payload["sessionEpoch"]
        if not isinstance(epoch_value, int):
            raise AssertionError("Agent session Event did not contain an integer epoch")
        epoch = epoch_value
        self.epochs[agent_id] = epoch
        return epoch

    async def query_work(self, work_item_id: str) -> WorkItem:
        result = await self.core.query(Query(kind=QueryKind.WORK_ITEM, entity_id=work_item_id))
        if not isinstance(result, WorkItem):
            raise AssertionError(f"missing WorkItem {work_item_id}")
        return result

    async def query_mission(self, mission_id: str) -> Mission:
        result = await self.core.query(Query(kind=QueryKind.MISSION, entity_id=mission_id))
        if not isinstance(result, Mission):
            raise AssertionError(f"missing Mission {mission_id}")
        return result

    async def add_worker(
        self,
        *,
        group_id: str,
        coordinator_id: str,
        coordinator_epoch: int,
        worker_id: str,
        reviewer: bool = False,
    ) -> None:
        roles = (Role.WORKER, Role.REVIEWER) if reviewer else (Role.WORKER,)
        await self.perform(
            self.command(
                CommandKind.ADD_MEMBERSHIP,
                Principal.agent(coordinator_id),
                AddMembershipPayload(
                    principal=Principal.agent(worker_id),
                    roles=roles,
                    provisional=True,
                ),
                group_id=group_id,
                coordinator_epoch=coordinator_epoch,
            )
        )

    async def create_work(
        self,
        *,
        group_id: str,
        coordinator_id: str,
        coordinator_epoch: int,
        work_item_id: str,
        contract: WorkContract,
        dependencies: tuple[str, ...] = (),
        proposal_id: str | None = None,
    ) -> Event:
        return await self.perform(
            self.command(
                CommandKind.CREATE_WORK_ITEM,
                Principal.agent(coordinator_id),
                CreateWorkItemPayload(
                    work_item_id=work_item_id,
                    contract=contract,
                    dependency_ids=dependencies,
                    proposal_id=proposal_id,
                ),
                group_id=group_id,
                coordinator_epoch=coordinator_epoch,
            )
        )

    async def assign(
        self,
        *,
        work_item_id: str,
        group_id: str,
        coordinator_id: str,
        coordinator_epoch: int,
        worker_id: str,
        ownership_lease_seconds: int = 3_600,
    ) -> WorkItem:
        work = await self.query_work(work_item_id)
        requirements = work.contract.required_capabilities
        await self.perform(
            self.command(
                CommandKind.OFFER_WORK_ITEM,
                Principal.agent(coordinator_id),
                OfferWorkItemPayload(
                    work_item_id=work_item_id,
                    candidate_agent_ids=(worker_id,),
                    selection_basis=SelectionBasis(
                        required_capabilities=requirements,
                        verified_capability_matches=tuple(item.id for item in requirements),
                        authorization_eligible=True,
                        availability_estimate="one coarse capacity slot",
                        policy_rules_applied=("organization-priority", "group-quota"),
                    ),
                    offer_expires_in_seconds=600,
                ),
                group_id=group_id,
                coordinator_epoch=coordinator_epoch,
            )
        )
        await self.perform(
            self.command(
                CommandKind.ACCEPT_WORK_OFFER,
                Principal.agent(worker_id),
                AcceptWorkOfferPayload(
                    work_item_id=work_item_id,
                    ownership_lease_seconds=ownership_lease_seconds,
                ),
                group_id=group_id,
            )
        )
        return await self.query_work(work_item_id)

    async def start(
        self,
        *,
        work_item_id: str,
        group_id: str,
        worker_id: str,
        ownership_epoch: int,
        execution_lease_seconds: int = 600,
    ) -> WorkItem:
        await self.perform(
            self.command(
                CommandKind.START_WORK_ITEM,
                Principal.agent(worker_id),
                StartWorkItemPayload(
                    work_item_id=work_item_id,
                    ownership_epoch=ownership_epoch,
                    execution_lease_seconds=execution_lease_seconds,
                ),
                group_id=group_id,
            )
        )
        return await self.query_work(work_item_id)

    async def publish_submit_verify(
        self,
        *,
        work_item_id: str,
        artifact_id: str,
        content: bytes,
        worker_id: str,
        coordinator_id: str,
        coordinator_epoch: int,
        capability: str,
        source_hashes: tuple[str, ...] = (),
    ) -> ArtifactManifest:
        work = await self.query_work(work_item_id)
        if work.status is not WorkItemStatus.ACTIVE or work.assignee_id != worker_id:
            raise AssertionError(f"WorkItem {work_item_id} is not active for {worker_id}")
        if work.execution_lease_id is None:
            raise AssertionError(f"WorkItem {work_item_id} has no Execution Lease ID")
        manifest = self.artifact_store.put(
            content,
            identity=self.identities[worker_id],
            agent_card_version=str(work.assigned_agent_card_version),
            capability=capability,
            capability_version="1",
            mission_id=work.mission_id,
            group_id=work.group_id,
            work_item_id=work.id,
            media_type="application/json",
            classification="internal",
            source_artifact_hashes=source_hashes,
            tool_versions={"python": "3.12", "pytest": "8"},
            model_versions={"worker": "deterministic-poc-v1"},
            created_at=self.clock(),
        )
        manifest.verify(self.identities[worker_id].public_key)
        if self.artifact_store.get(manifest) != content:
            raise AssertionError("Artifact bytes failed content-address verification")
        unsigned_artifact = Artifact(
            id=artifact_id,
            content_hash=manifest.content_hash,
            media_type=manifest.media_type,
            producing_agent_id=worker_id,
            agent_card_version=int(manifest.producer_agent_card_version),
            mission_id=work.mission_id,
            group_id=work.group_id,
            work_item_id=work.id,
            source_artifact_hashes=manifest.source_artifact_hashes,
            tool_versions=manifest.tool_versions,
            model_versions=manifest.model_versions,
            created_at=manifest.created_at,
            data_classification=manifest.classification,
            signature="pending",
        )
        artifact = unsigned_artifact.model_copy(
            update={
                "signature": self.identities[worker_id].sign(
                    canonical_bytes(unsigned_artifact.signing_payload())
                )
            }
        )
        await self.perform(
            self.command(
                CommandKind.PUBLISH_ARTIFACT,
                Principal.agent(worker_id),
                PublishArtifactPayload(
                    artifact=artifact,
                    ownership_epoch=work.ownership_epoch,
                    execution_lease_id=work.execution_lease_id,
                ),
                group_id=work.group_id,
            )
        )
        current = await self.query_work(work_item_id)
        await self.perform(
            self.command(
                CommandKind.SUBMIT_WORK_ITEM,
                Principal.agent(worker_id),
                SubmitWorkItemPayload(
                    work_item_id=work.id,
                    ownership_epoch=work.ownership_epoch,
                    execution_lease_id=work.execution_lease_id,
                    artifact_ids=(artifact.id,),
                    evidence=(
                        Evidence(
                            kind="deterministic-tests",
                            description=f"{work.id} acceptance checks passed",
                            data={"artifactHash": artifact.content_hash},
                        ),
                    ),
                ),
                group_id=work.group_id,
                expected_revision=current.revision,
            )
        )
        submitted = await self.query_work(work_item_id)
        await self.perform(
            self.command(
                CommandKind.VERIFY_WORK_ITEM,
                Principal.agent(coordinator_id),
                VerifyWorkItemPayload(
                    work_item_id=work.id,
                    evidence=(
                        Evidence(
                            kind="coordinator-verification",
                            description=f"{coordinator_id} verified exact Work Contract criteria",
                            data={"artifactHash": artifact.content_hash},
                        ),
                    ),
                ),
                group_id=work.group_id,
                coordinator_epoch=coordinator_epoch,
                expected_revision=submitted.revision,
            )
        )
        self.manifests[manifest.content_hash] = manifest
        return manifest

    async def complete_standard_work(
        self,
        *,
        work_item_id: str,
        artifact_id: str,
        content: bytes,
        group_id: str,
        coordinator_id: str,
        coordinator_epoch: int,
        worker_id: str,
        capability: str,
        source_hashes: tuple[str, ...] = (),
    ) -> ArtifactManifest:
        work = await self.assign(
            work_item_id=work_item_id,
            group_id=group_id,
            coordinator_id=coordinator_id,
            coordinator_epoch=coordinator_epoch,
            worker_id=worker_id,
        )
        await self.start(
            work_item_id=work.id,
            group_id=group_id,
            worker_id=worker_id,
            ownership_epoch=work.ownership_epoch,
        )
        return await self.publish_submit_verify(
            work_item_id=work.id,
            artifact_id=artifact_id,
            content=content,
            worker_id=worker_id,
            coordinator_id=coordinator_id,
            coordinator_epoch=coordinator_epoch,
            capability=capability,
            source_hashes=source_hashes,
        )

    async def post_message(
        self,
        *,
        actor_id: str,
        group_id: str,
        conversation_id: str,
        message_id: str,
        content: str,
        mentions: tuple[Principal, ...] = (),
    ) -> Event:
        event = await self.perform(
            self.command(
                CommandKind.POST_MESSAGE,
                Principal.agent(actor_id),
                PostMessagePayload(
                    message_id=message_id,
                    conversation_id=conversation_id,
                    content=content,
                    mentions=mentions,
                ),
                group_id=group_id,
            )
        )
        self.messages.append(message_id)
        return event


def _contract(
    scenario: _Scenario,
    *,
    goal: str,
    capability: str,
    priority: int = 50,
    duration_seconds: int = 300,
    deadline_hours: int = 8,
) -> WorkContract:
    return WorkContract(
        goal=goal,
        deliverables=(f"{goal} deliverable",),
        acceptance_criteria=(f"{goal} deterministic checks pass",),
        allowed_tools=("python", "pytest"),
        allowed_resources=("repository",),
        deadline=scenario.clock() + timedelta(hours=deadline_hours),
        requested_priority=priority,
        estimated_duration_seconds=duration_seconds,
        required_capabilities=(CapabilityRequirement(id=capability),),
        budget=ResourceBudget(model_tokens=10_000, tool_calls=100, compute_seconds=3_600),
    )


async def _group_heads(core: Core, group_ids: tuple[str, ...]) -> dict[str, int]:
    heads: dict[str, int] = {}
    for group_id in group_ids:
        events = await core.replay(group_id)
        heads[group_id] = 0 if not events else cast(int, events[-1].sequence)
    return heads


async def _reconcile_outbox_through_gateway(
    scenario: _Scenario,
    store: SQLiteAgentStore,
    connection: ClientConnection,
    *,
    session_epoch: int,
) -> tuple[int, tuple[str, ...]]:
    sent = 0
    accepted_kinds: list[str] = []
    for raw in store.pending_actions(REVIEWER):
        command = Command.model_validate(raw)
        if command.group_id is None:
            raise AssertionError("offline Command is missing its Group")
        membership = await scenario.core.query(
            Query(
                kind=QueryKind.MEMBERSHIP,
                entity_id=REVIEWER,
                group_id=command.group_id,
                actor_type=ActorType.AGENT,
            )
        )
        if not isinstance(membership, Membership):
            raise AssertionError("offline reconciliation could not refresh Membership")
        execution_lease_id: str | None = None
        if command.kind is CommandKind.CHECKPOINT_WORK_ITEM:
            raw_work_item_id = command.payload.get("workItemId")
            if not isinstance(raw_work_item_id, str):
                raise AssertionError("offline checkpoint is missing its WorkItem ID")
            work = await scenario.query_work(raw_work_item_id)
            if work.status is WorkItemStatus.QUEUED:
                work = await scenario.start(
                    work_item_id=work.id,
                    group_id=work.group_id,
                    worker_id=REVIEWER,
                    ownership_epoch=work.ownership_epoch,
                )
            if work.status is not WorkItemStatus.ACTIVE or work.execution_lease_id is None:
                raise AssertionError("offline checkpoint could not reacquire execution")
            execution_lease_id = work.execution_lease_id
        document = offline_command_to_wire(
            command,
            scenario.identities[REVIEWER],
            session_epoch=session_epoch,
            membership_epoch=membership.epoch,
            issued_at=scenario.clock(),
            execution_lease_id=execution_lease_id,
        )
        await connection.send(encode_frame(CommandFrame(command=document)))
        frame = parse_frame(await connection.recv())
        if not isinstance(frame, EventFrame):
            raise AssertionError(f"offline gateway reconciliation failed: {frame!r}")
        event_kind = frame.event.get("kind")
        if not isinstance(event_kind, str):
            raise AssertionError("gateway Event did not contain a kind")
        accepted_kinds.append(event_kind)
        store.mark_action_sent(REVIEWER, command.action_id)
        sent += 1
    return sent, tuple(accepted_kinds)


def _dispatch(actions: tuple[Dispatch | Preempt, ...]) -> Dispatch:
    dispatches = [action for action in actions if isinstance(action, Dispatch)]
    if len(dispatches) != 1:
        raise AssertionError(f"expected exactly one Dispatch, got {actions!r}")
    return dispatches[0]


async def _run(root: Path) -> POCReport:
    root.mkdir(parents=True, exist_ok=True)
    local_path = root / "reviewer-local.sqlite3"
    local_path.unlink(missing_ok=True)
    scenario = _Scenario(root)

    capabilities = {
        COORD_AUTH: ("coordination", "software.review"),
        COORD_CLI: ("coordination",),
        COORD_CLI_REPLACEMENT: ("coordination", "software.review"),
        ANALYST: ("software.analysis",),
        CODER: ("software.python", "software.testing", "software.integration"),
        REVIEWER: ("software.review",),
        SECURITY_COORDINATOR: ("coordination", "software.security-review"),
        SECURITY_WORKER: ("software.security",),
    }
    for agent_id, values in capabilities.items():
        await scenario.register(agent_id, values)

    root_auth = scenario.human_control.create(
        mission_id=MISSION_AUTH,
        group_id=GROUP_AUTH,
        coordinator_id=COORD_AUTH,
        title="Authentication feature",
        objective="Ship a secure authentication feature",
        definition_of_done=(
            "requirements analyzed",
            "implementation tested",
            "security child approved",
            "review and integration verified",
            "human approves exact Artifacts",
        ),
        budget=ResourceBudget(
            model_tokens=500_000,
            tool_calls=5_000,
            compute_seconds=100_000,
        ),
        deadline=scenario.clock() + timedelta(days=2),
        permissions=("repo.read", "repo.write"),
        coordinator_lease_seconds=86_400,
    )
    root_cli = scenario.human_control.create(
        mission_id=MISSION_CLI,
        group_id=GROUP_CLI,
        coordinator_id=COORD_CLI,
        title="CLI feature",
        objective="Ship a deterministic operator CLI",
        definition_of_done=(
            "implementation verified",
            "shared review verified",
            "human approves exact Artifacts",
        ),
        budget=ResourceBudget(
            model_tokens=300_000,
            tool_calls=3_000,
            compute_seconds=80_000,
        ),
        deadline=scenario.clock() + timedelta(days=2),
        permissions=("repo.read", "repo.write"),
        coordinator_lease_seconds=86_400,
    )
    root_auth_receipt, root_cli_receipt = await asyncio.gather(root_auth, root_cli)
    await asyncio.gather(
        scenario.observe_control_receipt(root_auth_receipt.command, root_auth_receipt.event),
        scenario.observe_control_receipt(root_cli_receipt.command, root_cli_receipt.event),
    )
    scenario.prove(
        "human_control_created_signed_roots",
        scenario.human_identity.verify(root_auth_receipt.command)
        and scenario.human_identity.verify(root_cli_receipt.command),
    )
    auth_mission, cli_mission = await asyncio.gather(
        scenario.query_mission(MISSION_AUTH),
        scenario.query_mission(MISSION_CLI),
    )
    scenario.prove(
        "concurrent_root_missions",
        auth_mission.status is MissionStatus.ACTIVE and cli_mission.status is MissionStatus.ACTIVE,
    )

    for worker_id, reviewer in ((ANALYST, False), (CODER, False), (REVIEWER, True)):
        await scenario.add_worker(
            group_id=GROUP_AUTH,
            coordinator_id=COORD_AUTH,
            coordinator_epoch=1,
            worker_id=worker_id,
            reviewer=reviewer,
        )
    for worker_id, reviewer in ((CODER, False), (REVIEWER, True)):
        await scenario.add_worker(
            group_id=GROUP_CLI,
            coordinator_id=COORD_CLI,
            coordinator_epoch=1,
            worker_id=worker_id,
            reviewer=reviewer,
        )

    await scenario.create_work(
        group_id=GROUP_AUTH,
        coordinator_id=COORD_AUTH,
        coordinator_epoch=1,
        work_item_id="auth:requirements",
        contract=_contract(
            scenario,
            goal="Analyze authentication requirements",
            capability="software.analysis",
        ),
    )
    await scenario.create_work(
        group_id=GROUP_AUTH,
        coordinator_id=COORD_AUTH,
        coordinator_epoch=1,
        work_item_id="auth:implementation",
        contract=_contract(
            scenario,
            goal="Implement authentication",
            capability="software.python",
        ),
        dependencies=("auth:requirements",),
    )
    await scenario.create_work(
        group_id=GROUP_AUTH,
        coordinator_id=COORD_AUTH,
        coordinator_epoch=1,
        work_item_id="auth:tests",
        contract=_contract(
            scenario,
            goal="Test authentication",
            capability="software.testing",
        ),
        dependencies=("auth:implementation",),
    )
    await scenario.create_work(
        group_id=GROUP_AUTH,
        coordinator_id=COORD_AUTH,
        coordinator_epoch=1,
        work_item_id="auth:security",
        contract=_contract(
            scenario,
            goal="Security review authentication",
            capability="software.security",
        ),
        dependencies=("auth:tests",),
    )
    await scenario.create_work(
        group_id=GROUP_AUTH,
        coordinator_id=COORD_AUTH,
        coordinator_epoch=1,
        work_item_id="auth:review",
        contract=_contract(
            scenario,
            goal="Review authentication code",
            capability="software.review",
            priority=20,
        ),
    )
    await scenario.create_work(
        group_id=GROUP_AUTH,
        coordinator_id=COORD_AUTH,
        coordinator_epoch=1,
        work_item_id="auth:integration",
        contract=_contract(
            scenario,
            goal="Integrate authentication release",
            capability="software.integration",
        ),
        dependencies=("auth:review", "auth:security"),
    )
    await scenario.create_work(
        group_id=GROUP_CLI,
        coordinator_id=COORD_CLI,
        coordinator_epoch=1,
        work_item_id="cli:implementation",
        contract=_contract(
            scenario,
            goal="Implement operator CLI",
            capability="software.python",
        ),
    )

    dependency_command = scenario.command(
        CommandKind.ADD_WORK_ITEM_DEPENDENCY,
        Principal.agent(COORD_AUTH),
        AddWorkItemDependencyPayload(
            work_item_id="auth:review",
            dependency_id="auth:tests",
        ),
        group_id=GROUP_AUTH,
        coordinator_epoch=1,
        action_id="poc:dynamic-dependency",
    )
    first_dependency = await scenario.perform(dependency_command)
    duplicate_dependency = await scenario.perform(dependency_command)
    scenario.prove("duplicate_command_idempotent", first_dependency == duplicate_dependency)
    changed_dependency = dependency_command.model_copy(deep=True)
    changed_dependency.payload["dependencyId"] = "auth:implementation"
    changed_dependency = scenario.resign(changed_dependency)
    await scenario.expect(
        "action_id_collision_rejected",
        ActionIdCollision,
        scenario.perform(changed_dependency),
    )
    dependency_events = [
        event
        for event in await scenario.core.replay(GROUP_AUTH)
        if event.action_id == dependency_command.action_id
    ]
    review = await scenario.query_work("auth:review")
    scenario.prove(
        "dynamic_dependency_committed_once",
        review.dependency_ids == ("auth:tests",) and len(dependency_events) == 1,
    )

    replacement_receipt = await scenario.human_control.replace_coordinator(
        MISSION_CLI,
        COORD_CLI_REPLACEMENT,
        lease_seconds=86_400,
    )
    await scenario.observe_control_receipt(
        replacement_receipt.command,
        replacement_receipt.event,
    )
    scenario.prove(
        "human_control_signed_coordinator_replacement",
        scenario.human_identity.verify(replacement_receipt.command),
    )
    previous_coordinator_command = scenario.command(
        CommandKind.CREATE_WORK_ITEM,
        Principal.agent(COORD_CLI),
        CreateWorkItemPayload(
            work_item_id="cli:previous-coordinator-attempt",
            contract=_contract(
                scenario,
                goal="Unauthorized previous Coordinator work",
                capability="software.review",
                priority=5,
            ),
            dependency_ids=("cli:implementation",),
        ),
        group_id=GROUP_CLI,
        coordinator_epoch=1,
    )
    await scenario.expect(
        "previous_coordinator_rejected_after_replacement",
        AuthorizationDenied,
        scenario.perform(previous_coordinator_command),
    )
    scenario.prove(
        "previous_coordinator_command_carried_old_epoch",
        previous_coordinator_command.actor == Principal.agent(COORD_CLI)
        and previous_coordinator_command.coordinator_epoch == 1,
    )
    stale_coordinator_command = scenario.command(
        CommandKind.CREATE_WORK_ITEM,
        Principal.agent(COORD_CLI_REPLACEMENT),
        CreateWorkItemPayload(
            work_item_id="cli:review",
            contract=_contract(
                scenario,
                goal="Review operator CLI",
                capability="software.review",
                priority=5,
            ),
            dependency_ids=("cli:implementation",),
        ),
        group_id=GROUP_CLI,
        coordinator_epoch=1,
    )
    await scenario.expect(
        "stale_coordinator_epoch_rejected",
        StaleCoordinatorEpoch,
        scenario.perform(stale_coordinator_command),
    )
    await scenario.create_work(
        group_id=GROUP_CLI,
        coordinator_id=COORD_CLI_REPLACEMENT,
        coordinator_epoch=2,
        work_item_id="cli:review",
        contract=_contract(
            scenario,
            goal="Review operator CLI",
            capability="software.review",
            priority=5,
        ),
        dependencies=("cli:implementation",),
    )
    replaced = await scenario.query_mission(MISSION_CLI)
    scenario.prove(
        "coordinator_replacement_committed",
        replaced.coordinator_id == COORD_CLI_REPLACEMENT and replaced.coordinator_epoch == 2,
    )

    requirements_manifest = await scenario.complete_standard_work(
        work_item_id="auth:requirements",
        artifact_id="artifact:auth:requirements",
        content=b'{"requirements":["mfa","audit-log"]}',
        group_id=GROUP_AUTH,
        coordinator_id=COORD_AUTH,
        coordinator_epoch=1,
        worker_id=ANALYST,
        capability="software.analysis",
    )

    implementation = await scenario.assign(
        work_item_id="auth:implementation",
        group_id=GROUP_AUTH,
        coordinator_id=COORD_AUTH,
        coordinator_epoch=1,
        worker_id=CODER,
    )
    active_implementation = await scenario.start(
        work_item_id=implementation.id,
        group_id=GROUP_AUTH,
        worker_id=CODER,
        ownership_epoch=implementation.ownership_epoch,
    )
    first_checkpoint = Checkpoint(
        phase="implementation-checkpoint",
        completed_milestones=("password flow",),
        next_step="add MFA",
        state_artifact_hash="sha256:" + "1" * 64,
        created_at=scenario.clock(),
    )
    await scenario.perform(
        scenario.command(
            CommandKind.CHECKPOINT_WORK_ITEM,
            Principal.agent(CODER),
            CheckpointWorkItemPayload(
                work_item_id=implementation.id,
                ownership_epoch=implementation.ownership_epoch,
                execution_lease_id=cast(str, active_implementation.execution_lease_id),
                checkpoint=first_checkpoint,
                resume_within_seconds=3_600,
            ),
            group_id=GROUP_AUTH,
        )
    )
    active_before_block = await scenario.start(
        work_item_id=implementation.id,
        group_id=GROUP_AUTH,
        worker_id=CODER,
        ownership_epoch=implementation.ownership_epoch,
    )
    blocked_checkpoint = Checkpoint(
        phase="blocked-on-schema",
        completed_milestones=("password flow", "MFA flow"),
        next_step="resume after schema decision",
        state_artifact_hash="sha256:" + "2" * 64,
        created_at=scenario.clock(),
    )
    await scenario.perform(
        scenario.command(
            CommandKind.BLOCK_WORK_ITEM,
            Principal.agent(CODER),
            BlockWorkItemPayload(
                work_item_id=implementation.id,
                ownership_epoch=implementation.ownership_epoch,
                execution_lease_id=cast(str, active_before_block.execution_lease_id),
                reason="awaiting authentication schema decision",
                checkpoint=blocked_checkpoint,
                blocked_lease_seconds=3_600,
            ),
            group_id=GROUP_AUTH,
        )
    )
    blocked = await scenario.query_work(implementation.id)
    await scenario.perform(
        scenario.command(
            CommandKind.UNBLOCK_WORK_ITEM,
            Principal.agent(COORD_AUTH),
            UnblockWorkItemPayload(work_item_id=implementation.id),
            group_id=GROUP_AUTH,
            coordinator_epoch=1,
        )
    )
    resumed = await scenario.start(
        work_item_id=implementation.id,
        group_id=GROUP_AUTH,
        worker_id=CODER,
        ownership_epoch=implementation.ownership_epoch,
    )
    scenario.prove(
        "blocked_checkpointed_resumed",
        blocked.status is WorkItemStatus.BLOCKED
        and len(resumed.checkpoints) == 2
        and resumed.status is WorkItemStatus.ACTIVE,
    )
    implementation_manifest = await scenario.publish_submit_verify(
        work_item_id=implementation.id,
        artifact_id="artifact:auth:implementation",
        content=b'{"module":"authentication","status":"implemented"}',
        worker_id=CODER,
        coordinator_id=COORD_AUTH,
        coordinator_epoch=1,
        capability="software.python",
        source_hashes=(requirements_manifest.content_hash,),
    )

    cli_assignment = await scenario.assign(
        work_item_id="cli:implementation",
        group_id=GROUP_CLI,
        coordinator_id=COORD_CLI_REPLACEMENT,
        coordinator_epoch=2,
        worker_id=CODER,
        ownership_lease_seconds=5,
    )
    active_cli_assignment = await scenario.start(
        work_item_id=cli_assignment.id,
        group_id=GROUP_CLI,
        worker_id=CODER,
        ownership_epoch=cli_assignment.ownership_epoch,
        execution_lease_seconds=2,
    )
    scenario.clock.advance(3)
    await scenario.expect(
        "execution_lease_expiry_rejected",
        LeaseExpired,
        scenario.perform(
            scenario.command(
                CommandKind.RENEW_EXECUTION_LEASE,
                Principal.agent(CODER),
                RenewExecutionLeasePayload(
                    work_item_id=cli_assignment.id,
                    ownership_epoch=cli_assignment.ownership_epoch,
                    execution_lease_id=cast(str, active_cli_assignment.execution_lease_id),
                    lease_seconds=60,
                ),
                group_id=GROUP_CLI,
            )
        ),
    )
    scenario.clock.advance(3)
    reassigned = await scenario.assign(
        work_item_id=cli_assignment.id,
        group_id=GROUP_CLI,
        coordinator_id=COORD_CLI_REPLACEMENT,
        coordinator_epoch=2,
        worker_id=CODER,
    )
    await scenario.expect(
        "stale_ownership_epoch_rejected",
        StaleOwnershipEpoch,
        scenario.perform(
            scenario.command(
                CommandKind.START_WORK_ITEM,
                Principal.agent(CODER),
                StartWorkItemPayload(
                    work_item_id=reassigned.id,
                    ownership_epoch=cli_assignment.ownership_epoch,
                    execution_lease_seconds=600,
                ),
                group_id=GROUP_CLI,
            )
        ),
    )
    scenario.prove(
        "ownership_epoch_advanced",
        reassigned.ownership_epoch > cli_assignment.ownership_epoch,
    )
    await scenario.start(
        work_item_id=reassigned.id,
        group_id=GROUP_CLI,
        worker_id=CODER,
        ownership_epoch=reassigned.ownership_epoch,
    )
    cli_implementation_manifest = await scenario.publish_submit_verify(
        work_item_id=reassigned.id,
        artifact_id="artifact:cli:implementation",
        content=b'{"command":"missionweaveprotocol-demo","status":"implemented"}',
        worker_id=CODER,
        coordinator_id=COORD_CLI_REPLACEMENT,
        coordinator_epoch=2,
        capability="software.python",
    )

    tests_manifest = await scenario.complete_standard_work(
        work_item_id="auth:tests",
        artifact_id="artifact:auth:tests",
        content=b'{"suite":"authentication","passed":true}',
        group_id=GROUP_AUTH,
        coordinator_id=COORD_AUTH,
        coordinator_epoch=1,
        worker_id=CODER,
        capability="software.testing",
        source_hashes=(implementation_manifest.content_hash,),
    )

    await scenario.perform(
        scenario.command(
            CommandKind.CREATE_CHILD_MISSION,
            Principal.agent(COORD_AUTH),
            CreateChildMissionPayload(
                mission_id=MISSION_SECURITY,
                group_id=GROUP_SECURITY,
                parent_work_item_id="auth:security",
                coordinator_id=SECURITY_COORDINATOR,
                title="Authentication security review",
                objective="Independently verify authentication security",
                definition_of_done=("security findings resolved",),
                budget=ResourceBudget(
                    model_tokens=10_000,
                    tool_calls=100,
                    compute_seconds=3_600,
                ),
                deadline=scenario.clock() + timedelta(hours=4),
                permissions=("repo.read",),
                failure_policy=ChildFailurePolicy.BLOCK_PARENT_WORK_ITEM,
                coordinator_lease_seconds=14_400,
            ),
            group_id=GROUP_AUTH,
            coordinator_epoch=1,
        )
    )
    await scenario.add_worker(
        group_id=GROUP_SECURITY,
        coordinator_id=SECURITY_COORDINATOR,
        coordinator_epoch=1,
        worker_id=SECURITY_WORKER,
    )
    await scenario.create_work(
        group_id=GROUP_SECURITY,
        coordinator_id=SECURITY_COORDINATOR,
        coordinator_epoch=1,
        work_item_id="security:review",
        contract=_contract(
            scenario,
            goal="Review authentication threat model",
            capability="software.security",
            deadline_hours=3,
        ),
    )
    security_manifest = await scenario.complete_standard_work(
        work_item_id="security:review",
        artifact_id="artifact:security:review",
        content=b'{"securityReview":"passed","findings":0}',
        group_id=GROUP_SECURITY,
        coordinator_id=SECURITY_COORDINATOR,
        coordinator_epoch=1,
        worker_id=SECURITY_WORKER,
        capability="software.security",
        source_hashes=(implementation_manifest.content_hash, tests_manifest.content_hash),
    )
    security_mission = await scenario.query_mission(MISSION_SECURITY)
    await scenario.perform(
        scenario.command(
            CommandKind.SUBMIT_MISSION,
            Principal.agent(SECURITY_COORDINATOR),
            SubmitMissionPayload(artifact_hashes=(security_manifest.content_hash,)),
            group_id=GROUP_SECURITY,
            coordinator_epoch=1,
            expected_revision=security_mission.revision,
        )
    )
    security_submitted = await scenario.query_mission(MISSION_SECURITY)
    if security_submitted.submitted_revision is None:
        raise AssertionError("security Mission was not submitted")
    await scenario.perform(
        scenario.command(
            CommandKind.APPROVE_MISSION,
            Principal.agent(COORD_AUTH),
            ApproveMissionPayload(
                approval_id="approval:security",
                mission_revision=security_submitted.submitted_revision,
                artifact_hashes=(security_manifest.content_hash,),
                acceptance_policy_version="acme-security-policy-v1",
                comments="Child security result accepted",
            ),
            group_id=GROUP_SECURITY,
        )
    )
    parent_security = await scenario.query_work("auth:security")
    scenario.prove(
        "child_security_mission_approved",
        (await scenario.query_mission(MISSION_SECURITY)).status is MissionStatus.APPROVED
        and parent_security.status is WorkItemStatus.VERIFIED,
    )

    reviewer_auth_membership = await scenario.core.query(
        Query(
            kind=QueryKind.MEMBERSHIP,
            entity_id=REVIEWER,
            group_id=GROUP_AUTH,
            actor_type=ActorType.AGENT,
        )
    )
    if not isinstance(reviewer_auth_membership, Membership):
        raise AssertionError("reviewer provisional Membership is missing")
    context_events = await scenario.core.replay(GROUP_AUTH)
    context_private_key = hashlib.sha256(f"missionweaveprotocol-poc:{COORD_AUTH}".encode()).digest()
    context_service = ContextPackageService(
        agent_id=COORD_AUTH,
        key_id="urn:missionweaveprotocol:key:coordinator-auth:context",
        private_key=context_private_key,
        public_key=scenario.identities[COORD_AUTH].public_key,
    )
    context_package = context_service.publish(
        mission_id=MISSION_AUTH,
        group_id=GROUP_AUTH,
        work_item_id="auth:review",
        version=1,
        events=context_events,
        summary="Authentication-only decisions and verified inputs for the late reviewer.",
        artifact_hashes=(
            implementation_manifest.content_hash,
            tests_manifest.content_hash,
            security_manifest.content_hash,
        ),
        constraints=(
            "Use only Group authentication provenance.",
            "Do not disclose CLI Mission context.",
        ),
        unresolved_questions=("Confirm MFA recovery edge cases.",),
        generated_at=scenario.clock(),
        context_package_id="context:authentication:reviewer:v1",
    )
    context_service.verify(context_package)
    scenario.prove(
        "signed_context_package_issued_for_late_provisional_reviewer",
        reviewer_auth_membership.status is MembershipStatus.PROVISIONAL
        and context_package.group_id == GROUP_AUTH
        and context_package.work_item_id == "auth:review"
        and context_package.source_event_range.to_sequence == len(context_events),
    )
    knowledge_publisher = KnowledgePublisher(
        publisher=Principal.agent(COORD_AUTH),
        key_id="urn:missionweaveprotocol:key:coordinator-auth:knowledge",
        private_key=context_private_key,
        public_key=scenario.identities[COORD_AUTH].public_key,
    )
    knowledge_publication = knowledge_publisher.publish(
        context=context_package,
        artifact_hash=security_manifest.content_hash,
        target_scope="knowledge:engineering:authentication",
        classification="internal",
        summary="Reusable authentication threat-model review with zero unresolved findings.",
        published_at=scenario.clock(),
    )
    knowledge_publisher.verify(knowledge_publication)
    scenario.prove(
        "classified_reusable_knowledge_has_event_and_artifact_provenance",
        knowledge_publication.classification == "internal"
        and knowledge_publication.artifact_hash in context_package.artifact_hashes
        and knowledge_publication.provenance_event_ids
        == context_package.source_event_range.event_ids,
    )
    context_packages: tuple[ContextPackage, ...] = (context_package,)
    knowledge_publications: tuple[KnowledgePublication, ...] = (knowledge_publication,)

    local_store = SQLiteAgentStore(local_path)

    async def ignore_baseline_event(_event: Event) -> EventProjection | None:
        return None

    baseline_replay = AgentReplay(
        REVIEWER,
        local_store,
        scenario.core.replay,
        cast(EventProjector, ignore_baseline_event),
        clock=scenario.clock,
    )
    await baseline_replay.reconcile((GROUP_AUTH, GROUP_CLI))
    baseline_cursors = {
        GROUP_AUTH: local_store.cursor(REVIEWER, GROUP_AUTH),
        GROUP_CLI: local_store.cursor(REVIEWER, GROUP_CLI),
    }
    duplicate_events = await scenario.core.replay(GROUP_AUTH, after=0)
    ignored = sum(not local_store.remember_event(REVIEWER, event.id) for event in duplicate_events)
    scenario.prove("duplicate_event_delivery_ignored", ignored == len(duplicate_events))

    auth_review = await scenario.assign(
        work_item_id="auth:review",
        group_id=GROUP_AUTH,
        coordinator_id=COORD_AUTH,
        coordinator_epoch=1,
        worker_id=REVIEWER,
    )
    cli_review = await scenario.assign(
        work_item_id="cli:review",
        group_id=GROUP_CLI,
        coordinator_id=COORD_CLI_REPLACEMENT,
        coordinator_epoch=2,
        worker_id=REVIEWER,
    )
    await scenario.post_message(
        actor_id=CODER,
        group_id=GROUP_AUTH,
        conversation_id=auth_review.conversation_id,
        message_id="message:auth:coder-to-reviewer",
        content="Implementation and tests are ready; please inspect the MFA edge cases.",
        mentions=(Principal.agent(REVIEWER),),
    )
    await scenario.post_message(
        actor_id=CODER,
        group_id=GROUP_CLI,
        conversation_id=cli_review.conversation_id,
        message_id="message:cli:coder-to-reviewer",
        content="CLI implementation is ready; please review error handling.",
        mentions=(Principal.agent(REVIEWER),),
    )

    scheduler_policy = SchedulerPolicy(
        capacity_slots=2,
        groups={
            GROUP_AUTH: GroupSchedulingPolicy(weight=2, slot_quota=1),
            GROUP_CLI: GroupSchedulingPolicy(weight=1, slot_quota=2),
        },
        supported_capabilities=frozenset({"software.review"}),
        aging_interval=timedelta(minutes=1),
        preemption_margin=0.0,
    )
    reviewer_scheduler = Scheduler(scheduler_policy, clock=scenario.clock)
    reviewer_scheduler.admit(
        WorkOffer.from_work_item(
            auth_review,
            organizational_priority=20,
            estimate=SchedulingEstimate(EstimateBand.MEDIUM),
            capability="software.review",
        ),
        now=scenario.clock(),
    )
    reviewer_scheduler.admit(
        WorkOffer.from_work_item(
            cli_review,
            organizational_priority=5,
            estimate=SchedulingEstimate(EstimateBand.SMALL),
            capability="software.review",
        ),
        now=scenario.clock(),
    )

    first_runtime = AgentRuntime(REVIEWER, reviewer_scheduler)
    first_session = first_runtime.start_session(
        scenario.epochs[REVIEWER],
        session_id="reviewer-session-1",
    )
    context_service.install(
        context_package,
        first_session,
        expected_mission_id=MISSION_AUTH,
    )
    auth_context = {
        "missionId": context_package.mission_id,
        "summary": context_package.summary,
        "artifactHashes": context_package.artifact_hashes,
        "sourceEventRange": context_package.source_event_range.model_dump(
            mode="json", by_alias=True
        ),
        "contextPackageHash": canonical_hash(
            context_package.model_dump(mode="json", by_alias=True)
        ),
    }
    cli_context = {"repository": "cli"}
    cli_credentials = {"token": "cli-scoped-token"}
    first_session.install_group_context(GROUP_CLI, cli_context, revision=1)
    first_session.install_group_credentials(GROUP_CLI, cli_credentials, revision=1)
    auth_context_probe = first_session.prepare(
        Dispatch(
            work_id=auth_review.id,
            group_id=GROUP_AUTH,
            run_id="context-probe:auth",
            slots=1,
            capability="software.review",
        )
    )
    cli_context_probe = first_session.prepare(
        Dispatch(
            work_id=cli_review.id,
            group_id=GROUP_CLI,
            run_id="context-probe:cli",
            slots=1,
            capability="software.review",
        )
    )
    scenario.prove(
        "context_package_installed_only_in_matching_group",
        auth_context_probe.values["summary"] == context_package.summary
        and auth_context_probe.context_revision == context_package.version
        and "Context Package" not in repr(cli_context_probe)
        and context_package.summary not in repr(cli_context_probe),
    )
    local_store.save_group_context(REVIEWER, GROUP_AUTH, 1, auth_context)
    local_store.save_group_context(REVIEWER, GROUP_CLI, 1, cli_context)
    local_store.save_scheduler(REVIEWER, reviewer_scheduler.snapshot())
    old_reviewer_epoch = scenario.epochs[REVIEWER]
    old_session_message = scenario.command(
        CommandKind.POST_MESSAGE,
        Principal.agent(REVIEWER),
        PostMessagePayload(
            message_id="message:stale-reviewer-session",
            conversation_id=auth_review.conversation_id,
            content="This stale runtime must be fenced.",
        ),
        group_id=GROUP_AUTH,
        session_epoch=old_reviewer_epoch,
    )
    first_session.close()
    local_store.close()
    await scenario.reopen(REVIEWER)
    await scenario.expect(
        "worker_restart_fences_old_session",
        StaleSessionEpoch,
        scenario.perform(old_session_message),
    )

    local_store = SQLiteAgentStore(local_path)
    stored_snapshot = local_store.load_scheduler(REVIEWER)
    if stored_snapshot is None:
        raise AssertionError("reviewer Scheduler snapshot was not durable")
    reviewer_scheduling = {
        auth_review.id: (20, SchedulingEstimate(EstimateBand.MEDIUM)),
        cli_review.id: (5, SchedulingEstimate(EstimateBand.SMALL)),
    }
    reviewer_projection_kinds = {
        EventKind.WORK_OFFER_ACCEPTED,
        EventKind.WORK_ITEM_CHECKPOINTED,
        EventKind.WORK_ITEM_UNBLOCKED,
    }

    async def project_reviewer_event(event: Event) -> EventProjection | None:
        if event.kind not in reviewer_projection_kinds:
            return None
        work_item_id = event.payload.get("workItemId")
        if not isinstance(work_item_id, str):
            return None
        work = await scenario.query_work(work_item_id)
        schedule_values = reviewer_scheduling.get(work.id)
        if (
            work.assignee_id != REVIEWER
            or work.status is not WorkItemStatus.QUEUED
            or schedule_values is None
        ):
            return None
        priority, estimate = schedule_values
        return EventProjection(
            work_offers=(
                WorkOffer.from_work_item(
                    work,
                    organizational_priority=priority,
                    estimate=estimate,
                    capability="software.review",
                ),
            )
        )

    reviewer_replay = AgentReplay(
        REVIEWER,
        local_store,
        scenario.core.replay,
        project_reviewer_event,
        scheduler_policy=scheduler_policy,
        clock=scenario.clock,
    )
    replay_results = await reviewer_replay.reconcile((GROUP_AUTH, GROUP_CLI))
    replayed_for_projection = {
        group_id: result.applied_events for group_id, result in replay_results.items()
    }
    reviewer_scheduler = reviewer_replay.scheduler
    live_gateway = _LiveGateway(scenario)
    await live_gateway.start()
    online_connection, online_welcome = await live_gateway.connect()
    scenario.epochs[REVIEWER] = online_welcome.session_epoch
    await live_gateway.subscribe(
        online_connection,
        await _group_heads(scenario.core, (GROUP_AUTH, GROUP_CLI)),
        subscription_id="urn:missionweaveprotocol:subscription:reviewer-online",
    )
    second_runtime = AgentRuntime(REVIEWER, reviewer_scheduler)
    second_session = second_runtime.start_session(
        scenario.epochs[REVIEWER],
        session_id="reviewer-session-2",
    )
    for group_id in (GROUP_AUTH, GROUP_CLI):
        stored_context = local_store.group_context(REVIEWER, group_id)
        if stored_context is None:
            raise AssertionError(f"missing durable Group context for {group_id}")
        revision, context_values = stored_context
        second_session.install_group_context(group_id, context_values, revision=revision)
    second_session.install_group_credentials(GROUP_CLI, cli_credentials, revision=1)
    rebuilt_groups = {
        record.offer.group_id
        for record in reviewer_scheduler.snapshot().records
        if record.state.value == "ready"
    }
    snapshot_work_ids = {record.offer.work_id for record in stored_snapshot.records}
    replay_work_ids = {record.offer.work_id for record in reviewer_scheduler.snapshot().records}
    scenario.prove(
        "worker_restart_rebuilt_per_group_queues_from_event_replay",
        rebuilt_groups == {GROUP_AUTH, GROUP_CLI}
        and replay_work_ids == snapshot_work_ids == {auth_review.id, cli_review.id}
        and replayed_for_projection[GROUP_AUTH] > 0
        and replayed_for_projection[GROUP_CLI] > 0
        and local_store.cursor(REVIEWER, GROUP_AUTH) > baseline_cursors[GROUP_AUTH]
        and local_store.cursor(REVIEWER, GROUP_CLI) > baseline_cursors[GROUP_CLI],
    )

    dispatch_order: list[str] = []
    initial_actions = reviewer_scheduler.schedule(now=scenario.clock())
    initial_dispatches = [action for action in initial_actions if isinstance(action, Dispatch)]
    if len(initial_dispatches) != 2:
        raise AssertionError("two reviewer capacity slots were not filled")
    initial_by_work = {action.work_id: action for action in initial_dispatches}
    auth_dispatch = initial_by_work[auth_review.id]
    cli_dispatch = initial_by_work[cli_review.id]
    dispatch_order.extend(action.work_id for action in initial_dispatches)
    auth_execution = second_session.prepare(auth_dispatch)
    cli_execution = second_session.prepare(cli_dispatch)
    scenario.prove(
        "per_group_context_isolation",
        auth_execution.values["summary"] == context_package.summary
        and auth_execution.values["contextPackageHash"] == auth_context["contextPackageHash"]
        and "cli-scoped-token" not in repr(auth_execution)
        and not auth_execution.credentials
        and cli_execution.credentials["token"] == "cli-scoped-token"
        and context_package.summary not in repr(cli_execution),
    )
    scenario.prove(
        "multiple_capacity_slots_active",
        scheduler_policy.capacity_slots == 2
        and {action.group_id for action in initial_dispatches} == {GROUP_AUTH, GROUP_CLI},
    )
    await scenario.start(
        work_item_id=auth_review.id,
        group_id=GROUP_AUTH,
        worker_id=REVIEWER,
        ownership_epoch=auth_review.ownership_epoch,
        execution_lease_seconds=900,
    )
    await scenario.start(
        work_item_id=cli_review.id,
        group_id=GROUP_CLI,
        worker_id=REVIEWER,
        ownership_epoch=cli_review.ownership_epoch,
        execution_lease_seconds=900,
    )

    await scenario.create_work(
        group_id=GROUP_CLI,
        coordinator_id=COORD_CLI_REPLACEMENT,
        coordinator_epoch=2,
        work_item_id="cli:urgent-review",
        contract=_contract(
            scenario,
            goal="Urgently review CLI release gate",
            capability="software.review",
            priority=100,
            duration_seconds=60,
        ),
        dependencies=("cli:implementation",),
    )
    urgent_review = await scenario.assign(
        work_item_id="cli:urgent-review",
        group_id=GROUP_CLI,
        coordinator_id=COORD_CLI_REPLACEMENT,
        coordinator_epoch=2,
        worker_id=REVIEWER,
    )
    reviewer_scheduler.admit(
        WorkOffer.from_work_item(
            urgent_review,
            organizational_priority=100,
            estimate=SchedulingEstimate(EstimateBand.TINY),
            capability="software.review",
        ),
        now=scenario.clock(),
    )
    scenario.prove(
        "unsafe_work_not_preempted",
        reviewer_scheduler.schedule(now=scenario.clock()) == (),
    )
    unsafe_checkpoint = CheckpointRef(
        checkpoint_id="checkpoint:auth-review:unsafe",
        work_id=auth_dispatch.work_id,
        group_id=auth_dispatch.group_id,
        run_id=auth_dispatch.run_id,
        created_at=scenario.clock(),
        durable=False,
        safe=True,
    )
    reviewer_scheduler.apply(
        WorkTransition(
            work_id=auth_dispatch.work_id,
            kind=TransitionKind.CHECKPOINT_SAVED,
            run_id=auth_dispatch.run_id,
            checkpoint=unsafe_checkpoint,
        ),
        now=scenario.clock(),
    )
    scenario.prove(
        "unsafe_checkpoint_not_preempted",
        reviewer_scheduler.schedule(now=scenario.clock()) == (),
    )
    safe_checkpoint = CheckpointRef(
        checkpoint_id="checkpoint:auth-review:safe",
        work_id=auth_dispatch.work_id,
        group_id=auth_dispatch.group_id,
        run_id=auth_dispatch.run_id,
        created_at=scenario.clock(),
        durable=True,
        safe=True,
    )
    reviewer_scheduler.apply(
        WorkTransition(
            work_id=auth_dispatch.work_id,
            kind=TransitionKind.CHECKPOINT_SAVED,
            run_id=auth_dispatch.run_id,
            checkpoint=safe_checkpoint,
        ),
        now=scenario.clock(),
    )

    await online_connection.close()
    scenario.prove(
        "real_gateway_websocket_disconnected",
        online_connection.close_code is not None,
    )
    active_auth_review = await scenario.query_work(auth_review.id)
    offline_budget_before = await scenario.core.query(
        Query(kind=QueryKind.BUDGET_REMAINING, entity_id=auth_review.id)
    )
    if not isinstance(offline_budget_before, ResourceBudget):
        raise AssertionError("offline WorkItem authoritative budget is missing")
    offline = OfflineExecutionPolicy(
        local_store,
        scenario.identities[REVIEWER],
        active_auth_review,
        disconnected_at=scenario.clock(),
        limits=OfflineLimits(
            max_disconnect_grace=timedelta(minutes=5),
            max_actions=2,
            max_usage=ResourceUsage(
                model_tokens=4,
                compute_seconds=2,
                wall_clock_seconds=4,
            ),
        ),
        clock=scenario.clock,
    )
    offline_message = scenario.command(
        CommandKind.POST_MESSAGE,
        Principal.agent(REVIEWER),
        PostMessagePayload(
            message_id="message:auth:offline-checkpoint",
            conversation_id=auth_review.conversation_id,
            content="Connection is down; reversible review notes are checkpointed locally.",
            mentions=(Principal.agent(CODER),),
        ),
        group_id=GROUP_AUTH,
    )
    core_checkpoint = Checkpoint(
        phase="review-safe-checkpoint",
        completed_milestones=("requirements traced", "tests inspected"),
        next_step="resume semantic review",
        state_artifact_hash="sha256:" + "3" * 64,
        created_at=scenario.clock(),
    )
    offline_checkpoint = scenario.command(
        CommandKind.CHECKPOINT_WORK_ITEM,
        Principal.agent(REVIEWER),
        CheckpointWorkItemPayload(
            work_item_id=auth_review.id,
            ownership_epoch=auth_review.ownership_epoch,
            execution_lease_id=cast(str, active_auth_review.execution_lease_id),
            checkpoint=core_checkpoint,
            resume_within_seconds=1_800,
        ),
        group_id=GROUP_AUTH,
    )
    offline_message = offline.buffer(
        offline_message,
        usage=ResourceUsage(model_tokens=1),
    )
    offline_checkpoint = offline.buffer(
        offline_checkpoint,
        usage=ResourceUsage(model_tokens=1, compute_seconds=1),
    )
    irreversible = scenario.command(
        CommandKind.SUBMIT_WORK_ITEM,
        Principal.agent(REVIEWER),
        SubmitWorkItemPayload(
            work_item_id=auth_review.id,
            ownership_epoch=auth_review.ownership_epoch,
            execution_lease_id=cast(str, active_auth_review.execution_lease_id),
            artifact_ids=("artifact:not-produced-offline",),
            evidence=(Evidence(kind="offline", description="must not submit offline"),),
        ),
        group_id=GROUP_AUTH,
    )
    try:
        offline.buffer(irreversible)
    except OfflinePolicyError:
        scenario.checks["offline_irreversible_action_rejected"] = True
        scenario.failure_injections.append("offline_irreversible_action_rejected")
    else:
        raise AssertionError("offline irreversible action was accepted")
    third_reversible = scenario.command(
        CommandKind.POST_MESSAGE,
        Principal.agent(REVIEWER),
        PostMessagePayload(
            message_id="message:auth:offline-over-budget",
            conversation_id=auth_review.conversation_id,
            content="This third offline action must exceed the bound.",
        ),
        group_id=GROUP_AUTH,
    )
    try:
        offline.buffer(third_reversible)
    except OfflinePolicyError:
        scenario.checks["offline_progress_bounded"] = True
        scenario.failure_injections.append("offline_progress_bounded")
    else:
        raise AssertionError("offline progress limit was not enforced")

    # Reconciliation deliberately happens in a later session timestamp; preserving the
    # buffered Command's original issuedAt would fall outside the replacement Session Grant.
    scenario.clock.advance(5)
    preemption_actions = reviewer_scheduler.schedule(now=scenario.clock())
    if len(preemption_actions) != 1 or not isinstance(preemption_actions[0], Preempt):
        raise AssertionError("safe checkpoint did not request cooperative preemption")
    preemption = preemption_actions[0]
    current_reviewer_auth_membership = await scenario.core.query(
        Query(
            kind=QueryKind.MEMBERSHIP,
            entity_id=REVIEWER,
            group_id=GROUP_AUTH,
            actor_type=ActorType.AGENT,
        )
    )
    if not isinstance(current_reviewer_auth_membership, Membership):
        raise AssertionError("reviewer active Membership is missing")

    stale_reconnection, stale_reconnect_welcome = await live_gateway.connect()
    scenario.epochs[REVIEWER] = stale_reconnect_welcome.session_epoch
    second_session.close()
    stale_membership_document = offline_command_to_wire(
        offline_message,
        scenario.identities[REVIEWER],
        session_epoch=stale_reconnect_welcome.session_epoch,
        membership_epoch=reviewer_auth_membership.epoch,
        issued_at=scenario.clock(),
    )
    await stale_reconnection.send(encode_frame(CommandFrame(command=stale_membership_document)))
    stale_membership_frame = parse_frame(await stale_reconnection.recv())
    await stale_reconnection.wait_closed()
    scenario.prove(
        "stale_membership_epoch_rejected_by_gateway",
        current_reviewer_auth_membership.status is MembershipStatus.ACTIVE
        and current_reviewer_auth_membership.epoch > reviewer_auth_membership.epoch
        and isinstance(stale_membership_frame, ErrorFrame)
        and "stale Membership epoch" in stale_membership_frame.error.message
        and stale_reconnection.close_code is not None,
    )
    scenario.failure_injections.append("stale_membership_epoch_rejected_by_gateway")

    reconnected, reconnect_welcome = await live_gateway.connect()
    scenario.epochs[REVIEWER] = reconnect_welcome.session_epoch
    reconnected_runtime = AgentRuntime(REVIEWER, reviewer_scheduler)
    second_session = reconnected_runtime.start_session(
        reconnect_welcome.session_epoch,
        session_id="reviewer-session-websocket-reconnected",
    )
    for group_id in (GROUP_AUTH, GROUP_CLI):
        stored_context = local_store.group_context(REVIEWER, group_id)
        if stored_context is None:
            raise AssertionError(f"missing durable Group context for {group_id}")
        revision, context_values = stored_context
        second_session.install_group_context(group_id, context_values, revision=revision)
    second_session.install_group_credentials(GROUP_CLI, cli_credentials, revision=1)
    await live_gateway.subscribe(
        reconnected,
        await _group_heads(scenario.core, (GROUP_AUTH, GROUP_CLI)),
        subscription_id="urn:missionweaveprotocol:subscription:reviewer-reconnected",
    )
    reconciled, gateway_event_kinds = await _reconcile_outbox_through_gateway(
        scenario,
        local_store,
        reconnected,
        session_epoch=reconnect_welcome.session_epoch,
    )
    await reconnected.close()
    await live_gateway.stop()
    scenario.messages.append("message:auth:offline-checkpoint")
    reviewer_scheduler.apply(
        WorkTransition(
            work_id=preemption.work_id,
            kind=TransitionKind.PREEMPTED,
            run_id=preemption.run_id,
            checkpoint=preemption.checkpoint,
        ),
        now=scenario.clock(),
    )
    await reviewer_replay.reconcile(GROUP_AUTH)
    scenario.prove(
        "offline_progress_reconciled_before_side_effects",
        reconciled == 2
        and not local_store.pending_actions(REVIEWER)
        and (await scenario.query_work(auth_review.id)).status is WorkItemStatus.QUEUED,
    )
    offline_budget_after = await scenario.core.query(
        Query(kind=QueryKind.BUDGET_REMAINING, entity_id=auth_review.id)
    )
    scenario.prove(
        "offline_usage_reconciled_into_authoritative_budget",
        isinstance(offline_budget_after, ResourceBudget)
        and offline_budget_before.model_tokens is not None
        and offline_budget_after.model_tokens == offline_budget_before.model_tokens - 2
        and offline_budget_before.compute_seconds is not None
        and offline_budget_after.compute_seconds == offline_budget_before.compute_seconds - 1,
    )
    scenario.prove(
        "real_gateway_websocket_reconnected_and_reconciled",
        stale_reconnect_welcome.session_epoch == online_welcome.session_epoch + 1
        and reconnect_welcome.session_epoch == stale_reconnect_welcome.session_epoch + 1
        and gateway_event_kinds
        == (EventKind.MESSAGE_POSTED.value, EventKind.WORK_ITEM_CHECKPOINTED.value),
    )
    rebased_offline_message = offline_command_to_wire(
        offline_message,
        scenario.identities[REVIEWER],
        session_epoch=reconnect_welcome.session_epoch,
        membership_epoch=current_reviewer_auth_membership.epoch,
        issued_at=scenario.clock(),
    )
    rebased_extensions = rebased_offline_message.get("extensions")
    rebased_issued_at = rebased_offline_message.get("issuedAt")
    scenario.prove(
        "offline_gateway_rebase_hook_verified",
        rebased_offline_message["sessionEpoch"] == reconnect_welcome.session_epoch
        and isinstance(rebased_issued_at, str)
        and rebased_issued_at > offline_message.issued_at.isoformat().replace("+00:00", "Z")
        and isinstance(rebased_extensions, dict)
        and rebased_extensions.get(OFFLINE_EXECUTION_EXTENSION)
        == offline_message.extensions[OFFLINE_EXECUTION_EXTENSION].model_dump(
            mode="json", by_alias=True
        ),
    )
    scenario.prove("safe_checkpoint_only_preemption", preemption.checkpoint.safe)

    urgent_dispatch = _dispatch(reviewer_scheduler.schedule(now=scenario.clock()))
    dispatch_order.append(urgent_dispatch.work_id)
    urgent_execution = second_session.prepare(urgent_dispatch)
    scenario.prove(
        "urgent_group_context_isolated",
        urgent_execution.credentials["token"] == "cli-scoped-token"
        and context_package.summary not in repr(urgent_execution),
    )
    await scenario.start(
        work_item_id=urgent_review.id,
        group_id=GROUP_CLI,
        worker_id=REVIEWER,
        ownership_epoch=urgent_review.ownership_epoch,
    )
    urgent_manifest = await scenario.publish_submit_verify(
        work_item_id=urgent_review.id,
        artifact_id="artifact:cli:urgent-review",
        content=b'{"releaseGate":"approved","severity":"urgent"}',
        worker_id=REVIEWER,
        coordinator_id=COORD_CLI_REPLACEMENT,
        coordinator_epoch=2,
        capability="software.review",
        source_hashes=(cli_implementation_manifest.content_hash,),
    )
    reviewer_scheduler.apply(
        WorkTransition(
            work_id=urgent_dispatch.work_id,
            kind=TransitionKind.COMPLETED,
            run_id=urgent_dispatch.run_id,
        ),
        now=scenario.clock(),
    )

    resumed_auth_dispatch = _dispatch(reviewer_scheduler.schedule(now=scenario.clock()))
    dispatch_order.append(resumed_auth_dispatch.work_id)
    scenario.prove(
        "preempted_work_resumed_from_checkpoint",
        resumed_auth_dispatch.work_id == auth_review.id
        and resumed_auth_dispatch.resume_from == safe_checkpoint,
    )
    await scenario.start(
        work_item_id=auth_review.id,
        group_id=GROUP_AUTH,
        worker_id=REVIEWER,
        ownership_epoch=auth_review.ownership_epoch,
    )
    await scenario.post_message(
        actor_id=REVIEWER,
        group_id=GROUP_AUTH,
        conversation_id=auth_review.conversation_id,
        message_id="message:auth:reviewer-to-coder",
        content="MFA edge cases are covered; review is complete.",
        mentions=(Principal.agent(CODER),),
    )
    auth_review_manifest = await scenario.publish_submit_verify(
        work_item_id=auth_review.id,
        artifact_id="artifact:auth:review",
        content=b'{"review":"approved","mfaEdges":"covered"}',
        worker_id=REVIEWER,
        coordinator_id=COORD_AUTH,
        coordinator_epoch=1,
        capability="software.review",
        source_hashes=(
            implementation_manifest.content_hash,
            tests_manifest.content_hash,
            security_manifest.content_hash,
        ),
    )
    reviewer_scheduler.apply(
        WorkTransition(
            work_id=resumed_auth_dispatch.work_id,
            kind=TransitionKind.COMPLETED,
            run_id=resumed_auth_dispatch.run_id,
        ),
        now=scenario.clock(),
    )

    current_cli_review = await scenario.query_work(cli_review.id)
    if current_cli_review.status is WorkItemStatus.QUEUED:
        await scenario.start(
            work_item_id=current_cli_review.id,
            group_id=current_cli_review.group_id,
            worker_id=REVIEWER,
            ownership_epoch=current_cli_review.ownership_epoch,
        )
    await scenario.post_message(
        actor_id=REVIEWER,
        group_id=GROUP_CLI,
        conversation_id=cli_review.conversation_id,
        message_id="message:cli:reviewer-to-coder",
        content="Error handling review passed with deterministic exit codes.",
        mentions=(Principal.agent(CODER),),
    )
    cli_review_manifest = await scenario.publish_submit_verify(
        work_item_id=cli_review.id,
        artifact_id="artifact:cli:review",
        content=b'{"review":"approved","exitCodes":"deterministic"}',
        worker_id=REVIEWER,
        coordinator_id=COORD_CLI_REPLACEMENT,
        coordinator_epoch=2,
        capability="software.review",
        source_hashes=(cli_implementation_manifest.content_hash,),
    )
    reviewer_scheduler.apply(
        WorkTransition(
            work_id=cli_dispatch.work_id,
            kind=TransitionKind.COMPLETED,
            run_id=cli_dispatch.run_id,
        ),
        now=scenario.clock(),
    )
    scenario.prove(
        "global_scheduler_served_both_groups",
        dispatch_order == ["auth:review", "cli:review", "cli:urgent-review", "auth:review"],
    )
    scenario.prove("worker_to_worker_conversations", len(scenario.messages) >= 4)

    integration_manifest = await scenario.complete_standard_work(
        work_item_id="auth:integration",
        artifact_id="artifact:auth:integration",
        content=b'{"release":"authentication","integrated":true}',
        group_id=GROUP_AUTH,
        coordinator_id=COORD_AUTH,
        coordinator_epoch=1,
        worker_id=CODER,
        capability="software.integration",
        source_hashes=(
            implementation_manifest.content_hash,
            tests_manifest.content_hash,
            auth_review_manifest.content_hash,
            security_manifest.content_hash,
        ),
    )
    verified_work = [
        await scenario.query_work(work_id)
        for work_id in (
            "auth:requirements",
            "auth:implementation",
            "auth:tests",
            "auth:security",
            "auth:review",
            "auth:integration",
            "cli:implementation",
            "cli:review",
            "cli:urgent-review",
        )
    ]
    scenario.prove(
        "coordinator_verification_precedes_approval",
        all(work.status is WorkItemStatus.VERIFIED for work in verified_work),
    )

    cli_hashes = tuple(
        sorted(
            {
                cli_implementation_manifest.content_hash,
                cli_review_manifest.content_hash,
                urgent_manifest.content_hash,
            }
        )
    )
    current_cli = await scenario.query_mission(MISSION_CLI)
    await scenario.perform(
        scenario.command(
            CommandKind.SUBMIT_MISSION,
            Principal.agent(COORD_CLI_REPLACEMENT),
            SubmitMissionPayload(artifact_hashes=cli_hashes),
            group_id=GROUP_CLI,
            coordinator_epoch=2,
            expected_revision=current_cli.revision,
        )
    )
    submitted_cli = await scenario.query_mission(MISSION_CLI)
    if submitted_cli.submitted_revision is None:
        raise AssertionError("CLI Mission was not submitted")
    cli_approval_receipt, _ = await scenario.human_control.approve(
        MISSION_CLI,
        approval_id="approval:cli:final",
        mission_revision=submitted_cli.submitted_revision,
        artifact_hashes=cli_hashes,
        acceptance_policy_version="acme-release-policy-v1",
        comments="CLI release approved",
    )

    initial_auth_hashes = tuple(
        sorted(
            {
                requirements_manifest.content_hash,
                implementation_manifest.content_hash,
                tests_manifest.content_hash,
                auth_review_manifest.content_hash,
                integration_manifest.content_hash,
            }
        )
    )
    current_auth = await scenario.query_mission(MISSION_AUTH)
    await scenario.perform(
        scenario.command(
            CommandKind.SUBMIT_MISSION,
            Principal.agent(COORD_AUTH),
            SubmitMissionPayload(artifact_hashes=initial_auth_hashes),
            group_id=GROUP_AUTH,
            coordinator_epoch=1,
            expected_revision=current_auth.revision,
        )
    )
    submitted_auth = await scenario.query_mission(MISSION_AUTH)
    if submitted_auth.submitted_revision is None:
        raise AssertionError("authentication Mission was not submitted")
    changes_receipt = await scenario.human_control.request_changes(
        MISSION_AUTH,
        "Add a migration note and prove backward compatibility.",
        mission_revision=submitted_auth.submitted_revision,
    )
    scenario.prove(
        "human_control_signed_change_request",
        scenario.human_identity.verify(changes_receipt.command),
    )
    correction_contract = _contract(
        scenario,
        goal="Add authentication migration note",
        capability="software.integration",
    )
    integration_work = await scenario.query_work("auth:integration")
    await scenario.post_message(
        actor_id=CODER,
        group_id=GROUP_AUTH,
        conversation_id=integration_work.conversation_id,
        message_id="message:auth:correction-proposal",
        content=(
            '{"type":"work-proposal","proposalId":"proposal:auth:correction",'
            '"goal":"Add authentication migration note"}'
        ),
        mentions=(Principal.agent(COORD_AUTH),),
    )
    await scenario.perform(
        scenario.command(
            CommandKind.PROPOSE_WORK_ITEM,
            Principal.agent(CODER),
            ProposeWorkItemPayload(
                proposal_id="proposal:auth:correction",
                contract=correction_contract,
                dependency_ids=("auth:integration",),
            ),
            group_id=GROUP_AUTH,
        )
    )
    proposed = await scenario.core.query(
        Query(
            kind=QueryKind.WORK_PROPOSAL,
            entity_id="proposal:auth:correction",
        )
    )
    not_yet_authorized = await scenario.core.query(
        Query(kind=QueryKind.WORK_ITEM, entity_id="auth:correction")
    )
    if not isinstance(proposed, WorkProposal):
        raise AssertionError("ordinary Worker proposal was not persisted")
    scenario.prove(
        "worker_proposal_is_non_authoritative",
        proposed.proposed_by == Principal.agent(CODER)
        and proposed.status is WorkProposalStatus.OPEN
        and not_yet_authorized is None,
    )
    authorization_event = await scenario.create_work(
        group_id=GROUP_AUTH,
        coordinator_id=COORD_AUTH,
        coordinator_epoch=1,
        work_item_id="auth:correction",
        contract=correction_contract,
        dependencies=("auth:integration",),
        proposal_id=proposed.id,
    )
    authorized_proposal = await scenario.core.query(
        Query(kind=QueryKind.WORK_PROPOSAL, entity_id=proposed.id)
    )
    authorized_work = await scenario.query_work("auth:correction")
    scenario.prove(
        "coordinator_explicitly_authorized_worker_subwork",
        isinstance(authorized_proposal, WorkProposal)
        and authorized_proposal.status is WorkProposalStatus.AUTHORIZED
        and authorized_proposal.authorized_work_item_id == authorized_work.id
        and authorization_event.actor == Principal.agent(COORD_AUTH)
        and authorization_event.kind is EventKind.WORK_ITEM_CREATED,
    )
    correction_manifest = await scenario.complete_standard_work(
        work_item_id="auth:correction",
        artifact_id="artifact:auth:correction",
        content=b'{"migration":"backward-compatible","note":"included"}',
        group_id=GROUP_AUTH,
        coordinator_id=COORD_AUTH,
        coordinator_epoch=1,
        worker_id=CODER,
        capability="software.integration",
        source_hashes=(integration_manifest.content_hash,),
    )
    final_auth_hashes = tuple(sorted((*initial_auth_hashes, correction_manifest.content_hash)))
    reopened_auth = await scenario.query_mission(MISSION_AUTH)
    await scenario.perform(
        scenario.command(
            CommandKind.SUBMIT_MISSION,
            Principal.agent(COORD_AUTH),
            SubmitMissionPayload(artifact_hashes=final_auth_hashes),
            group_id=GROUP_AUTH,
            coordinator_epoch=1,
            expected_revision=reopened_auth.revision,
        )
    )
    resubmitted_auth = await scenario.query_mission(MISSION_AUTH)
    if resubmitted_auth.submitted_revision is None:
        raise AssertionError("authentication Mission was not resubmitted")
    auth_approval_receipt, _ = await scenario.human_control.approve(
        MISSION_AUTH,
        approval_id="approval:auth:final",
        mission_revision=resubmitted_auth.submitted_revision,
        artifact_hashes=final_auth_hashes,
        acceptance_policy_version="acme-release-policy-v1",
        comments="Authentication release approved after requested changes",
    )

    final_auth = await scenario.query_mission(MISSION_AUTH)
    final_cli = await scenario.query_mission(MISSION_CLI)
    auth_approval_result = await scenario.core.query(
        Query(kind=QueryKind.APPROVAL, entity_id="approval:auth:final")
    )
    cli_approval_result = await scenario.core.query(
        Query(kind=QueryKind.APPROVAL, entity_id="approval:cli:final")
    )
    if not isinstance(auth_approval_result, Approval) or not isinstance(
        cli_approval_result, Approval
    ):
        raise AssertionError("final Approvals were not persisted")
    accepted_auth_approval = await scenario.human_control.accepted_command(
        auth_approval_receipt.event.id
    )
    accepted_cli_approval = await scenario.human_control.accepted_command(
        cli_approval_receipt.event.id
    )
    scenario.prove(
        "exact_signed_human_approvals",
        scenario.human_identity.verify(accepted_auth_approval)
        and scenario.human_identity.verify(accepted_cli_approval)
        and accepted_auth_approval == auth_approval_receipt.command
        and accepted_cli_approval == cli_approval_receipt.command
        and canonical_hash(accepted_auth_approval.signing_payload())
        == auth_approval_receipt.event.command_hash
        and canonical_hash(accepted_cli_approval.signing_payload())
        == cli_approval_receipt.event.command_hash
        and accepted_auth_approval.signature is not None
        and accepted_cli_approval.signature is not None
        and auth_approval_result.signature == accepted_auth_approval.signature.value
        and cli_approval_result.signature == accepted_cli_approval.signature.value
        and auth_approval_result.artifact_hashes == final_auth_hashes
        and cli_approval_result.artifact_hashes == cli_hashes,
    )
    auth_events = await scenario.core.replay(GROUP_AUTH)
    scenario.prove(
        "one_human_requested_changes_cycle",
        sum(event.kind is EventKind.MISSION_CHANGES_REQUESTED for event in auth_events) == 1,
    )

    provenance_edges = 0
    for manifest in scenario.manifests.values():
        manifest.verify(scenario.identities[manifest.producer_agent_id].public_key)
        if scenario.artifact_store.get(manifest) is None:  # pragma: no cover - bytes always return
            raise AssertionError("Artifact bytes missing")
        for source_hash in manifest.source_artifact_hashes:
            if source_hash not in scenario.manifests:
                raise AssertionError(f"unknown provenance source {source_hash}")
            provenance_edges += 1
    scenario.prove(
        "artifact_provenance_verified",
        provenance_edges >= 10
        and all(value in scenario.manifests for value in final_auth_hashes)
        and all(value in scenario.manifests for value in cli_hashes),
    )
    scenario.prove(
        "both_root_missions_approved",
        final_auth.status is MissionStatus.APPROVED and final_cli.status is MissionStatus.APPROVED,
    )

    await reviewer_replay.reconcile((GROUP_AUTH, GROUP_CLI))
    final_auth_events = await scenario.core.replay(GROUP_AUTH)
    final_cli_events = await scenario.core.replay(GROUP_CLI)
    final_security_events = await scenario.core.replay(GROUP_SECURITY)
    auth_approval_signature = accepted_auth_approval.signature
    cli_approval_signature = accepted_cli_approval.signature
    if auth_approval_signature is None or cli_approval_signature is None:
        raise AssertionError("accepted human Approvals are missing signatures")
    auth_approval_signature_value = auth_approval_signature.value
    cli_approval_signature_value = cli_approval_signature.value
    auth_signed_command_hash = auth_approval_receipt.event.command_hash
    cli_signed_command_hash = cli_approval_receipt.event.command_hash
    auth_approval_event_id = auth_approval_receipt.event.id
    if ":" not in auth_approval_event_id:
        auth_approval_event_id = f"urn:uuid:{auth_approval_event_id}"
    cli_approval_event_id = cli_approval_receipt.event.id
    if ":" not in cli_approval_event_id:
        cli_approval_event_id = f"urn:uuid:{cli_approval_event_id}"
    auth_policy_entry = PolicyLogEntry(
        entry_id="policy:authentication:exact-human-approval",
        decision="verified exact signed human approval before archiving",
        actor=scenario.owner,
        details={
            "approvalId": auth_approval_result.id,
            "approvalEventId": auth_approval_event_id,
            "approvalSignature": auth_approval_signature_value,
            "artifactHashes": list(auth_approval_result.artifact_hashes),
            "signatureVerified": scenario.human_identity.verify(accepted_auth_approval),
            "signedCommandHash": auth_signed_command_hash,
        },
        occurred_at=auth_approval_result.approved_at,
    )
    cli_policy_entry = PolicyLogEntry(
        entry_id="policy:cli:exact-human-approval",
        decision="verified exact signed human approval before archiving",
        actor=scenario.owner,
        details={
            "approvalId": cli_approval_result.id,
            "approvalEventId": cli_approval_event_id,
            "approvalSignature": cli_approval_signature_value,
            "artifactHashes": list(cli_approval_result.artifact_hashes),
            "signatureVerified": scenario.human_identity.verify(accepted_cli_approval),
            "signedCommandHash": cli_signed_command_hash,
        },
        occurred_at=cli_approval_result.approved_at,
    )
    auth_snapshot_state = {
        "mission": final_auth.model_dump(mode="json", by_alias=True),
        "approval": auth_approval_result.model_dump(mode="json", by_alias=True),
    }
    cli_snapshot_state = {
        "mission": final_cli.model_dump(mode="json", by_alias=True),
        "approval": cli_approval_result.model_dump(mode="json", by_alias=True),
    }
    snapshot_private_key = hashlib.sha256(f"missionweaveprotocol-poc:{SYSTEM_ID}".encode()).digest()
    snapshot_archive = SnapshotArchive(
        authority=scenario.system,
        key_id=SNAPSHOT_AUTHORITY_KEY_ID,
        private_key=snapshot_private_key,
        public_key=scenario.identities[SYSTEM_ID].public_key,
    )
    auth_snapshot = snapshot_archive.archive(
        group_id=GROUP_AUTH,
        events=final_auth_events,
        state=auth_snapshot_state,
        policy_log=(auth_policy_entry,),
        created_at=scenario.clock(),
    )
    cli_snapshot = snapshot_archive.archive(
        group_id=GROUP_CLI,
        events=final_cli_events,
        state=cli_snapshot_state,
        policy_log=(cli_policy_entry,),
        created_at=scenario.clock(),
    )
    snapshot_archive.verify(auth_snapshot)
    snapshot_archive.verify(cli_snapshot)
    group_snapshots: tuple[GroupSnapshot, ...] = (auth_snapshot, cli_snapshot)
    policy_log_entries = tuple(
        entry for snapshot in group_snapshots for entry in snapshot.policy_log
    )
    expected_auth_event_ids = tuple(
        event.id if ":" in event.id else f"urn:uuid:{event.id}" for event in final_auth_events
    )
    expected_cli_event_ids = tuple(
        event.id if ":" in event.id else f"urn:uuid:{event.id}" for event in final_cli_events
    )
    scenario.prove(
        "signed_root_group_snapshots_cover_complete_histories",
        auth_snapshot.through_sequence == len(final_auth_events)
        and cli_snapshot.through_sequence == len(final_cli_events)
        and auth_snapshot.event_ids == expected_auth_event_ids
        and cli_snapshot.event_ids == expected_cli_event_ids
        and auth_snapshot.state_hash == canonical_hash(auth_snapshot_state)
        and cli_snapshot.state_hash == canonical_hash(cli_snapshot_state)
        and snapshot_archive.get(auth_snapshot.snapshot_id) == auth_snapshot
        and snapshot_archive.get(cli_snapshot.snapshot_id) == cli_snapshot,
    )
    scenario.prove(
        "snapshot_policy_logs_prove_exact_signed_human_approvals",
        len(policy_log_entries) == 2
        and auth_policy_entry.actor == scenario.owner
        and cli_policy_entry.actor == scenario.owner
        and auth_policy_entry.details["signatureVerified"] is True
        and cli_policy_entry.details["signatureVerified"] is True
        and auth_policy_entry.details["signedCommandHash"] == auth_signed_command_hash
        and cli_policy_entry.details["signedCommandHash"] == cli_signed_command_hash
        and auth_policy_entry.details["approvalSignature"] == auth_approval_signature_value
        and cli_policy_entry.details["approvalSignature"] == cli_approval_signature_value
        and auth_policy_entry.details["approvalEventId"] in auth_snapshot.event_ids
        and cli_policy_entry.details["approvalEventId"] in cli_snapshot.event_ids,
    )
    auth_cursor = local_store.cursor(REVIEWER, GROUP_AUTH)
    cli_cursor = local_store.cursor(REVIEWER, GROUP_CLI)
    scenario.prove(
        "sqlite_cursors_reached_contiguous_group_heads",
        auth_cursor == cast(int, final_auth_events[-1].sequence)
        and cli_cursor == cast(int, final_cli_events[-1].sequence),
    )
    auth_archive_event = await scenario.perform(
        scenario.command(
            CommandKind.ARCHIVE_GROUP,
            scenario.system,
            ArchiveGroupPayload(snapshot=auth_snapshot),
            group_id=GROUP_AUTH,
        )
    )
    cli_archive_event = await scenario.perform(
        scenario.command(
            CommandKind.ARCHIVE_GROUP,
            scenario.system,
            ArchiveGroupPayload(snapshot=cli_snapshot),
            group_id=GROUP_CLI,
        )
    )
    persisted_auth_snapshot = await scenario.core.query(
        Query(kind=QueryKind.GROUP_SNAPSHOT, entity_id=auth_snapshot.snapshot_id)
    )
    persisted_cli_snapshot = await scenario.core.query(
        Query(kind=QueryKind.GROUP_SNAPSHOT, entity_id=cli_snapshot.snapshot_id)
    )
    archived_auth_group = await scenario.core.query(
        Query(kind=QueryKind.GROUP, entity_id=GROUP_AUTH)
    )
    archived_cli_group = await scenario.core.query(Query(kind=QueryKind.GROUP, entity_id=GROUP_CLI))
    if not isinstance(persisted_auth_snapshot, GroupSnapshot) or not isinstance(
        persisted_cli_snapshot, GroupSnapshot
    ):
        raise AssertionError("authoritative Core did not retain Group snapshots")
    if not isinstance(archived_auth_group, Group) or not isinstance(archived_cli_group, Group):
        raise AssertionError("authoritative Core did not retain archived Groups")
    group_snapshots = (persisted_auth_snapshot, persisted_cli_snapshot)
    scenario.prove(
        "authoritative_core_archived_groups_with_signed_snapshots",
        auth_archive_event.kind is EventKind.GROUP_ARCHIVED
        and cli_archive_event.kind is EventKind.GROUP_ARCHIVED
        and archived_auth_group.archive_snapshot_id == auth_snapshot.snapshot_id
        and archived_cli_group.archive_snapshot_id == cli_snapshot.snapshot_id
        and persisted_auth_snapshot == auth_snapshot
        and persisted_cli_snapshot == cli_snapshot,
    )
    local_store.save_scheduler(REVIEWER, reviewer_scheduler.snapshot())

    mission_results = (
        MissionResult(
            mission_id=MISSION_AUTH,
            group_id=GROUP_AUTH,
            status=final_auth.status.value,
            revision=final_auth.revision,
            approval_id=auth_approval_result.id,
            artifact_hashes=final_auth.approved_artifact_hashes,
            event_count=len(final_auth_events),
        ),
        MissionResult(
            mission_id=MISSION_CLI,
            group_id=GROUP_CLI,
            status=final_cli.status.value,
            revision=final_cli.revision,
            approval_id=cli_approval_result.id,
            artifact_hashes=final_cli.approved_artifact_hashes,
            event_count=len(final_cli_events),
        ),
    )
    checks = tuple(sorted(scenario.checks.items()))
    report = POCReport(
        passed=all(value for _, value in checks),
        checks=checks,
        missions=mission_results,
        scheduler_dispatch_order=tuple(dispatch_order),
        event_counts=(
            (GROUP_AUTH, len(final_auth_events)),
            (GROUP_CLI, len(final_cli_events)),
            (GROUP_SECURITY, len(final_security_events)),
        ),
        final_cursors=((GROUP_AUTH, auth_cursor), (GROUP_CLI, cli_cursor)),
        failure_injections=tuple(sorted(scenario.failure_injections)),
        artifact_provenance_edges=provenance_edges,
        worker_message_count=len(scenario.messages),
        context_package_count=len(context_packages),
        knowledge_publication_count=len(knowledge_publications),
        group_snapshot_count=len(group_snapshots),
        policy_log_entry_count=len(policy_log_entries),
    )
    report.require_success()
    second_session.close()
    local_store.close()
    await scenario.authoritative_store.close()
    return report


async def run_poc(workdir: Path | None = None) -> POCReport:
    """Run the deterministic MissionWeaveProtocol v0.1 scenario or raise on any missing behavior."""

    if workdir is not None:
        return await _run(workdir)
    with TemporaryDirectory(prefix="missionweaveprotocol-poc-") as temporary:
        return await _run(Path(temporary))


def run_poc_sync(workdir: Path | None = None) -> POCReport:
    """Synchronous command-line entry point."""

    return asyncio.run(run_poc(workdir))


__all__ = [
    "MissionResult",
    "OfflinePolicyError",
    "POCReport",
    "offline_command_to_wire",
    "run_poc",
    "run_poc_sync",
]
