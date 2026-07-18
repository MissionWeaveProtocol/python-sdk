from __future__ import annotations

import asyncio
import base64
import json
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from missionweaveprotocol import (
    AgentRegistryKeyResolver,
    SignedDocumentCodec,
    SignedDocumentKind,
    SignedDocumentVerificationError,
    VerificationStage,
)
from missionweaveprotocol.auth import (
    AgentIdentity,
    AgentKeyRegistry,
    SessionAuthority,
    SessionGrant,
    default_agent_key_id,
)
from missionweaveprotocol.canonical import canonical_bytes
from missionweaveprotocol.core import Core, StaleSessionEpoch
from missionweaveprotocol.crypto import generate_keypair
from missionweaveprotocol.gateway import (
    CommandAdmissionError,
    CoreGatewayAdapter,
    GroupGateway,
    UnknownCriticalExtension,
)
from missionweaveprotocol.ingress import CommandIngress
from missionweaveprotocol.models import (
    ActorType,
    AddMembershipPayload,
    AgentCard,
    Capability,
    Command,
    CommandKind,
    CreateMissionPayload,
    CreateWorkItemPayload,
    Event,
    Membership,
    OfferWorkItemPayload,
    OpenAgentSessionPayload,
    Principal,
    Query,
    QueryKind,
    RegisterAgentCardPayload,
    ResourceBudget,
    Role,
    SelectionBasis,
    WorkContract,
)
from missionweaveprotocol.store import InMemoryStore
from missionweaveprotocol.wire import (
    AckFrame,
    Acknowledgement,
    AttentionFilter,
    AuthFrame,
    ChallengeFrame,
    CommandFrame,
    ErrorCode,
    ErrorFrame,
    EventFrame,
    GroupCursor,
    HelloFrame,
    SubscribeFrame,
    WelcomeFrame,
    encode_frame,
    parse_frame,
)

AGENT_ID = "urn:missionweaveprotocol:agent:reviewer"
KEY_ID = "urn:missionweaveprotocol:key:reviewer"
GROUP_ID = "urn:missionweaveprotocol:group:mission"
OTHER_GROUP_ID = "urn:missionweaveprotocol:group:mission-two"
MISSION_ID = "urn:missionweaveprotocol:mission:one"
CONVERSATION_ID = f"{GROUP_ID}:mission"
WORK_ID = "urn:missionweaveprotocol:work:resource-usage"
SESSION_SECRET = b"x" * 32


def _command_key_resolver(
    *registrations: tuple[AgentIdentity, str],
    service_registrations: tuple[tuple[str, str, str], ...] = (),
    validity_history: dict[str, list[dict[str, Any]]] | None = None,
) -> AgentRegistryKeyResolver:
    bindings = [
        {
            "keyId": key_id,
            "principal": {"type": "agent", "id": identity.agent_id},
            "algorithm": "Ed25519",
            "publicKey": identity.public_key,
            "validFrom": "2000-01-01T00:00:00Z",
            "validityHistory": (validity_history or {}).get(key_id, []),
        }
        for identity, key_id in registrations
    ]
    bindings.extend(
        {
            "keyId": key_id,
            "principal": {"type": "service", "id": principal_id},
            "algorithm": "Ed25519",
            "publicKey": public_key,
            "validFrom": "2000-01-01T00:00:00Z",
            "validityHistory": [],
        }
        for key_id, principal_id, public_key in service_registrations
    )
    return AgentRegistryKeyResolver(
        json.dumps(
            {
                "organizationId": "urn:missionweaveprotocol:organization:gateway-tests",
                "bindings": bindings,
            },
            separators=(",", ":"),
        ).encode()
    )


def _session(
    identity: AgentIdentity,
    *,
    session_epoch: int,
    key_id: str = KEY_ID,
    now: datetime | None = None,
) -> SessionGrant:
    selected_now = now or datetime.now(UTC)
    return SessionGrant(
        agent_id=identity.agent_id,
        key_id=key_id,
        protocol_version="0.1",
        session_epoch=session_epoch,
        issued_at=selected_now - timedelta(minutes=1),
        expires_at=selected_now + timedelta(minutes=15),
        token="test-session-token",
    )


def _raw_command_frame(command_bytes: bytes, *, frame_id: str) -> str:
    return (
        '{"protocolVersion":"0.1","frameId":"'
        + frame_id
        + '","frameType":"COMMAND","command":'
        + command_bytes.decode("utf-8")
        + "}"
    )


async def _perform_with_current_membership(core: Core, command: Command) -> Event:
    if (
        command.group_id is not None
        and command.actor.type is not ActorType.SYSTEM
        and command.kind not in {CommandKind.CREATE_MISSION, CommandKind.CREATE_FOLLOW_UP_MISSION}
    ):
        membership = await core.query(
            Query(
                kind=QueryKind.MEMBERSHIP,
                entity_id=command.actor.id,
                group_id=command.group_id,
                actor_type=command.actor.type,
            )
        )
        if not isinstance(membership, Membership):
            raise AssertionError("gateway fixture command lacks an authoritative Membership")
        command = command.model_copy(update={"membership_epoch": membership.epoch})
    return await core.perform(command)


def _decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class FakeCore:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.session_epoch = 0

    async def current_session_epoch(self, agent_id: str) -> int:
        assert agent_id == AGENT_ID
        return self.session_epoch

    async def activate_session(self, agent_id: str, session_epoch: int) -> None:
        assert agent_id == AGENT_ID
        assert session_epoch == self.session_epoch + 1
        self.session_epoch = session_epoch

    async def perform(
        self,
        *,
        verify_session: Callable[[], SessionGrant],
        command_bytes: bytes,
    ) -> dict[str, Any]:
        session = verify_session()
        command = json.loads(command_bytes)
        assert isinstance(command, dict)
        group_id = str(command["groupId"])
        sequence = 1 + sum(event["groupId"] == group_id for event in self.events)
        payload = command.get("payload", {})
        emitted_kind = (
            str(payload.get("emitKind", "message.posted"))
            if isinstance(payload, dict)
            else "message.posted"
        )
        event = {
            "protocolVersion": "0.1",
            "eventId": f"urn:missionweaveprotocol:event:{len(self.events) + 1}",
            "groupId": group_id,
            "sequence": sequence,
            "aggregateRevision": sequence,
            "kind": emitted_kind,
            "actor": {"type": "agent", "id": session.agent_id},
            "cause": {"type": "command", "id": command["actionId"]},
            "correlationId": command["correlationId"],
            "occurredAt": "2026-07-15T00:00:01Z",
            "conversationId": command.get("conversationId"),
            "payload": {"sessionEpoch": session.session_epoch},
            "acceptedBy": {
                "type": "service",
                "id": "urn:missionweaveprotocol:service:group-gateway",
            },
            "signature": {
                "algorithm": "Ed25519",
                "keyId": "urn:missionweaveprotocol:key:group-gateway",
                "createdAt": "2026-07-15T00:00:01Z",
                "value": "c2lnbmF0dXJl",
            },
        }
        self.events.append(event)
        return event

    async def replay(
        self,
        actor: str,
        group_id: str,
        *,
        after_sequence: int,
    ) -> list[dict[str, Any]]:
        assert actor == AGENT_ID
        return [
            event
            for event in self.events
            if event["groupId"] == group_id and event["sequence"] > after_sequence
        ]


def _authenticate(
    socket: Any,
    identity: AgentIdentity,
    *,
    key_id: str = KEY_ID,
) -> WelcomeFrame:
    socket.send_text(
        encode_frame(
            HelloFrame(
                agent_id=identity.agent_id,
                key_id=key_id,
                client_nonce="Y2xpZW50LW5vbmNl",
            )
        )
    )
    challenge = parse_frame(socket.receive_text())
    assert isinstance(challenge, ChallengeFrame)
    socket.send_text(
        encode_frame(
            AuthFrame(
                agent_id=identity.agent_id,
                key_id=key_id,
                client_nonce=challenge.client_nonce,
                server_nonce=challenge.server_nonce,
                challenge_signature=identity.sign(_decode_base64url(challenge.challenge)),
            )
        )
    )
    welcome = parse_frame(socket.receive_text())
    assert isinstance(welcome, WelcomeFrame)
    return welcome


def _unsigned_command(
    *,
    action_number: int,
    session_epoch: int,
    group_id: str = GROUP_ID,
    emit_kind: str | None = None,
    issued_at: str | None = None,
) -> dict[str, Any]:
    command_issued_at = issued_at or datetime.now(UTC).isoformat().replace("+00:00", "Z")
    payload = {
        "messageId": f"urn:missionweaveprotocol:message:{action_number}",
        "content": f"message {action_number}",
    }
    if emit_kind is not None:
        payload["emitKind"] = emit_kind
    return {
        "protocolVersion": "0.1",
        "actionId": f"urn:missionweaveprotocol:action:{action_number}",
        "actor": {"type": "agent", "id": AGENT_ID},
        "sessionEpoch": session_epoch,
        "membershipEpoch": 1,
        "groupId": group_id,
        "conversationId": f"{group_id}:mission",
        "kind": "message.post",
        "correlationId": f"urn:missionweaveprotocol:correlation:{action_number}",
        "issuedAt": command_issued_at,
        "payload": payload,
    }


def _signed_command(
    identity: AgentIdentity,
    *,
    action_number: int,
    session_epoch: int,
    group_id: str = GROUP_ID,
    emit_kind: str | None = None,
    issued_at: str | None = None,
    signature_key_id: str = KEY_ID,
    signature_created_at: str | None = None,
) -> dict[str, Any]:
    command = _unsigned_command(
        action_number=action_number,
        session_epoch=session_epoch,
        group_id=group_id,
        emit_kind=emit_kind,
        issued_at=issued_at,
    )
    command["signature"] = {
        "algorithm": "Ed25519",
        "keyId": signature_key_id,
        "createdAt": signature_created_at or command["issuedAt"],
        "value": identity.sign(canonical_bytes(command)),
    }
    return command


def _signed_command_with_extensions(
    identity: AgentIdentity,
    *,
    action_number: int,
    session_epoch: int,
    extensions: dict[str, Any],
) -> dict[str, Any]:
    command = _unsigned_command(
        action_number=action_number,
        session_epoch=session_epoch,
    )
    command["extensions"] = extensions
    command["signature"] = {
        "algorithm": "Ed25519",
        "keyId": KEY_ID,
        "createdAt": command["issuedAt"],
        "value": identity.sign(canonical_bytes(command)),
    }
    return command


def _card(identity: AgentIdentity) -> AgentCard:
    return AgentCard(
        agent_id=identity.agent_id,
        version=1,
        display_name="Reviewer",
        owner="MissionWeaveProtocol tests",
        public_key=identity.public_key,
        capabilities=(Capability(id="code.review", version=1),),
        issued_at=datetime.now(UTC),
        signature="organization-signature",
    )


async def _register_card(core: Core, card: AgentCard) -> None:
    await _perform_with_current_membership(
        core,
        Command(
            action_id=(
                f"urn:missionweaveprotocol:action:register:{card.agent_id.rsplit(':', 1)[-1]}"
            ),
            kind=CommandKind.REGISTER_AGENT_CARD,
            actor=Principal.system("urn:missionweaveprotocol:service:registry"),
            issued_at=datetime.now(UTC),
            payload=RegisterAgentCardPayload(card=card),
            signature="registry-signature",
        ),
    )


async def _bootstrap_mission(core: Core, card: AgentCard) -> None:
    await _register_card(core, card)
    await _perform_with_current_membership(
        core,
        Command(
            action_id="urn:missionweaveprotocol:action:create-mission",
            kind=CommandKind.CREATE_MISSION,
            actor=Principal.human("urn:missionweaveprotocol:human:owner"),
            group_id=GROUP_ID,
            issued_at=datetime.now(UTC),
            payload=CreateMissionPayload(
                mission_id=MISSION_ID,
                group_id=GROUP_ID,
                coordinator_id=card.agent_id,
                title="Review transport",
                objective="Prove gateway and Core integration",
                definition_of_done=("signed message accepted",),
                deadline=datetime.now(UTC) + timedelta(hours=1),
            ),
            signature="owner-signature",
        ),
    )


async def _bootstrap_resource_usage_work(core: Core, card: AgentCard) -> None:
    await _register_card(core, card)
    await _perform_with_current_membership(
        core,
        Command(
            action_id="urn:missionweaveprotocol:action:create-usage-mission",
            kind=CommandKind.CREATE_MISSION,
            actor=Principal.human("urn:missionweaveprotocol:human:owner"),
            group_id=GROUP_ID,
            issued_at=datetime.now(UTC),
            payload=CreateMissionPayload(
                mission_id=MISSION_ID,
                group_id=GROUP_ID,
                coordinator_id=card.agent_id,
                title="Meter gateway execution",
                objective="Record authoritative resource usage",
                definition_of_done=("usage is durably metered",),
                budget=ResourceBudget(model_tokens=1),
                deadline=datetime.now(UTC) + timedelta(hours=1),
            ),
            signature="owner-signature",
        ),
    )
    session = await _perform_with_current_membership(
        core,
        Command(
            action_id="urn:missionweaveprotocol:action:open-usage-coordinator-session",
            kind=CommandKind.OPEN_AGENT_SESSION,
            actor=Principal.system("urn:missionweaveprotocol:service:registry"),
            issued_at=datetime.now(UTC),
            payload=OpenAgentSessionPayload(agent_id=card.agent_id),
            signature="registry-signature",
        ),
    )
    session_epoch = int(session.payload["sessionEpoch"])
    await _perform_with_current_membership(
        core,
        Command(
            action_id="urn:missionweaveprotocol:action:add-usage-worker-role",
            kind=CommandKind.ADD_MEMBERSHIP,
            actor=Principal.agent(card.agent_id),
            group_id=GROUP_ID,
            session_epoch=session_epoch,
            coordinator_epoch=1,
            issued_at=datetime.now(UTC),
            payload=AddMembershipPayload(
                principal=Principal.agent(card.agent_id),
                roles=(Role.WORKER,),
            ),
            signature="coordinator-signature",
        ),
    )
    contract = WorkContract(
        goal="Consume exactly one model token",
        deliverables=("usage event",),
        acceptance_criteria=("usage delta is authoritative",),
        budget=ResourceBudget(model_tokens=1),
        deadline=datetime.now(UTC) + timedelta(minutes=30),
    )
    await _perform_with_current_membership(
        core,
        Command(
            action_id="urn:missionweaveprotocol:action:create-usage-work",
            kind=CommandKind.CREATE_WORK_ITEM,
            actor=Principal.agent(card.agent_id),
            group_id=GROUP_ID,
            session_epoch=session_epoch,
            coordinator_epoch=1,
            issued_at=datetime.now(UTC),
            payload=CreateWorkItemPayload(work_item_id=WORK_ID, contract=contract),
            signature="coordinator-signature",
        ),
    )
    await _perform_with_current_membership(
        core,
        Command(
            action_id="urn:missionweaveprotocol:action:offer-usage-work",
            kind=CommandKind.OFFER_WORK_ITEM,
            actor=Principal.agent(card.agent_id),
            group_id=GROUP_ID,
            session_epoch=session_epoch,
            coordinator_epoch=1,
            issued_at=datetime.now(UTC),
            payload=OfferWorkItemPayload(
                work_item_id=WORK_ID,
                candidate_agent_ids=(card.agent_id,),
                selection_basis=SelectionBasis(),
            ),
            signature="coordinator-signature",
        ),
    )


def _signed_work_command(
    identity: AgentIdentity,
    *,
    action_number: int,
    session_epoch: int,
    kind: str,
    payload: dict[str, Any],
) -> dict[str, Any]:
    issued_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    command: dict[str, Any] = {
        "protocolVersion": "0.1",
        "actionId": f"urn:missionweaveprotocol:action:usage:{action_number}",
        "actor": {"type": "agent", "id": identity.agent_id},
        "sessionEpoch": session_epoch,
        "membershipEpoch": 2,
        "groupId": GROUP_ID,
        "workItemId": WORK_ID,
        "kind": kind,
        "correlationId": f"urn:missionweaveprotocol:correlation:usage:{action_number}",
        "issuedAt": issued_at,
        "payload": payload,
    }
    command["signature"] = {
        "algorithm": "Ed25519",
        "keyId": KEY_ID,
        "createdAt": issued_at,
        "value": identity.sign(canonical_bytes(command)),
    }
    return command


def _signed_coordinator_command(
    identity: AgentIdentity,
    *,
    action_number: int,
    session_epoch: int,
    coordinator_epoch: int,
    cooperation_override_grant_id: str | None = None,
    expected_revision: int | None = None,
) -> dict[str, Any]:
    issued_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    command: dict[str, Any] = {
        "protocolVersion": "0.1",
        "actionId": f"urn:missionweaveprotocol:action:coordinator:{action_number}",
        "actor": {"type": "agent", "id": identity.agent_id},
        "sessionEpoch": session_epoch,
        "membershipEpoch": 1,
        "coordinatorEpoch": coordinator_epoch,
        "groupId": GROUP_ID,
        "conversationId": CONVERSATION_ID,
        "workItemId": "urn:missionweaveprotocol:work:context-only",
        "kind": CommandKind.RENEW_COORDINATOR_LEASE.value,
        "correlationId": "urn:missionweaveprotocol:correlation:coordinator-ingress",
        "causedByEventId": "urn:missionweaveprotocol:event:coordinator-trigger",
        "issuedAt": issued_at,
        "payload": {"leaseSeconds": 600},
    }
    if cooperation_override_grant_id is not None:
        command["cooperationOverrideGrantId"] = cooperation_override_grant_id
    if expected_revision is not None:
        command["expectedRevision"] = expected_revision
    command["signature"] = {
        "algorithm": "Ed25519",
        "keyId": KEY_ID,
        "createdAt": issued_at,
        "value": identity.sign(canonical_bytes(command)),
    }
    return command


def test_command_ingress_preserves_signed_provenance() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    document = _signed_coordinator_command(
        identity,
        action_number=19,
        session_epoch=7,
        coordinator_epoch=4,
        cooperation_override_grant_id="urn:missionweaveprotocol:override:context-only",
        expected_revision=0,
    )
    ingress = CommandIngress()
    verified = ingress.verify(
        canonical_bytes(document),
        _command_key_resolver((identity, KEY_ID)),
    )
    projected = ingress.project_verified(verified)

    assert projected.coordinator_epoch == 4
    assert projected.correlation_id == document["correlationId"]
    assert projected.caused_by_event_id == document["causedByEventId"]
    assert projected.conversation_id == document["conversationId"]
    assert projected.work_item_id == document["workItemId"]
    assert projected.cooperation_override_grant_id == document["cooperationOverrideGrantId"]
    assert projected.expected_revision == 0
    assert projected.payload == {"leaseSeconds": 600}
    assert projected.signature is not None
    assert projected.signature.key_id == KEY_ID
    assert projected.signature.value == document["signature"]["value"]
    assert projected.verified_signing_hash == verified.signing_hash


async def _add_active_member(
    core: Core,
    *,
    coordinator: AgentCard,
    member: AgentCard,
    visibility_after_sequence: int,
) -> None:
    await _register_card(core, member)
    session = await _perform_with_current_membership(
        core,
        Command(
            action_id="urn:missionweaveprotocol:action:open-coordinator-session",
            kind=CommandKind.OPEN_AGENT_SESSION,
            actor=Principal.system("urn:missionweaveprotocol:service:registry"),
            issued_at=datetime.now(UTC),
            payload=OpenAgentSessionPayload(agent_id=coordinator.agent_id),
            signature="registry-signature",
        ),
    )
    await _perform_with_current_membership(
        core,
        Command(
            action_id="urn:missionweaveprotocol:action:add-late-member",
            kind=CommandKind.ADD_MEMBERSHIP,
            actor=Principal.agent(coordinator.agent_id),
            group_id=GROUP_ID,
            session_epoch=int(session.payload["sessionEpoch"]),
            coordinator_epoch=1,
            issued_at=datetime.now(UTC),
            payload=AddMembershipPayload(
                principal=Principal.agent(member.agent_id),
                roles=(Role.WORKER,),
                provisional=False,
                visibility_after_sequence=visibility_after_sequence,
            ),
            signature="coordinator-signature",
        ),
    )


def test_authenticated_session_multiplexes_command_event_and_replay() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    keys = AgentKeyRegistry()
    keys.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    core = FakeCore()
    gateway = GroupGateway(core, SessionAuthority(keys, secret=SESSION_SECRET))

    with TestClient(gateway.app) as client:
        with client.websocket_connect("/ws") as socket:
            welcome = _authenticate(socket, identity)
            socket.send_text(
                encode_frame(
                    SubscribeFrame(
                        subscription_id="urn:missionweaveprotocol:subscription:one",
                        groups=(GroupCursor(group_id=GROUP_ID),),
                    )
                )
            )
            socket.send_text(
                encode_frame(
                    CommandFrame(
                        command=_signed_command(
                            identity,
                            action_number=1,
                            session_epoch=welcome.session_epoch,
                        )
                    )
                )
            )
            event = parse_frame(socket.receive_text())
            assert isinstance(event, EventFrame)
            assert event.event["actor"] == {"type": "agent", "id": identity.agent_id}
            assert event.event["sequence"] == 1

        with client.websocket_connect("/ws") as replay_socket:
            _authenticate(replay_socket, identity)
            replay_socket.send_text(
                encode_frame(
                    SubscribeFrame(
                        subscription_id="urn:missionweaveprotocol:subscription:two",
                        groups=(GroupCursor(group_id=GROUP_ID),),
                    )
                )
            )
            replayed = parse_frame(replay_socket.receive_text())
            assert isinstance(replayed, EventFrame)
            assert replayed.event["eventId"] == "urn:missionweaveprotocol:event:1"


def test_hello_rejects_an_unregistered_key_id() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    keys = AgentKeyRegistry()
    keys.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    gateway = GroupGateway(FakeCore(), SessionAuthority(keys, secret=SESSION_SECRET))

    with TestClient(gateway.app) as client, client.websocket_connect("/ws") as socket:
        socket.send_text(
            encode_frame(
                HelloFrame(
                    agent_id=identity.agent_id,
                    key_id="urn:missionweaveprotocol:key:unregistered",
                    client_nonce="Y2xpZW50LW5vbmNl",
                )
            )
        )
        rejected = parse_frame(socket.receive_text())

    assert isinstance(rejected, ErrorFrame)
    assert rejected.error.code is ErrorCode.AUTH_INVALID_SIGNATURE


def test_command_key_id_must_match_the_authenticated_key() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    alternate_identity = AgentIdentity.generate(AGENT_ID)
    alternate_key_id = "urn:missionweaveprotocol:key:other"
    keys = AgentKeyRegistry()
    keys.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    adapter = CoreGatewayAdapter(
        Core(InMemoryStore()),
        keys,
        _command_key_resolver(
            (identity, KEY_ID),
            (alternate_identity, alternate_key_id),
        ),
    )
    command = _signed_command(
        alternate_identity,
        action_number=2,
        session_epoch=1,
        signature_key_id=alternate_key_id,
    )

    with pytest.raises(CommandAdmissionError, match="key ID") as rejected:
        asyncio.run(
            adapter.perform(
                verify_session=lambda: _session(identity, session_epoch=1),
                command_bytes=canonical_bytes(command),
            )
        )
    assert rejected.value.reason == "Command key ID does not match the authenticated session"


def test_command_timestamp_must_be_inside_the_authenticated_session() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    keys = AgentKeyRegistry()
    keys.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    adapter = CoreGatewayAdapter(
        Core(InMemoryStore()),
        keys,
        _command_key_resolver((identity, KEY_ID)),
    )
    command = _signed_command(
        identity,
        action_number=3,
        session_epoch=1,
        issued_at="2000-01-01T00:00:00Z",
    )

    with pytest.raises(CommandAdmissionError, match="outside"):
        asyncio.run(
            adapter.perform(
                verify_session=lambda: _session(identity, session_epoch=1),
                command_bytes=canonical_bytes(command),
            )
        )


def test_nested_duplicate_command_member_is_a_non_oracular_protocol_failure() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    keys = AgentKeyRegistry()
    keys.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    core = Core(InMemoryStore())
    adapter = CoreGatewayAdapter(
        core,
        keys,
        _command_key_resolver((identity, KEY_ID)),
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await _register_card(core, _card(identity))
        yield

    gateway = GroupGateway(
        adapter,
        SessionAuthority(keys, secret=SESSION_SECRET),
        app=FastAPI(lifespan=lifespan),
    )

    with TestClient(gateway.app) as client, client.websocket_connect("/ws") as socket:
        welcome = _authenticate(socket, identity)
        command = _signed_command(
            identity,
            action_number=4,
            session_epoch=welcome.session_epoch,
        )
        raw = json.dumps(command, separators=(",", ":")).replace(
            '"content":"message 4"',
            '"content":"message 4","content":"duplicate"',
        )
        socket.send_text(
            _raw_command_frame(
                raw.encode(),
                frame_id="urn:missionweaveprotocol:frame:duplicate-command",
            )
        )
        rejected = parse_frame(socket.receive_text())

    assert isinstance(rejected, ErrorFrame)
    assert rejected.error.code is ErrorCode.PROTOCOL_VIOLATION
    assert rejected.error.message == "signed document rejected"
    assert rejected.error.details is None


def test_unsupported_command_algorithm_uses_codec_schema_wire_error() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    keys = AgentKeyRegistry()
    keys.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    core = Core(InMemoryStore())
    adapter = CoreGatewayAdapter(
        core,
        keys,
        _command_key_resolver((identity, KEY_ID)),
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await _register_card(core, _card(identity))
        yield

    gateway = GroupGateway(
        adapter,
        SessionAuthority(keys, secret=SESSION_SECRET),
        app=FastAPI(lifespan=lifespan),
    )

    with TestClient(gateway.app) as client, client.websocket_connect("/ws") as socket:
        welcome = _authenticate(socket, identity)
        command = _signed_command(
            identity,
            action_number=7,
            session_epoch=welcome.session_epoch,
        )
        signature = command["signature"]
        assert isinstance(signature, dict)
        signature["algorithm"] = "RSA"
        socket.send_text(
            _raw_command_frame(
                json.dumps(command, separators=(",", ":")).encode(),
                frame_id="urn:missionweaveprotocol:frame:unsupported-algorithm",
            )
        )
        rejected = parse_frame(socket.receive_text())

    assert isinstance(rejected, ErrorFrame)
    assert rejected.error.code is ErrorCode.SCHEMA_VALIDATION_FAILED
    assert rejected.error.message == "signed document rejected"
    assert rejected.error.details is None


@pytest.mark.asyncio
async def test_out_of_binary64_command_number_reaches_codec_canonicalization() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    keys = AgentKeyRegistry()
    keys.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    adapter = CoreGatewayAdapter(
        Core(InMemoryStore()),
        keys,
        _command_key_resolver((identity, KEY_ID)),
    )
    command = _signed_command_with_extensions(
        identity,
        action_number=5,
        session_epoch=1,
        extensions={
            "https://profiles.example/numeric": {
                "version": "1.0.0",
                "critical": False,
                "data": {"probe": 0},
            }
        },
    )
    raw = json.dumps(command, separators=(",", ":")).replace('"probe":0', '"probe":1e400')

    with pytest.raises(SignedDocumentVerificationError) as captured:
        await adapter.perform(
            verify_session=lambda: _session(identity, session_epoch=1),
            command_bytes=raw.encode(),
        )

    assert captured.value.protected_error.stage is VerificationStage.CANONICALIZATION


@pytest.mark.asyncio
async def test_key_revoked_before_admission_is_rejected_after_codec_verification() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    keys = AgentKeyRegistry()
    now = datetime.now(UTC)
    keys.register(
        identity.agent_id,
        identity.public_key,
        key_id=KEY_ID,
        valid_from=now - timedelta(hours=1),
    )
    revoked_at = now - timedelta(seconds=1)
    adapter = CoreGatewayAdapter(
        Core(InMemoryStore()),
        keys,
        _command_key_resolver(
            (identity, KEY_ID),
            validity_history={
                KEY_ID: [
                    {
                        "sequence": 1,
                        "recordedAt": now.isoformat().replace("+00:00", "Z"),
                        "revokedAt": revoked_at.isoformat().replace("+00:00", "Z"),
                    }
                ]
            },
        ),
        clock=lambda: now,
    )
    command = _signed_command(
        identity,
        action_number=6,
        session_epoch=1,
        issued_at=(now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
    )
    with pytest.raises(CommandAdmissionError, match="revoked"):
        await adapter.perform(
            verify_session=lambda: _session(identity, session_epoch=1, now=now),
            command_bytes=canonical_bytes(command),
        )


def test_real_core_accepts_signed_command_and_fences_replaced_session() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    card = _card(identity)
    store = InMemoryStore()
    core = Core(store)
    keys = AgentKeyRegistry()
    keys.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    adapter = CoreGatewayAdapter(core, keys, _command_key_resolver((identity, KEY_ID)))

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await _bootstrap_mission(core, card)
        yield

    app = FastAPI(lifespan=lifespan)
    gateway = GroupGateway(
        adapter,
        SessionAuthority(keys, secret=SESSION_SECRET),
        app=app,
    )

    with (
        TestClient(gateway.app) as client,
        client.websocket_connect("/ws") as original_socket,
    ):
        original = _authenticate(original_socket, identity)
        original_socket.send_text(
            encode_frame(
                SubscribeFrame(
                    subscription_id="urn:missionweaveprotocol:subscription:real",
                    groups=(GroupCursor(group_id=GROUP_ID, after_sequence=1),),
                )
            )
        )
        original_socket.send_text(
            encode_frame(
                CommandFrame(
                    command=_signed_command(
                        identity,
                        action_number=10,
                        session_epoch=original.session_epoch,
                    )
                )
            )
        )
        accepted = parse_frame(original_socket.receive_text())
        assert isinstance(accepted, EventFrame)
        assert accepted.event["kind"] == "message.posted"

        with client.websocket_connect("/ws") as replacement_socket:
            replacement = _authenticate(replacement_socket, identity)
            assert replacement.session_epoch == original.session_epoch + 1

            original_socket.send_text(
                encode_frame(
                    CommandFrame(
                        command=_signed_command(
                            identity,
                            action_number=11,
                            session_epoch=original.session_epoch,
                        )
                    )
                )
            )
            fenced = parse_frame(original_socket.receive_text())
            assert isinstance(fenced, ErrorFrame)
            assert fenced.error.code is ErrorCode.AUTH_INVALID_SIGNATURE
            assert fenced.error.message == "signed document rejected"
            assert fenced.error.details is None

    stale_command = _signed_command(
        identity,
        action_number=12,
        session_epoch=original.session_epoch,
    )
    with pytest.raises(StaleSessionEpoch):
        asyncio.run(
            adapter.perform(
                verify_session=lambda: _session(
                    identity,
                    session_epoch=original.session_epoch,
                ),
                command_bytes=canonical_bytes(stale_command),
            )
        )


def test_real_gateway_preserves_command_authority_and_provenance() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    core = Core(InMemoryStore())
    keys = AgentKeyRegistry()
    keys.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    adapter = CoreGatewayAdapter(core, keys, _command_key_resolver((identity, KEY_ID)))

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await _bootstrap_mission(core, _card(identity))
        yield

    app = FastAPI(lifespan=lifespan)
    gateway = GroupGateway(
        adapter,
        SessionAuthority(keys, secret=SESSION_SECRET),
        app=app,
    )

    with TestClient(gateway.app) as client, client.websocket_connect("/ws") as socket:
        welcome = _authenticate(socket, identity)
        socket.send_text(
            encode_frame(
                SubscribeFrame(
                    subscription_id="urn:missionweaveprotocol:subscription:coordinator-ingress",
                    groups=(GroupCursor(group_id=GROUP_ID, after_sequence=1),),
                )
            )
        )
        command = _signed_coordinator_command(
            identity,
            action_number=20,
            session_epoch=welcome.session_epoch,
            coordinator_epoch=1,
        )
        socket.send_text(encode_frame(CommandFrame(command=command)))
        accepted = parse_frame(socket.receive_text())
        assert isinstance(accepted, EventFrame)
        assert accepted.event["kind"] == "mission.coordinator.renewed"
        assert accepted.event["correlationId"] == command["correlationId"]

        stale = _signed_coordinator_command(
            identity,
            action_number=21,
            session_epoch=welcome.session_epoch,
            coordinator_epoch=2,
        )
        socket.send_text(encode_frame(CommandFrame(command=stale)))
        rejected = parse_frame(socket.receive_text())
        assert isinstance(rejected, ErrorFrame)
        assert rejected.error.code is ErrorCode.AUTH_STALE_COORDINATOR

    events = asyncio.run(core.replay(GROUP_ID))
    renewed = next(event for event in events if event.action_id == command["actionId"])
    stored = asyncio.run(core.query(Query(kind=QueryKind.COMMAND, entity_id=renewed.id)))
    assert isinstance(stored, Command)
    assert renewed.correlation_id == command["correlationId"]
    assert renewed.caused_by_event_id == command["causedByEventId"]
    assert stored.coordinator_epoch == 1
    assert stored.correlation_id == command["correlationId"]
    assert stored.caused_by_event_id == command["causedByEventId"]
    assert stored.conversation_id == command["conversationId"]
    assert stored.work_item_id == command["workItemId"]
    assert stored.cooperation_override_grant_id is None
    assert stored.payload == {"leaseSeconds": 600}
    assert stored.signature is not None
    assert stored.signature.key_id == KEY_ID
    assert stored.signature.value == command["signature"]["value"]
    verified = SignedDocumentCodec().verify(
        SignedDocumentKind.COMMAND,
        canonical_bytes(command),
        _command_key_resolver((identity, KEY_ID)),
    )
    assert stored.verified_signing_hash == verified.signing_hash
    assert renewed.command_hash == stored.verified_signing_hash


def test_real_gateway_records_signed_usage_maps_overflow_and_rejects_tampering() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    card = _card(identity)
    core = Core(InMemoryStore())
    keys = AgentKeyRegistry()
    keys.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    authority_private_key, authority_public_key = generate_keypair()
    authority_key_id = "urn:missionweaveprotocol:key:usage-authority"
    adapter = CoreGatewayAdapter(
        core,
        keys,
        _command_key_resolver((identity, KEY_ID)),
        authority_key_id=authority_key_id,
        authority_private_key=authority_private_key,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await _bootstrap_resource_usage_work(core, card)
        yield

    app = FastAPI(lifespan=lifespan)
    gateway = GroupGateway(
        adapter,
        SessionAuthority(keys, secret=SESSION_SECRET),
        app=app,
    )

    with TestClient(gateway.app) as client, client.websocket_connect("/ws") as socket:
        welcome = _authenticate(socket, identity)
        socket.send_text(
            encode_frame(
                SubscribeFrame(
                    subscription_id="urn:missionweaveprotocol:subscription:resource-usage",
                    groups=(GroupCursor(group_id=GROUP_ID, after_sequence=4),),
                )
            )
        )
        socket.send_text(
            encode_frame(
                CommandFrame(
                    command=_signed_work_command(
                        identity,
                        action_number=100,
                        session_epoch=welcome.session_epoch,
                        kind=CommandKind.ACCEPT_WORK_OFFER.value,
                        payload={
                            "workItemId": WORK_ID,
                            "ownershipLeaseSeconds": 600,
                        },
                    )
                )
            )
        )
        accepted_offer = parse_frame(socket.receive_text())
        assert isinstance(accepted_offer, EventFrame)
        assert accepted_offer.event["kind"] == "work.offer.accepted"

        socket.send_text(
            encode_frame(
                CommandFrame(
                    command=_signed_work_command(
                        identity,
                        action_number=101,
                        session_epoch=welcome.session_epoch,
                        kind=CommandKind.START_WORK_ITEM.value,
                        payload={
                            "workItemId": WORK_ID,
                            "ownershipEpoch": 1,
                            "executionLeaseSeconds": 300,
                        },
                    )
                )
            )
        )
        started = parse_frame(socket.receive_text())
        assert isinstance(started, EventFrame)
        execution_lease = started.event["payload"]["executionLease"]
        assert isinstance(execution_lease, dict)
        execution_lease_id = execution_lease["leaseId"]
        assert isinstance(execution_lease_id, str)

        usage_payload = {
            "workItemId": WORK_ID,
            "ownershipEpoch": 1,
            "executionLeaseId": execution_lease_id,
            "usageDelta": {"modelTokens": 1},
        }
        socket.send_text(
            encode_frame(
                CommandFrame(
                    command=_signed_work_command(
                        identity,
                        action_number=102,
                        session_epoch=welcome.session_epoch,
                        kind=CommandKind.RECORD_RESOURCE_USAGE.value,
                        payload=usage_payload,
                    )
                )
            )
        )
        usage_recorded = parse_frame(socket.receive_text())
        assert isinstance(usage_recorded, EventFrame)
        assert (
            usage_recorded.event["kind"] == "ext.missionweaveprotocol.core.resource_usage_recorded"
        )
        assert usage_recorded.event["payload"]["usageDelta"]["modelTokens"] == 1
        assert usage_recorded.event["payload"]["remainingBudget"]["modelTokens"] == 0
        event_signature = usage_recorded.event["signature"]
        assert isinstance(event_signature, dict)
        assert event_signature["keyId"] == authority_key_id
        verified_event = SignedDocumentCodec().verify(
            SignedDocumentKind.EVENT,
            json.dumps(usage_recorded.event, separators=(",", ":")).encode(),
            _command_key_resolver(
                (identity, KEY_ID),
                service_registrations=(
                    (
                        authority_key_id,
                        "urn:missionweaveprotocol:service:group-gateway",
                        authority_public_key,
                    ),
                ),
            ),
        )
        assert verified_event.resolved_key.principal.type == "service"

        socket.send_text(
            encode_frame(
                CommandFrame(
                    command=_signed_work_command(
                        identity,
                        action_number=103,
                        session_epoch=welcome.session_epoch,
                        kind=CommandKind.RECORD_RESOURCE_USAGE.value,
                        payload=usage_payload,
                    )
                )
            )
        )
        overflow = parse_frame(socket.receive_text())
        assert isinstance(overflow, ErrorFrame)
        assert overflow.error.code is ErrorCode.BUDGET_EXCEEDED

        with client.websocket_connect("/ws") as tampered_socket:
            replacement = _authenticate(tampered_socket, identity)
            tampered = _signed_work_command(
                identity,
                action_number=104,
                session_epoch=replacement.session_epoch,
                kind=CommandKind.RECORD_RESOURCE_USAGE.value,
                payload=usage_payload,
            )
            tampered_payload = tampered["payload"]
            assert isinstance(tampered_payload, dict)
            usage_delta = tampered_payload["usageDelta"]
            assert isinstance(usage_delta, dict)
            usage_delta["modelTokens"] = 2
            tampered_socket.send_text(encode_frame(CommandFrame(command=tampered)))
            rejected = parse_frame(tampered_socket.receive_text())
            assert isinstance(rejected, ErrorFrame)
            assert rejected.error.code is ErrorCode.AUTH_INVALID_SIGNATURE
            assert rejected.error.message == "signed document rejected"
            assert rejected.error.details is None


def test_gateway_restart_seeds_token_epoch_from_authoritative_core() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    core = Core(InMemoryStore())
    asyncio.run(_register_card(core, _card(identity)))
    keys = AgentKeyRegistry()
    keys.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    adapter = CoreGatewayAdapter(core, keys, _command_key_resolver((identity, KEY_ID)))

    first = GroupGateway(adapter, SessionAuthority(keys, secret=SESSION_SECRET))
    with TestClient(first.app) as client, client.websocket_connect("/ws") as socket:
        first_welcome = _authenticate(socket, identity)
    assert first_welcome.session_epoch == 1

    restarted = GroupGateway(adapter, SessionAuthority(keys, secret=SESSION_SECRET))
    with TestClient(restarted.app) as client, client.websocket_connect("/ws") as socket:
        restarted_welcome = _authenticate(socket, identity)
    assert restarted_welcome.session_epoch == 2
    assert (
        asyncio.run(core.query(Query(kind=QueryKind.SESSION_EPOCH, entity_id=identity.agent_id)))
        == 2
    )


def test_one_connection_multiplexes_groups_and_filters_replay_and_live_events() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    keys = AgentKeyRegistry()
    keys.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    gateway = GroupGateway(
        FakeCore(),
        SessionAuthority(keys, secret=SESSION_SECRET),
    )

    with TestClient(gateway.app) as client, client.websocket_connect("/ws") as socket:
        welcome = _authenticate(socket, identity)
        for action_number, emitted_kind in ((40, "work.started"), (41, "message.posted")):
            socket.send_text(
                encode_frame(
                    CommandFrame(
                        command=_signed_command(
                            identity,
                            action_number=action_number,
                            session_epoch=welcome.session_epoch,
                            emit_kind=emitted_kind,
                        )
                    )
                )
            )

        socket.send_text(
            encode_frame(
                SubscribeFrame(
                    subscription_id="urn:missionweaveprotocol:subscription:multiplexed",
                    groups=(
                        GroupCursor(
                            group_id=GROUP_ID,
                            attention=AttentionFilter(event_kinds=("message.posted",)),
                        ),
                        GroupCursor(group_id=OTHER_GROUP_ID),
                    ),
                )
            )
        )
        filtered_replay = parse_frame(socket.receive_text())
        assert isinstance(filtered_replay, EventFrame)
        assert filtered_replay.event["kind"] == "message.posted"
        assert filtered_replay.event["cause"] == {
            "type": "command",
            "id": "urn:missionweaveprotocol:action:41",
        }

        for action_number, group_id, emitted_kind in (
            (42, GROUP_ID, "work.started"),
            (43, OTHER_GROUP_ID, "message.posted"),
            (44, GROUP_ID, "message.posted"),
        ):
            socket.send_text(
                encode_frame(
                    CommandFrame(
                        command=_signed_command(
                            identity,
                            action_number=action_number,
                            session_epoch=welcome.session_epoch,
                            group_id=group_id,
                            emit_kind=emitted_kind,
                        )
                    )
                )
            )

        delivered = [parse_frame(socket.receive_text()), parse_frame(socket.receive_text())]
        assert all(isinstance(frame, EventFrame) for frame in delivered)
        assert [frame.event["groupId"] for frame in delivered if isinstance(frame, EventFrame)] == [
            OTHER_GROUP_ID,
            GROUP_ID,
        ]


def test_subscription_denies_non_member_without_disclosing_group_existence() -> None:
    coordinator_identity = AgentIdentity.generate(AGENT_ID)
    intruder = AgentIdentity.generate("urn:missionweaveprotocol:agent:intruder")
    core = Core(InMemoryStore())
    keys = AgentKeyRegistry()
    intruder_key_id = default_agent_key_id(intruder.agent_id)
    keys.register(coordinator_identity.agent_id, coordinator_identity.public_key, key_id=KEY_ID)
    keys.register(intruder.agent_id, intruder.public_key, key_id=intruder_key_id)
    adapter = CoreGatewayAdapter(
        core,
        keys,
        _command_key_resolver(
            (coordinator_identity, KEY_ID),
            (intruder, intruder_key_id),
        ),
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await _bootstrap_mission(core, _card(coordinator_identity))
        await _register_card(core, _card(intruder))
        yield

    app = FastAPI(lifespan=lifespan)
    gateway = GroupGateway(
        adapter,
        SessionAuthority(keys, secret=SESSION_SECRET),
        app=app,
    )

    with TestClient(gateway.app) as client, client.websocket_connect("/ws") as socket:
        _authenticate(socket, intruder, key_id=intruder_key_id)
        socket.send_text(
            encode_frame(
                SubscribeFrame(
                    subscription_id="urn:missionweaveprotocol:subscription:unauthorized",
                    groups=(GroupCursor(group_id=GROUP_ID),),
                )
            )
        )
        denied = parse_frame(socket.receive_text())

    assert isinstance(denied, ErrorFrame)
    assert denied.error.code is ErrorCode.MEMBERSHIP_REQUIRED
    assert GROUP_ID not in denied.error.message


def test_late_member_replay_starts_after_membership_visibility_sequence() -> None:
    coordinator_identity = AgentIdentity.generate(AGENT_ID)
    late_identity = AgentIdentity.generate("urn:missionweaveprotocol:agent:late-worker")
    coordinator = _card(coordinator_identity)
    late_member = _card(late_identity)
    core = Core(InMemoryStore())
    keys = AgentKeyRegistry()
    late_key_id = default_agent_key_id(late_identity.agent_id)
    keys.register(coordinator_identity.agent_id, coordinator_identity.public_key, key_id=KEY_ID)
    keys.register(late_identity.agent_id, late_identity.public_key, key_id=late_key_id)
    adapter = CoreGatewayAdapter(
        core,
        keys,
        _command_key_resolver(
            (coordinator_identity, KEY_ID),
            (late_identity, late_key_id),
        ),
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await _bootstrap_mission(core, coordinator)
        await _add_active_member(
            core,
            coordinator=coordinator,
            member=late_member,
            visibility_after_sequence=1,
        )
        yield

    app = FastAPI(lifespan=lifespan)
    gateway = GroupGateway(
        adapter,
        SessionAuthority(keys, secret=SESSION_SECRET),
        app=app,
    )

    with TestClient(gateway.app) as client, client.websocket_connect("/ws") as socket:
        _authenticate(socket, late_identity, key_id=late_key_id)
        socket.send_text(
            encode_frame(
                SubscribeFrame(
                    subscription_id="urn:missionweaveprotocol:subscription:late-member",
                    groups=(GroupCursor(group_id=GROUP_ID, after_sequence=0),),
                )
            )
        )
        first_visible = parse_frame(socket.receive_text())

    assert isinstance(first_visible, EventFrame)
    assert first_visible.event["sequence"] == 2
    assert first_visible.event["kind"] == "membership.changed"


def test_websocket_disconnect_reconnect_replays_only_after_durable_ack() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    card = _card(identity)
    core = Core(InMemoryStore())
    keys = AgentKeyRegistry()
    keys.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    adapter = CoreGatewayAdapter(core, keys, _command_key_resolver((identity, KEY_ID)))

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await _bootstrap_mission(core, card)
        yield

    app = FastAPI(lifespan=lifespan)
    gateway = GroupGateway(
        adapter,
        SessionAuthority(keys, secret=SESSION_SECRET),
        app=app,
    )

    with TestClient(gateway.app) as client:
        with client.websocket_connect("/ws") as socket:
            welcome = _authenticate(socket, identity)
            socket.send_text(
                encode_frame(
                    SubscribeFrame(
                        subscription_id="urn:missionweaveprotocol:subscription:before-disconnect",
                        groups=(GroupCursor(group_id=GROUP_ID, after_sequence=1),),
                    )
                )
            )
            socket.send_text(
                encode_frame(
                    CommandFrame(
                        command=_signed_command(
                            identity,
                            action_number=50,
                            session_epoch=welcome.session_epoch,
                        )
                    )
                )
            )
            acknowledged = parse_frame(socket.receive_text())
            assert isinstance(acknowledged, EventFrame)
            assert acknowledged.event["sequence"] == 2
            socket.send_text(
                encode_frame(
                    AckFrame(
                        acknowledgements=(Acknowledgement(group_id=GROUP_ID, sequence=2),),
                        sent_at=datetime.now(UTC),
                    )
                )
            )
            socket.send_text(
                encode_frame(
                    CommandFrame(
                        command=_signed_command(
                            identity,
                            action_number=51,
                            session_epoch=welcome.session_epoch,
                        )
                    )
                )
            )
            unacknowledged = parse_frame(socket.receive_text())
            assert isinstance(unacknowledged, EventFrame)
            assert unacknowledged.event["sequence"] == 3

        with client.websocket_connect("/ws") as reconnected:
            _authenticate(reconnected, identity)
            reconnected.send_text(
                encode_frame(
                    SubscribeFrame(
                        subscription_id="urn:missionweaveprotocol:subscription:after-disconnect",
                        groups=(GroupCursor(group_id=GROUP_ID, after_sequence=0),),
                    )
                )
            )
            replayed = parse_frame(reconnected.receive_text())

    assert isinstance(replayed, EventFrame)
    assert replayed.event["sequence"] == 3
    assert replayed.event["eventId"] == unacknowledged.event["eventId"]


@pytest.mark.asyncio
async def test_adapter_completes_codec_verification_before_session_verification() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    keys = AgentKeyRegistry()
    keys.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    adapter = CoreGatewayAdapter(
        Core(InMemoryStore()),
        keys,
        _command_key_resolver((identity, KEY_ID)),
    )

    def unexpected_session_verification() -> SessionGrant:
        raise AssertionError("session verification ran before the codec rejected the Command")

    command = _signed_command(identity, action_number=89, session_epoch=1)
    payload = command["payload"]
    assert isinstance(payload, dict)
    payload["content"] = "tampered after signing"

    with pytest.raises(SignedDocumentVerificationError) as captured:
        await adapter.perform(
            verify_session=unexpected_session_verification,
            command_bytes=canonical_bytes(command),
        )
    assert captured.value.protected_error.stage is VerificationStage.SIGNATURE


@pytest.mark.asyncio
async def test_adapter_preserves_unknown_noncritical_extension_without_core_overrides() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    card = _card(identity)
    core = Core(InMemoryStore())
    keys = AgentKeyRegistry()
    keys.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    adapter = CoreGatewayAdapter(core, keys, _command_key_resolver((identity, KEY_ID)))
    extensions = {
        "https://profiles.example/audit": {
            "version": "1.2.3",
            "critical": False,
            "data": {
                "kind": "mission.approved",
                "actor": {"type": "human", "id": "urn:missionweaveprotocol:human:forged"},
                "groupId": "urn:missionweaveprotocol:group:forged",
                "sequence": 999,
                "payload": {"forged": True},
                "acceptedBy": {"type": "service", "id": "urn:missionweaveprotocol:service:forged"},
                "signature": {"value": "forged"},
                " opaque key ": "  preserve opaque whitespace  ",
            },
        }
    }

    await _bootstrap_mission(core, card)
    await adapter.activate_session(identity.agent_id, 1)
    command = _signed_command_with_extensions(
        identity,
        action_number=90,
        session_epoch=1,
        extensions=extensions,
    )
    event = await adapter.perform(
        verify_session=lambda: _session(identity, session_epoch=1),
        command_bytes=canonical_bytes(command),
    )

    assert event["kind"] == "message.posted"
    assert event["actor"] == {"type": "agent", "id": identity.agent_id}
    assert event["groupId"] == GROUP_ID
    assert event["sequence"] != 999
    assert event["payload"]["message"]["content"] == "message 90"  # type: ignore[index]
    assert event["acceptedBy"] == {
        "type": "service",
        "id": "urn:missionweaveprotocol:service:group-gateway",
    }
    assert event["signature"] != {"value": "forged"}
    assert event["extensions"] == extensions

    duplicate = await adapter.perform(
        verify_session=lambda: _session(identity, session_epoch=1),
        command_bytes=canonical_bytes(command),
    )
    sequence = event["sequence"]
    assert isinstance(sequence, int)
    replayed = await adapter.replay(
        identity.agent_id,
        GROUP_ID,
        after_sequence=sequence - 1,
    )

    assert duplicate["eventId"] == event["eventId"]
    assert duplicate["extensions"] == extensions
    assert [item["eventId"] for item in replayed] == [event["eventId"]]
    assert replayed[0]["extensions"] == extensions


def test_unknown_critical_extension_returns_specific_wire_error() -> None:
    identity = AgentIdentity.generate(AGENT_ID)
    card = _card(identity)
    core = Core(InMemoryStore())
    keys = AgentKeyRegistry()
    keys.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    adapter = CoreGatewayAdapter(core, keys, _command_key_resolver((identity, KEY_ID)))

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        await _bootstrap_mission(core, card)
        yield

    app = FastAPI(lifespan=lifespan)
    gateway = GroupGateway(
        adapter,
        SessionAuthority(keys, secret=SESSION_SECRET),
        app=app,
    )

    with TestClient(gateway.app) as client, client.websocket_connect("/ws") as socket:
        welcome = _authenticate(socket, identity)
        socket.send_text(
            encode_frame(
                SubscribeFrame(
                    subscription_id="urn:missionweaveprotocol:subscription:critical-extension",
                    groups=(GroupCursor(group_id=GROUP_ID, after_sequence=1),),
                )
            )
        )
        socket.send_text(
            encode_frame(
                CommandFrame(
                    command=_signed_command_with_extensions(
                        identity,
                        action_number=91,
                        session_epoch=welcome.session_epoch,
                        extensions={
                            "https://profiles.example/required": {
                                "version": "2.0.0",
                                "critical": True,
                                "data": {"policy": "required"},
                            }
                        },
                    )
                )
            )
        )
        rejected = parse_frame(socket.receive_text())

    assert isinstance(rejected, ErrorFrame)
    assert rejected.error.code is ErrorCode.UNKNOWN_CRITICAL_EXTENSION


@pytest.mark.asyncio
async def test_critical_extension_requires_exact_configured_profile_version() -> None:
    profile_uri = "https://profiles.example/required"
    identity = AgentIdentity.generate(AGENT_ID)
    card = _card(identity)
    core = Core(InMemoryStore())
    keys = AgentKeyRegistry()
    keys.register(identity.agent_id, identity.public_key, key_id=KEY_ID)
    adapter = CoreGatewayAdapter(
        core,
        keys,
        _command_key_resolver((identity, KEY_ID)),
        supported_profiles={profile_uri: "2.0.0"},
    )

    await _bootstrap_mission(core, card)
    await adapter.activate_session(identity.agent_id, 1)
    accepted_extensions = {
        profile_uri: {
            "version": "2.0.0",
            "critical": True,
            "data": {"policy": "required"},
        }
    }
    accepted = await adapter.perform(
        verify_session=lambda: _session(identity, session_epoch=1),
        command_bytes=canonical_bytes(
            _signed_command_with_extensions(
                identity,
                action_number=92,
                session_epoch=1,
                extensions=accepted_extensions,
            )
        ),
    )

    assert accepted["extensions"] == accepted_extensions

    with pytest.raises(UnknownCriticalExtension) as caught:
        await adapter.perform(
            verify_session=lambda: _session(identity, session_epoch=1),
            command_bytes=canonical_bytes(
                _signed_command_with_extensions(
                    identity,
                    action_number=93,
                    session_epoch=1,
                    extensions={
                        profile_uri: {
                            "version": "2.0.1",
                            "critical": True,
                            "data": {"policy": "required"},
                        }
                    },
                )
            ),
        )

    assert caught.value.details == {
        "profileUri": profile_uri,
        "receivedVersion": "2.0.1",
        "supportedVersion": "2.0.0",
    }
