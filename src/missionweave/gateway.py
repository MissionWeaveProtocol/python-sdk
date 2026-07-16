"""Authenticated multiplexed WebSocket Adapter for the MissionWeave core Interface."""

from __future__ import annotations

import asyncio
import base64
import json
import re
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, cast
from uuid import uuid4

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from jsonschema import ValidationError as JSONSchemaValidationError
from pydantic import JsonValue
from pydantic import ValidationError as PydanticValidationError

from missionweave.auth import (
    AgentKeyRegistry,
    AuthenticationError,
    SessionAuthority,
    SessionGrant,
)
from missionweave.canonical import canonical_hash, canonical_json
from missionweave.conformance import SchemaCatalog
from missionweave.core import Core, InvalidCommand, MissionWeaveError
from missionweave.crypto import PrivateKeyLike, generate_keypair, sign_canonical, verify_canonical
from missionweave.models import (
    ActorType,
    Command,
    CommandKind,
    Event,
    Membership,
    MembershipStatus,
    OpenAgentSessionPayload,
    Principal,
    Query,
    QueryKind,
)
from missionweave.offline import OFFLINE_EXECUTION_EXTENSION, OFFLINE_EXECUTION_EXTENSION_VERSION
from missionweave.wire import (
    AckFrame,
    AttentionFilter,
    AuthFrame,
    ChallengeFrame,
    CommandFrame,
    ErrorDocument,
    ErrorFrame,
    EventFrame,
    Frame,
    HelloFrame,
    PingFrame,
    SubscribeFrame,
    WelcomeFrame,
    encode_frame,
    parse_frame,
)
from missionweave.wire import (
    ErrorCode as WireErrorCode,
)


class GatewaySchemaError(ValueError):
    """A transport document did not conform to a normative MissionWeave schema."""

    def __init__(self, message: str, *, details: dict[str, JsonValue] | None = None) -> None:
        super().__init__(message)
        self.details = details or {}


class SubscriptionDenied(ValueError):
    """The caller has no active Membership visible through a subscription."""


class UnknownCriticalExtension(ValueError):
    """A Command depends on an Extension Profile this gateway cannot interpret."""

    def __init__(
        self,
        profile_uri: str,
        received_version: str,
        supported_version: str | None,
    ) -> None:
        if supported_version is None:
            message = f"critical Extension Profile is not supported: {profile_uri}"
        else:
            message = (
                "critical Extension Profile version does not match configured support: "
                f"{profile_uri} (received={received_version}, supported={supported_version})"
            )
        super().__init__(message)
        self.details: dict[str, JsonValue] = {
            "profileUri": profile_uri,
            "receivedVersion": received_version,
        }
        if supported_version is not None:
            self.details["supportedVersion"] = supported_version


class GatewayCore(Protocol):
    """Owned port exposing only the core behavior required by the transport Adapter."""

    async def current_session_epoch(self, agent_id: str) -> int: ...

    async def activate_session(self, agent_id: str, session_epoch: int) -> None: ...

    async def perform(
        self,
        *,
        actor: str,
        session_epoch: int,
        command: dict[str, JsonValue],
    ) -> dict[str, JsonValue]: ...

    async def replay(
        self,
        actor: str,
        group_id: str,
        *,
        after_sequence: int,
    ) -> list[dict[str, JsonValue]]: ...


Clock = Callable[[], datetime]

_URI_PATTERN = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$")


class CoreGatewayAdapter:
    """Validate normative documents and adapt them to the typed authoritative Core."""

    def __init__(
        self,
        core: Core,
        command_keys: AgentKeyRegistry,
        *,
        schema_root: Path | None = None,
        authority_key_id: str = "urn:missionweave:key:group-gateway",
        authority_private_key: PrivateKeyLike | None = None,
        clock: Clock | None = None,
        supported_profiles: Mapping[str, str] | None = None,
    ) -> None:
        self._core = core
        self._command_keys = command_keys
        self._schemas = SchemaCatalog(schema_root)
        self._authority_key_id = authority_key_id
        self._authority_private_key = authority_private_key or generate_keypair()[0]
        self._clock = clock or (lambda: datetime.now(UTC))
        self._supported_profiles = {
            OFFLINE_EXECUTION_EXTENSION: OFFLINE_EXECUTION_EXTENSION_VERSION,
            **dict(supported_profiles or {}),
        }

    async def current_session_epoch(self, agent_id: str) -> int:
        result = await self._core.query(Query(kind=QueryKind.SESSION_EPOCH, entity_id=agent_id))
        if result is None:
            return 0
        if not isinstance(result, int):
            raise RuntimeError("Core returned a non-integer Agent session epoch")
        return result

    async def activate_session(self, agent_id: str, session_epoch: int) -> None:
        current = await self.current_session_epoch(agent_id)
        if session_epoch != current + 1:
            raise AuthenticationError(
                "gateway and authoritative Core session epochs diverged "
                f"(Core={current}, grant={session_epoch})"
            )
        event = await self._core.perform(
            Command(
                action_id=f"urn:uuid:{uuid4()}",
                kind=CommandKind.OPEN_AGENT_SESSION,
                actor=Principal.system("urn:missionweave:service:group-gateway"),
                issued_at=self._now(),
                payload=cast(
                    dict[str, JsonValue],
                    OpenAgentSessionPayload(agent_id=agent_id).model_dump(
                        mode="json", by_alias=True
                    ),
                ),
                signature="gateway-session-authority",
            )
        )
        activated_epoch = event.payload.get("sessionEpoch")
        if activated_epoch != session_epoch:
            raise AuthenticationError(
                "authoritative Core activated an unexpected session epoch "
                f"(expected={session_epoch}, actual={activated_epoch})"
            )

    async def perform(
        self,
        *,
        actor: str,
        session_epoch: int,
        command: dict[str, JsonValue],
    ) -> dict[str, JsonValue]:
        self._validate_command_schema(command)
        self._verify_command_identity(command, actor, session_epoch)
        await self._verify_command_membership(command, actor)
        self._verify_command_extensions(command)
        parsed = self._translate_command(command)
        event = await self._core.perform(parsed)
        return self._translate_event(event)

    async def replay(
        self,
        actor: str,
        group_id: str,
        *,
        after_sequence: int,
    ) -> list[dict[str, JsonValue]]:
        membership = await self._core.query(
            Query(
                kind=QueryKind.MEMBERSHIP,
                entity_id=actor,
                group_id=group_id,
                actor_type=ActorType.AGENT,
            )
        )
        if (
            not isinstance(membership, Membership)
            or membership.status is not MembershipStatus.ACTIVE
        ):
            raise SubscriptionDenied("active Group Membership is required")
        effective_after = max(after_sequence, membership.visibility_after_sequence)
        events = await self._core.replay(group_id, after=effective_after)
        return [self._translate_event(event) for event in events]

    def _validate_command_schema(self, command: dict[str, JsonValue]) -> None:
        try:
            self._schemas.validate("command.schema.json", command)
        except JSONSchemaValidationError as error:
            raise GatewaySchemaError(
                "Command does not conform to command.schema.json",
                details={
                    "path": "/".join(str(item) for item in error.absolute_path),
                    "reason": error.message,
                },
            ) from error

    def _verify_command_identity(
        self,
        command: dict[str, JsonValue],
        actor: str,
        session_epoch: int,
    ) -> None:
        command_actor = command.get("actor")
        if not isinstance(command_actor, dict):
            raise GatewaySchemaError("Command actor must be an object")
        if command_actor.get("type") != "agent" or command_actor.get("id") != actor:
            raise AuthenticationError("Command actor does not match the authenticated Agent")
        if command.get("sessionEpoch") != session_epoch:
            raise AuthenticationError("Command epoch does not match the authenticated session")
        signature = command.get("signature")
        if not isinstance(signature, dict):
            raise GatewaySchemaError("Command signature must be an Ed25519 signature object")
        if signature.get("algorithm") != "Ed25519":
            raise GatewaySchemaError("Command signature must use Ed25519")
        key_id = signature.get("keyId")
        created_at_value = signature.get("createdAt")
        signature_value = signature.get("value")
        if (
            not isinstance(key_id, str)
            or not isinstance(created_at_value, str)
            or not isinstance(signature_value, str)
        ):
            raise GatewaySchemaError("Command signature must be an Ed25519 signature object")
        created_at = _parse_timestamp(created_at_value, field="Command signature createdAt")
        signing_payload = dict(command)
        del signing_payload["signature"]
        public_key = self._command_keys.resolve(actor, key_id, at=created_at)
        self._command_keys.resolve(actor, key_id, at=self._now())
        if not verify_canonical(signing_payload, signature_value, public_key):
            raise AuthenticationError("durable Command signature is invalid")

    async def _verify_command_membership(
        self,
        command: dict[str, JsonValue],
        actor: str,
    ) -> None:
        group_id = command.get("groupId")
        membership_epoch = command.get("membershipEpoch")
        if not isinstance(group_id, str) or not isinstance(membership_epoch, int):
            raise GatewaySchemaError("Command requires Group and Membership epochs")
        membership = await self._core.query(
            Query(
                kind=QueryKind.MEMBERSHIP,
                entity_id=actor,
                group_id=group_id,
                actor_type=ActorType.AGENT,
            )
        )
        kind = command.get("kind")
        allowed_statuses = (
            {MembershipStatus.ACTIVE, MembershipStatus.PROVISIONAL}
            if kind == CommandKind.ACCEPT_WORK_OFFER.value
            else {MembershipStatus.ACTIVE}
        )
        if not isinstance(membership, Membership) or membership.status not in allowed_statuses:
            raise AuthenticationError("active Group Membership is required")
        if membership.epoch != membership_epoch:
            raise AuthenticationError("Command carries a stale Membership epoch")

    def _verify_command_extensions(self, command: dict[str, JsonValue]) -> None:
        extensions = command.get("extensions")
        if extensions is None:
            return
        if not isinstance(extensions, dict):
            raise GatewaySchemaError("Command extensions must be an object")
        for profile_uri, envelope in extensions.items():
            if not isinstance(profile_uri, str) or not isinstance(envelope, dict):
                raise GatewaySchemaError("Command Extension Profile envelope is invalid")
            version = envelope.get("version")
            critical = envelope.get("critical")
            if not isinstance(version, str) or not isinstance(critical, bool):
                raise GatewaySchemaError("Command Extension Profile envelope is invalid")
            supported_version = self._supported_profiles.get(profile_uri)
            if critical and supported_version != version:
                raise UnknownCriticalExtension(profile_uri, version, supported_version)

    def _translate_command(self, command: dict[str, JsonValue]) -> Command:
        try:
            kind = CommandKind(str(command["kind"]))
        except (KeyError, ValueError) as error:
            raise InvalidCommand(
                "the reference Core does not implement this normative Command kind",
                kind=command.get("kind"),
            ) from error

        payload_value = command.get("payload")
        if not isinstance(payload_value, dict):
            raise GatewaySchemaError("Command payload must be an object")
        payload = dict(payload_value)
        if kind is CommandKind.POST_MESSAGE:
            conversation_id = command.get("conversationId")
            if conversation_id is not None:
                payload.setdefault("conversationId", conversation_id)
            payload.pop("authority", None)

        expected_revision = command.get("expectedRevision")
        if expected_revision == 0:
            expected_revision = None
        signature = cast(dict[str, JsonValue], command["signature"])
        candidate: dict[str, Any] = {
            "protocolVersion": command["protocolVersion"],
            "actionId": command["actionId"],
            "kind": kind,
            "actor": command["actor"],
            "groupId": command["groupId"],
            "sessionEpoch": command["sessionEpoch"],
            "membershipEpoch": command["membershipEpoch"],
            "issuedAt": command["issuedAt"],
            "payload": payload,
            "extensions": command.get("extensions", {}),
            "signature": signature["value"],
        }
        if expected_revision is not None:
            candidate["expectedRevision"] = expected_revision
        coordinator_epoch = payload.pop("coordinatorEpoch", None)
        if coordinator_epoch is not None:
            candidate["coordinatorEpoch"] = coordinator_epoch
        try:
            return Command.model_validate(candidate)
        except PydanticValidationError as error:
            raise InvalidCommand(
                "normative Command cannot be executed by the reference Core",
                errors=error.errors(include_url=False),
            ) from error

    def _translate_event(self, event: Event) -> dict[str, JsonValue]:
        if event.group_id is None or event.sequence is None:
            raise RuntimeError("only Group Events can be delivered over a subscription")
        occurred_at = event.occurred_at.isoformat().replace("+00:00", "Z")
        document: dict[str, JsonValue] = {
            "protocolVersion": "0.1",
            "eventId": self._identifier(event.id, namespace="event"),
            "groupId": self._identifier(event.group_id, namespace="group"),
            "sequence": event.sequence,
            "aggregateRevision": event.sequence,
            "kind": event.kind.value,
            "actor": self._actor_document(event.actor),
            "cause": {
                "type": "command",
                "id": self._identifier(event.action_id, namespace="action"),
            },
            "correlationId": self._identifier(event.action_id, namespace="correlation"),
            "occurredAt": occurred_at,
            "payload": event.payload,
            "acceptedBy": {
                "type": "service",
                "id": "urn:missionweave:service:group-gateway",
            },
            "commandHash": event.command_hash,
        }
        conversation_id = _event_reference(event.payload, "conversationId")
        if conversation_id is not None:
            document["conversationId"] = self._identifier(
                conversation_id,
                namespace="conversation",
            )
        work_item_id = _event_reference(event.payload, "workItemId")
        if work_item_id is not None:
            document["workItemId"] = self._identifier(
                work_item_id,
                namespace="work-item",
            )
        if event.extensions:
            document["extensions"] = cast(
                dict[str, JsonValue],
                event.model_dump(mode="json", by_alias=True, include={"extensions"})["extensions"],
            )
        signature_value = sign_canonical(document, self._authority_private_key)
        document["signature"] = {
            "algorithm": "Ed25519",
            "keyId": self._authority_key_id,
            "createdAt": occurred_at,
            "value": signature_value,
        }
        try:
            self._schemas.validate("event.schema.json", document)
        except JSONSchemaValidationError as error:
            raise RuntimeError(
                f"Core Event cannot be represented by event.schema.json: {error.message}"
            ) from error
        return document

    @staticmethod
    def _actor_document(actor: Principal) -> dict[str, JsonValue]:
        actor_type = "service" if actor.type is ActorType.SYSTEM else actor.type.value
        return {"type": actor_type, "id": CoreGatewayAdapter._identifier(actor.id, "actor")}

    @staticmethod
    def _identifier(value: str, namespace: str) -> str:
        if _URI_PATTERN.fullmatch(value):
            return value
        return f"urn:missionweave:{namespace}:{canonical_hash(value).removeprefix('sha256:')}"

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise RuntimeError("CoreGatewayAdapter clock must return an aware datetime")
        return now.astimezone(UTC)


class CursorStore(Protocol):
    async def acknowledge(self, agent_id: str, group_id: str, through_sequence: int) -> None: ...

    async def cursor(self, agent_id: str, group_id: str) -> int: ...


class InMemoryCursorStore:
    def __init__(self) -> None:
        self._cursors: dict[tuple[str, str], int] = {}
        self._lock = asyncio.Lock()

    async def acknowledge(self, agent_id: str, group_id: str, through_sequence: int) -> None:
        async with self._lock:
            key = (agent_id, group_id)
            current = self._cursors.get(key, 0)
            if through_sequence < current:
                return
            self._cursors[key] = through_sequence

    async def cursor(self, agent_id: str, group_id: str) -> int:
        return self._cursors.get((agent_id, group_id), 0)


@dataclass(slots=True)
class _Connection:
    websocket: WebSocket
    grant: SessionGrant
    groups: dict[str, AttentionFilter | None] = field(default_factory=dict)
    send_lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def send(self, frame: Frame) -> None:
        async with self.send_lock:
            await self.websocket.send_text(encode_frame(frame))


class GroupGateway:
    """Deep transport Module hiding authentication, replay, multiplexing, and fan-out."""

    def __init__(
        self,
        core: GatewayCore,
        sessions: SessionAuthority,
        *,
        cursors: CursorStore | None = None,
        app: FastAPI | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._core = core
        self._sessions = sessions
        self._cursors = cursors or InMemoryCursorStore()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._connections: dict[int, _Connection] = {}
        self._connections_lock = asyncio.Lock()
        self._session_open_lock = asyncio.Lock()
        self.app = app or FastAPI(title="MissionWeave Group Gateway", version="0.1.0")
        self.app.websocket("/ws")(self._handle)

    async def _handle(self, websocket: WebSocket) -> None:
        await websocket.accept()
        connection: _Connection | None = None
        try:
            connection = await self._authenticate(websocket)
            async with self._connections_lock:
                self._connections[id(websocket)] = connection
            while True:
                frame = parse_frame(await websocket.receive_text())
                await self._dispatch(connection, frame)
        except WebSocketDisconnect:
            pass
        except Exception as error:  # transport converts domain/auth failures to protocol errors
            await self._send_error(websocket, error)
        finally:
            async with self._connections_lock:
                self._connections.pop(id(websocket), None)

    async def _authenticate(self, websocket: WebSocket) -> _Connection:
        hello = parse_frame(await websocket.receive_text())
        if not isinstance(hello, HelloFrame):
            raise AuthenticationError("first frame must be HELLO/client_init")
        challenge = self._sessions.issue_challenge(
            hello.agent_id,
            key_id=hello.key_id,
            client_nonce=hello.client_nonce,
            protocol_version=hello.protocol_version,
        )
        await websocket.send_text(
            encode_frame(
                ChallengeFrame(
                    client_nonce=hello.client_nonce,
                    server_nonce=challenge.server_nonce,
                    challenge=_b64encode(challenge.signing_bytes()),
                )
            )
        )
        proof = parse_frame(await websocket.receive_text())
        if not isinstance(proof, AuthFrame):
            raise AuthenticationError("HELLO/client_init must be followed by client_response")
        if (
            proof.agent_id != hello.agent_id
            or proof.key_id != hello.key_id
            or proof.client_nonce != hello.client_nonce
            or proof.server_nonce != challenge.server_nonce
            or proof.protocol_version != challenge.protocol_version
        ):
            raise AuthenticationError("HELLO challenge transcript does not match")
        async with self._session_open_lock:
            authoritative_epoch = await self._core.current_session_epoch(hello.agent_id)
            self._sessions.synchronize_epoch(
                hello.agent_id,
                authoritative_epoch,
                key_id=hello.key_id,
            )
            grant = self._sessions.open_session(challenge.challenge_id, proof.challenge_signature)
            await self._core.activate_session(grant.agent_id, grant.session_epoch)
        await websocket.send_text(
            encode_frame(
                WelcomeFrame(
                    session_epoch=grant.session_epoch,
                    session_token=grant.token,
                    expires_at=grant.expires_at,
                )
            )
        )
        return _Connection(websocket=websocket, grant=grant)

    async def _dispatch(self, connection: _Connection, frame: Frame) -> None:
        if isinstance(frame, SubscribeFrame):
            for requested in frame.groups:
                after = max(
                    requested.after_sequence,
                    await self._cursors.cursor(connection.grant.agent_id, requested.group_id),
                )
                for event in await self._core.replay(
                    connection.grant.agent_id,
                    requested.group_id,
                    after_sequence=after,
                ):
                    if _matches_attention(
                        event,
                        requested.attention,
                        agent_id=connection.grant.agent_id,
                    ):
                        await connection.send(EventFrame(event=event))
                connection.groups[requested.group_id] = requested.attention
            return

        if isinstance(frame, CommandFrame):
            grant = self._sessions.verify_session(connection.grant.token)
            self._bind_command_to_session(frame.command, grant)
            event = await self._core.perform(
                actor=grant.agent_id,
                session_epoch=grant.session_epoch,
                command=frame.command,
            )
            await self._fanout(event)
            return

        if isinstance(frame, AckFrame):
            grant = self._sessions.verify_session(connection.grant.token)
            for acknowledgement in frame.acknowledgements:
                await self._cursors.acknowledge(
                    grant.agent_id,
                    acknowledgement.group_id,
                    acknowledgement.sequence,
                )
            return

        if isinstance(frame, PingFrame):
            if frame.reply_to_nonce is None:
                await connection.send(
                    PingFrame(
                        nonce=secrets.token_urlsafe(18),
                        reply_to_nonce=frame.nonce,
                        sent_at=self._now(),
                    )
                )
            return

        raise ValueError(f"frame {type(frame).__name__} is not valid after authentication")

    def _bind_command_to_session(
        self,
        command: dict[str, JsonValue],
        grant: SessionGrant,
    ) -> None:
        if command.get("protocolVersion") != grant.protocol_version:
            raise AuthenticationError(
                "Command protocol version does not match the authenticated session"
            )
        signature = command.get("signature")
        if not isinstance(signature, dict):
            raise GatewaySchemaError("Command signature must be an Ed25519 signature object")
        if signature.get("keyId") != grant.key_id:
            raise AuthenticationError("Command key ID does not match the authenticated session")
        issued_at = _parse_timestamp(command.get("issuedAt"), field="Command issuedAt")
        created_at = _parse_timestamp(
            signature.get("createdAt"),
            field="Command signature createdAt",
        )
        if created_at != issued_at:
            raise AuthenticationError("Command signature createdAt does not match Command issuedAt")
        if issued_at < grant.issued_at or issued_at >= grant.expires_at:
            raise AuthenticationError("Command timestamp is outside the authenticated session")
        if issued_at > self._now():
            raise AuthenticationError("Command timestamp is in the future")

    async def _fanout(self, event: dict[str, JsonValue]) -> None:
        raw_group_id = event.get("groupId")
        if raw_group_id is None:
            return
        group_id = str(raw_group_id)
        async with self._connections_lock:
            targets = [item for item in self._connections.values() if group_id in item.groups]
        sequence = event.get("sequence")
        if not isinstance(sequence, int):
            raise RuntimeError("live Event lacks a numeric Group sequence")
        deliveries: list[tuple[_Connection, dict[str, JsonValue]]] = []
        for target in targets:
            try:
                authorized = await self._core.replay(
                    target.grant.agent_id,
                    group_id,
                    after_sequence=sequence - 1,
                )
            except SubscriptionDenied:
                target.groups.pop(group_id, None)
                continue
            live = next(
                (candidate for candidate in authorized if candidate.get("sequence") == sequence),
                None,
            )
            if live is not None and _matches_attention(
                live,
                target.groups[group_id],
                agent_id=target.grant.agent_id,
            ):
                deliveries.append((target, live))
        await asyncio.gather(*(target.send(EventFrame(event=live)) for target, live in deliveries))

    async def _send_error(self, websocket: WebSocket, error: Exception) -> None:
        code = _wire_error_code(error)
        details = getattr(error, "details", {})
        normalized_details = cast(
            dict[str, JsonValue],
            json.loads(canonical_json(details)) if isinstance(details, dict) else {},
        )
        try:
            await websocket.send_text(
                encode_frame(
                    ErrorFrame(
                        error=ErrorDocument(
                            code=code,
                            message=str(error) or type(error).__name__,
                            retryable=False,
                            occurred_at=self._now(),
                            details=normalized_details or None,
                        )
                    )
                )
            )
        except (RuntimeError, WebSocketDisconnect):
            return

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise RuntimeError("GroupGateway clock must return an aware datetime")
        return now.astimezone(UTC)


def _wire_error_code(error: Exception) -> WireErrorCode:
    if isinstance(error, UnknownCriticalExtension):
        return WireErrorCode.UNKNOWN_CRITICAL_EXTENSION
    if isinstance(error, GatewaySchemaError | PydanticValidationError | JSONSchemaValidationError):
        return WireErrorCode.SCHEMA_VALIDATION_FAILED
    if isinstance(error, AuthenticationError):
        if "stale" in str(error).lower() or "epoch" in str(error).lower():
            return WireErrorCode.AUTH_STALE_SESSION
        return WireErrorCode.AUTH_INVALID_SIGNATURE
    if isinstance(error, SubscriptionDenied):
        return WireErrorCode.MEMBERSHIP_REQUIRED
    if isinstance(error, MissionWeaveError):
        mapping = {
            "invalid_command": WireErrorCode.INVALID_COMMAND,
            "not_found": WireErrorCode.GROUP_NOT_FOUND,
            "already_exists": WireErrorCode.INVALID_STATE_TRANSITION,
            "authorization_denied": WireErrorCode.AUTH_FORBIDDEN,
            "action_id_collision": WireErrorCode.ACTION_ID_COLLISION,
            "stale_session_epoch": WireErrorCode.AUTH_STALE_SESSION,
            "stale_coordinator_epoch": WireErrorCode.MEMBERSHIP_STALE,
            "stale_ownership_epoch": WireErrorCode.WORK_STALE_OWNERSHIP,
            "lease_expired": WireErrorCode.WORK_LEASE_EXPIRED,
            "invalid_transition": WireErrorCode.INVALID_STATE_TRANSITION,
            "revision_conflict": WireErrorCode.REVISION_CONFLICT,
            "dependency_error": WireErrorCode.INVALID_COMMAND,
            "policy_violation": WireErrorCode.APPROVAL_REQUIRED,
            "budget_exceeded": WireErrorCode.BUDGET_EXCEEDED,
        }
        return mapping.get(error.code.value, WireErrorCode.INVALID_COMMAND)
    if isinstance(error, ValueError):
        return WireErrorCode.PROTOCOL_VIOLATION
    return WireErrorCode.INTERNAL_ERROR


def _parse_timestamp(value: object, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise GatewaySchemaError(f"{field} must be an RFC 3339 timestamp")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise GatewaySchemaError(f"{field} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise GatewaySchemaError(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _event_reference(payload: dict[str, JsonValue], name: str) -> str | None:
    direct = payload.get(name)
    if isinstance(direct, str):
        return direct
    for nested_name in ("message", "workItem", "artifact", "membership"):
        nested = payload.get(nested_name)
        if isinstance(nested, dict):
            value = nested.get(name)
            if isinstance(value, str):
                return value
    return None


def _matches_attention(
    event: dict[str, JsonValue],
    attention: AttentionFilter | None,
    *,
    agent_id: str,
) -> bool:
    if attention is None:
        return True
    payload = event.get("payload")
    payload_document = payload if isinstance(payload, dict) else {}
    if attention.announcements and payload_document.get("announcement") is True:
        return True
    if attention.event_kinds is not None and event.get("kind") not in attention.event_kinds:
        return False
    if (
        attention.conversation_ids is not None
        and event.get("conversationId") not in attention.conversation_ids
    ):
        return False
    if (
        attention.work_item_ids is not None
        and event.get("workItemId") not in attention.work_item_ids
    ):
        return False
    return not (attention.mentions_only and agent_id not in _event_mentions(payload_document))


def _event_mentions(payload: dict[str, JsonValue]) -> set[str]:
    message = payload.get("message")
    source = message if isinstance(message, dict) else payload
    mentions = source.get("mentions")
    if not isinstance(mentions, list):
        return set()
    return {
        str(item["id"])
        for item in mentions
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }
