"""Normative MissionWeaveProtocol 0.1 canonical JSON WebSocket frame models."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, JsonValue, TypeAdapter

from .canonical import canonical_json
from .conformance import SchemaCatalog


def _to_camel(name: str) -> str:
    head, *tail = name.split("_")
    return head + "".join(part.capitalize() for part in tail)


def _frame_id() -> str:
    return f"urn:uuid:{uuid4()}"


Identifier = Annotated[
    str,
    Field(pattern=r"^[A-Za-z][A-Za-z0-9+.-]*:[^\s]+$", max_length=512),
]
Base64Url = Annotated[
    str,
    Field(pattern=r"^[A-Za-z0-9_-]+$", min_length=2, max_length=4096),
]
SafeInteger = Annotated[int, Field(ge=0, le=9_007_199_254_740_991)]


class FrameModel(BaseModel):
    model_config = ConfigDict(
        alias_generator=_to_camel,
        extra="forbid",
        populate_by_name=True,
    )

    protocol_version: Literal["0.1"] = "0.1"
    frame_id: Identifier = Field(default_factory=_frame_id)


class HelloFrame(FrameModel):
    frame_type: Literal["HELLO"] = "HELLO"
    phase: Literal["client_init"] = "client_init"
    agent_id: Identifier
    key_id: Identifier
    client_nonce: Base64Url
    supported_versions: tuple[Literal["0.1"], ...] = ("0.1",)


class ChallengeFrame(FrameModel):
    frame_type: Literal["HELLO"] = "HELLO"
    phase: Literal["server_challenge"] = "server_challenge"
    selected_version: Literal["0.1"] = "0.1"
    client_nonce: Base64Url
    server_nonce: Base64Url
    challenge: Base64Url


class AuthFrame(FrameModel):
    frame_type: Literal["HELLO"] = "HELLO"
    phase: Literal["client_response"] = "client_response"
    agent_id: Identifier
    key_id: Identifier
    client_nonce: Base64Url
    server_nonce: Base64Url
    challenge_signature: Base64Url


class WelcomeFrame(FrameModel):
    frame_type: Literal["HELLO"] = "HELLO"
    phase: Literal["server_accept"] = "server_accept"
    selected_version: Literal["0.1"] = "0.1"
    session_token: Annotated[str, Field(min_length=16, max_length=8192)]
    session_epoch: Annotated[int, Field(ge=1, le=9_007_199_254_740_991)]
    expires_at: datetime


class AttentionFilter(BaseModel):
    model_config = ConfigDict(
        alias_generator=_to_camel,
        extra="forbid",
        populate_by_name=True,
    )

    event_kinds: tuple[str, ...] | None = None
    conversation_ids: tuple[Identifier, ...] | None = None
    work_item_ids: tuple[Identifier, ...] | None = None
    mentions_only: bool | None = None
    announcements: bool | None = None


class GroupCursor(BaseModel):
    model_config = ConfigDict(
        alias_generator=_to_camel,
        extra="forbid",
        populate_by_name=True,
    )

    group_id: Identifier
    after_sequence: SafeInteger = 0
    attention: AttentionFilter | None = None


class SubscribeFrame(FrameModel):
    frame_type: Literal["SUBSCRIBE"] = "SUBSCRIBE"
    subscription_id: Identifier
    groups: Annotated[tuple[GroupCursor, ...], Field(min_length=1)]


class CommandFrame(FrameModel):
    frame_type: Literal["COMMAND"] = "COMMAND"
    command: dict[str, JsonValue]


class EventFrame(FrameModel):
    frame_type: Literal["EVENT"] = "EVENT"
    event: dict[str, JsonValue]


class Acknowledgement(BaseModel):
    model_config = ConfigDict(
        alias_generator=_to_camel,
        extra="forbid",
        populate_by_name=True,
    )

    group_id: Identifier
    sequence: SafeInteger


class AckFrame(FrameModel):
    frame_type: Literal["ACK"] = "ACK"
    acknowledgements: Annotated[tuple[Acknowledgement, ...], Field(min_length=1)]
    sent_at: datetime


class PingFrame(FrameModel):
    frame_type: Literal["PING"] = "PING"
    nonce: Base64Url
    reply_to_nonce: Base64Url | None = None
    sent_at: datetime
    presence: dict[str, JsonValue] | None = None


class ErrorCode(StrEnum):
    UNSUPPORTED_VERSION = "UNSUPPORTED_VERSION"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    AUTH_INVALID_SIGNATURE = "AUTH_INVALID_SIGNATURE"
    AUTH_STALE_SESSION = "AUTH_STALE_SESSION"
    AUTH_STALE_COORDINATOR = "AUTH_STALE_COORDINATOR"
    AUTH_FORBIDDEN = "AUTH_FORBIDDEN"
    GROUP_NOT_FOUND = "GROUP_NOT_FOUND"
    MEMBERSHIP_REQUIRED = "MEMBERSHIP_REQUIRED"
    MEMBERSHIP_STALE = "MEMBERSHIP_STALE"
    SCHEMA_VALIDATION_FAILED = "SCHEMA_VALIDATION_FAILED"
    INVALID_COMMAND = "INVALID_COMMAND"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    REVISION_CONFLICT = "REVISION_CONFLICT"
    ACTION_ID_COLLISION = "ACTION_ID_COLLISION"
    UNKNOWN_CRITICAL_EXTENSION = "UNKNOWN_CRITICAL_EXTENSION"
    WORK_CONTRACT_INCOMPLETE = "WORK_CONTRACT_INCOMPLETE"
    WORK_OFFER_EXPIRED = "WORK_OFFER_EXPIRED"
    WORK_ALREADY_OWNED = "WORK_ALREADY_OWNED"
    WORK_LEASE_EXPIRED = "WORK_LEASE_EXPIRED"
    WORK_STALE_OWNERSHIP = "WORK_STALE_OWNERSHIP"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
    RATE_LIMITED = "RATE_LIMITED"
    BACKPRESSURE = "BACKPRESSURE"
    CURSOR_TOO_OLD = "CURSOR_TOO_OLD"
    PROTOCOL_VIOLATION = "PROTOCOL_VIOLATION"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class ErrorDocument(BaseModel):
    model_config = ConfigDict(
        alias_generator=_to_camel,
        extra="forbid",
        populate_by_name=True,
    )

    code: ErrorCode
    message: Annotated[str, Field(min_length=1, max_length=2000)]
    retryable: bool
    occurred_at: datetime
    fatal: bool | None = None
    related_frame_id: Identifier | None = None
    related_action_id: Identifier | None = None
    group_id: Identifier | None = None
    expected_revision: SafeInteger | None = None
    current_revision: SafeInteger | None = None
    retry_after_ms: SafeInteger | None = None
    snapshot_artifact_hash: str | None = None
    details: dict[str, JsonValue] | None = None


class ErrorFrame(FrameModel):
    frame_type: Literal["ERROR"] = "ERROR"
    error: ErrorDocument


# The normative PING frame represents both request and response through replyToNonce.
PongFrame = PingFrame


Frame = (
    HelloFrame
    | ChallengeFrame
    | AuthFrame
    | WelcomeFrame
    | SubscribeFrame
    | CommandFrame
    | EventFrame
    | AckFrame
    | PingFrame
    | ErrorFrame
)


@dataclass(frozen=True, slots=True)
class ReceivedCommandFrame:
    """Validated COMMAND frame envelope plus the exact nested Command JSON bytes."""

    protocol_version: str
    frame_id: str
    command_bytes: bytes


_FRAME_ADAPTER: TypeAdapter[Frame] = TypeAdapter(Frame)
_FRAME_SCHEMAS = SchemaCatalog()


def _reject_duplicate_members(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON object member: {key}")
        value[key] = item
    return value


def parse_frame(payload: str | bytes) -> Frame:
    """Parse one UTF-8 frame and validate it against the normative JSON Schema."""

    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    document = json.loads(payload, object_pairs_hook=_reject_duplicate_members)
    _FRAME_SCHEMAS.validate("websocket-frame.schema.json", document)
    return _FRAME_ADAPTER.validate_python(document)


def parse_received_frame(payload: str | bytes) -> Frame | ReceivedCommandFrame:
    """Parse an inbound frame without decoding away nested Command byte evidence."""

    if isinstance(payload, bytes):
        payload = payload.decode("utf-8", errors="strict")
    members, spans = _root_members(payload)
    if members.get("frameType") != "COMMAND":
        return parse_frame(payload)

    command_span = spans.get("command")
    envelope = dict(members)
    envelope["command"] = {}
    validated = CommandFrame.model_validate(envelope)
    if command_span is None:
        raise ValueError("COMMAND frame has no command member")
    start, end = command_span
    try:
        command_bytes = payload[start:end].encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise ValueError("Command contains text outside strict UTF-8") from error
    return ReceivedCommandFrame(
        protocol_version=validated.protocol_version,
        frame_id=validated.frame_id,
        command_bytes=command_bytes,
    )


def _root_members(payload: str) -> tuple[dict[str, Any], dict[str, tuple[int, int]]]:
    decoder = json.JSONDecoder()
    length = len(payload)

    def skip_whitespace(position: int) -> int:
        while position < length and payload[position] in " \t\r\n":
            position += 1
        return position

    position = skip_whitespace(0)
    if position >= length or payload[position] != "{":
        raise ValueError("frame must be one JSON object")
    position = skip_whitespace(position + 1)
    members: dict[str, Any] = {}
    spans: dict[str, tuple[int, int]] = {}
    if position < length and payload[position] == "}":
        position = skip_whitespace(position + 1)
        if position != length:
            raise ValueError("frame has trailing JSON data")
        return members, spans

    while True:
        try:
            name, name_end = decoder.raw_decode(payload, position)
        except json.JSONDecodeError as error:
            raise ValueError("frame has an invalid JSON member name") from error
        if not isinstance(name, str):
            raise ValueError("frame JSON member names must be strings")
        if name in members:
            raise ValueError(f"duplicate JSON object member: {name}")
        position = skip_whitespace(name_end)
        if position >= length or payload[position] != ":":
            raise ValueError("frame JSON member has no colon")
        value_start = skip_whitespace(position + 1)
        try:
            value, value_end = decoder.raw_decode(payload, value_start)
        except json.JSONDecodeError as error:
            raise ValueError(f"frame member {name!r} has invalid JSON") from error
        members[name] = value
        spans[name] = (value_start, value_end)
        position = skip_whitespace(value_end)
        if position >= length:
            raise ValueError("frame JSON object is not closed")
        if payload[position] == "}":
            position = skip_whitespace(position + 1)
            if position != length:
                raise ValueError("frame has trailing JSON data")
            return members, spans
        if payload[position] != ",":
            raise ValueError("frame JSON members are not comma-separated")
        position = skip_whitespace(position + 1)


def encode_frame(frame: Frame) -> str:
    """Encode one schema-valid frame using canonical MissionWeaveProtocol JSON."""

    value = _FRAME_ADAPTER.dump_python(frame, mode="json", by_alias=True, exclude_none=True)
    _FRAME_SCHEMAS.validate("websocket-frame.schema.json", value)
    return canonical_json(value)
