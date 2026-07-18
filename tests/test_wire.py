from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
from jsonschema import ValidationError as JSONSchemaValidationError

from missionweaveprotocol.conformance import SchemaCatalog
from missionweaveprotocol.wire import (
    AckFrame,
    Acknowledgement,
    AuthFrame,
    ChallengeFrame,
    CommandFrame,
    ErrorCode,
    ErrorDocument,
    ErrorFrame,
    EventFrame,
    GroupCursor,
    HelloFrame,
    PingFrame,
    ReceivedCommandFrame,
    SubscribeFrame,
    WelcomeFrame,
    encode_frame,
    parse_frame,
    parse_received_frame,
)

NOW = datetime(2026, 7, 15, tzinfo=UTC)
SIGNATURE = {
    "algorithm": "Ed25519",
    "keyId": "urn:missionweaveprotocol:key:agent",
    "createdAt": "2026-07-15T00:00:00Z",
    "value": "c2lnbmF0dXJl",
}
COMMAND = {
    "protocolVersion": "0.1",
    "actionId": "urn:uuid:00000000-0000-4000-8000-000000000001",
    "actor": {"type": "agent", "id": "urn:missionweaveprotocol:agent:reviewer"},
    "sessionEpoch": 1,
    "membershipEpoch": 1,
    "groupId": "urn:missionweaveprotocol:group:mission",
    "kind": "message.post",
    "correlationId": "urn:uuid:00000000-0000-4000-8000-000000000099",
    "issuedAt": "2026-07-15T00:00:00Z",
    "payload": {},
    "signature": SIGNATURE,
}
EVENT = {
    "protocolVersion": "0.1",
    "eventId": "urn:uuid:00000000-0000-4000-8000-000000000002",
    "groupId": "urn:missionweaveprotocol:group:mission",
    "sequence": 1,
    "aggregateRevision": 1,
    "kind": "message.posted",
    "actor": {"type": "agent", "id": "urn:missionweaveprotocol:agent:reviewer"},
    "cause": {"type": "command", "id": COMMAND["actionId"]},
    "correlationId": COMMAND["correlationId"],
    "occurredAt": "2026-07-15T00:00:01Z",
    "payload": {},
    "acceptedBy": {"type": "service", "id": "urn:missionweaveprotocol:service:gateway"},
    "signature": SIGNATURE,
}


def _frames() -> tuple[object, ...]:
    return (
        HelloFrame(
            agent_id="urn:missionweaveprotocol:agent:reviewer",
            key_id="urn:missionweaveprotocol:key:agent",
            client_nonce="Y2xpZW50",
        ),
        ChallengeFrame(
            client_nonce="Y2xpZW50",
            server_nonce="c2VydmVy",
            challenge="Y2hhbGxlbmdl",
        ),
        AuthFrame(
            agent_id="urn:missionweaveprotocol:agent:reviewer",
            key_id="urn:missionweaveprotocol:key:agent",
            client_nonce="Y2xpZW50",
            server_nonce="c2VydmVy",
            challenge_signature="c2lnbmF0dXJl",
        ),
        WelcomeFrame(
            session_token="a-valid-session-token",
            session_epoch=1,
            expires_at=NOW,
        ),
        SubscribeFrame(
            subscription_id="urn:missionweaveprotocol:subscription:reviewer",
            groups=(GroupCursor(group_id="urn:missionweaveprotocol:group:mission"),),
        ),
        CommandFrame(command=COMMAND),
        EventFrame(event=EVENT),
        AckFrame(
            acknowledgements=(
                Acknowledgement(group_id="urn:missionweaveprotocol:group:mission", sequence=1),
            ),
            sent_at=NOW,
        ),
        PingFrame(nonce="cGluZw", sent_at=NOW),
        ErrorFrame(
            error=ErrorDocument(
                code=ErrorCode.INVALID_COMMAND,
                message="invalid",
                retryable=False,
                occurred_at=NOW,
            )
        ),
    )


@pytest.mark.parametrize("frame", _frames())
def test_every_encoded_frame_validates_against_normative_schema(frame: object) -> None:
    encoded = encode_frame(frame)  # type: ignore[arg-type]

    SchemaCatalog().validate("websocket-frame.schema.json", json.loads(encoded))
    assert encoded == encode_frame(parse_frame(encoded))


def test_one_subscription_multiplexes_many_group_cursors() -> None:
    frame = SubscribeFrame(
        subscription_id="urn:missionweaveprotocol:subscription:reviewer",
        groups=(
            GroupCursor(group_id="urn:missionweaveprotocol:group:auth", after_sequence=10),
            GroupCursor(group_id="urn:missionweaveprotocol:group:cli", after_sequence=4),
        ),
    )

    parsed = parse_frame(encode_frame(frame))

    assert isinstance(parsed, SubscribeFrame)
    assert [cursor.group_id for cursor in parsed.groups] == [
        "urn:missionweaveprotocol:group:auth",
        "urn:missionweaveprotocol:group:cli",
    ]


def test_unknown_extra_and_duplicate_frame_fields_are_rejected() -> None:
    with pytest.raises(JSONSchemaValidationError):
        parse_frame('{"protocolVersion":"0.1","frameId":"urn:x:1","frameType":"UNKNOWN"}')
    with pytest.raises(ValueError, match="duplicate JSON object member"):
        parse_frame(
            '{"protocolVersion":"0.1","protocolVersion":"0.1",'
            '"frameId":"urn:x:1","frameType":"UNKNOWN"}'
        )


def test_hello_has_identity_but_no_role_authority() -> None:
    hello = HelloFrame(
        agent_id="urn:missionweaveprotocol:agent:reviewer",
        key_id="urn:missionweaveprotocol:key:agent",
        client_nonce="Y2xpZW50",
    )
    encoded = encode_frame(hello)

    assert "role" not in encoded.lower()


def test_command_frame_round_trips_extension_data_without_promoting_core_fields() -> None:
    extensions = {
        "https://profiles.example/audit": {
            "version": "1.2.3",
            "critical": False,
            "data": {
                "kind": "mission.approved",
                "actor": {"type": "human", "id": "urn:missionweaveprotocol:human:forged"},
                "groupId": "urn:missionweaveprotocol:group:forged",
                "payload": {"forged": True},
                "signature": {"value": "forged"},
            },
        }
    }
    command = {**COMMAND, "extensions": extensions}

    parsed = parse_frame(encode_frame(CommandFrame(command=command)))

    assert isinstance(parsed, CommandFrame)
    assert parsed.command["extensions"] == extensions
    assert parsed.command["kind"] == COMMAND["kind"]
    assert parsed.command["actor"] == COMMAND["actor"]
    assert parsed.command["groupId"] == COMMAND["groupId"]
    assert parsed.command["payload"] == COMMAND["payload"]
    assert parsed.command["signature"] == COMMAND["signature"]


def test_received_command_frame_preserves_exact_nested_json_bytes() -> None:
    raw_command = '{\n  "payload": {"number": 1e400},\n  "protocolVersion": "0.1"\n}'
    raw_frame = (
        '{"protocolVersion":"0.1","frameId":"urn:missionweaveprotocol:frame:raw",'
        '"frameType":"COMMAND","command":' + raw_command + "}"
    )

    parsed = parse_received_frame(raw_frame)

    assert isinstance(parsed, ReceivedCommandFrame)
    assert parsed.command_bytes == raw_command.encode()
