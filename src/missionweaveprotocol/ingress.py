"""Verified wire Command ingress and lossless execution projection."""

from __future__ import annotations

from collections.abc import Collection, Mapping, Sequence
from typing import Any, cast

from pydantic import JsonValue

from .models import Command, CommandKind
from .signed_documents import (
    KeyResolver,
    SignedDocumentCodec,
    SignedDocumentKind,
    VerifiedSignedDocument,
)


class CommandIngress:
    """Verify raw wire Commands and project their immutable proof into typed execution state."""

    def __init__(self, codec: SignedDocumentCodec | None = None) -> None:
        self._codec = codec or SignedDocumentCodec()

    def verify(self, raw_command_bytes: bytes, key_resolver: KeyResolver) -> VerifiedSignedDocument:
        return self._codec.verify(
            SignedDocumentKind.COMMAND,
            raw_command_bytes,
            key_resolver,
        )

    @staticmethod
    def project_verified(verified: VerifiedSignedDocument) -> Command:
        if verified.kind is not SignedDocumentKind.COMMAND:
            raise ValueError("CommandIngress requires a verified Command")
        document = _thaw_json(verified.document)
        if not isinstance(document, dict):
            raise ValueError("verified Command document is not an object")
        candidate: dict[str, Any] = {
            "protocolVersion": document["protocolVersion"],
            "actionId": document["actionId"],
            "kind": CommandKind(str(document["kind"])),
            "actor": document["actor"],
            "groupId": document.get("groupId"),
            "sessionEpoch": document.get("sessionEpoch"),
            "membershipEpoch": document.get("membershipEpoch"),
            "coordinatorEpoch": document.get("coordinatorEpoch"),
            "correlationId": document.get("correlationId"),
            "causedByEventId": document.get("causedByEventId"),
            "conversationId": document.get("conversationId"),
            "workItemId": document.get("workItemId"),
            "cooperationOverrideGrantId": document.get("cooperationOverrideGrantId"),
            "expectedRevision": document.get("expectedRevision"),
            "issuedAt": document["issuedAt"],
            "payload": document["payload"],
            "extensions": document.get("extensions", {}),
            "signature": document["signature"],
            "verifiedSigningHash": verified.signing_hash,
        }
        return Command.model_validate(candidate)

    @staticmethod
    def execution_payload(
        command: Command,
        *,
        payload_fields: Collection[str],
    ) -> dict[str, JsonValue]:
        """Adapt top-level wire references without mutating the persisted signed payload."""

        payload = dict(command.payload)
        if command.conversation_id is not None and "conversation_id" in payload_fields:
            payload.setdefault("conversationId", command.conversation_id)
        if command.work_item_id is not None and "work_item_id" in payload_fields:
            payload.setdefault("workItemId", command.work_item_id)
        if command.kind is CommandKind.POST_MESSAGE:
            payload.pop("authority", None)
        return payload


def _thaw_json(value: object) -> JsonValue:
    if value is None or type(value) in {bool, int, float, str}:
        return cast(JsonValue, value)
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_thaw_json(item) for item in value]
    raise TypeError(f"verified document contains non-JSON value {type(value).__name__}")


__all__ = [
    "CommandIngress",
]
