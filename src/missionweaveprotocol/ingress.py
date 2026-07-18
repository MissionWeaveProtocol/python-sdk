"""Verified wire Command ingress and lossless execution projection."""

from __future__ import annotations

from collections.abc import Collection, Mapping
from typing import Any

from pydantic import JsonValue

from .canonical import canonical_hash
from .conformance import SchemaCatalog
from .models import Command, CommandKind


def signing_document(document: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """Return exactly the wire members covered by the Command signature."""

    value = dict(document)
    value.pop("signature", None)
    return value


def signing_hash(document: Mapping[str, JsonValue]) -> str:
    """Hash the verified wire signing document without re-projecting its provenance."""

    return canonical_hash(signing_document(document))


class CommandIngress:
    """Validate a wire Command and project all signed provenance into one typed Command."""

    def __init__(self, schemas: SchemaCatalog | None = None) -> None:
        self._schemas = schemas or SchemaCatalog()

    def validate(self, document: Mapping[str, JsonValue]) -> None:
        self._schemas.validate("command.schema.json", document)

    @staticmethod
    def project_verified(
        document: Mapping[str, JsonValue],
        *,
        verified_signing_hash: str,
    ) -> Command:
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
            "verifiedSigningHash": verified_signing_hash,
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


__all__ = [
    "CommandIngress",
    "signing_document",
    "signing_hash",
]
