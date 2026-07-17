"""Signed Context Packages, deliberate knowledge publication, and Group archives."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, Any, Literal
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, field_validator

from .agent import AgentRuntimeSession
from .canonical import canonical_hash
from .conformance import SchemaCatalog
from .crypto import PrivateKeyLike, PublicKeyLike, sign_canonical, verify_canonical
from .models import (
    ActorType,
    Event,
    GroupSnapshot,
    PolicyLogEntry,
    Principal,
    ProtocolModel,
    SignatureEnvelope,
)

Classification = Literal["public", "internal", "confidential", "restricted"]
Sha256 = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]


def _uri(value: str, namespace: str) -> str:
    if ":" in value:
        return value
    try:
        return f"urn:uuid:{UUID(value)}"
    except ValueError:
        return f"urn:missionweaveprotocol:{namespace}:{value}"


class SourceEventRange(ProtocolModel):
    from_sequence: Annotated[int, Field(gt=0)]
    to_sequence: Annotated[int, Field(gt=0)]
    event_ids: tuple[str, ...]

    @field_validator("event_ids")
    @classmethod
    def event_ids_are_nonempty_and_unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(value) != len(set(value)):
            raise ValueError("source Event IDs must be nonempty and unique")
        return value


class ContextDecision(ProtocolModel):
    description: str
    source_event_ids: tuple[str, ...]


class ContextPackage(ProtocolModel):
    context_package_id: str
    version: Annotated[int, Field(gt=0)]
    previous_context_package_id: str | None = None
    mission_id: str
    group_id: str
    work_item_id: str | None = None
    source_event_range: SourceEventRange
    artifact_hashes: tuple[Sha256, ...] = ()
    summary: str
    decisions: tuple[ContextDecision, ...] = ()
    constraints: tuple[str, ...] = ()
    unresolved_questions: tuple[str, ...] = ()
    generated_by: Principal
    generated_at: AwareDatetime
    signature: SignatureEnvelope

    def signing_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="python", by_alias=True, exclude={"signature"})


class ContextPackageService:
    """Create, verify, and install scoped late-member context."""

    def __init__(
        self,
        *,
        agent_id: str,
        key_id: str,
        private_key: PrivateKeyLike,
        public_key: PublicKeyLike,
        schemas: SchemaCatalog | None = None,
    ) -> None:
        self._agent = Principal.agent(agent_id)
        self._key_id = key_id
        self._private_key = private_key
        self._public_key = public_key
        self._schemas = schemas or SchemaCatalog()

    def publish(
        self,
        *,
        mission_id: str,
        group_id: str,
        version: int,
        events: tuple[Event, ...],
        summary: str,
        artifact_hashes: tuple[str, ...] = (),
        decisions: tuple[ContextDecision, ...] = (),
        constraints: tuple[str, ...] = (),
        unresolved_questions: tuple[str, ...] = (),
        work_item_id: str | None = None,
        previous_context_package_id: str | None = None,
        generated_at: datetime | None = None,
        context_package_id: str | None = None,
    ) -> ContextPackage:
        if not events:
            raise ValueError("a Context Package requires source Events")
        if any(event.group_id != group_id or event.sequence is None for event in events):
            raise ValueError("Context Package Events must belong to one Group")
        ordered = tuple(sorted(events, key=lambda event: int(event.sequence or 0)))
        sequences = tuple(int(event.sequence or 0) for event in ordered)
        if sequences != tuple(range(sequences[0], sequences[-1] + 1)):
            raise ValueError("Context Package source Event range must be contiguous")
        created = (generated_at or datetime.now(UTC)).astimezone(UTC)
        unsigned: dict[str, Any] = {
            "contextPackageId": context_package_id or f"urn:uuid:{uuid4()}",
            "version": version,
            "missionId": _uri(mission_id, "mission"),
            "groupId": _uri(group_id, "group"),
            "sourceEventRange": {
                "fromSequence": sequences[0],
                "toSequence": sequences[-1],
                "eventIds": tuple(_uri(event.id, "event") for event in ordered),
            },
            "artifactHashes": artifact_hashes,
            "summary": summary,
            "decisions": decisions,
            "constraints": constraints,
            "unresolvedQuestions": unresolved_questions,
            "generatedBy": self._agent,
            "generatedAt": created,
        }
        if work_item_id is not None:
            unsigned["workItemId"] = _uri(work_item_id, "work")
        if previous_context_package_id is not None:
            unsigned["previousContextPackageId"] = _uri(previous_context_package_id, "context")
        placeholder = ContextPackage.model_validate(
            {
                **unsigned,
                "signature": SignatureEnvelope(
                    key_id=self._key_id,
                    created_at=created,
                    value="AA",
                ),
            }
        )
        package = placeholder.model_copy(
            update={
                "signature": placeholder.signature.model_copy(
                    update={
                        "value": sign_canonical(placeholder.signing_payload(), self._private_key)
                    }
                )
            }
        )
        self.verify(package)
        return package

    def verify(self, package: ContextPackage) -> None:
        document = package.model_dump(mode="json", by_alias=True, exclude_none=True)
        self._schemas.validate("context-package.schema.json", document)
        if package.generated_by != self._agent:
            raise ValueError("Context Package generator does not match its signing service")
        if not verify_canonical(
            package.signing_payload(), package.signature.value, self._public_key
        ):
            raise ValueError("Context Package signature is invalid")

    def install(
        self,
        package: ContextPackage,
        session: AgentRuntimeSession,
        *,
        expected_mission_id: str,
    ) -> None:
        self.verify(package)
        if package.mission_id != _uri(expected_mission_id, "mission"):
            raise ValueError("Context Package belongs to a different Mission")
        session.install_group_context(
            package.group_id,
            {
                "missionId": package.mission_id,
                "workItemId": package.work_item_id,
                "summary": package.summary,
                "decisions": tuple(
                    decision.model_dump(mode="json", by_alias=True)
                    for decision in package.decisions
                ),
                "constraints": package.constraints,
                "unresolvedQuestions": package.unresolved_questions,
                "artifactHashes": package.artifact_hashes,
                "sourceEventRange": package.source_event_range.model_dump(
                    mode="json", by_alias=True
                ),
                "contextPackageHash": canonical_hash(
                    package.model_dump(mode="json", by_alias=True)
                ),
            },
            revision=package.version,
        )


class KnowledgePublication(ProtocolModel):
    publication_id: str
    source_context_package_id: str
    source_group_id: str
    target_scope: str
    artifact_hash: Sha256
    classification: Classification
    summary: str
    provenance_event_ids: tuple[str, ...]
    published_by: Principal
    published_at: AwareDatetime
    signature: SignatureEnvelope

    def signing_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="python", by_alias=True, exclude={"signature"})


class KnowledgePublisher:
    """Turn Group-scoped output into an explicit classified reusable publication."""

    def __init__(
        self,
        *,
        publisher: Principal,
        key_id: str,
        private_key: PrivateKeyLike,
        public_key: PublicKeyLike,
    ) -> None:
        self._publisher = publisher
        self._key_id = key_id
        self._private_key = private_key
        self._public_key = public_key

    def publish(
        self,
        *,
        context: ContextPackage,
        artifact_hash: str,
        target_scope: str,
        classification: Classification,
        summary: str,
        published_at: datetime | None = None,
    ) -> KnowledgePublication:
        created = (published_at or datetime.now(UTC)).astimezone(UTC)
        unsigned: dict[str, Any] = {
            "publicationId": f"urn:uuid:{uuid4()}",
            "sourceContextPackageId": context.context_package_id,
            "sourceGroupId": context.group_id,
            "targetScope": _uri(target_scope, "scope"),
            "artifactHash": artifact_hash,
            "classification": classification,
            "summary": summary,
            "provenanceEventIds": context.source_event_range.event_ids,
            "publishedBy": self._publisher,
            "publishedAt": created,
        }
        placeholder = KnowledgePublication.model_validate(
            {
                **unsigned,
                "signature": SignatureEnvelope(
                    key_id=self._key_id,
                    created_at=created,
                    value="AA",
                ),
            }
        )
        publication = placeholder.model_copy(
            update={
                "signature": placeholder.signature.model_copy(
                    update={
                        "value": sign_canonical(placeholder.signing_payload(), self._private_key)
                    }
                )
            }
        )
        self.verify(publication)
        return publication

    def verify(self, publication: KnowledgePublication) -> None:
        if publication.published_by != self._publisher:
            raise ValueError("knowledge publisher does not match its signature")
        if not publication.provenance_event_ids:
            raise ValueError("reusable knowledge requires Event provenance")
        if not verify_canonical(
            publication.signing_payload(),
            publication.signature.value,
            self._public_key,
        ):
            raise ValueError("knowledge publication signature is invalid")


class SnapshotArchive:
    """Create and retain immutable signed Group snapshots with policy-log provenance."""

    def __init__(
        self,
        *,
        authority: Principal,
        key_id: str,
        private_key: PrivateKeyLike,
        public_key: PublicKeyLike,
    ) -> None:
        if authority.type is not ActorType.SYSTEM:
            raise ValueError("Group snapshots must be signed by a service authority")
        self._authority = authority
        self._key_id = key_id
        self._private_key = private_key
        self._public_key = public_key
        self._snapshots: dict[str, GroupSnapshot] = {}
        self._schemas = SchemaCatalog()

    def archive(
        self,
        *,
        group_id: str,
        events: tuple[Event, ...],
        state: object,
        policy_log: tuple[PolicyLogEntry, ...],
        created_at: datetime | None = None,
    ) -> GroupSnapshot:
        if not events or any(event.group_id != group_id for event in events):
            raise ValueError("a snapshot requires Events from exactly one Group")
        ordered = tuple(sorted(events, key=lambda event: int(event.sequence or 0)))
        sequences = tuple(int(event.sequence or 0) for event in ordered)
        if sequences != tuple(range(1, sequences[-1] + 1)):
            raise ValueError("a Group snapshot must cover a contiguous history from sequence 1")
        created = (created_at or datetime.now(UTC)).astimezone(UTC)
        unsigned: dict[str, Any] = {
            "snapshotId": f"urn:uuid:{uuid4()}",
            "groupId": GroupSnapshot.protocol_group_id(group_id),
            "throughSequence": sequences[-1],
            "eventIds": tuple(GroupSnapshot.protocol_event_id(event.id) for event in ordered),
            "stateHash": canonical_hash(state),
            "policyLog": policy_log,
            "createdBy": self._authority,
            "createdAt": created,
        }
        placeholder = GroupSnapshot.model_validate(
            {
                **unsigned,
                "signature": SignatureEnvelope(
                    key_id=self._key_id,
                    created_at=created,
                    value="AA",
                ),
            }
        )
        snapshot = placeholder.model_copy(
            update={
                "signature": placeholder.signature.model_copy(
                    update={
                        "value": sign_canonical(placeholder.signing_payload(), self._private_key)
                    }
                )
            }
        )
        self.verify(snapshot)
        self._snapshots[snapshot.snapshot_id] = snapshot
        return snapshot

    def get(self, snapshot_id: str) -> GroupSnapshot:
        try:
            return self._snapshots[snapshot_id]
        except KeyError as error:
            raise KeyError("unknown Group snapshot") from error

    def verify(self, snapshot: GroupSnapshot) -> None:
        if snapshot.created_by != self._authority:
            raise ValueError("snapshot authority does not match its signature")
        if snapshot.signature.key_id != self._key_id:
            raise ValueError("snapshot signature key ID does not match its authority")
        self._schemas.validate("group-snapshot.schema.json", snapshot.protocol_document())
        if not verify_canonical(
            snapshot.signing_payload(), snapshot.signature.value, self._public_key
        ):
            raise ValueError("Group snapshot signature is invalid")


__all__ = [
    "ContextDecision",
    "ContextPackage",
    "ContextPackageService",
    "GroupSnapshot",
    "KnowledgePublication",
    "KnowledgePublisher",
    "PolicyLogEntry",
    "SignatureEnvelope",
    "SnapshotArchive",
    "SourceEventRange",
]
