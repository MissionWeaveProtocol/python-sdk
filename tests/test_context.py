from datetime import UTC, datetime

import pytest

from missionweave.agent import AgentRuntime
from missionweave.context import (
    ContextDecision,
    ContextPackageService,
    KnowledgePublisher,
    PolicyLogEntry,
    SnapshotArchive,
)
from missionweave.crypto import generate_keypair
from missionweave.models import Event, EventKind, Principal
from missionweave.scheduler import Dispatch, Scheduler

NOW = datetime(2026, 7, 15, 8, 0, tzinfo=UTC)


def _events() -> tuple[Event, ...]:
    actor = Principal.agent("agent:coordinator")
    return tuple(
        Event(
            id=f"event:{sequence}",
            kind=EventKind.MESSAGE_POSTED,
            group_id="group:context",
            sequence=sequence,
            actor=actor,
            action_id=f"action:{sequence}",
            command_hash="sha256:" + f"{sequence:064x}",
            payload={"sequence": sequence},
            occurred_at=NOW,
        )
        for sequence in (1, 2)
    )


def test_signed_context_package_is_schema_valid_scoped_and_installable() -> None:
    private_key, public_key = generate_keypair()
    service = ContextPackageService(
        agent_id="agent:coordinator",
        key_id="key:coordinator",
        private_key=private_key,
        public_key=public_key,
    )
    package = service.publish(
        mission_id="mission:context",
        group_id="group:context",
        version=3,
        events=_events(),
        summary="Only the decisions needed by the late reviewer.",
        artifact_hashes=("sha256:" + "a" * 64,),
        decisions=(
            ContextDecision(
                description="Use canonical JSON.",
                source_event_ids=("event:1",),
            ),
        ),
        constraints=("Do not disclose another Mission.",),
        generated_at=NOW,
        context_package_id="context:reviewer-v3",
    )
    runtime = AgentRuntime("agent:reviewer", Scheduler(clock=lambda: NOW))
    session = runtime.start_session(1, session_id="session:reviewer")
    service.install(package, session, expected_mission_id="mission:context")
    execution = session.prepare(
        Dispatch(
            work_id="work:review",
            group_id="group:context",
            run_id="run:review",
            slots=1,
            capability="software.review",
        )
    )

    assert execution.context_revision == 3
    assert execution.values["summary"] == package.summary
    assert execution.values["artifactHashes"] == package.artifact_hashes
    assert "another Mission" in execution.values["constraints"][0]

    tampered = package.model_copy(update={"summary": "tampered"})
    with pytest.raises(ValueError, match="signature"):
        service.verify(tampered)
    with pytest.raises(ValueError, match="different Mission"):
        service.install(package, session, expected_mission_id="mission:other")


def test_reusable_knowledge_requires_classification_signature_and_event_provenance() -> None:
    private_key, public_key = generate_keypair()
    context_service = ContextPackageService(
        agent_id="agent:coordinator",
        key_id="key:coordinator",
        private_key=private_key,
        public_key=public_key,
    )
    package = context_service.publish(
        mission_id="mission:context",
        group_id="group:context",
        version=1,
        events=_events(),
        summary="Reusable canonicalization finding.",
        generated_at=NOW,
    )
    publisher = KnowledgePublisher(
        publisher=Principal.agent("agent:coordinator"),
        key_id="key:coordinator",
        private_key=private_key,
        public_key=public_key,
    )
    publication = publisher.publish(
        context=package,
        artifact_hash="sha256:" + "b" * 64,
        target_scope="knowledge:engineering",
        classification="internal",
        summary="Canonical JSON interoperability guidance.",
        published_at=NOW,
    )

    publisher.verify(publication)
    assert publication.classification == "internal"
    assert publication.provenance_event_ids == package.source_event_range.event_ids
    with pytest.raises(ValueError, match="provenance"):
        publisher.verify(publication.model_copy(update={"provenance_event_ids": ()}))


def test_group_archive_signs_contiguous_snapshot_and_policy_log() -> None:
    private_key, public_key = generate_keypair()
    archive = SnapshotArchive(
        authority=Principal.system("service:group-authority"),
        key_id="key:group-authority",
        private_key=private_key,
        public_key=public_key,
    )
    snapshot = archive.archive(
        group_id="group:context",
        events=_events(),
        state={"missionId": "mission:context", "status": "approved"},
        policy_log=(
            PolicyLogEntry(
                entry_id="policy:approval-check",
                decision="human approval signature verified",
                actor=Principal.system("service:authorization"),
                occurred_at=NOW,
            ),
        ),
        created_at=NOW,
    )

    archive.verify(snapshot)
    assert archive.get(snapshot.snapshot_id) == snapshot
    assert snapshot.through_sequence == 2
    assert snapshot.policy_log[0].entry_id == "policy:approval-check"
    with pytest.raises(ValueError, match="signature"):
        archive.verify(snapshot.model_copy(update={"through_sequence": 1}))
