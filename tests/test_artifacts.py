from __future__ import annotations

from datetime import UTC, datetime

import pytest

from missionweave.artifacts import ArtifactError, LocalArtifactStore
from missionweave.auth import AgentIdentity


def test_artifact_is_content_addressed_signed_and_provenance_linked(tmp_path) -> None:
    identity = AgentIdentity.generate("agent://acme/coder")
    store = LocalArtifactStore(tmp_path)

    source = store.put(
        b"requirements",
        identity=identity,
        agent_card_version="1.2.0",
        capability="org.acme.software.analysis",
        capability_version="1.0",
        mission_id="mission-auth",
        group_id="group-auth",
        work_item_id="work-requirements",
        media_type="text/plain",
        classification="internal",
        created_at=datetime(2026, 7, 15, tzinfo=UTC),
    )
    result = store.put(
        b"implementation",
        identity=identity,
        agent_card_version="1.2.0",
        capability="org.acme.software.implementation",
        capability_version="2.0",
        mission_id="mission-auth",
        group_id="group-auth",
        work_item_id="work-code",
        media_type="text/plain",
        classification="internal",
        source_artifact_hashes=(source.content_hash,),
        tool_versions={"python": "3.12.13"},
        model_versions={"planner": "test-model"},
        created_at=datetime(2026, 7, 15, tzinfo=UTC),
    )

    result.verify(identity.public_key)
    assert store.get(result) == b"implementation"
    assert result.source_artifact_hashes == (source.content_hash,)


def test_tampered_manifest_signature_is_rejected(tmp_path) -> None:
    identity = AgentIdentity.generate("agent://acme/coder")
    store = LocalArtifactStore(tmp_path)
    manifest = store.put(
        b"output",
        identity=identity,
        agent_card_version="1.0.0",
        capability="org.acme.software.implementation",
        capability_version="1.0",
        mission_id="mission",
        group_id="group",
        work_item_id="work",
        media_type="text/plain",
        classification="internal",
    )
    tampered = manifest.model_copy(update={"work_item_id": "other-work"})

    with pytest.raises(ArtifactError, match="signature"):
        tampered.verify(identity.public_key)
