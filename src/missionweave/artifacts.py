"""Immutable content-addressed Artifact storage with signed provenance."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ConfigDict, Field

from missionweave.auth import AgentIdentity
from missionweave.canonical import canonical_bytes


class ArtifactError(ValueError):
    """Raised when Artifact content or provenance is invalid."""


def _canonical(value: object) -> bytes:
    return canonical_bytes(value)


class ArtifactManifest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    content_hash: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    size: int = Field(ge=0)
    media_type: str
    producer_agent_id: str
    producer_agent_card_version: str
    capability: str
    capability_version: str
    mission_id: str
    group_id: str
    work_item_id: str
    source_artifact_hashes: tuple[str, ...] = ()
    tool_versions: dict[str, str] = Field(default_factory=dict)
    model_versions: dict[str, str] = Field(default_factory=dict)
    classification: Literal["public", "internal", "confidential", "restricted"]
    created_at: datetime
    signature: str = ""

    def signing_bytes(self) -> bytes:
        return _canonical(self.model_dump(mode="json", exclude={"signature"}))

    def signed_by(self, identity: AgentIdentity) -> ArtifactManifest:
        if identity.agent_id != self.producer_agent_id:
            raise ArtifactError("Artifact producer does not match signing Agent")
        return self.model_copy(update={"signature": identity.sign(self.signing_bytes())})

    def verify(self, public_key: str) -> None:
        try:
            raw_key = base64.urlsafe_b64decode(public_key + "=" * (-len(public_key) % 4))
            signature = base64.urlsafe_b64decode(self.signature + "=" * (-len(self.signature) % 4))
            Ed25519PublicKey.from_public_bytes(raw_key).verify(signature, self.signing_bytes())
        except (InvalidSignature, ValueError) as error:
            raise ArtifactError("invalid Artifact manifest signature") from error


class LocalArtifactStore:
    """Filesystem Adapter for immutable content-addressed Artifact bytes."""

    def __init__(self, root: Path) -> None:
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True)

    def put(
        self,
        content: bytes,
        *,
        identity: AgentIdentity,
        agent_card_version: str,
        capability: str,
        capability_version: str,
        mission_id: str,
        group_id: str,
        work_item_id: str,
        media_type: str,
        classification: Literal["public", "internal", "confidential", "restricted"],
        source_artifact_hashes: tuple[str, ...] = (),
        tool_versions: dict[str, str] | None = None,
        model_versions: dict[str, str] | None = None,
        created_at: datetime | None = None,
    ) -> ArtifactManifest:
        digest = hashlib.sha256(content).hexdigest()
        content_hash = f"sha256:{digest}"
        path = self._path(content_hash)
        if path.exists() and path.read_bytes() != content:
            raise ArtifactError("content hash collision")
        if not path.exists():
            temporary = path.with_suffix(".tmp")
            temporary.write_bytes(content)
            temporary.replace(path)

        return ArtifactManifest(
            content_hash=content_hash,
            size=len(content),
            media_type=media_type,
            producer_agent_id=identity.agent_id,
            producer_agent_card_version=agent_card_version,
            capability=capability,
            capability_version=capability_version,
            mission_id=mission_id,
            group_id=group_id,
            work_item_id=work_item_id,
            source_artifact_hashes=source_artifact_hashes,
            tool_versions=tool_versions or {},
            model_versions=model_versions or {},
            classification=classification,
            created_at=created_at or datetime.now(UTC),
        ).signed_by(identity)

    def get(self, manifest: ArtifactManifest) -> bytes:
        content = self._path(manifest.content_hash).read_bytes()
        actual = f"sha256:{hashlib.sha256(content).hexdigest()}"
        if actual != manifest.content_hash or len(content) != manifest.size:
            raise ArtifactError("stored Artifact bytes do not match manifest")
        return content

    def _path(self, content_hash: str) -> Path:
        algorithm, digest = content_hash.split(":", 1)
        if algorithm != "sha256" or len(digest) != 64:
            raise ArtifactError("unsupported content hash")
        directory = self._root / digest[:2]
        directory.mkdir(parents=True, exist_ok=True)
        return directory / digest[2:]
