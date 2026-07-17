"""One active Worker runtime session and Group-isolated execution context."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from dataclasses import dataclass
from threading import RLock
from types import MappingProxyType
from typing import Any
from uuid import uuid4

from missionweaveprotocol.scheduler import Dispatch, Scheduler


class ActiveSessionError(RuntimeError):
    """Raised when a stable Agent identity already has an active local runtime."""


class StaleSessionEpochError(RuntimeError):
    """Raised when a replacement runtime does not advance the Session Epoch."""


class ClosedSessionError(RuntimeError):
    """Raised when work is attempted through a fenced local session."""


class StaleContextError(RuntimeError):
    """Raised when an older Context Package attempts to replace a newer revision."""


def _freeze(value: Any) -> Any:
    """Copy and recursively freeze Group context before retaining or returning it."""

    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze(item) for key, item in value.items()})
    if isinstance(value, list | tuple):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, set | frozenset):
        return frozenset(_freeze(item) for item in value)
    return deepcopy(value)


@dataclass(frozen=True, slots=True)
class SessionDescriptor:
    agent_id: str
    session_id: str
    session_epoch: int


@dataclass(frozen=True, slots=True)
class ExecutionContext:
    """Only the context belonging to the Dispatch's Group."""

    agent_id: str
    session_id: str
    session_epoch: int
    work_id: str
    group_id: str
    context_revision: int | None
    values: Mapping[str, Any]
    credential_revision: int | None
    credentials: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _GroupContext:
    revision: int
    values: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class _GroupCredentials:
    revision: int
    values: Mapping[str, Any]


class AgentRuntimeSession:
    """The single active runtime session for one stable Agent identity."""

    def __init__(
        self,
        owner: AgentRuntime,
        descriptor: SessionDescriptor,
    ) -> None:
        self._owner = owner
        self._descriptor = descriptor
        self._contexts: dict[str, _GroupContext] = {}
        self._credentials: dict[str, _GroupCredentials] = {}
        self._closed = False

    @property
    def descriptor(self) -> SessionDescriptor:
        return self._descriptor

    @property
    def scheduler(self) -> Scheduler:
        self._ensure_active()
        return self._owner.scheduler

    def install_group_context(
        self,
        group_id: str,
        values: Mapping[str, Any],
        *,
        revision: int,
    ) -> None:
        """Replace one Group's context without exposing or touching another Group."""

        self._ensure_active()
        if not group_id:
            raise ValueError("group_id must not be empty")
        if revision < 0:
            raise ValueError("context revision must not be negative")
        current = self._contexts.get(group_id)
        if current is not None and revision < current.revision:
            raise StaleContextError(
                f"Group {group_id} context revision {revision} is older than {current.revision}"
            )
        frozen = _freeze(values)
        if not isinstance(frozen, Mapping):  # Mapping input guarantees this; narrows typing.
            raise TypeError("Group context must be a mapping")
        self._contexts[group_id] = _GroupContext(revision=revision, values=frozen)

    def install_group_credentials(
        self,
        group_id: str,
        credentials: Mapping[str, Any],
        *,
        revision: int,
    ) -> None:
        """Install ephemeral credentials visible only to one Group's execution slots."""

        self._ensure_active()
        if not group_id:
            raise ValueError("group_id must not be empty")
        if revision < 0:
            raise ValueError("credential revision must not be negative")
        current = self._credentials.get(group_id)
        if current is not None and revision < current.revision:
            raise StaleContextError(
                f"Group {group_id} credential revision {revision} is older than {current.revision}"
            )
        frozen = _freeze(credentials)
        if not isinstance(frozen, Mapping):
            raise TypeError("Group credentials must be a mapping")
        self._credentials[group_id] = _GroupCredentials(revision=revision, values=frozen)

    def prepare(self, dispatch: Dispatch) -> ExecutionContext:
        """Prepare a Dispatch with exactly one Group's local context."""

        self._ensure_active()
        stored = self._contexts.get(dispatch.group_id)
        if stored is None:
            revision: int | None = None
            values: Mapping[str, Any] = MappingProxyType({})
        else:
            revision = stored.revision
            copied = _freeze(stored.values)
            if not isinstance(copied, Mapping):  # pragma: no cover - defensive typing guard
                raise TypeError("stored Group context is not a mapping")
            values = copied
        stored_credentials = self._credentials.get(dispatch.group_id)
        if stored_credentials is None:
            credential_revision: int | None = None
            credentials: Mapping[str, Any] = MappingProxyType({})
        else:
            credential_revision = stored_credentials.revision
            copied_credentials = _freeze(stored_credentials.values)
            if not isinstance(copied_credentials, Mapping):  # pragma: no cover
                raise TypeError("stored Group credentials are not a mapping")
            credentials = copied_credentials
        return ExecutionContext(
            agent_id=self._descriptor.agent_id,
            session_id=self._descriptor.session_id,
            session_epoch=self._descriptor.session_epoch,
            work_id=dispatch.work_id,
            group_id=dispatch.group_id,
            context_revision=revision,
            values=values,
            credential_revision=credential_revision,
            credentials=credentials,
        )

    def close(self) -> None:
        """Fence the session and erase its Group context references."""

        if self._closed:
            return
        self._closed = True
        self._contexts.clear()
        self._credentials.clear()
        self._owner._close_session(self)

    def _ensure_active(self) -> None:
        if self._closed or self._owner._active is not self:
            raise ClosedSessionError(f"session {self._descriptor.session_id} is not active")

    def __enter__(self) -> AgentRuntimeSession:
        self._ensure_active()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


class AgentRuntime:
    """Stable Agent identity with one Scheduler and at most one active session."""

    def __init__(self, agent_id: str, scheduler: Scheduler) -> None:
        if not agent_id:
            raise ValueError("agent_id must not be empty")
        self.agent_id = agent_id
        self.scheduler = scheduler
        self._active: AgentRuntimeSession | None = None
        self._last_session_epoch = -1
        self._lock = RLock()

    @property
    def active_session(self) -> SessionDescriptor | None:
        with self._lock:
            return None if self._active is None else self._active.descriptor

    def start_session(
        self,
        session_epoch: int,
        *,
        session_id: str | None = None,
    ) -> AgentRuntimeSession:
        """Start the sole local runtime session, advancing its fencing epoch."""

        with self._lock:
            if self._active is not None:
                raise ActiveSessionError(
                    f"Agent {self.agent_id} already has active session "
                    f"{self._active.descriptor.session_id}"
                )
            if session_epoch <= self._last_session_epoch:
                raise StaleSessionEpochError(
                    f"Session Epoch {session_epoch} must exceed {self._last_session_epoch}"
                )
            descriptor = SessionDescriptor(
                agent_id=self.agent_id,
                session_id=session_id or str(uuid4()),
                session_epoch=session_epoch,
            )
            session = AgentRuntimeSession(self, descriptor)
            self._active = session
            self._last_session_epoch = session_epoch
            return session

    def _close_session(self, session: AgentRuntimeSession) -> None:
        with self._lock:
            if self._active is session:
                self._active = None


__all__ = [
    "ActiveSessionError",
    "AgentRuntime",
    "AgentRuntimeSession",
    "ClosedSessionError",
    "ExecutionContext",
    "SessionDescriptor",
    "StaleContextError",
    "StaleSessionEpochError",
]
