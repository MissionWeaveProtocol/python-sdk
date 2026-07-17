"""Authoritative Store seam and its in-memory, SQLite, and PostgreSQL adapters.

The core Module mutates one typed snapshot inside ``transact``.  Adapters are responsible for
atomic commit and isolation; callers never coordinate entity writes themselves.  The SQL adapter
uses optimistic revision fencing, which works across multiple application processes without
making database mechanics part of the core interface.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Any, Protocol, TypeVar

import aiosqlite
import asyncpg  # type: ignore[import-untyped]
from pydantic import Field

from .budget import BudgetLedgerSnapshot
from .canonical import canonical_json
from .lease import ExecutionLease
from .models import (
    AgentCard,
    Approval,
    Artifact,
    Command,
    Conversation,
    CooperationOverrideGrant,
    DelegationGrant,
    Event,
    ExecutionApproval,
    Group,
    GroupSnapshot,
    Membership,
    Message,
    MessageAmendment,
    Mission,
    PolicyLogEntry,
    ProtocolModel,
    WorkItem,
    WorkProposal,
)


class DedupRecord(ProtocolModel):
    command_hash: str
    event: Event


class AuthoritativeState(ProtocolModel):
    accepted_commands: dict[str, Command] = Field(default_factory=dict)
    agent_cards: dict[str, AgentCard] = Field(default_factory=dict)
    sessions: dict[str, int] = Field(default_factory=dict)
    missions: dict[str, Mission] = Field(default_factory=dict)
    groups: dict[str, Group] = Field(default_factory=dict)
    group_snapshots: dict[str, GroupSnapshot] = Field(default_factory=dict)
    memberships: dict[str, Membership] = Field(default_factory=dict)
    conversations: dict[str, Conversation] = Field(default_factory=dict)
    messages: dict[str, Message] = Field(default_factory=dict)
    message_amendments: dict[str, MessageAmendment] = Field(default_factory=dict)
    work_proposals: dict[str, WorkProposal] = Field(default_factory=dict)
    work_items: dict[str, WorkItem] = Field(default_factory=dict)
    artifacts: dict[str, Artifact] = Field(default_factory=dict)
    approvals: dict[str, Approval] = Field(default_factory=dict)
    execution_approvals: dict[str, ExecutionApproval] = Field(default_factory=dict)
    cooperation_override_grants: dict[str, CooperationOverrideGrant] = Field(default_factory=dict)
    delegation_grants: dict[str, DelegationGrant] = Field(default_factory=dict)
    execution_leases: dict[str, ExecutionLease] = Field(default_factory=dict)
    budget_ledger: BudgetLedgerSnapshot = Field(default_factory=BudgetLedgerSnapshot)
    events: dict[str, list[Event]] = Field(default_factory=dict)
    policy_log: dict[str, list[PolicyLogEntry]] = Field(default_factory=dict)
    group_sequences: dict[str, int] = Field(default_factory=dict)
    deduplication: dict[str, DedupRecord] = Field(default_factory=dict)


T = TypeVar("T")
StateOperation = Callable[[AuthoritativeState], T]


class AuthoritativeStore(Protocol):
    """The persistence seam required by the authoritative core Module."""

    async def transact(self, operation: StateOperation[T]) -> T:
        """Run ``operation`` against an isolated state and atomically commit on success."""

    async def inspect(self, operation: StateOperation[T]) -> T:
        """Run a read-only operation against a consistent state snapshot."""

    async def close(self) -> None:
        """Release adapter resources."""


class InMemoryStore:
    """Deterministic Store adapter for tests and single-process demonstrations."""

    def __init__(self, state: AuthoritativeState | None = None) -> None:
        self._state = (state or AuthoritativeState()).model_copy(deep=True)
        self._lock = asyncio.Lock()

    async def transact(self, operation: StateOperation[T]) -> T:
        async with self._lock:
            candidate = self._state.model_copy(deep=True)
            result = operation(candidate)
            self._state = candidate
            return result

    async def inspect(self, operation: StateOperation[T]) -> T:
        async with self._lock:
            snapshot = self._state.model_copy(deep=True)
        return operation(snapshot)

    async def close(self) -> None:
        return None


class SQLStore:
    """Portable authoritative Store facade backed by SQLite or PostgreSQL.

    MissionWeaveProtocol 0.1 prioritizes correct transition serialization over storage layout. A
    single typed document keeps the seam small while an optimistic ``revision`` column fences
    concurrent writers. The representation can later be normalized without changing ``Core`` or
    callers.
    """

    def __init__(self, url: str, *, echo: bool = False) -> None:
        del echo  # Driver-level tracing is intentionally outside the Store interface.
        if url.startswith(("sqlite://", "sqlite+aiosqlite://")):
            self._backend: _SQLBackend = _SQLiteBackend(url)
        elif url.startswith(("postgres://", "postgresql://", "postgresql+asyncpg://")):
            self._backend = _PostgreSQLBackend(url)
        else:
            raise ValueError("SQLStore requires a SQLite or PostgreSQL URL")

    @property
    def dialect_name(self) -> str:
        return self._backend.dialect_name

    @property
    def url(self) -> str:
        return self._backend.safe_url

    async def initialize(self) -> None:
        await self._backend.initialize()

    async def transact(self, operation: StateOperation[T]) -> T:
        return await self._backend.transact(operation)

    async def inspect(self, operation: StateOperation[T]) -> T:
        return await self._backend.inspect(operation)

    async def close(self) -> None:
        await self._backend.close()


class _SQLBackend(Protocol):
    dialect_name: str
    safe_url: str

    async def initialize(self) -> None: ...

    async def transact(self, operation: StateOperation[T]) -> T: ...

    async def inspect(self, operation: StateOperation[T]) -> T: ...

    async def close(self) -> None: ...


class _SQLiteBackend:
    dialect_name = "sqlite"

    def __init__(self, url: str) -> None:
        normalized = url.replace("sqlite+aiosqlite://", "sqlite://", 1)
        if not normalized.startswith("sqlite:///"):
            raise ValueError("SQLite URL must contain a database path")
        path = normalized.removeprefix("sqlite:///")
        self._path = ":memory:" if path == ":memory:" else f"/{path.lstrip('/')}"
        self.safe_url = (
            "sqlite:///:memory:" if self._path == ":memory:" else f"sqlite://{self._path}"
        )
        self._connection: aiosqlite.Connection | None = None
        self._initialization_lock = asyncio.Lock()
        self._operation_lock = asyncio.Lock()

    async def initialize(self) -> None:
        if self._connection is not None:
            return
        async with self._initialization_lock:
            if self._connection is not None:
                return
            connection = await aiosqlite.connect(self._path)
            await connection.execute(
                """
                CREATE TABLE IF NOT EXISTS missionweaveprotocol_authoritative_state (
                    singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                    revision INTEGER NOT NULL,
                    document TEXT NOT NULL
                )
                """
            )
            await connection.execute(
                """
                INSERT OR IGNORE INTO missionweaveprotocol_authoritative_state(
                    singleton_id, revision, document
                )
                VALUES (1, 0, ?)
                """,
                (canonical_json(AuthoritativeState()),),
            )
            await connection.commit()
            self._connection = connection

    async def transact(self, operation: StateOperation[T]) -> T:
        await self.initialize()
        connection = cast_connection(self._connection)
        async with self._operation_lock:
            await connection.execute("BEGIN IMMEDIATE")
            try:
                cursor = await connection.execute(
                    "SELECT revision, document "
                    "FROM missionweaveprotocol_authoritative_state "
                    "WHERE singleton_id = 1"
                )
                row = await cursor.fetchone()
                await cursor.close()
                if row is None:
                    raise RuntimeError("authoritative state row is missing")
                revision, document = int(row[0]), str(row[1])
                state = AuthoritativeState.model_validate_json(document)
                result = operation(state)
                cursor = await connection.execute(
                    """
                    UPDATE missionweaveprotocol_authoritative_state
                    SET revision = ?, document = ?
                    WHERE singleton_id = 1 AND revision = ?
                    """,
                    (revision + 1, canonical_json(state), revision),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("authoritative SQLite revision fence failed")
                await cursor.close()
                await connection.commit()
                return result
            except BaseException:
                await connection.rollback()
                raise

    async def inspect(self, operation: StateOperation[T]) -> T:
        await self.initialize()
        connection = cast_connection(self._connection)
        async with self._operation_lock:
            cursor = await connection.execute(
                "SELECT document FROM missionweaveprotocol_authoritative_state "
                "WHERE singleton_id = 1"
            )
            row = await cursor.fetchone()
            await cursor.close()
        if row is None:
            raise RuntimeError("authoritative state row is missing")
        return operation(AuthoritativeState.model_validate_json(str(row[0])))

    async def close(self) -> None:
        if self._connection is not None:
            await self._connection.close()
            self._connection = None


class _PostgreSQLBackend:
    dialect_name = "postgresql"

    def __init__(self, url: str) -> None:
        normalized = url.replace("postgresql+asyncpg://", "postgresql://", 1)
        normalized = normalized.replace("postgres://", "postgresql://", 1)
        self._url = normalized
        self.safe_url = _hide_url_password(normalized)
        self._pool: asyncpg.Pool[Any] | None = None
        self._initialization_lock = asyncio.Lock()

    async def initialize(self) -> None:
        if self._pool is not None:
            return
        async with self._initialization_lock:
            if self._pool is not None:
                return
            pool = await asyncpg.create_pool(self._url, min_size=1, max_size=10)
            if pool is None:
                raise RuntimeError("asyncpg did not create a connection pool")
            async with pool.acquire() as connection:
                await connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS missionweaveprotocol_authoritative_state (
                        singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                        revision BIGINT NOT NULL,
                        document TEXT NOT NULL
                    )
                    """
                )
                await connection.execute(
                    """
                    INSERT INTO missionweaveprotocol_authoritative_state(
                        singleton_id, revision, document
                    )
                    VALUES (1, 0, $1)
                    ON CONFLICT (singleton_id) DO NOTHING
                    """,
                    canonical_json(AuthoritativeState()),
                )
            self._pool = pool

    async def transact(self, operation: StateOperation[T]) -> T:
        await self.initialize()
        pool = cast_pool(self._pool)
        async with pool.acquire() as connection, connection.transaction():
            row = await connection.fetchrow(
                """
                SELECT revision, document FROM missionweaveprotocol_authoritative_state
                WHERE singleton_id = 1 FOR UPDATE
                """
            )
            if row is None:
                raise RuntimeError("authoritative state row is missing")
            revision = int(row["revision"])
            state = AuthoritativeState.model_validate_json(str(row["document"]))
            result = operation(state)
            status = await connection.execute(
                """
                UPDATE missionweaveprotocol_authoritative_state
                SET revision = $1, document = $2
                WHERE singleton_id = 1 AND revision = $3
                """,
                revision + 1,
                canonical_json(state),
                revision,
            )
            if status != "UPDATE 1":
                raise RuntimeError("authoritative PostgreSQL revision fence failed")
            return result

    async def inspect(self, operation: StateOperation[T]) -> T:
        await self.initialize()
        pool = cast_pool(self._pool)
        async with pool.acquire() as connection:
            document = await connection.fetchval(
                "SELECT document FROM missionweaveprotocol_authoritative_state "
                "WHERE singleton_id = 1"
            )
        if document is None:
            raise RuntimeError("authoritative state row is missing")
        return operation(AuthoritativeState.model_validate_json(str(document)))

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None


def cast_connection(connection: aiosqlite.Connection | None) -> aiosqlite.Connection:
    if connection is None:
        raise RuntimeError("SQLite Store is not initialized")
    return connection


def cast_pool(pool: asyncpg.Pool[Any] | None) -> asyncpg.Pool[Any]:
    if pool is None:
        raise RuntimeError("PostgreSQL Store is not initialized")
    return pool


def _hide_url_password(url: str) -> str:
    scheme, separator, remainder = url.partition("://")
    if not separator or "@" not in remainder or ":" not in remainder.partition("@")[0]:
        return url
    credentials, at, host = remainder.partition("@")
    username, _, _password = credentials.partition(":")
    return f"{scheme}://{username}:***{at}{host}"


class SQLiteStore(SQLStore):
    """Local authoritative Store adapter using ``aiosqlite``."""

    def __init__(self, path: str | Path = ":memory:", *, echo: bool = False) -> None:
        rendered = str(path)
        if rendered.startswith("sqlite+"):
            url = rendered
        elif rendered == ":memory:":
            url = "sqlite+aiosqlite:///:memory:"
        else:
            url = f"sqlite+aiosqlite:///{Path(rendered).expanduser().absolute()}"
        super().__init__(url, echo=echo)


class PostgreSQLStore(SQLStore):
    """Production authoritative Store adapter using ``asyncpg``."""

    def __init__(self, url: str, *, echo: bool = False) -> None:
        if not url.startswith(("postgres://", "postgresql://", "postgresql+asyncpg://")):
            raise ValueError("PostgreSQLStore requires a PostgreSQL asyncpg URL")
        super().__init__(url, echo=echo)


def membership_key(group_id: str, principal_type: str, principal_id: str) -> str:
    return f"{group_id}\x1f{principal_type}\x1f{principal_id}"


def deduplication_key(principal_type: str, principal_id: str, action_id: str) -> str:
    return f"{principal_type}\x1f{principal_id}\x1f{action_id}"
