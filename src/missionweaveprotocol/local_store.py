"""SQLite Adapter for rebuildable Agent-local MissionWeaveProtocol state."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from missionweaveprotocol.scheduler import (
    CheckpointRef,
    EstimateBand,
    QueueRecord,
    SchedulerSnapshot,
    SchedulingEstimate,
    WorkOffer,
    WorkState,
)


class LocalStoreError(ValueError):
    """Raised when local idempotency or stored state is inconsistent."""


def _checkpoint_scope(
    agent_id: str,
    group_id: str,
    work_id: str,
    checkpoint_id: str,
) -> tuple[str, str, str, str]:
    scope = (agent_id, group_id, work_id, checkpoint_id)
    if any(not value.strip() for value in scope):
        raise ValueError("checkpoint scope identifiers must be nonempty")
    return scope


class SQLiteAgentStore:
    """Durable local Adapter for queues, Cursors, checkpoints, inbox, and outbox state."""

    def __init__(self, path: Path) -> None:
        self._connection = sqlite3.connect(path)
        self._connection.row_factory = sqlite3.Row
        self._connection.executescript(
            """
            PRAGMA journal_mode = WAL;
            CREATE TABLE IF NOT EXISTS cursors (
                agent_id TEXT NOT NULL,
                group_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                PRIMARY KEY (agent_id, group_id)
            );
            CREATE TABLE IF NOT EXISTS inbox (
                agent_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                group_id TEXT,
                sequence INTEGER,
                PRIMARY KEY (agent_id, event_id)
            );
            CREATE TABLE IF NOT EXISTS outbox (
                agent_id TEXT NOT NULL,
                action_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                sent INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (agent_id, action_id)
            );
            CREATE TABLE IF NOT EXISTS scheduler_snapshots (
                agent_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS group_contexts (
                agent_id TEXT NOT NULL,
                group_id TEXT NOT NULL,
                revision INTEGER NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (agent_id, group_id)
            );
            CREATE TABLE IF NOT EXISTS checkpoint_contents (
                agent_id TEXT NOT NULL,
                group_id TEXT NOT NULL,
                work_id TEXT NOT NULL,
                checkpoint_id TEXT NOT NULL,
                payload TEXT NOT NULL,
                PRIMARY KEY (agent_id, group_id, work_id, checkpoint_id)
            );
            """
        )
        inbox_columns = {
            str(row["name"])
            for row in self._connection.execute("PRAGMA table_info(inbox)").fetchall()
        }
        if "group_id" not in inbox_columns:
            self._connection.execute("ALTER TABLE inbox ADD COLUMN group_id TEXT")
        if "sequence" not in inbox_columns:
            self._connection.execute("ALTER TABLE inbox ADD COLUMN sequence INTEGER")
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()

    def acknowledge(self, agent_id: str, group_id: str, sequence: int) -> None:
        if sequence < 0:
            raise ValueError("Cursor sequence must not be negative")
        self._connection.execute(
            """
            INSERT INTO cursors(agent_id, group_id, sequence) VALUES (?, ?, ?)
            ON CONFLICT(agent_id, group_id) DO UPDATE SET sequence = excluded.sequence
            WHERE excluded.sequence > cursors.sequence
            """,
            (agent_id, group_id, sequence),
        )
        self._connection.commit()

    def cursor(self, agent_id: str, group_id: str) -> int:
        row = self._connection.execute(
            "SELECT sequence FROM cursors WHERE agent_id = ? AND group_id = ?",
            (agent_id, group_id),
        ).fetchone()
        return int(row["sequence"]) if row is not None else 0

    def remember_event(
        self,
        agent_id: str,
        event_id: str,
        *,
        group_id: str | None = None,
        sequence: int | None = None,
    ) -> bool:
        if (group_id is None) != (sequence is None):
            raise ValueError("Event Group and sequence must be supplied together")
        if group_id is not None and not group_id.strip():
            raise ValueError("Event Group must not be empty")
        if sequence is not None and sequence < 1:
            raise ValueError("Event sequence must be positive")
        existing = self._connection.execute(
            "SELECT group_id, sequence FROM inbox WHERE agent_id = ? AND event_id = ?",
            (agent_id, event_id),
        ).fetchone()
        if existing is not None:
            if group_id is not None and sequence is not None:
                stored_group = existing["group_id"]
                stored_sequence = existing["sequence"]
                if stored_group is None or stored_sequence is None:
                    self._connection.execute(
                        """
                        UPDATE inbox SET group_id = ?, sequence = ?
                        WHERE agent_id = ? AND event_id = ?
                        """,
                        (group_id, sequence, agent_id, event_id),
                    )
                elif stored_group != group_id or int(stored_sequence) != sequence:
                    raise LocalStoreError("Event ID collision in Agent inbox")
            self._connection.commit()
            return False
        self._connection.execute(
            """
            INSERT INTO inbox(agent_id, event_id, group_id, sequence)
            VALUES (?, ?, ?, ?)
            """,
            (agent_id, event_id, group_id, sequence),
        )
        self._connection.commit()
        return True

    def has_event(self, agent_id: str, event_id: str) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM inbox WHERE agent_id = ? AND event_id = ?",
            (agent_id, event_id),
        ).fetchone()
        return row is not None

    def event_position(self, agent_id: str, event_id: str) -> tuple[str, int] | None:
        row = self._connection.execute(
            """
            SELECT group_id, sequence FROM inbox
            WHERE agent_id = ? AND event_id = ?
            """,
            (agent_id, event_id),
        ).fetchone()
        if row is None or row["group_id"] is None or row["sequence"] is None:
            return None
        return str(row["group_id"]), int(row["sequence"])

    def enqueue_action(self, agent_id: str, action_id: str, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        existing = self._connection.execute(
            "SELECT payload FROM outbox WHERE agent_id = ? AND action_id = ?",
            (agent_id, action_id),
        ).fetchone()
        if existing is not None:
            if str(existing["payload"]) != encoded:
                raise LocalStoreError("action ID collision in Agent outbox")
            return
        self._connection.execute(
            "INSERT INTO outbox(agent_id, action_id, payload) VALUES (?, ?, ?)",
            (agent_id, action_id, encoded),
        )
        self._connection.commit()

    def pending_actions(self, agent_id: str) -> list[dict[str, Any]]:
        rows = self._connection.execute(
            "SELECT payload FROM outbox WHERE agent_id = ? AND sent = 0 ORDER BY rowid",
            (agent_id,),
        ).fetchall()
        return [json.loads(str(row["payload"])) for row in rows]

    def mark_action_sent(self, agent_id: str, action_id: str) -> None:
        self._connection.execute(
            "UPDATE outbox SET sent = 1 WHERE agent_id = ? AND action_id = ?",
            (agent_id, action_id),
        )
        self._connection.commit()

    def save_group_context(
        self,
        agent_id: str,
        group_id: str,
        revision: int,
        values: dict[str, Any],
    ) -> None:
        encoded = json.dumps(values, sort_keys=True, separators=(",", ":"))
        current = self._connection.execute(
            "SELECT revision FROM group_contexts WHERE agent_id = ? AND group_id = ?",
            (agent_id, group_id),
        ).fetchone()
        if current is not None and int(current["revision"]) > revision:
            raise LocalStoreError("cannot replace Group context with an older revision")
        self._connection.execute(
            """
            INSERT INTO group_contexts(agent_id, group_id, revision, payload)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(agent_id, group_id) DO UPDATE SET
                revision = excluded.revision,
                payload = excluded.payload
            """,
            (agent_id, group_id, revision, encoded),
        )
        self._connection.commit()

    def group_context(self, agent_id: str, group_id: str) -> tuple[int, dict[str, Any]] | None:
        row = self._connection.execute(
            "SELECT revision, payload FROM group_contexts WHERE agent_id = ? AND group_id = ?",
            (agent_id, group_id),
        ).fetchone()
        if row is None:
            return None
        return int(row["revision"]), json.loads(str(row["payload"]))

    def save_checkpoint(
        self,
        agent_id: str,
        group_id: str,
        work_id: str,
        checkpoint_id: str,
        content: dict[str, Any],
    ) -> None:
        """Store immutable content at one Agent/Group/WorkItem/Checkpoint scope.

        Repeating the same canonical content is idempotent. Reusing the exact scope for different
        content raises :class:`LocalStoreError`.
        """

        payload = json.dumps(content, sort_keys=True, separators=(",", ":"))
        scope = _checkpoint_scope(agent_id, group_id, work_id, checkpoint_id)
        try:
            cursor = self._connection.execute(
                """
                INSERT OR IGNORE INTO checkpoint_contents(
                    agent_id, group_id, work_id, checkpoint_id, payload
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (*scope, payload),
            )
            if cursor.rowcount == 0:
                existing = self._connection.execute(
                    """
                    SELECT payload FROM checkpoint_contents
                    WHERE agent_id = ? AND group_id = ? AND work_id = ? AND checkpoint_id = ?
                    """,
                    scope,
                ).fetchone()
                if existing is None or str(existing["payload"]) != payload:
                    raise LocalStoreError("checkpoint content collision in Agent-local store")
            self._connection.commit()
        except BaseException:
            self._connection.rollback()
            raise

    def load_checkpoint(
        self,
        agent_id: str,
        group_id: str,
        work_id: str,
        checkpoint_id: str,
    ) -> dict[str, Any] | None:
        """Load checkpoint content only when every scope identifier matches."""

        scope = _checkpoint_scope(agent_id, group_id, work_id, checkpoint_id)
        row = self._connection.execute(
            """
            SELECT payload FROM checkpoint_contents
            WHERE agent_id = ? AND group_id = ? AND work_id = ? AND checkpoint_id = ?
            """,
            scope,
        ).fetchone()
        return None if row is None else json.loads(str(row["payload"]))

    def delete_checkpoint(
        self,
        agent_id: str,
        group_id: str,
        work_id: str,
        checkpoint_id: str,
    ) -> bool:
        """Delete exactly one scoped checkpoint, returning whether it existed."""

        scope = _checkpoint_scope(agent_id, group_id, work_id, checkpoint_id)
        cursor = self._connection.execute(
            """
            DELETE FROM checkpoint_contents
            WHERE agent_id = ? AND group_id = ? AND work_id = ? AND checkpoint_id = ?
            """,
            scope,
        )
        self._connection.commit()
        return cursor.rowcount == 1

    def save_scheduler(self, agent_id: str, snapshot: SchedulerSnapshot) -> None:
        payload = json.dumps(_snapshot_to_json(snapshot), sort_keys=True, separators=(",", ":"))
        self._connection.execute(
            """
            INSERT INTO scheduler_snapshots(agent_id, payload) VALUES (?, ?)
            ON CONFLICT(agent_id) DO UPDATE SET payload = excluded.payload
            """,
            (agent_id, payload),
        )
        self._connection.commit()

    def load_scheduler(self, agent_id: str) -> SchedulerSnapshot | None:
        row = self._connection.execute(
            "SELECT payload FROM scheduler_snapshots WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        return None if row is None else _snapshot_from_json(json.loads(str(row["payload"])))


def _datetime(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value is not None else None


def _checkpoint_to_json(value: CheckpointRef | None) -> dict[str, Any] | None:
    if value is None:
        return None
    result = asdict(value)
    result["created_at"] = value.created_at.isoformat()
    return result


def _checkpoint_from_json(value: dict[str, Any] | None) -> CheckpointRef | None:
    if value is None:
        return None
    return CheckpointRef(
        checkpoint_id=str(value["checkpoint_id"]),
        work_id=str(value["work_id"]),
        group_id=str(value["group_id"]),
        run_id=str(value["run_id"]),
        created_at=datetime.fromisoformat(str(value["created_at"])),
        durable=bool(value["durable"]),
        safe=bool(value["safe"]),
    )


def _snapshot_to_json(snapshot: SchedulerSnapshot) -> dict[str, Any]:
    records: list[dict[str, Any]] = []
    for record in snapshot.records:
        records.append(
            {
                "offer": {
                    "work_id": record.offer.work_id,
                    "group_id": record.offer.group_id,
                    "organizational_priority": record.offer.organizational_priority,
                    "deadline": (
                        record.offer.deadline.isoformat()
                        if record.offer.deadline is not None
                        else None
                    ),
                    "estimate": {
                        "effort": int(record.offer.estimate.effort),
                        "slots": record.offer.estimate.slots,
                    },
                    "capability": record.offer.capability,
                    "preemptible": record.offer.preemptible,
                },
                "state": record.state.value,
                "sequence": record.sequence,
                "admitted_at": record.admitted_at.isoformat(),
                "ready_since": (
                    record.ready_since.isoformat() if record.ready_since is not None else None
                ),
                "accumulated_ready_seconds": record.accumulated_ready_seconds,
                "generation": record.generation,
                "run_id": record.run_id,
                "checkpoint": _checkpoint_to_json(record.checkpoint),
                "retry_at": record.retry_at.isoformat() if record.retry_at is not None else None,
                "blocked_reason": record.blocked_reason,
            }
        )
    return {
        "version": snapshot.version,
        "records": records,
        "fair_credit": list(snapshot.fair_credit),
        "next_sequence": snapshot.next_sequence,
    }


def _snapshot_from_json(value: dict[str, Any]) -> SchedulerSnapshot:
    records: list[QueueRecord] = []
    for raw in value["records"]:
        offer = raw["offer"]
        estimate = offer["estimate"]
        records.append(
            QueueRecord(
                offer=WorkOffer(
                    work_id=str(offer["work_id"]),
                    group_id=str(offer["group_id"]),
                    organizational_priority=int(offer["organizational_priority"]),
                    deadline=_datetime(offer["deadline"]),
                    estimate=SchedulingEstimate(
                        effort=EstimateBand(int(estimate["effort"])),
                        slots=int(estimate["slots"]),
                    ),
                    capability=offer["capability"],
                    preemptible=bool(offer["preemptible"]),
                ),
                state=WorkState(str(raw["state"])),
                sequence=int(raw["sequence"]),
                admitted_at=datetime.fromisoformat(str(raw["admitted_at"])),
                ready_since=_datetime(raw["ready_since"]),
                accumulated_ready_seconds=float(raw["accumulated_ready_seconds"]),
                generation=int(raw["generation"]),
                run_id=raw["run_id"],
                checkpoint=_checkpoint_from_json(raw["checkpoint"]),
                retry_at=_datetime(raw["retry_at"]),
                blocked_reason=raw["blocked_reason"],
            )
        )
    return SchedulerSnapshot(
        version=int(value["version"]),
        records=tuple(records),
        fair_credit=tuple((str(group), float(credit)) for group, credit in value["fair_credit"]),
        next_sequence=int(value["next_sequence"]),
    )
