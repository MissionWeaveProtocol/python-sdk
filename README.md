# MissionWeave Python SDK

<p align="center">
  <img src="https://raw.githubusercontent.com/MissionWeaveProject/missionweaveprotocol/main/assets/brand/missionweave-icon.svg" width="160" alt="MissionWeave icon">
</p>

<p align="center">
  <strong><a href="https://missionweaveproject.github.io/missionweaveprotocol.github.io/">Official website and documentation</a></strong>
</p>

The MissionWeave Python SDK is the official Python reference implementation of the
[MissionWeave Protocol](https://github.com/MissionWeaveProject/missionweaveprotocol). It includes
the authoritative Core, Agent runtime, Worker Scheduler, Group gateway, storage adapters,
conformance runner, and executable proof of concept.

The current wire protocol is **MissionWeave Protocol 0.1**. The Python distribution and import
package are both named `missionweave`; command-line entry points use the `missionweave-` prefix.

## Protocol compatibility

| Python SDK | MissionWeave Protocol |
| --- | --- |
| `0.1.x` | `0.1` |

The protocol repository is normative. [`PROTOCOL_PIN.json`](PROTOCOL_PIN.json) records the exact
protocol commit and SHA-256 digests for the local [`schemas/`](schemas/README.md) and
[`conformance/`](conformance/README.md) snapshots used for offline validation, tests, and wheel
packaging.

Protocol and Python releases are versioned independently.

## What v0.1 implements

- one temporary Group and monotonic Event history per Mission;
- a human root MissionOwner and replaceable, epoch-fenced Coordinator Agent;
- Organization-signed Agent Cards separated from ephemeral Presence Records;
- peer Conversation plus explicit Work Proposal, authorization, offer, acceptance, ownership,
  execution lease, checkpoint, Evidence, review, and Approval transitions;
- expiring, target-scoped Delegation Grants fenced by capability, budget, depth, Membership, and
  Coordinator epochs;
- recursive child Missions and linked follow-up Missions;
- per-Group Worker queues with a weighted-fair global Scheduler and isolated capacity slots;
- at-least-once Delivery, stable Action IDs, deduplication, Cursors, replay, and local recovery;
- signed Context Packages, classified reusable-knowledge publication, and signed Group archives;
- short-lived Membership and capability tokens fenced by session, Membership, ownership, lease,
  scope, Approval, and budget;
- authoritative six-dimensional Mission/WorkItem allocation and cumulative usage accounting;
- canonical RFC 8785 JSON and Ed25519 signatures over schema-valid WebSocket/TLS frames;
- PostgreSQL authoritative state, SQLite Agent-local projections, and content-addressed Artifacts.

## Install and verify

Python 3.12+, `uv`, and Docker are recommended.

```bash
uv sync --extra dev
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run missionweave-conformance --root .
```

The conformance command validates all 43 vendored vectors against the 21 vendored Draft 2020-12
schemas with format checking. It exits non-zero on a validity mismatch. It can also validate a
separate protocol checkout or release bundle:

```bash
uv run missionweave-conformance --root ../missionweaveprotocol
```

## Run the two-Mission POC

```bash
uv run missionweave-demo --workdir .missionweave/poc
```

The command emits one canonical JSON report and exits non-zero if any required behavior is
missing. Its report contains 50 named checks. The deterministic scenario runs two concurrent
software-development Missions with a shared reviewer, formal Worker-proposed sub-work, a child
security Mission, Worker-to-Worker clarification, two isolated execution slots, checkpoint-only
preemption, blocked/resumed work, Coordinator review, one human change request, and exact signed
final Approvals.

It also injects duplicate Delivery, Action-ID collision, Event-based queue reconstruction after a
Worker restart, previous-Coordinator fencing, stale Session/Membership/Ownership epochs, real
WebSocket disconnect/reconnect, lease expiry, offline reconciliation, signed late-member Context,
classified knowledge publication, and signed archival snapshots. See [poc/README.md](poc/README.md).

## Verify PostgreSQL authoritative persistence

```bash
docker compose up -d --wait postgres
MISSIONWEAVE_TEST_POSTGRES_URL=postgresql://missionweave:missionweave@127.0.0.1:55432/missionweave \
  uv run pytest tests/test_core.py -q
```

The integration test creates authoritative state, closes the first adapter, opens a second
PostgreSQL adapter, and verifies Mission state plus ordered replay.

## Run the WebSocket Group gateway

Create disposable local keys and an Organization-signed registry:

```bash
uv run python examples/create_dev_registry.py
export MISSIONWEAVE_ORGANIZATION_PUBLIC_KEY="$(uv run python -c \
  'import json; print(json.load(open(".missionweave/dev-keys.json"))["organizationPublicKey"])')"
export MISSIONWEAVE_AUTHORITY_PRIVATE_KEY="$(uv run python -c \
  'import json; print(json.load(open(".missionweave/dev-keys.json"))["authorityPrivateKey"])')"
export MISSIONWEAVE_SESSION_SECRET='development-only-session-secret-32-bytes'

uv run missionweave-server \
  --registry .missionweave/dev-registry.json \
  --database-url postgresql://missionweave:missionweave@127.0.0.1:55432/missionweave \
  --organization-public-key "$MISSIONWEAVE_ORGANIZATION_PUBLIC_KEY" \
  --allow-insecure
```

`--allow-insecure` is only for loopback development. A deployment must omit it and provide
`--tls-certfile` plus `--tls-keyfile`; MissionWeave 0.1 requires `wss` over TLS 1.3. One authenticated
connection multiplexes many Group subscriptions. The gateway schema-validates frames, rejects
duplicate JSON members, verifies Agent Command signatures and Session/Membership epochs, enforces
Membership visibility and attention filters, signs Events, and replays after acknowledged Cursors.

## Human control interface

`HumanControl` exposes signed create, inspect, direct, request-changes, approve, cancel,
Coordinator-replacement, and high-risk Execution-Approval operations without exposing storage or
transport details.

```python
import asyncio
from datetime import UTC, datetime, timedelta

from missionweave.control import HumanControl, HumanIdentity
from missionweave.core import Core
from missionweave.store import PostgreSQLStore


async def main() -> None:
    store = PostgreSQLStore("postgresql://missionweave:missionweave@127.0.0.1:55432/missionweave")
    await store.initialize()
    try:
        control = HumanControl(Core(store), HumanIdentity.generate("human:mission-owner"))
        receipt = await control.create(
            mission_id="mission:release",
            group_id="group:release",
            coordinator_id="urn:missionweave:agent:developer",
            title="Ship release",
            objective="Produce and verify the release",
            definition_of_done=("tests pass", "human approves"),
            deadline=datetime.now(UTC) + timedelta(days=1),
        )
        inspection = await control.inspect("mission:release")
        print(receipt.event.id, inspection.mission.id)
    finally:
        await store.close()


if __name__ == "__main__":
    asyncio.run(main())
```

## Implementation interface

- `models.py` contains the compact authoritative Core projection; these classes are not sent
  directly as wire objects.
- `delegation.py`, `lease.py`, and `budget.py` enforce scoped work authority, structured
  execution fencing, and hierarchical six-dimensional accounting.
- `documents.py`, `wire.py`, and `gateway.py` adapt projections into pinned schema-valid, signed
  protocol documents.
- `Core` owns state transitions behind the small `perform`, `query`, and `replay` interface.
- transport, authentication, authoritative storage, Agent-local storage, Artifact storage,
  policy/token issuance, Context publication, scheduling, and human control are adapters at
  explicit seams.

This separation lets another implementation choose different internal models, storage, or a
different language while conforming to the same protocol bundle.

## Build a distributable wheel

```bash
uv build
```

The wheel includes `py.typed` and all 21 pinned schemas needed for runtime frame validation.

## License

The Python SDK is licensed under [Apache-2.0](LICENSE). The normative specification
and protocol artifacts live in the separate
[missionweaveprotocol](https://github.com/MissionWeaveProject/missionweaveprotocol) repository.
