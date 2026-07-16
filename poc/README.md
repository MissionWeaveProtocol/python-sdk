# MissionWeave 0.1 proof of concept

The POC is an executable conformance scenario, not a conversational mock.

## Participants

- `human://acme/owner` — MissionOwner for both root Missions.
- `agent://acme/coordinator-auth` — Coordinator for the authentication Mission.
- `agent://acme/coordinator-cli` — Coordinator for the CLI Mission.
- `agent://acme/coordinator-cli-v2` — epoch-fenced replacement CLI Coordinator.
- `agent://acme/analyst` — requirements capability.
- `agent://acme/coder` — Python implementation capability.
- `agent://acme/reviewer` — shared review capability and two per-Group queues.
- `agent://acme/security-coordinator` — Coordinator for a child security-review Mission.
- `agent://acme/security-worker` — security-review capability in the child Mission.

## Mission A: authentication feature

The Mission requires requirements analysis, implementation, tests, review, integration, and
human approval. The Coordinator promotes security analysis into a child Mission with its own
Group and Coordinator. The child result returns as a provenance-linked Artifact.

## Mission B: CLI feature

The Mission creates a competing review assignment for the shared reviewer. Its organization
priority is lower initially, then a policy-approved urgency change causes safe checkpoint
preemption at the reviewer's next checkpoint.

## Required cooperation behavior

1. Both root Mission Groups exist concurrently.
2. The shared reviewer accepts WorkItems into separate per-Group queues.
3. The global Scheduler exposes estimates without leaking the other Mission's content.
4. Worker-to-Worker clarification occurs in WorkItem Conversations.
5. A Worker proposes sub-work; only the Coordinator authorizes it.
6. At least one WorkItem blocks, checkpoints, releases capacity, and later resumes.
7. The security WorkItem becomes a child Mission and is approved by the Parent Coordinator.
8. Deterministic evidence and reviewer evidence precede Coordinator acceptance.
9. The human requests changes once, the same Mission reopens, and corrective work is verified.
10. Final approval signs exact Mission revisions and Artifact hashes.
11. A signed late-member Context Package is installed only in its matching Group context.
12. Reusable knowledge is explicitly classified and retains Event and Artifact provenance.
13. Signed final Group snapshots cover complete histories and retain human-approval policy logs.
14. Offline progress rebases into a later Session and charges the authoritative budget ledger.

## Required failure injection

- Duplicate a durable Command and prove idempotent acceptance.
- Reuse an action ID with different content and prove collision rejection.
- Restart a Worker and rebuild its per-Group queues from Events and Cursors.
- Replace a Coordinator and reject the previous Coordinator epoch.
- Disconnect an active Worker, permit bounded reversible progress, and reconcile it atomically
  with its authoritative resource usage.
- Reject a buffered Command carrying a stale Membership Epoch before refreshing Membership.
- Expire an execution lease and fence the previous ownership epoch.
- Preempt active work only after a safe checkpoint.

The automated POC currently proves the scenario through 50 named checks and MUST exit non-zero
when any required behavior is missing.
