from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from missionweave.auth import AgentIdentity
from missionweave.crypto import verify_canonical
from missionweave.models import (
    Command,
    CommandKind,
    ExtensionEnvelope,
    PostMessagePayload,
    Principal,
)
from missionweave.offline import OFFLINE_EXECUTION_EXTENSION
from missionweave.poc import (
    OfflinePolicyError,
    POCReport,
    offline_command_to_wire,
    run_poc,
    run_poc_sync,
)


@pytest.mark.asyncio
async def test_poc_runs_two_missions_and_reports_every_required_behavior(
    tmp_path: Path,
) -> None:
    report = await run_poc(tmp_path)

    assert report.passed
    assert all(passed for _, passed in report.checks)
    assert [mission.status for mission in report.missions] == ["approved", "approved"]
    assert report.scheduler_dispatch_order == (
        "auth:review",
        "cli:review",
        "cli:urgent-review",
        "auth:review",
    )
    assert report.worker_message_count >= 4
    assert report.artifact_provenance_edges >= 10
    assert {group for group, _ in report.final_cursors} == {
        "group:authentication",
        "group:cli",
    }
    assert {
        "action_id_collision_rejected",
        "execution_lease_expiry_rejected",
        "previous_coordinator_rejected_after_replacement",
        "stale_coordinator_epoch_rejected",
        "stale_membership_epoch_rejected_by_gateway",
        "stale_ownership_epoch_rejected",
        "worker_restart_fences_old_session",
    }.issubset(report.failure_injections)
    assert report.context_package_count == 1
    assert report.knowledge_publication_count == 1
    assert report.group_snapshot_count == 2
    assert report.policy_log_entry_count >= 2
    checks = dict(report.checks)
    assert checks["signed_context_package_issued_for_late_provisional_reviewer"]
    assert checks["classified_reusable_knowledge_has_event_and_artifact_provenance"]
    assert checks["context_package_installed_only_in_matching_group"]
    assert checks["worker_restart_rebuilt_per_group_queues_from_event_replay"]
    assert checks["multiple_capacity_slots_active"]
    assert checks["coordinator_explicitly_authorized_worker_subwork"]
    assert checks["stale_membership_epoch_rejected_by_gateway"]
    assert checks["real_gateway_websocket_reconnected_and_reconciled"]
    assert checks["offline_usage_reconciled_into_authoritative_budget"]
    assert checks["signed_root_group_snapshots_cover_complete_histories"]
    assert checks["snapshot_policy_logs_prove_exact_signed_human_approvals"]
    assert (tmp_path / "reviewer-local.sqlite3").is_file()
    assert json.loads(json.dumps(report.to_dict()))["passed"] is True


@pytest.mark.asyncio
async def test_poc_report_is_deterministic_across_clean_local_stores(tmp_path: Path) -> None:
    first = await run_poc(tmp_path / "first")
    second = await run_poc(tmp_path / "second")

    assert first.to_dict() == second.to_dict()


def test_sync_entrypoint_and_failed_report_behavior(tmp_path: Path) -> None:
    successful = run_poc_sync(tmp_path / "sync")
    assert successful.passed

    failed = POCReport(
        passed=False,
        checks=(("injected_missing_behavior", False),),
        missions=(),
        scheduler_dispatch_order=(),
        event_counts=(),
        final_cursors=(),
        failure_injections=(),
        artifact_provenance_edges=0,
        worker_message_count=0,
        context_package_count=0,
        knowledge_publication_count=0,
        group_snapshot_count=0,
        policy_log_entry_count=0,
    )
    with pytest.raises(AssertionError, match="injected_missing_behavior"):
        failed.require_success()


def test_offline_gateway_hook_rebases_only_reversible_commands() -> None:
    identity = AgentIdentity.generate("agent://acme/reviewer")
    buffered_at = datetime(2026, 7, 15, tzinfo=UTC)
    reconciled_at = buffered_at + timedelta(seconds=10)
    buffered = Command(
        action_id="poc:offline:message",
        kind=CommandKind.POST_MESSAGE,
        actor=Principal.agent(identity.agent_id),
        group_id="group:authentication",
        session_epoch=1,
        issued_at=buffered_at,
        payload=PostMessagePayload(
            message_id="message:offline",
            conversation_id="group:authentication:work:review",
            content="reversible note",
        ).model_dump(mode="json", by_alias=True),
        extensions={
            OFFLINE_EXECUTION_EXTENSION: ExtensionEnvelope(
                version="0.1.0",
                critical=True,
                data={
                    "agentId": identity.agent_id,
                    "groupId": "group:authentication",
                    "workItemId": "work:review",
                    "sessionEpoch": 1,
                    "ownershipEpoch": 1,
                    "executionLeaseId": "lease:offline",
                    "disconnectedAt": buffered_at.isoformat(),
                    "bufferedAt": buffered_at.isoformat(),
                    "graceDeadline": (buffered_at + timedelta(minutes=1)).isoformat(),
                    "executionLeaseExpiresAt": (buffered_at + timedelta(minutes=5)).isoformat(),
                    "resourceUsageDelta": {"modelTokens": 1},
                },
            )
        },
        signature="old-session-signature",
    )

    document = offline_command_to_wire(
        buffered,
        identity,
        session_epoch=2,
        membership_epoch=3,
        issued_at=reconciled_at,
    )
    signature = document["signature"]
    assert isinstance(signature, dict)
    signature_value = signature["value"]
    assert isinstance(signature_value, str)
    signing_payload = dict(document)
    del signing_payload["signature"]
    assert document["sessionEpoch"] == 2
    assert document["membershipEpoch"] == 3
    assert document["issuedAt"] == reconciled_at.isoformat().replace("+00:00", "Z")
    assert (
        document["extensions"]
        == buffered.model_dump(mode="json", by_alias=True, include={"extensions"})["extensions"]
    )
    assert verify_canonical(signing_payload, signature_value, identity.public_key)

    irreversible = buffered.model_copy(update={"kind": CommandKind.SUBMIT_WORK_ITEM})
    with pytest.raises(OfflinePolicyError, match="not an offline wire Command"):
        offline_command_to_wire(
            irreversible,
            identity,
            session_epoch=2,
            membership_epoch=3,
        )
