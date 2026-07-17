from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from jsonschema import ValidationError as SchemaValidationError
from pydantic import ValidationError

from missionweaveprotocol.conformance import SchemaCatalog
from missionweaveprotocol.lease import ExecutionLease, LeaseState

NOW = datetime(2026, 1, 1, tzinfo=UTC)
MAX_SAFE_INTEGER = 9_007_199_254_740_991


def _lease(**updates: object) -> ExecutionLease:
    values: dict[str, object] = {
        "lease_id": "lease:execution:1",
        "mission_id": "mission:1",
        "group_id": "group:1",
        "work_item_id": "work:1",
        "holder_agent_id": "agent:worker",
        "session_epoch": 2,
        "ownership_epoch": 3,
        "issued_at": NOW,
        "starts_at": NOW,
        "expires_at": NOW + timedelta(minutes=5),
    }
    values.update(updates)
    return ExecutionLease.model_validate(values)


def _document(**updates: object) -> dict[str, object]:
    document = _lease().model_dump(mode="json", by_alias=True, exclude_none=True)
    document.update(updates)
    return document


def test_execution_lease_renews_without_changing_fencing_identity() -> None:
    original = _lease()

    renewed = original.renew(
        at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=7),
    )

    assert renewed.lease_id == original.lease_id
    assert renewed.session_epoch == 2
    assert renewed.ownership_epoch == 3
    assert renewed.renewal_count == 1
    assert renewed.last_renewed_at == NOW + timedelta(minutes=2)
    assert renewed.expires_at == NOW + timedelta(minutes=7)


@pytest.mark.parametrize(
    ("at", "expires_at", "message"),
    [
        (
            NOW - timedelta(seconds=1),
            NOW + timedelta(minutes=7),
            "before its start",
        ),
        (
            NOW + timedelta(minutes=5),
            NOW + timedelta(minutes=7),
            "before its current expiry",
        ),
        (
            NOW + timedelta(minutes=6),
            NOW + timedelta(minutes=7),
            "before its current expiry",
        ),
        (
            NOW + timedelta(minutes=2),
            NOW + timedelta(minutes=5),
            "strictly extend",
        ),
        (
            NOW + timedelta(minutes=2),
            NOW + timedelta(minutes=4),
            "strictly extend",
        ),
    ],
)
def test_execution_lease_rejects_invalid_renewal_window(
    at: datetime, expires_at: datetime, message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        _lease().renew(at=at, expires_at=expires_at)


def test_execution_lease_requires_strictly_monotonic_renewal_times() -> None:
    renewed = _lease().renew(
        at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=7),
    )

    for renewal_time in (NOW + timedelta(minutes=1), NOW + timedelta(minutes=2)):
        with pytest.raises(ValueError, match="monotonically"):
            renewed.renew(
                at=renewal_time,
                expires_at=NOW + timedelta(minutes=8),
            )


def test_execution_lease_epochs_and_renewal_count_are_javascript_safe() -> None:
    _lease(
        session_epoch=MAX_SAFE_INTEGER,
        ownership_epoch=MAX_SAFE_INTEGER,
        renewal_count=MAX_SAFE_INTEGER,
        last_renewed_at=NOW + timedelta(minutes=1),
    )

    for field in ("session_epoch", "ownership_epoch", "renewal_count"):
        with pytest.raises(ValidationError, match="less than or equal"):
            _lease(**{field: MAX_SAFE_INTEGER + 1})

    saturated = _lease(
        renewal_count=MAX_SAFE_INTEGER,
        last_renewed_at=NOW + timedelta(minutes=1),
    )
    with pytest.raises(ValueError, match="safe-integer limit"):
        saturated.renew(
            at=NOW + timedelta(minutes=2),
            expires_at=NOW + timedelta(minutes=7),
        )


def test_execution_lease_records_immutable_terminal_audit_metadata() -> None:
    released = _lease().close(
        LeaseState.RELEASED,
        at=NOW + timedelta(minutes=4),
        reason=" work checkpointed ",
    )

    assert released.closed_at == NOW + timedelta(minutes=4)
    assert released.closure_reason == "work checkpointed"
    assert (
        released.close(
            LeaseState.RELEASED,
            at=NOW + timedelta(minutes=4),
            reason="work checkpointed",
        )
        is released
    )
    with pytest.raises(ValueError, match="rewrite its closure"):
        released.close(
            LeaseState.REVOKED,
            at=NOW + timedelta(minutes=4),
            reason="work checkpointed",
        )
    with pytest.raises(ValueError, match="rewrite its closure"):
        released.close(
            LeaseState.RELEASED,
            at=NOW + timedelta(minutes=4),
            reason="different reason",
        )
    with pytest.raises(ValueError, match="active"):
        released.renew(
            at=NOW + timedelta(minutes=4),
            expires_at=NOW + timedelta(minutes=8),
        )


def test_execution_lease_natural_expiry_cannot_be_recorded_early() -> None:
    with pytest.raises(ValueError, match="cannot close before its expiry"):
        _lease().close(
            LeaseState.EXPIRED,
            at=NOW + timedelta(minutes=4),
            reason="natural expiry",
        )

    expired = _lease().close(
        LeaseState.EXPIRED,
        at=NOW + timedelta(minutes=5),
        reason="natural expiry",
    )

    assert expired.state is LeaseState.EXPIRED
    assert expired.closed_at == expired.expires_at


def test_execution_lease_elapsed_closure_must_be_expired() -> None:
    with pytest.raises(ValueError, match="must close as expired"):
        _lease().close(
            LeaseState.REVOKED,
            at=NOW + timedelta(minutes=5),
            reason="session restarted",
        )


def test_execution_lease_projects_through_the_normative_schema() -> None:
    lease = _lease().renew(
        at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=7),
    )

    document = lease.model_dump(mode="json", by_alias=True, exclude_none=True)
    SchemaCatalog().validate("lease.schema.json", document)

    assert "capabilityTokenId" not in document


def test_terminal_execution_lease_projects_through_the_normative_schema() -> None:
    lease = _lease().close(
        LeaseState.RELEASED,
        at=NOW + timedelta(minutes=4),
        reason="work checkpointed",
    )

    SchemaCatalog().validate(
        "lease.schema.json",
        lease.model_dump(mode="json", by_alias=True, exclude_none=True),
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("coordinatorEpoch", 4),
        ("startBy", "2026-01-01T00:01:00Z"),
        ("graceExpiresAt", "2026-01-01T00:06:00Z"),
        ("capabilityTokenId", "token:1"),
    ],
)
def test_execution_lease_schema_rejects_fields_from_other_authority_records(
    field: str, value: object
) -> None:
    with pytest.raises(SchemaValidationError):
        SchemaCatalog().validate("lease.schema.json", _document(**{field: value}))


@pytest.mark.parametrize(
    "updates",
    [
        {"state": "active", "closedAt": "2026-01-01T00:04:00Z"},
        {"state": "active", "closureReason": "work checkpointed"},
        {"state": "released"},
        {"state": "released", "closedAt": "2026-01-01T00:04:00Z"},
        {"state": "released", "closureReason": "work checkpointed"},
    ],
)
def test_execution_lease_schema_requires_coherent_closure_metadata(
    updates: dict[str, object],
) -> None:
    with pytest.raises(SchemaValidationError):
        SchemaCatalog().validate("lease.schema.json", _document(**updates))


@pytest.mark.parametrize(
    "updates",
    [
        {"renewalCount": 0, "lastRenewedAt": "2026-01-01T00:02:00Z"},
        {"renewalCount": 1},
    ],
)
def test_execution_lease_schema_requires_coherent_renewal_metadata(
    updates: dict[str, object],
) -> None:
    with pytest.raises(SchemaValidationError):
        SchemaCatalog().validate("lease.schema.json", _document(**updates))


@pytest.mark.parametrize("field", ["sessionEpoch", "ownershipEpoch", "renewalCount"])
def test_execution_lease_schema_rejects_unsafe_integers(field: str) -> None:
    with pytest.raises(SchemaValidationError):
        SchemaCatalog().validate(
            "lease.schema.json",
            _document(**{field: MAX_SAFE_INTEGER + 1}),
        )


@pytest.mark.parametrize(
    ("updates", "message"),
    [
        ({"starts_at": NOW - timedelta(seconds=1)}, "before issuance"),
        ({"expires_at": NOW}, "expiry must follow"),
        ({"renewal_count": 1}, "requires a renewal timestamp"),
        ({"last_renewed_at": NOW + timedelta(seconds=1)}, "unrenewed"),
        (
            {
                "renewal_count": 1,
                "last_renewed_at": NOW + timedelta(minutes=6),
            },
            "within the lease",
        ),
        ({"state": LeaseState.RELEASED}, "requires closure metadata"),
        (
            {
                "closed_at": NOW + timedelta(minutes=4),
                "closure_reason": "work checkpointed",
            },
            "active.*closure metadata",
        ),
        (
            {
                "state": LeaseState.EXPIRED,
                "closed_at": NOW + timedelta(minutes=4),
                "closure_reason": "natural expiry",
            },
            "cannot close before its expiry",
        ),
        (
            {
                "state": LeaseState.REVOKED,
                "closed_at": NOW + timedelta(minutes=5),
                "closure_reason": "session restarted",
            },
            "must close as expired",
        ),
        (
            {
                "state": LeaseState.REVOKED,
                "closed_at": NOW - timedelta(seconds=1),
                "closure_reason": "session restarted",
            },
            "before issuance",
        ),
        (
            {
                "state": LeaseState.RELEASED,
                "renewal_count": 1,
                "last_renewed_at": NOW + timedelta(minutes=2),
                "closed_at": NOW + timedelta(minutes=1),
                "closure_reason": "work checkpointed",
            },
            "before its latest renewal",
        ),
    ],
)
def test_execution_lease_rejects_inconsistent_state(
    updates: dict[str, object], message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        _lease(**updates)
