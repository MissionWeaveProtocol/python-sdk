"""Structured, fenced execution leases.

An Execution Lease is issued before capability tokens.  Tokens therefore bind to the stable
``lease_id``; the lease deliberately does not point back to one token because a Worker may rotate
or narrow several short-lived tokens during the same execution interval.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final, Literal, Self

from pydantic import AwareDatetime, Field, model_validator

from .models import Identifier, ProtocolModel

MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991
ClosureReason = Annotated[str, Field(min_length=1, max_length=512)]


class LeaseState(StrEnum):
    """Authoritative lifecycle of a fenced lease record."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    RELEASED = "released"


class ExecutionLease(ProtocolModel):
    """One renewable execution interval fenced by Agent, Session, and ownership identity."""

    lease_id: Identifier
    lease_type: Literal["execution"] = "execution"
    mission_id: Identifier
    group_id: Identifier
    work_item_id: Identifier
    holder_agent_id: Identifier
    session_epoch: int = Field(gt=0, le=MAX_SAFE_INTEGER)
    ownership_epoch: int = Field(gt=0, le=MAX_SAFE_INTEGER)
    issued_at: AwareDatetime
    starts_at: AwareDatetime
    expires_at: AwareDatetime
    state: LeaseState = LeaseState.ACTIVE
    renewal_count: int = Field(default=0, ge=0, le=MAX_SAFE_INTEGER)
    last_renewed_at: AwareDatetime | None = None
    closed_at: AwareDatetime | None = None
    closure_reason: ClosureReason | None = None

    @model_validator(mode="after")
    def timestamps_and_renewals_are_consistent(self) -> ExecutionLease:
        if self.starts_at < self.issued_at:
            raise ValueError("Execution Lease cannot start before issuance")
        if self.expires_at <= self.starts_at:
            raise ValueError("Execution Lease expiry must follow its start")
        if self.renewal_count == 0 and self.last_renewed_at is not None:
            raise ValueError("an unrenewed Execution Lease cannot have a renewal timestamp")
        if self.renewal_count > 0 and self.last_renewed_at is None:
            raise ValueError("a renewed Execution Lease requires a renewal timestamp")
        if self.last_renewed_at is not None and not (
            self.starts_at <= self.last_renewed_at < self.expires_at
        ):
            raise ValueError("Execution Lease renewal timestamp must fall within the lease")
        if self.state is LeaseState.ACTIVE:
            if self.closed_at is not None or self.closure_reason is not None:
                raise ValueError("an active Execution Lease cannot have closure metadata")
            return self
        if self.closed_at is None or self.closure_reason is None:
            raise ValueError("a terminal Execution Lease requires closure metadata")
        if self.closed_at < self.issued_at:
            raise ValueError("Execution Lease cannot close before issuance")
        if self.last_renewed_at is not None and self.closed_at < self.last_renewed_at:
            raise ValueError("Execution Lease cannot close before its latest renewal")
        if self.state is LeaseState.EXPIRED:
            if self.closed_at < self.expires_at:
                raise ValueError("an expired Execution Lease cannot close before its expiry")
        elif self.closed_at >= self.expires_at:
            raise ValueError("an elapsed Execution Lease must close as expired")
        return self

    def renew(self, *, at: datetime, expires_at: datetime) -> Self:
        """Return the next immutable projection of this active lease."""

        if self.state is not LeaseState.ACTIVE:
            raise ValueError("only an active Execution Lease may be renewed")
        self._require_aware(at, "renewal time")
        self._require_aware(expires_at, "expiry")
        if at < self.starts_at:
            raise ValueError("Execution Lease cannot renew before its start")
        if at >= self.expires_at:
            raise ValueError("Execution Lease must be renewed before its current expiry")
        if self.last_renewed_at is not None and at <= self.last_renewed_at:
            raise ValueError("Execution Lease renewal time must advance monotonically")
        if expires_at <= self.expires_at:
            raise ValueError("Execution Lease renewal must strictly extend its expiry")
        if self.renewal_count >= MAX_SAFE_INTEGER:
            raise ValueError("Execution Lease renewal count exceeds the safe-integer limit")
        values = self.model_dump()
        values.update(
            expires_at=expires_at,
            renewal_count=self.renewal_count + 1,
            last_renewed_at=at,
        )
        return type(self).model_validate(values)

    def close(self, state: LeaseState, *, at: datetime, reason: str) -> Self:
        """Return a terminal projection without discarding its fencing history."""

        if state is LeaseState.ACTIVE:
            raise ValueError("closing an Execution Lease requires a terminal state")
        self._require_aware(at, "closure time")
        reason = reason.strip()
        if not reason:
            raise ValueError("Execution Lease closure reason must not be empty")
        if len(reason) > 512:
            raise ValueError("Execution Lease closure reason exceeds 512 characters")
        if self.state is not LeaseState.ACTIVE:
            if self.state is state and self.closed_at == at and self.closure_reason == reason:
                return self
            raise ValueError("a terminal Execution Lease cannot rewrite its closure")
        values = self.model_dump()
        values.update(state=state, closed_at=at, closure_reason=reason)
        return type(self).model_validate(values)

    @staticmethod
    def _require_aware(value: datetime, label: str) -> None:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError(f"Execution Lease {label} must be timezone-aware")


__all__ = ["ExecutionLease", "LeaseState"]
