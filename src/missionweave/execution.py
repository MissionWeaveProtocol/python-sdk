"""Bounded Work Contract retry execution and stable side-effect idempotency keys."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from .canonical import canonical_hash
from .models import WorkContract
from .policy import BudgetMeter, PolicyError, ResourceUsage

Clock = Callable[[], datetime]


class RetryExhausted(PolicyError):
    """No further attempt is permitted by deadline, count, or budget."""


@dataclass(frozen=True, slots=True)
class Attempt:
    attempt_number: int
    idempotency_key: str
    started_at: datetime


@dataclass(frozen=True, slots=True)
class RetrySchedule:
    retry: bool
    retry_at: datetime | None
    reason: str


class RetryController:
    """Enforce one Work Contract's attempt, backoff, deadline, and budget policy."""

    def __init__(
        self,
        contract: WorkContract,
        *,
        mission_id: str,
        work_item_id: str,
        ownership_epoch: int,
        clock: Clock | None = None,
    ) -> None:
        if ownership_epoch < 1:
            raise ValueError("ownership_epoch must be positive")
        self.contract = contract
        self.mission_id = mission_id
        self.work_item_id = work_item_id
        self.ownership_epoch = ownership_epoch
        self._clock = clock or (lambda: datetime.now(UTC))
        self._meter = BudgetMeter(contract.budget)
        self._attempts = 0
        self._active: Attempt | None = None

    @property
    def attempts(self) -> int:
        return self._attempts

    @property
    def usage(self) -> ResourceUsage:
        return self._meter.usage

    def begin(
        self,
        logical_operation_id: str,
        *,
        reserved_usage: ResourceUsage | None = None,
    ) -> Attempt:
        if self._active is not None:
            raise PolicyError("an attempt is already active")
        now = self._now()
        if now >= self.contract.deadline:
            raise RetryExhausted("Work Contract deadline has expired")
        if self._attempts >= self.contract.retry_policy.max_attempts:
            raise RetryExhausted("Work Contract attempt limit exhausted")
        if reserved_usage is not None:
            try:
                self._meter.consume(reserved_usage)
            except PolicyError as error:
                raise RetryExhausted(str(error)) from error
        self._attempts += 1
        attempt = Attempt(
            attempt_number=self._attempts,
            idempotency_key=self.idempotency_key(logical_operation_id),
            started_at=now,
        )
        self._active = attempt
        return attempt

    def finish(self, *, success: bool, retryable: bool = True) -> RetrySchedule:
        if self._active is None:
            raise PolicyError("no attempt is active")
        self._active = None
        if success:
            return RetrySchedule(retry=False, retry_at=None, reason="completed")
        if not retryable:
            return RetrySchedule(retry=False, retry_at=None, reason="permanent_failure")
        if self._attempts >= self.contract.retry_policy.max_attempts:
            return RetrySchedule(retry=False, retry_at=None, reason="attempts_exhausted")
        now = self._now()
        backoff = self._backoff(self._attempts)
        retry_at = now + backoff
        if retry_at >= self.contract.deadline:
            return RetrySchedule(retry=False, retry_at=None, reason="deadline_exhausted")
        return RetrySchedule(retry=True, retry_at=retry_at, reason="retryable_failure")

    def consume(self, usage: ResourceUsage) -> ResourceUsage:
        try:
            return self._meter.consume(usage)
        except PolicyError as error:
            raise RetryExhausted(str(error)) from error

    def idempotency_key(self, logical_operation_id: str) -> str:
        if not logical_operation_id:
            raise ValueError("logical_operation_id must not be empty")
        return canonical_hash(
            {
                "missionId": self.mission_id,
                "workItemId": self.work_item_id,
                "ownershipEpoch": self.ownership_epoch,
                "logicalOperationId": logical_operation_id,
            }
        )

    def _backoff(self, completed_attempts: int) -> timedelta:
        policy = self.contract.retry_policy
        initial = policy.initial_backoff_seconds
        maximum = policy.maximum_backoff_seconds
        if initial == 0 or maximum == 0:
            return timedelta(0)
        seconds = min(maximum, initial * (2 ** max(0, completed_attempts - 1)))
        return timedelta(seconds=seconds)

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise RuntimeError("RetryController clock must return an aware datetime")
        return now.astimezone(UTC)


__all__ = ["Attempt", "RetryController", "RetryExhausted", "RetrySchedule"]
