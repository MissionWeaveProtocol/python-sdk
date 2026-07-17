from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from missionweaveprotocol.execution import RetryController, RetryExhausted
from missionweaveprotocol.models import ResourceBudget, RetryPolicy, WorkContract
from missionweaveprotocol.policy import ResourceUsage


@dataclass
class Clock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value


NOW = datetime(2026, 7, 15, 8, 0, tzinfo=UTC)


def _contract() -> WorkContract:
    return WorkContract(
        goal="Call one retryable external operation",
        deliverables=("receipt",),
        acceptance_criteria=("receipt verified",),
        deadline=NOW + timedelta(minutes=10),
        budget=ResourceBudget(tool_calls=3, model_tokens=100),
        retry_policy=RetryPolicy(
            max_attempts=3,
            initial_backoff_seconds=10,
            maximum_backoff_seconds=30,
        ),
    )


def test_retry_controller_enforces_attempts_backoff_and_stable_side_effect_key() -> None:
    clock = Clock(NOW)
    controller = RetryController(
        _contract(),
        mission_id="mission:retry",
        work_item_id="work:retry",
        ownership_epoch=4,
        clock=clock,
    )
    first = controller.begin(
        "external:create-ticket",
        reserved_usage=ResourceUsage(tool_calls=1),
    )
    retry = controller.finish(success=False)
    clock.value = retry.retry_at or clock.value
    second = controller.begin(
        "external:create-ticket",
        reserved_usage=ResourceUsage(tool_calls=1),
    )

    assert retry.retry_at == NOW + timedelta(seconds=10)
    assert first.idempotency_key == second.idempotency_key
    assert second.attempt_number == 2

    retry = controller.finish(success=False)
    clock.value = retry.retry_at or clock.value
    controller.begin("external:create-ticket", reserved_usage=ResourceUsage(tool_calls=1))
    exhausted = controller.finish(success=False)
    assert exhausted.retry is False
    assert exhausted.reason == "attempts_exhausted"
    with pytest.raises(RetryExhausted, match="attempt limit"):
        controller.begin("external:create-ticket")


def test_retry_controller_stops_at_budget_and_deadline() -> None:
    clock = Clock(NOW)
    controller = RetryController(
        _contract(),
        mission_id="mission:retry",
        work_item_id="work:retry",
        ownership_epoch=1,
        clock=clock,
    )
    with pytest.raises(RetryExhausted, match="model_tokens"):
        controller.begin(
            "model:generate",
            reserved_usage=ResourceUsage(model_tokens=101),
        )

    clock.value = NOW + timedelta(minutes=10)
    with pytest.raises(RetryExhausted, match="deadline"):
        controller.begin("model:generate")


def test_ownership_epoch_changes_external_idempotency_scope() -> None:
    first = RetryController(
        _contract(),
        mission_id="mission:retry",
        work_item_id="work:retry",
        ownership_epoch=1,
        clock=lambda: NOW,
    )
    reassigned = RetryController(
        _contract(),
        mission_id="mission:retry",
        work_item_id="work:retry",
        ownership_epoch=2,
        clock=lambda: NOW,
    )

    assert first.idempotency_key("external:send") != reassigned.idempotency_key("external:send")
