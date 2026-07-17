"""Least-privilege tokens, execution authorization, budgets, and cooperation policy."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Literal, Protocol

from pydantic import (
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from missionweaveprotocol.canonical import canonical_bytes
from missionweaveprotocol.crypto import PublicKeyLike, verify_canonical
from missionweaveprotocol.lease import ExecutionLease, LeaseState
from missionweaveprotocol.models import (
    ActorType,
    Command,
    CommandKind,
    Event,
    EventKind,
    ExecutionApproval,
    GrantExecutionApprovalPayload,
    Membership,
    MembershipStatus,
    Mission,
    Principal,
    Query,
    QueryKind,
    ResourceBudget,
    ResourceUsage,
    Role,
    WorkItem,
    WorkItemStatus,
)


class PolicyError(ValueError):
    """Raised when policy, authorization, or budget constraints are violated."""


_HIGH_RISK_PREFIXES = ("production.", "payment.", "external.send", "destructive.")


def _requires_human_approval(operation: str) -> bool:
    return operation.startswith(_HIGH_RISK_PREFIXES)


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _b64decode(value: str) -> bytes:
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError, TypeError) as error:
        raise PolicyError("invalid base64url token component") from error


def _aware_utc(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise PolicyError(f"{name} must be timezone-aware")
    return value.astimezone(UTC)


def _validated_ttl(ttl: timedelta, maximum: timedelta) -> None:
    if ttl <= timedelta(0):
        raise PolicyError("token TTL must be positive")
    if ttl > maximum:
        raise PolicyError("token TTL exceeds the configured short-lived maximum")


def _encode_token(claims: BaseModel, secret: bytes) -> str:
    payload = _b64encode(canonical_bytes(claims.model_dump(mode="json")))
    signature = hmac.new(secret, payload.encode(), hashlib.sha256).digest()
    return f"{payload}.{_b64encode(signature)}"


def _decode_token[ClaimsT: BaseModel](
    token: str,
    secret: bytes,
    claims_type: type[ClaimsT],
    *,
    label: str,
) -> ClaimsT:
    try:
        payload, encoded_signature = token.split(".", 1)
    except (AttributeError, ValueError) as error:
        raise PolicyError(f"malformed {label} token") from error
    signature = _b64decode(encoded_signature)
    expected = hmac.new(secret, payload.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, signature):
        raise PolicyError(f"invalid {label} token signature")
    try:
        return claims_type.model_validate_json(_b64decode(payload))
    except ValidationError as error:
        raise PolicyError(f"invalid {label} token claims") from error


class MembershipTokenClaims(BaseModel):
    """Short-lived authorization for one Agent Membership epoch."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    token_id: str
    principal: Principal
    group_id: str
    roles: tuple[Role, ...]
    membership_epoch: int = Field(gt=0)
    session_epoch: int = Field(gt=0)
    issued_at: AwareDatetime
    expires_at: AwareDatetime

    @field_validator("roles")
    @classmethod
    def roles_are_nonempty_and_unique(cls, value: tuple[Role, ...]) -> tuple[Role, ...]:
        if not value:
            raise ValueError("Membership token requires at least one role")
        if len(value) != len(set(value)):
            raise ValueError("Membership token roles must be unique")
        return tuple(sorted(value, key=lambda role: role.value))

    @model_validator(mode="after")
    def expiry_follows_issue(self) -> MembershipTokenClaims:
        if self.expires_at <= self.issued_at:
            raise ValueError("Membership token expiry must follow issuance")
        if self.principal.type is not ActorType.AGENT:
            raise ValueError("Membership tokens carrying Session Epochs are Agent-only")
        return self


@dataclass(frozen=True, slots=True)
class IssuedMembershipToken:
    claims: MembershipTokenClaims
    token: str


class MembershipTokenService:
    """Issues and verifies fenced, least-privilege Membership tokens."""

    def __init__(
        self,
        secret: bytes | None = None,
        *,
        maximum_ttl: timedelta = timedelta(minutes=15),
    ) -> None:
        if maximum_ttl <= timedelta(0):
            raise ValueError("maximum Membership token TTL must be positive")
        self._secret = secret or secrets.token_bytes(32)
        self._maximum_ttl = maximum_ttl

    def issue(
        self,
        *,
        principal: Principal,
        group_id: str,
        roles: tuple[Role, ...],
        membership_epoch: int,
        session_epoch: int,
        ttl: timedelta,
        now: datetime | None = None,
    ) -> IssuedMembershipToken:
        _validated_ttl(ttl, self._maximum_ttl)
        issued_at = _aware_utc(now or datetime.now(UTC), "Membership token issue time")
        claims = MembershipTokenClaims(
            token_id=secrets.token_urlsafe(16),
            principal=principal,
            group_id=group_id,
            roles=roles,
            membership_epoch=membership_epoch,
            session_epoch=session_epoch,
            issued_at=issued_at,
            expires_at=issued_at + ttl,
        )
        return IssuedMembershipToken(claims, _encode_token(claims, self._secret))

    def issue_for_membership(
        self,
        membership: Membership,
        *,
        session_epoch: int,
        ttl: timedelta,
        now: datetime | None = None,
    ) -> IssuedMembershipToken:
        """Issue directly from the authoritative Membership projection and its epoch."""

        if membership.status is not MembershipStatus.ACTIVE:
            raise PolicyError("Membership token requires an active Membership")
        return self.issue(
            principal=membership.principal,
            group_id=membership.group_id,
            roles=membership.roles,
            membership_epoch=membership.epoch,
            session_epoch=session_epoch,
            ttl=ttl,
            now=now,
        )

    def verify(
        self,
        token: str,
        *,
        principal: Principal,
        group_id: str,
        roles: tuple[Role, ...],
        membership_epoch: int,
        session_epoch: int,
        now: datetime | None = None,
    ) -> MembershipTokenClaims:
        claims = _decode_token(token, self._secret, MembershipTokenClaims, label="Membership")
        current = _aware_utc(now or datetime.now(UTC), "Membership verification time")
        if claims.expires_at <= current:
            raise PolicyError("Membership token expired")
        if claims.principal != principal or claims.group_id != group_id:
            raise PolicyError("Membership token principal or Group scope mismatch")
        expected_roles = tuple(sorted(set(roles), key=lambda role: role.value))
        if claims.roles != expected_roles:
            raise PolicyError("Membership token role scope mismatch")
        if claims.membership_epoch != membership_epoch:
            raise PolicyError("stale Membership token epoch")
        if claims.session_epoch != session_epoch:
            raise PolicyError("stale Membership token Session Epoch")
        return claims

    def verify_membership(
        self,
        token: str,
        membership: Membership,
        *,
        session_epoch: int,
        now: datetime | None = None,
    ) -> MembershipTokenClaims:
        """Fence a token against the current durable Membership epoch and role set."""

        if membership.status is not MembershipStatus.ACTIVE:
            raise PolicyError("Membership is no longer active")
        return self.verify(
            token,
            principal=membership.principal,
            group_id=membership.group_id,
            roles=membership.roles,
            membership_epoch=membership.epoch,
            session_epoch=session_epoch,
            now=now,
        )


class CapabilityGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    grant_id: str
    worker_id: str
    session_epoch: int = Field(gt=0)
    work_item_id: str
    ownership_epoch: int = Field(gt=0)
    execution_lease_id: str
    execution_lease_expires_at: AwareDatetime
    allowed_tools: tuple[str, ...] = ()
    allowed_resources: tuple[str, ...] = ()
    allowed_operations: tuple[str, ...] = ()
    budget: ResourceBudget = Field(default_factory=ResourceBudget)
    issued_at: AwareDatetime
    expires_at: AwareDatetime
    approval_id: str | None = None

    @model_validator(mode="after")
    def expiry_is_bounded_by_execution_lease(self) -> CapabilityGrant:
        if self.expires_at <= self.issued_at:
            raise ValueError("capability token expiry must follow issuance")
        if self.execution_lease_expires_at <= self.issued_at:
            raise ValueError("Execution Lease must be live when capability token is issued")
        if self.expires_at > self.execution_lease_expires_at:
            raise ValueError("capability token expiry exceeds its Execution Lease")
        return self


@dataclass(frozen=True, slots=True)
class IssuedCapabilityGrant:
    claims: CapabilityGrant
    token: str


class AuthorizationService:
    """Issues short-lived capability tokens fenced by session, ownership, and lease."""

    def __init__(
        self,
        secret: bytes | None = None,
        *,
        maximum_ttl: timedelta = timedelta(minutes=15),
    ) -> None:
        if maximum_ttl <= timedelta(0):
            raise ValueError("maximum capability token TTL must be positive")
        self._secret = secret or secrets.token_bytes(32)
        self._maximum_ttl = maximum_ttl

    def issue(
        self,
        *,
        worker_id: str,
        session_epoch: int,
        work_item_id: str,
        ownership_epoch: int,
        execution_lease: ExecutionLease,
        ttl: timedelta,
        allowed_tools: tuple[str, ...] = (),
        allowed_resources: tuple[str, ...] = (),
        allowed_operations: tuple[str, ...] = (),
        budget: ResourceBudget | None = None,
        high_risk: bool = False,
        approval_id: str | None = None,
        now: datetime | None = None,
    ) -> IssuedCapabilityGrant:
        if (
            high_risk
            or approval_id is not None
            or any(_requires_human_approval(operation) for operation in allowed_operations)
        ):
            raise PolicyError(
                "high-risk capability tokens require validated ExecutionAuthorization"
            )
        return self._issue(
            worker_id=worker_id,
            session_epoch=session_epoch,
            work_item_id=work_item_id,
            ownership_epoch=ownership_epoch,
            execution_lease=execution_lease,
            ttl=ttl,
            allowed_tools=allowed_tools,
            allowed_resources=allowed_resources,
            allowed_operations=allowed_operations,
            budget=budget,
            approval_id=None,
            expires_at_limit=None,
            now=now,
        )

    def _issue(
        self,
        *,
        worker_id: str,
        session_epoch: int,
        work_item_id: str,
        ownership_epoch: int,
        execution_lease: ExecutionLease,
        ttl: timedelta,
        allowed_tools: tuple[str, ...],
        allowed_resources: tuple[str, ...],
        allowed_operations: tuple[str, ...],
        budget: ResourceBudget | None,
        approval_id: str | None,
        expires_at_limit: datetime | None,
        now: datetime | None,
    ) -> IssuedCapabilityGrant:
        _validated_ttl(ttl, self._maximum_ttl)
        issued_at = _aware_utc(now or datetime.now(UTC), "capability token issue time")
        self._validate_live_lease(
            execution_lease,
            worker_id=worker_id,
            session_epoch=session_epoch,
            work_item_id=work_item_id,
            ownership_epoch=ownership_epoch,
            now=issued_at,
        )
        lease_expiry = _aware_utc(execution_lease.expires_at, "Execution Lease expiry")
        expires_at = issued_at + ttl
        if expires_at > lease_expiry:
            raise PolicyError("capability token expiry exceeds its Execution Lease")
        if expires_at_limit is not None:
            approval_expiry = _aware_utc(expires_at_limit, "Execution Approval expiry")
            if expires_at > approval_expiry:
                raise PolicyError("capability token expiry exceeds its Execution Approval")
        claims = CapabilityGrant(
            grant_id=secrets.token_urlsafe(16),
            worker_id=worker_id,
            session_epoch=session_epoch,
            work_item_id=work_item_id,
            ownership_epoch=ownership_epoch,
            execution_lease_id=execution_lease.lease_id,
            execution_lease_expires_at=lease_expiry,
            allowed_tools=allowed_tools,
            allowed_resources=allowed_resources,
            allowed_operations=allowed_operations,
            budget=budget or ResourceBudget(),
            issued_at=issued_at,
            expires_at=expires_at,
            approval_id=approval_id,
        )
        return IssuedCapabilityGrant(claims, _encode_token(claims, self._secret))

    def verify(
        self,
        token: str,
        *,
        worker_id: str,
        session_epoch: int,
        work_item_id: str,
        ownership_epoch: int,
        execution_lease: ExecutionLease,
        operation: str | None = None,
        now: datetime | None = None,
    ) -> CapabilityGrant:
        claims = _decode_token(token, self._secret, CapabilityGrant, label="capability")
        current = _aware_utc(now or datetime.now(UTC), "capability verification time")
        self._validate_live_lease(
            execution_lease,
            worker_id=worker_id,
            session_epoch=session_epoch,
            work_item_id=work_item_id,
            ownership_epoch=ownership_epoch,
            now=current,
        )
        if claims.expires_at <= current:
            raise PolicyError("capability token expired")
        if claims.execution_lease_expires_at <= current:
            raise PolicyError("capability token Execution Lease expired")
        if claims.worker_id != worker_id or claims.work_item_id != work_item_id:
            raise PolicyError("capability token scope mismatch")
        if claims.session_epoch != session_epoch:
            raise PolicyError("stale capability token Session Epoch")
        if claims.ownership_epoch != ownership_epoch:
            raise PolicyError("stale capability token ownership epoch")
        if claims.execution_lease_id != execution_lease.lease_id:
            raise PolicyError("stale capability token Execution Lease ID")
        if claims.execution_lease_expires_at > execution_lease.expires_at:
            raise PolicyError("capability token outlives the current Execution Lease")
        if operation is not None and operation not in claims.allowed_operations:
            raise PolicyError("operation is outside capability token scope")
        return claims

    @staticmethod
    def _validate_live_lease(
        lease: ExecutionLease,
        *,
        worker_id: str,
        session_epoch: int,
        work_item_id: str,
        ownership_epoch: int,
        now: datetime,
    ) -> None:
        if lease.state is not LeaseState.ACTIVE or lease.expires_at <= now:
            raise PolicyError("Execution Lease is not active")
        if lease.holder_agent_id != worker_id or lease.work_item_id != work_item_id:
            raise PolicyError("Execution Lease scope mismatch")
        if lease.session_epoch != session_epoch:
            raise PolicyError("stale Execution Lease Session Epoch")
        if lease.ownership_epoch != ownership_epoch:
            raise PolicyError("stale Execution Lease ownership epoch")


class AuthoritativePolicyReader(Protocol):
    """Read-only Core seam needed for execution authorization decisions."""

    async def query(self, query: Query) -> object: ...

    async def replay(
        self,
        group_id: str,
        *,
        after: int = 0,
        limit: int = 1_000,
    ) -> tuple[Event, ...]: ...


PublicKeyResolver = Callable[[Principal], PublicKeyLike | None]
Clock = Callable[[], datetime]


class ExecutionAuthorization:
    """Validates live Core state before issuing an execution capability token."""

    def __init__(
        self,
        core: AuthoritativePolicyReader,
        authorization: AuthorizationService,
        *,
        approval_key_resolver: PublicKeyResolver,
        policy: PolicyGuard | None = None,
        clock: Clock | None = None,
    ) -> None:
        self._core = core
        self._authorization = authorization
        self._approval_key_resolver = approval_key_resolver
        self._policy = policy or PolicyGuard(CooperationLimits())
        self._clock = clock or (lambda: datetime.now(UTC))

    async def issue(
        self,
        *,
        worker_id: str,
        session_epoch: int,
        work_item_id: str,
        ownership_epoch: int,
        ttl: timedelta,
        allowed_tools: tuple[str, ...] = (),
        allowed_resources: tuple[str, ...] = (),
        allowed_operations: tuple[str, ...] = (),
        budget: ResourceBudget | None = None,
        approval_id: str | None = None,
    ) -> IssuedCapabilityGrant:
        now = _aware_utc(self._clock(), "ExecutionAuthorization clock")
        work = await self._work_item(work_item_id)
        mission = await self._mission(work.mission_id)
        authoritative_session = await self._core.query(
            Query(kind=QueryKind.SESSION_EPOCH, entity_id=worker_id)
        )
        if not isinstance(authoritative_session, int) or authoritative_session != session_epoch:
            raise PolicyError("stale Agent Session Epoch")
        if work.assignee_id != worker_id:
            raise PolicyError("Worker does not own the WorkItem")
        if work.ownership_epoch != ownership_epoch:
            raise PolicyError("stale WorkItem Ownership Epoch")
        if work.status is not WorkItemStatus.ACTIVE:
            raise PolicyError("WorkItem is not active for execution authorization")
        if work.ownership_lease_expires_at is None or work.ownership_lease_expires_at <= now:
            raise PolicyError("WorkItem ownership lease expired")
        if work.execution_lease_id is None:
            raise PolicyError("WorkItem has no authoritative Execution Lease")
        execution_lease = await self._execution_lease(work.execution_lease_id)
        if (
            execution_lease.mission_id != mission.id
            or execution_lease.group_id != mission.group_id
            or execution_lease.work_item_id != work.id
            or execution_lease.holder_agent_id != worker_id
            or execution_lease.session_epoch != session_epoch
            or execution_lease.ownership_epoch != ownership_epoch
            or execution_lease.state is not LeaseState.ACTIVE
            or execution_lease.expires_at <= now
            or work.execution_lease_expires_at != execution_lease.expires_at
        ):
            raise PolicyError("authoritative Execution Lease scope is stale or inconsistent")
        if not set(allowed_tools).issubset(work.contract.allowed_tools):
            raise PolicyError("requested tools exceed the Work Contract")
        if not set(allowed_resources).issubset(work.contract.allowed_resources):
            raise PolicyError("requested resources exceed the Work Contract")
        if not set(allowed_operations).issubset(mission.permissions):
            raise PolicyError("requested operations exceed Mission permissions")
        remaining_value = await self._core.query(
            Query(kind=QueryKind.BUDGET_REMAINING, entity_id=work.id)
        )
        if not isinstance(remaining_value, ResourceBudget):
            raise PolicyError("authoritative remaining budget is unavailable")
        requested_budget = remaining_value if budget is None else budget
        if not work.contract.budget.contains(requested_budget):
            raise PolicyError("requested capability budget exceeds the Work Contract")
        if not remaining_value.contains(requested_budget):
            raise PolicyError("requested capability budget exceeds authoritative remaining budget")

        policy_high_risk = any(
            self._policy.classify_action(operation) == "human_approval_required"
            for operation in allowed_operations
        )
        contract_requires_approval = work.contract.execution_approval != "not_required"
        approval_required = policy_high_risk or contract_requires_approval
        validated_approval_id: str | None = None
        approval_expiry: datetime | None = None
        if approval_required:
            if approval_id is None:
                raise PolicyError("high-risk execution requires a persisted signed Approval")
            approval = await self._validate_approval(
                approval_id,
                mission,
                work,
                operations=allowed_operations,
                resources=allowed_resources,
                budget=requested_budget,
                now=now,
            )
            validated_approval_id = approval_id
            approval_expiry = approval.expires_at
        elif approval_id is not None:
            raise PolicyError("Approval may only be attached to a high-risk capability token")

        return self._authorization._issue(
            worker_id=worker_id,
            session_epoch=session_epoch,
            work_item_id=work.id,
            ownership_epoch=ownership_epoch,
            execution_lease=execution_lease,
            ttl=ttl,
            allowed_tools=allowed_tools,
            allowed_resources=allowed_resources,
            allowed_operations=allowed_operations,
            budget=requested_budget,
            approval_id=validated_approval_id,
            expires_at_limit=approval_expiry,
            now=now,
        )

    async def _work_item(self, work_item_id: str) -> WorkItem:
        value = await self._core.query(Query(kind=QueryKind.WORK_ITEM, entity_id=work_item_id))
        if not isinstance(value, WorkItem):
            raise PolicyError("WorkItem does not exist")
        return value

    async def _mission(self, mission_id: str) -> Mission:
        value = await self._core.query(Query(kind=QueryKind.MISSION, entity_id=mission_id))
        if not isinstance(value, Mission):
            raise PolicyError("Mission does not exist")
        return value

    async def _execution_lease(self, lease_id: str) -> ExecutionLease:
        value = await self._core.query(Query(kind=QueryKind.EXECUTION_LEASE, entity_id=lease_id))
        if not isinstance(value, ExecutionLease):
            raise PolicyError("Execution Lease does not exist")
        return value

    async def _validate_approval(
        self,
        approval_id: str,
        mission: Mission,
        work: WorkItem,
        *,
        operations: tuple[str, ...],
        resources: tuple[str, ...],
        budget: ResourceBudget,
        now: datetime,
    ) -> ExecutionApproval:
        value = await self._core.query(
            Query(kind=QueryKind.EXECUTION_APPROVAL, entity_id=approval_id)
        )
        if (
            not isinstance(value, ExecutionApproval)
            or value.mission_id != mission.id
            or value.work_item_id != work.id
        ):
            raise PolicyError(
                "high-risk Execution Approval is missing or belongs to another WorkItem"
            )
        if value.ownership_epoch != work.ownership_epoch:
            raise PolicyError("high-risk Execution Approval targets stale ownership")
        if value.expires_at <= now:
            raise PolicyError("high-risk Execution Approval expired")
        if not set(operations).issubset(value.operations):
            raise PolicyError("requested operations exceed the Execution Approval")
        if not set(resources).issubset(value.resources):
            raise PolicyError("requested resources exceed the Execution Approval")
        if not value.budget.contains(budget):
            raise PolicyError("requested budget exceeds the Execution Approval")
        if value.approver.type is not ActorType.HUMAN:
            raise PolicyError("high-risk Approval must be signed by a human")

        event = await self._approval_event(mission.group_id, approval_id)
        command_value = await self._core.query(Query(kind=QueryKind.COMMAND, entity_id=event.id))
        if not isinstance(command_value, Command):
            raise PolicyError("Approval has no persisted accepted Command")
        command = command_value
        if (
            command.kind is not CommandKind.GRANT_EXECUTION_APPROVAL
            or command.actor != value.approver
            or command.group_id != mission.group_id
            or command.signature != value.signature
        ):
            raise PolicyError("persisted Approval does not match its accepted Command")
        try:
            payload = GrantExecutionApprovalPayload.model_validate(command.payload)
        except ValidationError as error:
            raise PolicyError("persisted Approval Command payload is invalid") from error
        if (
            payload.approval_id != value.id
            or payload.work_item_id != value.work_item_id
            or payload.ownership_epoch != value.ownership_epoch
            or set(payload.operations) != set(value.operations)
            or set(payload.resources) != set(value.resources)
            or payload.budget != value.budget
        ):
            raise PolicyError("persisted Approval claims do not match its Command")
        public_key = self._approval_key_resolver(value.approver)
        signature = command.signature
        if (
            public_key is None
            or signature is None
            or not verify_canonical(command.signing_payload(), signature, public_key)
        ):
            raise PolicyError("persisted high-risk Approval signature is invalid")
        return value

    async def _approval_event(self, group_id: str, approval_id: str) -> Event:
        events = await self._core.replay(group_id)
        for event in reversed(events):
            if event.kind is not EventKind.EXECUTION_APPROVAL_GRANTED:
                continue
            raw = event.payload.get("approval")
            if isinstance(raw, Mapping) and raw.get("id") == approval_id:
                return event
        raise PolicyError("Approval is not present in the authoritative Group history")


class BudgetMeter:
    """Tracks usage against one capability grant without silently exceeding limits."""

    def __init__(self, limit: ResourceBudget) -> None:
        self.limit = limit
        self.usage = ResourceUsage()

    def consume(self, delta: ResourceUsage) -> ResourceUsage:
        next_usage = ResourceUsage(
            **{
                field_name: getattr(self.usage, field_name) + getattr(delta, field_name)
                for field_name in ResourceUsage.model_fields
            }
        )
        for field_name in ResourceUsage.model_fields:
            limit = getattr(self.limit, field_name)
            used = getattr(next_usage, field_name)
            if used > 0 and limit is None:
                raise PolicyError(f"resource budget is not allocated: {field_name}")
            if limit is not None and used > limit:
                raise PolicyError(f"resource budget exceeded: {field_name}")
        self.usage = next_usage
        return self.usage


class CooperationLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    maximum_delegation_depth: int = Field(default=3, ge=0)
    maximum_queued_work_items: int = Field(default=100, ge=1)
    maximum_active_work_items: int = Field(default=4, ge=1)
    maximum_unresolved_clarifications: int = Field(default=5, ge=0)
    maximum_message_rate_per_minute: int = Field(default=120, ge=1)
    maximum_proposal_rate_per_minute: int = Field(default=30, ge=1)
    maximum_clarification_rate_per_minute: int = Field(default=30, ge=1)


class PolicyGuard:
    """Stateful local guardrails; authoritative escalation is handled by Core grants."""

    def __init__(self, limits: CooperationLimits) -> None:
        self.limits = limits
        self._rate_events: dict[tuple[str, str, str], deque[datetime]] = {}
        self._lock = RLock()

    def check_delegation_depth(self, depth: int) -> None:
        if depth < 0:
            raise PolicyError("delegation depth cannot be negative")
        if depth > self.limits.maximum_delegation_depth:
            raise PolicyError("delegation depth requires MissionOwner or policy approval")

    def check_queue(
        self,
        queued: int,
        active: int,
    ) -> None:
        if queued < 0 or active < 0:
            raise PolicyError("Worker queue counts cannot be negative")
        if queued > self.limits.maximum_queued_work_items:
            raise PolicyError("Worker queue limit requires approved escalation")
        if active > self.limits.maximum_active_work_items:
            raise PolicyError("Worker active-work limit requires approved escalation")

    def check_unresolved_clarifications(
        self,
        unresolved: int,
    ) -> None:
        if unresolved < 0:
            raise PolicyError("unresolved clarification count cannot be negative")
        if unresolved > self.limits.maximum_unresolved_clarifications:
            raise PolicyError("clarification limit requires approved escalation")

    def check_message_rate(
        self,
        principal_id: str,
        group_id: str,
        *,
        now: datetime | None = None,
    ) -> None:
        self._check_rate(
            "message",
            principal_id,
            group_id,
            self.limits.maximum_message_rate_per_minute,
            now=now,
        )

    def check_proposal_rate(
        self,
        principal_id: str,
        group_id: str,
        *,
        now: datetime | None = None,
    ) -> None:
        self._check_rate(
            "proposal",
            principal_id,
            group_id,
            self.limits.maximum_proposal_rate_per_minute,
            now=now,
        )

    def check_clarification_rate(
        self,
        principal_id: str,
        group_id: str,
        *,
        now: datetime | None = None,
    ) -> None:
        self._check_rate(
            "clarification",
            principal_id,
            group_id,
            self.limits.maximum_clarification_rate_per_minute,
            now=now,
        )

    def _check_rate(
        self,
        kind: str,
        principal_id: str,
        group_id: str,
        limit: int,
        *,
        now: datetime | None,
    ) -> None:
        current = _aware_utc(now or datetime.now(UTC), f"{kind} rate-check time")
        cutoff = current - timedelta(minutes=1)
        key = (kind, principal_id, group_id)
        with self._lock:
            events = self._rate_events.setdefault(key, deque())
            while events and events[0] <= cutoff:
                events.popleft()
            if len(events) >= limit:
                raise PolicyError(f"{kind} rate limit requires approved escalation")
            events.append(current)

    def classify_action(self, operation: str) -> Literal["automatic", "human_approval_required"]:
        return "human_approval_required" if _requires_human_approval(operation) else "automatic"


__all__ = [
    "AuthoritativePolicyReader",
    "AuthorizationService",
    "BudgetMeter",
    "CapabilityGrant",
    "CooperationLimits",
    "ExecutionAuthorization",
    "IssuedCapabilityGrant",
    "IssuedMembershipToken",
    "MembershipTokenClaims",
    "MembershipTokenService",
    "PolicyError",
    "PolicyGuard",
    "ResourceUsage",
]
