"""Scoped authoritative Delegation Grant validation."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from enum import StrEnum

from missionweaveprotocol.models import (
    ActorType,
    DelegationGrant,
    Membership,
    MembershipStatus,
    Mission,
    Principal,
    ResourceBudget,
    Role,
    WorkContract,
    WorkItem,
    WorkItemStatus,
)


class DelegationViolationKind(StrEnum):
    IDENTITY = "identity"
    MEMBERSHIP = "membership"
    MEMBERSHIP_EPOCH = "membership_epoch"
    SCOPE = "scope"
    CAPABILITY = "capability"
    BUDGET = "budget"
    DEPTH = "depth"
    COORDINATOR_EPOCH = "coordinator_epoch"
    EXPIRED = "expired"


class DelegationViolation(ValueError):
    """A stored Delegation Grant does not authorize one requested use."""

    def __init__(self, kind: DelegationViolationKind, message: str) -> None:
        super().__init__(message)
        self.kind = kind


def budget_within_ceiling(candidate: ResourceBudget, ceiling: ResourceBudget) -> bool:
    """Return whether every explicit candidate dimension fits its ceiling.

    An omitted candidate dimension consumes zero. An omitted ceiling permits only zero, matching
    authoritative Mission budget semantics without requiring callers to manufacture allocations.
    """

    for field_name in ResourceBudget.model_fields:
        candidate_value = getattr(candidate, field_name) or 0
        ceiling_value = getattr(ceiling, field_name)
        if candidate_value > (ceiling_value if ceiling_value is not None else 0):
            return False
    return True


class DelegationAuthority:
    """Validate all invariants for one stored grant before delegated work changes."""

    def __init__(
        self,
        grant: DelegationGrant,
        *,
        actor: Principal,
        mission: Mission,
        membership: Membership | None,
        work_items: Mapping[str, WorkItem],
        now: datetime,
    ) -> None:
        self.grant = grant
        self._mission = mission
        self._work_items = work_items
        if actor.type is not ActorType.AGENT or actor.id != grant.grantee_agent_id:
            raise DelegationViolation(
                DelegationViolationKind.IDENTITY,
                "Delegation Grant may be used only by its grantee Agent",
            )
        if grant.mission_id != mission.id or grant.group_id != mission.group_id:
            raise DelegationViolation(
                DelegationViolationKind.SCOPE,
                "Delegation Grant belongs to another Mission or Group",
            )
        if membership is None or membership.principal != actor:
            raise DelegationViolation(
                DelegationViolationKind.MEMBERSHIP,
                "Delegation grantee lacks its Group Membership",
            )
        if membership.status is not MembershipStatus.ACTIVE or Role.WORK_DELEGATE not in (
            membership.roles
        ):
            raise DelegationViolation(
                DelegationViolationKind.MEMBERSHIP,
                "Delegation grantee requires an active work_delegate Membership",
            )
        if membership.epoch != grant.grantee_membership_epoch:
            raise DelegationViolation(
                DelegationViolationKind.MEMBERSHIP_EPOCH,
                "Delegation Grant carries a stale grantee Membership epoch",
            )
        if grant.coordinator_epoch != mission.coordinator_epoch:
            raise DelegationViolation(
                DelegationViolationKind.COORDINATOR_EPOCH,
                "Delegation Grant carries a stale Coordinator epoch",
            )
        if grant.granted_by != Principal.agent(mission.coordinator_id):
            raise DelegationViolation(
                DelegationViolationKind.COORDINATOR_EPOCH,
                "Delegation Grant was not issued by the current Coordinator",
            )
        if now < grant.granted_at or now >= grant.expires_at:
            raise DelegationViolation(
                DelegationViolationKind.EXPIRED,
                "Delegation Grant is not currently valid",
            )
        target = work_items.get(grant.target_work_item_id)
        if target is None or target.mission_id != mission.id or target.group_id != mission.group_id:
            raise DelegationViolation(
                DelegationViolationKind.SCOPE,
                "Delegation Grant target WorkItem is missing or outside its Group",
            )
        if target.status in {
            WorkItemStatus.VERIFIED,
            WorkItemStatus.FAILED,
            WorkItemStatus.CANCELLED,
        }:
            raise DelegationViolation(
                DelegationViolationKind.SCOPE,
                "Delegation Grant target WorkItem is terminal",
            )

    def authorize_existing(self, work: WorkItem) -> int:
        """Authorize offering an existing WorkItem, returning its relative scope depth."""

        depth = self._scope_depth(work)
        if work.delegation_grant_id not in {None, self.grant.id}:
            raise DelegationViolation(
                DelegationViolationKind.SCOPE,
                "WorkItem is attributed to another Delegation Grant",
            )
        self._validate_contract(work.contract)
        extra = None if work.delegation_grant_id == self.grant.id else work.contract.budget
        self._validate_cumulative_budget(extra)
        return depth

    def authorize_descendant(self, parent: WorkItem, contract: WorkContract) -> int:
        """Authorize a new child WorkItem and return its absolute delegation depth."""

        relative_depth = self._scope_depth(parent) + 1
        if relative_depth > self.grant.max_descendant_depth:
            raise DelegationViolation(
                DelegationViolationKind.DEPTH,
                "Delegated WorkItem exceeds the Grant's maximum descendant depth",
            )
        self._validate_contract(contract)
        self._validate_cumulative_budget(contract.budget)
        return parent.delegation_depth + 1

    def _scope_depth(self, work: WorkItem) -> int:
        if work.mission_id != self._mission.id or work.group_id != self._mission.group_id:
            raise DelegationViolation(
                DelegationViolationKind.SCOPE,
                "WorkItem belongs to another Mission or Group",
            )
        current = work
        seen: set[str] = set()
        depth = 0
        while True:
            if current.id == self.grant.target_work_item_id:
                if depth > self.grant.max_descendant_depth:
                    raise DelegationViolation(
                        DelegationViolationKind.DEPTH,
                        "WorkItem exceeds the Grant's maximum descendant depth",
                    )
                return depth
            if current.id in seen or current.parent_work_item_id is None:
                raise DelegationViolation(
                    DelegationViolationKind.SCOPE,
                    "WorkItem is outside the Delegation Grant target scope",
                )
            seen.add(current.id)
            parent = self._work_items.get(current.parent_work_item_id)
            if parent is None:
                raise DelegationViolation(
                    DelegationViolationKind.SCOPE,
                    "Delegation scope contains a missing parent WorkItem",
                )
            current = parent
            depth += 1

    def _validate_contract(self, contract: WorkContract) -> None:
        allowed = {
            requirement.id: requirement.minimum_version
            for requirement in self.grant.allowed_capabilities
        }
        for requirement in contract.required_capabilities:
            minimum = allowed.get(requirement.id)
            if minimum is None:
                raise DelegationViolation(
                    DelegationViolationKind.CAPABILITY,
                    f"Capability {requirement.id} is outside the Delegation Grant",
                )
            if requirement.minimum_version < minimum:
                raise DelegationViolation(
                    DelegationViolationKind.CAPABILITY,
                    f"Capability {requirement.id} requires version {minimum} or newer",
                )

    def _validate_cumulative_budget(self, extra: ResourceBudget | None) -> None:
        totals = {field_name: 0 for field_name in ResourceBudget.model_fields}
        for work in self._work_items.values():
            if work.delegation_grant_id != self.grant.id:
                continue
            for field_name in totals:
                totals[field_name] += getattr(work.contract.budget, field_name) or 0
        if extra is not None:
            for field_name in totals:
                totals[field_name] += getattr(extra, field_name) or 0
        for field_name, total in totals.items():
            ceiling = getattr(self.grant.budget, field_name)
            if ceiling is None or total > ceiling:
                raise DelegationViolation(
                    DelegationViolationKind.BUDGET,
                    f"Delegated WorkItems exceed the {field_name} budget ceiling",
                )


__all__ = [
    "DelegationAuthority",
    "DelegationViolation",
    "DelegationViolationKind",
    "budget_within_ceiling",
]
