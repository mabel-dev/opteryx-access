"""An in-memory PolicyStore for tests -- no Firestore required."""

import itertools
from dataclasses import replace

from opteryx_access.actions import action_allowed_for_role
from opteryx_access.models import Policy


class FakePolicyStore:
    def __init__(self) -> None:
        self._by_workspace: dict[str, dict[str, Policy]] = {}
        self._ids = itertools.count(1)

    def seed(self, workspace: str, policy: Policy) -> str:
        policy_id = policy.policy_id or f"policy-{next(self._ids)}"
        policy.policy_id = policy_id
        self._by_workspace.setdefault(workspace, {})[policy_id] = policy
        return policy_id

    def list_policies(self, workspace: str) -> list[Policy]:
        return list(self._by_workspace.get(workspace, {}).values())

    def list_policies_for_principal(self, workspace: str, principal: str) -> list[Policy]:
        # Filters from the backing store directly rather than via
        # `list_policies`, mirroring a real backend that pushes the predicate
        # down -- so a test can tell the two access paths apart.
        return [
            policy
            for policy in self._by_workspace.get(workspace, {}).values()
            if policy.principal == principal
        ]

    def has_any_policies(self, workspace: str) -> bool:
        return bool(self._by_workspace.get(workspace))

    def list_owner_policies(self, principal: str) -> list[Policy]:
        return [
            replace(policy, workspace=workspace)
            for workspace, policies in self._by_workspace.items()
            for policy in policies.values()
            if policy.principal == principal and action_allowed_for_role(policy.role, "GRANT")
        ]

    def get_policy(self, workspace: str, policy_id: str) -> Policy | None:
        return self._by_workspace.get(workspace, {}).get(policy_id)

    def create_policy(self, workspace: str, policy: Policy) -> str:
        return self.seed(workspace, policy)

    def update_policy(
        self, workspace: str, policy_id: str, *, role: str, pattern: str, updated_by: str
    ) -> None:
        policy = self._by_workspace[workspace][policy_id]
        policy.role = role
        policy.pattern = pattern
        policy.updated_by = updated_by

    def delete_policy(self, workspace: str, policy_id: str) -> None:
        del self._by_workspace[workspace][policy_id]
