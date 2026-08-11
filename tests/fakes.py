"""An in-memory PolicyStore for tests -- no Firestore required."""

import itertools

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
