"""The storage contract: what a backend has to provide, and nothing else.

This module is the data-access boundary. It declares operations in terms of
`Policy` documents and says nothing about when any of them may be called --
no role checks, no pattern validation, no self-service rule. Those live in
`opteryx_access.grants`, which is the only thing that should be calling a
store to mutate anything.

An implementation is therefore free to be a dumb translation to its backend,
and must be: a store that quietly filtered out policies it considered invalid,
or refused a write it thought was unauthorized, would be enforcing policy in
a second place, where none of the tests for those rules can see it.

See `opteryx_access.adapters.firestore` for an implementation over the
`{workspace}/$policies/access` layout policy.opteryx/control.opteryx already
use.
"""

from typing import Protocol
from typing import runtime_checkable

from opteryx_access.models import Policy


@runtime_checkable
class PolicyStore(Protocol):
    """Persistence for access-policy documents, scoped to a workspace."""

    def list_policies(self, workspace: str) -> list[Policy]:
        """Every policy currently stored for `workspace`.

        For callers that genuinely want the whole set -- a policy-list screen,
        an effective-permissions export. Anything narrowing to one principal
        should use `list_policies_for_principal` instead.
        """
        ...

    def list_policies_for_principal(self, workspace: str, principal: str) -> list[Policy]:
        """Only the policies in `workspace` issued to `principal`.

        Implementations must push the filter down to the backend rather than
        reading the workspace and discarding most of it: a workspace's policy
        list grows with its membership, and this is read on every mutation.
        """
        ...

    def list_owner_policies(self, principal: str) -> list[Policy]:
        """Every policy, in any workspace, that makes `principal` an owner.

        The one operation here that is not workspace-scoped, and deliberately
        the only cross-workspace one: it answers "what would become unowned if
        this identity went away", which is the question offboarding has to ask
        before anyone is removed. Returned policies carry their `workspace`.

        Not a general cross-workspace policy dump -- "where can this user
        read" has no action attached to it, and supporting it would widen both
        this contract and the indexes a backend needs.
        """
        ...

    def has_any_policies(self, workspace: str) -> bool:
        """Whether `workspace` has at least one policy.

        Separate from `list_policies` so the answer costs one row rather than
        the whole workspace -- it gates workspace bootstrap, where the
        expected answer is "no" and the interesting case is a workspace that
        has grown since.
        """
        ...

    def get_policy(self, workspace: str, policy_id: str) -> Policy | None:
        """The policy `policy_id` in `workspace`, or None if there is no such document."""
        ...

    def create_policy(self, workspace: str, policy: Policy) -> str:
        """Persist a new policy document, returning its assigned id."""
        ...

    def update_policy(
        self, workspace: str, policy_id: str, *, role: str, pattern: str, updated_by: str
    ) -> None:
        """Update an existing policy's role and pattern in place.

        The principal is not updatable: re-pointing a policy at someone else
        is a revoke and a grant, each of which has its own rules to clear.
        """
        ...

    def delete_policy(self, workspace: str, policy_id: str) -> None:
        """Remove a policy document."""
        ...
