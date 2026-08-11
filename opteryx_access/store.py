"""Where permissions are granted, updated, and revoked.

Ported from policy.opteryx/control.opteryx's `app/routes/v1/access.py`
(`create_policy`, `update_policy`, `delete_policy`, `create_genesis_policies`),
which is where these rules previously lived -- duplicated byte-for-byte
between the two repos (see control.opteryx's `docs/design/consolidation.md`).

This module owns the *policy invariants* -- role validity, the
wildcard/reserved-resource rules, the no-self-service rule, requiring the
actor's own administrative authority to cover the pattern being touched, and
conflict detection against what the principal already holds -- plus the
storage call to apply the change. It deliberately does NOT own:

- Whether the principal or the resource named in the request actually
  exist, or whether the principal is currently active/blocked. Those are
  lookups against each service's own user directory and catalog, not a
  permissions concern -- call them before invoking `grant()` and let a
  failure there short-circuit before this module is reached.
- Any age-gate / billing-eligibility rule, HTTP status mapping, or audit
  logging -- transport and platform-policy concerns that belong to the
  caller, which already knows what request it received and what it needs to
  tell the client or write to its audit sink. Catch the exceptions this
  module raises and translate them there.
"""

from collections.abc import Iterable
from typing import Protocol
from typing import runtime_checkable

from opteryx_access.checks import can_administer_pattern
from opteryx_access.exceptions import AccessDeniedError
from opteryx_access.exceptions import InvalidRoleError
from opteryx_access.exceptions import PolicyConflictError
from opteryx_access.exceptions import PolicyNotFoundError
from opteryx_access.exceptions import SelfAccessError
from opteryx_access.exceptions import WorkspaceAlreadyBootstrappedError
from opteryx_access.models import Policy
from opteryx_access.patterns import WILDCARD_PRINCIPAL
from opteryx_access.patterns import resource_matches
from opteryx_access.patterns import validate_pattern_does_not_target_reserved_resource
from opteryx_access.patterns import validate_wildcard_rule
from opteryx_access.roles import ROLES
from opteryx_access.roles import role_outranks_or_equals


@runtime_checkable
class PolicyStore(Protocol):
    """What a storage backend must provide. See `opteryx_access.adapters` for
    a Firestore implementation matching the layout policy.opteryx/control.opteryx
    already use (`{workspace}/$policies/access`)."""

    def list_policies(self, workspace: str) -> list[Policy]:
        """Every policy document currently stored for `workspace`."""
        ...

    def get_policy(self, workspace: str, policy_id: str) -> Policy | None:
        """The policy document `policy_id` in `workspace`, or None if absent."""
        ...

    def create_policy(self, workspace: str, policy: Policy) -> str:
        """Persist a new policy document, returning its assigned id."""
        ...

    def update_policy(
        self, workspace: str, policy_id: str, *, role: str, pattern: str, updated_by: str
    ) -> None:
        """Update an existing policy document's role and pattern in place."""
        ...

    def delete_policy(self, workspace: str, policy_id: str) -> None:
        """Remove a policy document."""
        ...


def _validate_role(role: str) -> None:
    if role not in ROLES:
        raise InvalidRoleError(f"invalid role {role!r}, must be one of: {', '.join(ROLES)}")


def find_conflict(
    policies: Iterable[Policy], principal: str, pattern: str, role: str
) -> str | None:
    """Whether granting `role` on `pattern` to `principal` conflicts with a
    policy that principal already holds.

    Two shapes of conflict are rejected:

    - The principal already has a policy on this *exact* pattern. Two
      separate policy documents for the same (principal, pattern) pair is
      always a bug -- whichever role is correct should be reached by
      updating or revoking the existing policy, not layering a second
      document on top of it.
    - The principal already has a policy on a pattern that is a broader
      ancestor of this one (e.g. `analytics.*` already covers
      `analytics.sales.q1`) at a role that is already as privileged, or more
      privileged, than the one being requested. The new grant would be
      entirely redundant. A *more* privileged role on the narrower pattern is
      legitimate (it elevates access on that one resource beyond the general
      grant) and is not flagged.

    Returns a human-readable reason if a conflict exists, else None.
    """
    for policy in policies:
        if policy.principal not in (principal, WILDCARD_PRINCIPAL):
            continue

        if policy.pattern == pattern:
            return (
                f"{principal!r} already has a {policy.role!r} policy on {pattern!r} "
                f"(policy {policy.policy_id}) -- revoke or update that policy instead of "
                "creating a new one"
            )

        if resource_matches(pattern, policy.pattern) and role_outranks_or_equals(policy.role, role):
            return (
                f"{principal!r} already has {policy.role!r} via the broader pattern "
                f"{policy.pattern!r} (policy {policy.policy_id}), which already covers "
                f"{pattern!r} at an equal or higher level -- revoke that policy first if a "
                "different role is needed here"
            )

    return None


def grant(
    store: PolicyStore,
    *,
    actor: str,
    workspace: str,
    principal: str,
    role: str,
    pattern: str,
) -> str:
    """Grant `role` on `pattern` to `principal` in `workspace`. Returns the new policy id.

    Raises:
        InvalidRoleError: `role` is not one of `opteryx_access.roles.ROLES`.
        InvalidPatternError: `pattern` breaks the wildcard-principal rule or
            targets a reserved resource.
        SelfAccessError: `actor == principal` -- nobody may grant themselves
            access, regardless of what authority they otherwise hold; ask
            another owner/admin to do it.
        AccessDeniedError: `actor` lacks owner/admin authority covering
            `pattern` (see `opteryx_access.checks.can_administer_pattern`).
        PolicyConflictError: see `find_conflict`.
    """
    _validate_role(role)
    validate_wildcard_rule(principal, pattern)
    validate_pattern_does_not_target_reserved_resource(pattern)

    if principal == actor:
        raise SelfAccessError(
            "you cannot grant yourself access; ask another owner or admin to do it"
        )

    existing = store.list_policies(workspace)

    if not can_administer_pattern(existing, actor, pattern):
        raise AccessDeniedError("insufficient permissions to create a policy for this pattern")

    conflict = find_conflict(existing, principal, pattern, role)
    if conflict:
        raise PolicyConflictError(conflict)

    return store.create_policy(
        workspace, Policy(principal=principal, role=role, pattern=pattern, updated_by=actor)
    )


def update_grant(
    store: PolicyStore,
    *,
    actor: str,
    workspace: str,
    policy_id: str,
    role: str,
    pattern: str,
) -> None:
    """Update policy `policy_id` in `workspace` to grant `role` on `pattern`.

    The request carries no principal -- an update could otherwise widen an
    existing wildcard-principal policy's pattern into a glob, so the new
    pattern is checked against the principal already stored on the document.

    Raises:
        PolicyNotFoundError, InvalidRoleError, InvalidPatternError: as above.
        SelfAccessError: the policy belongs to `actor` -- nobody may modify
            their own access.
        AccessDeniedError: `actor` lacks owner/admin authority covering
            EITHER the policy's current pattern or the requested new one --
            otherwise a grantor could edit a policy scoped to a pattern they
            don't govern, or use the edit to move it under one they don't.
    """
    _validate_role(role)

    existing_policy = store.get_policy(workspace, policy_id)
    if existing_policy is None:
        raise PolicyNotFoundError(f"policy {policy_id!r} not found in workspace {workspace!r}")

    if existing_policy.principal == actor:
        raise SelfAccessError(
            "you cannot modify your own access; ask another owner or admin to do it"
        )

    all_policies = store.list_policies(workspace)
    if not can_administer_pattern(
        all_policies, actor, existing_policy.pattern
    ) or not can_administer_pattern(all_policies, actor, pattern):
        raise AccessDeniedError("insufficient permissions to update this policy")

    validate_wildcard_rule(existing_policy.principal, pattern)
    validate_pattern_does_not_target_reserved_resource(pattern)

    store.update_policy(workspace, policy_id, role=role, pattern=pattern, updated_by=actor)


def revoke(store: PolicyStore, *, actor: str, workspace: str, policy_id: str) -> None:
    """Revoke policy `policy_id` in `workspace`.

    Raises:
        PolicyNotFoundError: no such policy.
        SelfAccessError: the policy belongs to `actor` -- nobody may revoke
            their own access.
        AccessDeniedError: `actor` lacks owner/admin authority covering the
            policy's pattern -- not just anywhere in the workspace.
    """
    existing_policy = store.get_policy(workspace, policy_id)
    if existing_policy is None:
        raise PolicyNotFoundError(f"policy {policy_id!r} not found in workspace {workspace!r}")

    if existing_policy.principal == actor:
        raise SelfAccessError(
            "you cannot revoke your own access; ask another owner or admin to do it"
        )

    all_policies = store.list_policies(workspace)
    if not can_administer_pattern(all_policies, actor, existing_policy.pattern):
        raise AccessDeniedError("insufficient permissions to delete this policy")

    store.delete_policy(workspace, policy_id)


def bootstrap_workspace(
    store: PolicyStore,
    *,
    actor: str,
    workspace: str,
    grants: Iterable[tuple],
) -> list[str]:
    """Create the initial policies for a brand-new workspace, one per
    `(principal, role)` pair in `grants`, each scoped to the whole workspace
    (`{workspace}.*`).

    A trusted, one-time bootstrap: whatever creates the workspace record in
    the first place hands it an explicit member list at creation time, rather
    than every caller becoming sole owner. Unlike `grant()`, this skips the
    self-grant, pattern-authority, and conflict checks -- a genuinely new
    workspace has no existing owner to protect and nothing for a new grant to
    conflict with; those checks only make sense once one exists.

    Raises:
        InvalidRoleError, InvalidPatternError: as above, checked for every
            grant up front, before writing any of them -- a bad entry partway
            through the list must not leave a partially-bootstrapped
            workspace behind.
        WorkspaceAlreadyBootstrappedError: `workspace` already has at least
            one policy. This can only be used once, to bootstrap a workspace
            that doesn't have policies yet -- not to add owners to one that
            already does, which would let anyone holding a valid token mint
            themselves a fresh owner grant with none of `grant()`'s checks.
    """
    pattern = f"{workspace}.*"
    validate_pattern_does_not_target_reserved_resource(pattern)

    grants = list(grants)
    for principal, role in grants:
        _validate_role(role)
        validate_wildcard_rule(principal, pattern)

    if store.list_policies(workspace):
        raise WorkspaceAlreadyBootstrappedError(
            f"workspace {workspace!r} already has access policies; bootstrap_workspace can only "
            "be used on a brand-new workspace"
        )

    return [
        store.create_policy(
            workspace, Policy(principal=principal, role=role, pattern=pattern, updated_by=actor)
        )
        for principal, role in grants
    ]
