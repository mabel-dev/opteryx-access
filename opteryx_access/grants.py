"""Granting, revoking, and reading back what someone holds.

Ported from policy.opteryx/control.opteryx's `app/routes/v1/access.py`
(`create_policy`, `update_policy`, `delete_policy`, `create_genesis_policies`),
which is where these rules previously lived -- duplicated byte-for-byte
between the two repos (see control.opteryx's `docs/design/consolidation.md`).

This is the write half of the package, and the only place that mutates a
`PolicyStore`. It owns the rules a change has to clear -- role validity,
principal and pattern validity (see `opteryx_access.patterns`), the
no-self-service rule, requiring the actor's own authority to cover the
pattern being touched, and conflict detection against what the principal
already holds -- and then calls the store, which owns none of them.

Every successful change is recorded through `opteryx_access.audit`, after the
write lands. That belongs here rather than in each caller for the same reason
the rules do: an audit trail assembled by whoever remembers to assemble it is
one refactor away from having a hole in it, and a hole in this particular
trail is invisible until someone needs it.

It deliberately does NOT own:

- Whether the principal or the resource named in the request actually exist,
  or whether the principal is currently active/blocked. Those are lookups
  against each service's own user directory and catalog, not a permissions
  concern -- call them before `grant()` and let a failure there short-circuit
  before this module is reached.
- Any age-gate / billing-eligibility rule, or HTTP status mapping -- transport
  and platform-policy concerns belonging to the caller, which already knows
  what request it received and what it needs to tell the client. Catch the
  exceptions raised here and translate them there.
"""

from collections.abc import Iterable

from opteryx_access.audit import POLICY_CREATED
from opteryx_access.audit import POLICY_DELETED
from opteryx_access.audit import POLICY_UPDATED
from opteryx_access.audit import record_change
from opteryx_access.checks import can_administer_pattern
from opteryx_access.exceptions import AccessDeniedError
from opteryx_access.exceptions import InvalidRoleError
from opteryx_access.exceptions import PolicyConflictError
from opteryx_access.exceptions import PolicyNotFoundError
from opteryx_access.exceptions import SelfAccessError
from opteryx_access.exceptions import WorkspaceAlreadyBootstrappedError
from opteryx_access.models import Grant
from opteryx_access.models import Policy
from opteryx_access.patterns import normalize
from opteryx_access.patterns import resource_matches
from opteryx_access.patterns import validate_pattern
from opteryx_access.patterns import validate_principal
from opteryx_access.roles import ROLES
from opteryx_access.roles import role_outranks_or_equals
from opteryx_access.store import PolicyStore


def _validate_role(role: str) -> None:
    if role not in ROLES:
        raise InvalidRoleError(f"invalid role {role!r}, must be one of: {', '.join(ROLES)}")


def grants_for_principal(store: PolicyStore, *, workspace: str, identity: str) -> list[Grant]:
    """The issued grants that apply to `identity` in `workspace`, ready to
    pass to `opteryx_access.checks.can_perform_action`/`can_perform_workspace_action`.

    The store-backed counterpart to `opteryx_access.models.parse_policy_claim`:
    a JWT's `policies` claim already arrives scoped to its own holder, minted
    that way by whatever issued the token, so there is nothing to filter
    there -- a caller working from live policy state instead of a token has no
    equivalent step of its own, which is what this fills in.

    Deliberately does NOT include `opteryx_access.checks.implicit_grants` --
    those are layered on by the check functions themselves regardless of where
    the issued grants came from. Adding them here too would be redundant, but
    it would also break parity: `parse_policy_claim` never includes them
    either, so having both fetch paths return exactly the issued grants keeps
    them interchangeable.
    """
    return [
        policy.as_grant()
        for policy in store.list_policies_for_principal(workspace, normalize(identity))
    ]


def owned_by(store: PolicyStore, *, identity: str) -> list[Policy]:
    """Every policy, in any workspace, that makes `identity` an owner.

    The question offboarding has to ask before removing someone: what would
    become unowned if this identity went away. A workspace whose last owner is
    deleted cannot be administered by anyone -- nobody left can grant, revoke,
    or hand ownership on -- so this is what tells you which grants have to be
    reassigned first. Each returned `Policy` carries its `workspace`.

    Ownership only. There is deliberately no "everything this identity can
    reach" equivalent: it would mostly return reader rows nobody acts on,
    while being the expensive query shape and widening what a backend has to
    index. If a use for it turns up, it should arrive as its own named
    operation with that use written down, not as a general dump.
    """
    return store.list_owner_policies(normalize(identity))


def find_conflict(
    policies: Iterable[Policy], principal: str, pattern: str, role: str
) -> str | None:
    """Whether granting `role` on `pattern` to `principal` conflicts with a
    policy that principal already holds.

    Two shapes of conflict are rejected:

    - The principal already has a policy on this *exact* pattern. Two separate
      policy documents for the same (principal, pattern) pair is always a bug
      -- whichever role is correct should be reached by updating or revoking
      the existing policy, not layering a second document on top of it.
    - The principal already has a policy on a pattern that is a broader
      ancestor of this one (e.g. `analytics.*` already covers
      `analytics.sales.q1`) at a role that is already as privileged, or more
      privileged, than the one being requested. The new grant would be
      entirely redundant. A *more* privileged role on the narrower pattern is
      legitimate (it elevates access on that one resource beyond the general
      grant) and is not flagged.

    `policies` is expected to be `principal`'s own policies; the principal is
    re-checked here so a mis-scoped fetch cannot make one principal's grants
    look like another's.

    Returns a human-readable reason if a conflict exists, else None.
    """
    principal = normalize(principal)
    for policy in policies:
        if normalize(policy.principal) != principal:
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

    The principal and pattern are stored normalized (see
    `opteryx_access.patterns`), so the same grant written with different
    casing is the same stored policy.

    Raises:
        InvalidRoleError: `role` is not one of `opteryx_access.roles.ROLES`.
        InvalidPatternError: `principal` does not name one individual, or
            `pattern` is not a usable pattern, names no workspace, or targets
            a reserved resource.
        SelfAccessError: `actor == principal` -- nobody may grant themselves
            access, regardless of what authority they otherwise hold; ask
            another owner to do it.
        AccessDeniedError: `actor` lacks owner authority covering `pattern`
            (see `opteryx_access.checks.can_administer_pattern`).
        PolicyConflictError: see `find_conflict`.
    """
    _validate_role(role)
    principal = validate_principal(principal)
    pattern = validate_pattern(pattern)
    actor = normalize(actor)

    if principal == actor:
        raise SelfAccessError("you cannot grant yourself access; ask another owner to do it")

    if not can_administer_pattern(
        store.list_policies_for_principal(workspace, actor), actor, pattern
    ):
        raise AccessDeniedError("insufficient permissions to create a policy for this pattern")

    conflict = find_conflict(
        store.list_policies_for_principal(workspace, principal), principal, pattern, role
    )
    if conflict:
        raise PolicyConflictError(conflict)

    policy_id = store.create_policy(
        workspace, Policy(principal=principal, role=role, pattern=pattern, updated_by=actor)
    )
    record_change(
        POLICY_CREATED,
        actor=actor,
        workspace=workspace,
        policy_id=policy_id,
        principal=principal,
        role=role,
        pattern=pattern,
    )
    return policy_id


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

    Raises:
        PolicyNotFoundError, InvalidRoleError, InvalidPatternError: as above.
        SelfAccessError: the policy belongs to `actor` -- nobody may modify
            their own access.
        AccessDeniedError: `actor` lacks owner authority covering EITHER the
            policy's current pattern or the requested new one -- otherwise a
            grantor could edit a policy scoped to a pattern they don't govern,
            or use the edit to move it under one they don't.
    """
    _validate_role(role)
    pattern = validate_pattern(pattern)
    actor = normalize(actor)

    existing_policy = store.get_policy(workspace, policy_id)
    if existing_policy is None:
        raise PolicyNotFoundError(f"policy {policy_id!r} not found in workspace {workspace!r}")

    if normalize(existing_policy.principal) == actor:
        raise SelfAccessError("you cannot modify your own access; ask another owner to do it")

    actor_policies = store.list_policies_for_principal(workspace, actor)
    if not can_administer_pattern(
        actor_policies, actor, existing_policy.pattern
    ) or not can_administer_pattern(actor_policies, actor, pattern):
        raise AccessDeniedError("insufficient permissions to update this policy")

    # Read off what is being replaced BEFORE the write. A store is free to
    # hand back a live object rather than a snapshot -- an in-memory one, a
    # cache, an ORM identity map -- and updating in place would then leave
    # `existing_policy` already showing the new values, so the record would
    # report the change as having replaced itself.
    principal = existing_policy.principal
    previous_role = existing_policy.role
    previous_pattern = existing_policy.pattern

    store.update_policy(workspace, policy_id, role=role, pattern=pattern, updated_by=actor)
    record_change(
        POLICY_UPDATED,
        actor=actor,
        workspace=workspace,
        policy_id=policy_id,
        principal=principal,
        role=role,
        pattern=pattern,
        previous_role=previous_role,
        previous_pattern=previous_pattern,
    )


def revoke(store: PolicyStore, *, actor: str, workspace: str, policy_id: str) -> None:
    """Revoke policy `policy_id` in `workspace`.

    Raises:
        PolicyNotFoundError: no such policy.
        SelfAccessError: the policy belongs to `actor` -- nobody may revoke
            their own access.
        AccessDeniedError: `actor` lacks owner authority covering the policy's
            pattern -- not just anywhere in the workspace.
    """
    actor = normalize(actor)

    existing_policy = store.get_policy(workspace, policy_id)
    if existing_policy is None:
        raise PolicyNotFoundError(f"policy {policy_id!r} not found in workspace {workspace!r}")

    if normalize(existing_policy.principal) == actor:
        raise SelfAccessError("you cannot revoke your own access; ask another owner to do it")

    actor_policies = store.list_policies_for_principal(workspace, actor)
    if not can_administer_pattern(actor_policies, actor, existing_policy.pattern):
        raise AccessDeniedError("insufficient permissions to delete this policy")

    # Captured before the delete, for the same reason as in `update_grant`:
    # what the record describes must not depend on what the store does to the
    # object it handed back.
    principal = existing_policy.principal
    previous_role = existing_policy.role
    previous_pattern = existing_policy.pattern

    store.delete_policy(workspace, policy_id)
    record_change(
        POLICY_DELETED,
        actor=actor,
        workspace=workspace,
        policy_id=policy_id,
        principal=principal,
        previous_role=previous_role,
        previous_pattern=previous_pattern,
    )


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

    This is the data half of workspace genesis (see the README's "Scope"
    section): whatever creates the workspace hands it an explicit member list
    at creation time, rather than every caller becoming sole owner. Whether
    the caller was entitled to create a workspace at all is a billing question
    settled before this is reached -- nothing here knows about billing.

    Unlike `grant()`, this skips the self-grant, pattern-authority, and
    conflict checks: a genuinely new workspace has no existing owner to
    protect and nothing for a new grant to conflict with, so those checks have
    nothing to say until one exists.

    Raises:
        InvalidRoleError, InvalidPatternError: as above, checked for every
            grant up front, before writing any of them -- a bad entry partway
            through the list must not leave a partially-bootstrapped workspace
            behind.
        WorkspaceAlreadyBootstrappedError: `workspace` already has at least
            one policy. This can only be used once, to bootstrap a workspace
            that doesn't have policies yet -- not to add owners to one that
            already does, which would let anyone holding a valid token mint
            themselves a fresh owner grant with none of `grant()`'s checks.
    """
    pattern = validate_pattern(f"{workspace}.*")
    actor = normalize(actor)

    validated = []
    for principal, role in grants:
        _validate_role(role)
        validated.append((validate_principal(principal), role))

    if store.has_any_policies(workspace):
        raise WorkspaceAlreadyBootstrappedError(
            f"workspace {workspace!r} already has access policies; bootstrap_workspace can only "
            "be used on a brand-new workspace"
        )

    created = []
    for principal, role in validated:
        policy_id = store.create_policy(
            workspace, Policy(principal=principal, role=role, pattern=pattern, updated_by=actor)
        )
        record_change(
            POLICY_CREATED,
            actor=actor,
            workspace=workspace,
            policy_id=policy_id,
            principal=principal,
            role=role,
            pattern=pattern,
            bootstrap=True,
        )
        created.append(policy_id)
    return created
