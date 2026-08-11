"""Whether a caller may do something, given the grants they hold.

Two families of check, ported from two previously-separate implementations:

- `can_perform_action` / `can_perform_workspace_action` -- data-plane checks
  against a resource, ported from opteryx-core's
  `opteryx.managers.permissions.can_perform_action` /
  `can_perform_workspace_action`. Takes a plain list of `Grant` (role +
  pattern only), matching what a JWT's `policies` claim / an
  `ExecutionContext.access_policies` carries.
- `can_administer_pattern` / `has_workspace_access` / `has_workspace_owner_access`
  -- administrative-plane checks against stored `Policy` documents, ported
  from policy.opteryx/control.opteryx's `app/routes/v1/access.py`
  (`_check_pattern_access`, `_check_workspace_access`,
  `_check_workspace_owner_access`).

Both families are kept because they answer different questions over
different inputs -- see `opteryx_access.roles` for why they must not be
collapsed into one rank comparison.
"""

from collections.abc import Iterable

from opteryx_access.actions import action_allowed_for_role
from opteryx_access.models import Grant
from opteryx_access.models import Policy
from opteryx_access.patterns import WILDCARD_PRINCIPAL
from opteryx_access.patterns import resource_matches
from opteryx_access.roles import ADMINISTRATIVE_ROLES
from opteryx_access.roles import OWNER_ONLY_ROLES


def implicit_grants(identity: str | None) -> list[Grant]:
    """Grants every session holds without a policy being issued for them.

    These are hardcoded, not handed over by a policy store, so they never
    appear in a token's `policies` claim -- this is the single declaration of
    them, so a data-action check and a "what do I have access to" listing
    can't drift into disagreeing about what a caller implicitly holds.

    Every pattern is `<namespace>.*`; `can_perform_action` matches it as a
    literal prefix rather than a glob -- see that function for why.

    An anonymous session (no identity) holds no personal namespace: there is
    no `personal.<nobody>` for it to own.
    """
    grants = []
    if identity:
        grants.append(Grant(role="owner", pattern=f"personal.{identity}.*"))
    grants.append(Grant(role="reader", pattern="public.*"))
    return grants


def can_perform_action(
    grants: Iterable[Grant],
    resource: str,
    action: str,
    *,
    identity: str | None = None,
) -> bool:
    """Whether any grant in `grants` (plus the identity's implicit grants)
    permits `action` on `resource`.

    A bare `resource` with no dot is treated as a local, in-session table:
    reading it is always allowed, nothing else is -- there is no workspace to
    check a policy against.

    Implicit grants (see `implicit_grants`) are checked first and CAP what
    they cover: a resource inside `public.` or inside the caller's own
    `personal.` namespace is answered here and does not fall through to
    `grants`. That is what makes `public.` read-only for everyone regardless
    of what an issued policy might otherwise say about it. The trailing `*`
    is matched as a literal prefix, not a glob, so glob metacharacters in an
    identity can't widen the namespace it owns.
    """
    if resource.count(".") == 0:
        return action == "READ"

    for implicit in implicit_grants(identity):
        prefix = implicit.pattern[:-1]  # strip the trailing "*", keep the "."
        if resource.startswith(prefix):
            return action_allowed_for_role(implicit.role, action)

    for grant in grants:
        if action_allowed_for_role(grant.role, action) and resource_matches(
            resource, grant.pattern
        ):
            return True

    return False


def can_perform_workspace_action(
    grants: Iterable[Grant],
    workspace: str,
    action: str = "ALTER",
) -> bool:
    """Whether any grant in `grants` permits `action` at the whole-workspace level.

    Deliberately not `can_perform_action`: that function reads a name with no
    dots as a local table and short-circuits to READ-only, so a bare
    workspace name can never clear it there.

    A grant covers a workspace action only when it covers the workspace in
    full: `ws.*` (how ownership of a whole workspace is issued) qualifies, as
    does a pattern matching the bare name (`ws`, `*`). A grant scoped to part
    of a workspace (`ws.coll.*`) does not -- stripped of its trailing `.*` it
    reduces to `ws.coll`, which is not the workspace itself.
    """
    for grant in grants:
        if not action_allowed_for_role(grant.role, action):
            continue
        covered = grant.pattern.removesuffix(".*")
        if resource_matches(workspace, covered):
            return True
    return False


def can_administer_pattern(policies: Iterable[Policy], identity: str, pattern: str) -> bool:
    """Whether `identity` holds administrative (owner/admin) authority over `pattern`.

    Having owner/admin authority *somewhere* in the workspace is not enough:
    a grantor who owns `billing.*` must not be able to mint grants on an
    unrelated pattern like `ops.*` they have no authority over. This requires
    the caller's own owner/admin pattern to cover (via `resource_matches`)
    the pattern being granted, updated, or deleted, so authority can't
    escalate outside the scope the grantor was actually given.
    """
    if not pattern:
        return False
    for policy in policies:
        if policy.principal not in (identity, WILDCARD_PRINCIPAL):
            continue
        if policy.role in ADMINISTRATIVE_ROLES and resource_matches(pattern, policy.pattern):
            return True
    return False


def has_workspace_access(policies: Iterable[Policy], identity: str) -> bool:
    """Whether `identity` holds owner/admin access anywhere among `policies`.

    `policies` is expected to already be scoped to one workspace (i.e. the
    result of listing that workspace's policy store). Weaker than
    `can_administer_pattern`: this only proves administrative authority
    exists somewhere, not that it covers a specific pattern. Use this for
    "may view this workspace's policy list"; use `can_administer_pattern`
    before mutating any specific one.
    """
    for policy in policies:
        if (
            policy.principal in (identity, WILDCARD_PRINCIPAL)
            and policy.role in ADMINISTRATIVE_ROLES
        ):
            return True
    return False


def has_workspace_owner_access(policies: Iterable[Policy], identity: str) -> bool:
    """Whether `identity` holds *owner* (not just admin) access anywhere among `policies`.

    Same workspace-scoping expectation as `has_workspace_access`. Reserved
    for operations with a bigger blast radius than an ordinary policy
    mutation -- e.g. exporting the full effective-permissions map for a
    workspace in one document.
    """
    for policy in policies:
        if policy.principal in (identity, WILDCARD_PRINCIPAL) and policy.role in OWNER_ONLY_ROLES:
            return True
    return False
