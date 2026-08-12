"""Whether a caller may do something, given the grants they hold.

Two families of check, ported from two previously-separate implementations:

- `can_perform_action` / `can_perform_workspace_action` -- data-plane checks
  against a resource, ported from opteryx-core's
  `opteryx.managers.permissions.can_perform_action` /
  `can_perform_workspace_action`. Takes a plain list of `Grant` (role +
  pattern only), matching what a JWT's `policies` claim / an
  `ExecutionContext.access_policies` carries.
- `can_administer_pattern` / `has_workspace_access` -- administrative-plane
  checks against stored `Policy` documents, ported from policy.opteryx/
  control.opteryx's `app/routes/v1/access.py` (`_check_pattern_access`,
  `_check_workspace_access`).

The two families take different inputs because they answer different
questions: a `Grant` is role plus pattern, all that deciding a data action
needs; a `Policy` also carries the principal it was issued to, which is what
an administrative check has to reason about.

Administering grants is not a separate notion of authority with its own role
list -- it is the `GRANT` action in `opteryx_access.actions.ACTION_ROLES`,
checked the same way as any other action, so what it requires is stated once
in that table alongside `DROP` and the rest.
"""

from collections.abc import Iterable

from opteryx_access.actions import action_allowed_for_role
from opteryx_access.models import Grant
from opteryx_access.models import Policy
from opteryx_access.patterns import escape_glob
from opteryx_access.patterns import normalize
from opteryx_access.patterns import resource_matches


# Identities that maintain the `public` workspace rather than merely read it:
# the platform's own automation. `public` holds curated open data (GDELT,
# vulnerability feeds, and the rest) that something has to load and keep
# compacted, and `public` is a reserved workspace -- `validate_pattern` refuses
# to write a policy over it, so this access cannot be issued as a grant no
# matter who asks. Declared here instead, as the one place the exception is
# stated.
#
# This is deliberately a short, closed list of platform identities, not a role
# or a flag on an account: it is an exception to "public is read-only for
# everyone", and an exception that anything could opt into would not be one.
# Everything held here is reported by `SHOW GRANTS` for these identities (see
# `opteryx_access.capability`), so it is at least visible where a policy row
# would have been.
#
# What this rests on: whoever issues tokens must never mint one whose `sub` is
# a name in this set for anyone but the platform. Nothing here can check that
# -- an identity arrives already authenticated -- so these names have to be
# unregisterable wherever accounts are created.
PLATFORM_IDENTITIES: frozenset[str] = frozenset({"federator", "xb500"})


def implicit_grants(identity: str | None) -> list[Grant]:
    """Grants every session holds without a policy being issued for them.

    These are hardcoded, not handed over by a policy store, so they never
    appear in a token's `policies` claim -- this is the single declaration of
    them, so a data-action check and a "what do I have access to" listing
    can't drift into disagreeing about what a caller implicitly holds.

    The identity is escaped into its pattern (see `escape_glob`): unlike an
    issued policy's pattern, this one is built around a value that was never
    validated as a pattern, so glob metacharacters in it must not widen the
    namespace the caller owns.

    An anonymous session (no identity) holds no personal namespace: there is
    no `personal.<nobody>` for it to own.

    A platform identity (see `PLATFORM_IDENTITIES`) holds `writer` on
    `public.*` rather than `reader`. Writer, not owner: these identities load
    and compact what is in `public`, and neither dropping a public dataset nor
    granting anyone access to one is theirs to do.
    """
    grants = []
    if identity:
        normalized = normalize(identity)
        grants.append(Grant(role="owner", pattern=f"personal.{escape_glob(normalized)}.*"))
        if normalized in PLATFORM_IDENTITIES:
            # ORDER IS LOAD-BEARING: `can_perform_action` answers from the first
            # implicit grant whose pattern matches and does not look further, so
            # this has to precede the reader grant below or it would never be
            # reached.
            grants.append(Grant(role="writer", pattern="public.*"))
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
    `personal.` namespace is answered there and does not fall through to
    `grants`. That is what makes `public.` read-only for everyone regardless
    of what an issued policy might otherwise say about it -- everyone except
    the platform identities that maintain it, whose writer grant is itself one
    of the implicit grants and so is decided in the same pass.
    """
    if resource.count(".") == 0:
        return action == "READ"

    for implicit in implicit_grants(identity):
        if resource_matches(resource, implicit.pattern):
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
    does the bare name `ws`. A grant scoped to part of a workspace
    (`ws.coll.*`) does not -- stripped of its trailing `.*` it reduces to
    `ws.coll`, which is not the workspace itself.
    """
    for grant in grants:
        if not action_allowed_for_role(grant.role, action):
            continue
        covered = normalize(grant.pattern).removesuffix(".*")
        if resource_matches(workspace, covered):
            return True
    return False


def can_administer_pattern(policies: Iterable[Policy], identity: str, pattern: str) -> bool:
    """Whether `identity` may grant and revoke access covering `pattern`.

    Holding a grantable role *somewhere* in the workspace is not enough: a
    grantor who owns `billing.*` must not be able to mint grants on an
    unrelated pattern like `ops.*` they have no authority over. Their own
    policy has to cover (via `resource_matches`) the pattern being granted,
    updated, or deleted, so authority can't escalate outside the scope they
    were actually given.

    `policies` may be pre-filtered to `identity` by the caller -- the
    principal is checked here regardless, so that a store which filters
    wrongly cannot widen who is treated as the grantor. Both sides are
    normalized, so a policy stored before principals were casefolded still
    resolves to the identity it was meant for.
    """
    if not pattern:
        return False
    identity = normalize(identity)
    for policy in policies:
        if normalize(policy.principal) != identity:
            continue
        if action_allowed_for_role(policy.role, "GRANT") and resource_matches(
            pattern, policy.pattern
        ):
            return True
    return False


def has_workspace_access(policies: Iterable[Policy], identity: str) -> bool:
    """Whether `identity` holds a policy that can administer anything here.

    `policies` is expected to already be scoped to one workspace (i.e. the
    result of listing that workspace's policy store). Weaker than
    `can_administer_pattern`: this proves only that such a policy exists, not
    that it covers a specific pattern. Use it for "may view this workspace's
    policy list" and "may export its effective-permissions map"; use
    `can_administer_pattern` before mutating any specific policy.
    """
    identity = normalize(identity)
    for policy in policies:
        if normalize(policy.principal) == identity and action_allowed_for_role(
            policy.role, "GRANT"
        ):
            return True
    return False
