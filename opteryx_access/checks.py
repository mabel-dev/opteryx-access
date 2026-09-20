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

The data-plane checks also take `entitlements` (see
`opteryx_access.entitlements`) -- authority over a namespace's OPERATIONS,
carried as actions on a pattern rather than as a role, and resolved from the
names the identity system issues. They are consulted before everything else,
for the reason spelled out in `can_perform_action`.
"""

from collections.abc import Iterable

import os

from opteryx_access.actions import action_allowed_for_role
from opteryx_access.entitlements import entitlement_permits
from opteryx_access.entitlements import entitlement_permits_workspace_action
from opteryx_access.models import Entitlement
from opteryx_access.models import Grant
from opteryx_access.models import Policy
from opteryx_access.patterns import escape_glob
from opteryx_access.patterns import is_engine_private
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


# The one platform identity the compactor submits as, and so the one a
# workspace's `maintenance` setting grants WRITE to.
#
# ONE NAME FOR ONE THING, and the name is `COMPACTION_IDENTITY` because two
# other services already read that variable for the same identity: xb500's
# `trigger_compaction`, which submits the `OPTIMIZE`, and jobs.opteryx's
# `maintenance_billing.platform_identity`, which decides both what is
# house-billed and who may claim trigger provenance. Three readers, one
# variable: pointing the platform at a new identity moves all of them or none.
# Splitting them is the documented failure mode - a gate matching an identity
# nothing submits as, which fails quietly.
#
# Defaulted rather than required, because an unset value here must not stop a
# workspace answering "is maintenance on"; the default is the identity in use.
MAINTENANCE_IDENTITY_ENV = "COMPACTION_IDENTITY"
MAINTENANCE_IDENTITY_DEFAULT = "federator"


def maintenance_identity() -> str:
    """The identity a workspace's `maintenance` setting grants WRITE to.

    Read per call rather than bound at import: the retirement of `federator`
    moves this, and a module-level constant would be frozen for the life of
    the process and need a redeploy to notice.
    """
    return normalize(
        os.environ.get(MAINTENANCE_IDENTITY_ENV, "").strip() or MAINTENANCE_IDENTITY_DEFAULT
    )


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

    The personal namespace takes TWO patterns, because `fnmatch` does not
    treat `personal.alice.*` as covering `personal.alice` -- the trailing
    `.` is a literal that the bare collection name has nothing to match.
    Without the exact-name pattern an identity owns every dataset in their
    personal collection while holding nothing on the collection itself, and
    the engine's collection-level statements (CREATE COLLECTION, DROP
    COLLECTION, LOAD SAMPLE) all check the two-part name. Ordinary
    workspaces never hit this: an owner's `ws.*` does match `ws.collection`.
    The two patterns are disjoint -- no resource matches both -- so unlike
    the `public.*` pair below their order is not load-bearing.

    A platform identity (see `PLATFORM_IDENTITIES`) holds `writer` on
    `public.*` and `samples.*` rather than `reader`. Writer, not owner: these
    identities load and compact what is in them, and neither dropping one of
    those datasets nor granting anyone access to one is theirs to do.

    `samples.*` is UNIVERSALLY READABLE and read-only, exactly as `public.*`
    is, so anyone can query a sample or fork one with `CREATE TABLE ... CLONE`
    without a policy being issued to them.

    It is NOT LISTED, and that follows from being here rather than from a
    second rule somewhere: implicit grants never appear in a token's `policies`
    claim, and odata.opteryx builds its service document -- which is what draws
    Studio's catalog tree -- from that claim. `public` is in the tree only
    because the service document unions it in by name. `samples` deliberately
    is not: five scale factors of TPC-H would be forty datasets in the catalog
    of every account on the platform, forever, to be forked once. Someone who
    wants to look before forking can still `SELECT` from it.
    """
    grants = []
    if identity:
        normalized = normalize(identity)
        grants.append(Grant(role="owner", pattern=f"personal.{escape_glob(normalized)}"))
        grants.append(Grant(role="owner", pattern=f"personal.{escape_glob(normalized)}.*"))
        if normalized in PLATFORM_IDENTITIES:
            # ORDER IS LOAD-BEARING: `can_perform_action` answers from the first
            # implicit grant whose pattern matches and does not look further, so
            # this has to precede the reader grant below or it would never be
            # reached.
            grants.append(Grant(role="writer", pattern="public.*"))
            grants.append(Grant(role="writer", pattern="samples.*"))
    grants.append(Grant(role="reader", pattern="public.*"))
    grants.append(Grant(role="reader", pattern="samples.*"))
    return grants


def can_perform_action(
    grants: Iterable[Grant],
    resource: str,
    action: str,
    *,
    identity: str | None = None,
    entitlements: Iterable[Entitlement] = (),
) -> bool:
    """Whether any grant in `grants` (plus the identity's implicit grants, plus
    any `entitlements` held) permits `action` on `resource`.

    A bare `resource` with no dot is treated as a local, in-session table:
    reading it is always allowed, nothing else is -- there is no workspace to
    check a policy against.

    Implicit grants (see `implicit_grants`) CAP what they cover: a resource
    inside `public.` or inside the caller's own `personal.` namespace is
    answered there and does not fall through to `grants`. That is what makes
    `public.` read-only for everyone regardless of what an issued policy might
    otherwise say about it -- everyone except the platform identities that
    maintain it, whose writer grant is itself one of the implicit grants and so
    is decided in the same pass.

    Entitlements are consulted BEFORE both the cap and the issued grants, and
    this order is the whole point of them. They say who runs the OPERATIONS of
    a namespace, which is a decision above both -- above the cap, because
    `AUTOMATE` on `public.*` is otherwise reachable by nobody at all; and
    above an issued policy, because a workspace run by bots has no human owner
    to grant it. See `opteryx_access.entitlements` for what each name confers
    and why the table is short.

    An entitlement is additive, never subtractive: it can only turn a False
    into a True. What it cannot do is reach an engine-private name or confer
    policy administration -- both refused in `entitlement_permits`, whatever
    it was built from.
    """
    if resource.count(".") == 0:
        return action == "READ"

    # `$`-prefixed names are denied here, before a single grant is looked at,
    # and for every action and every identity including the platform ones.
    # `validate_pattern` already refuses to ISSUE a policy naming one, but that
    # is not the same guarantee: a pattern's `*` covers everything below it, so
    # an ordinary `ws.*` owner grant matches `ws.$anything`. Nothing is stored
    # under such a name today -- see ENGINE_PRIVATE_PREFIX in patterns.py for
    # why the reservation is made ahead of the need.
    if is_engine_private(resource):
        return False

    for entitlement in entitlements:
        if entitlement_permits(entitlement, resource, action):
            return True

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
    *,
    entitlements: Iterable[Entitlement] = (),
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

    `entitlements` are checked by the identical rule, over the actions they
    confer instead of a role. Deliberately the same rule and not a laxer one:
    an entitlement is narrower authority than a role, so it must not reach a
    whole workspace from a pattern that would not have.
    """
    if is_engine_private(workspace):
        return False

    for entitlement in entitlements:
        if entitlement_permits_workspace_action(entitlement, workspace, action):
            return True

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
    if is_engine_private(pattern):
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
