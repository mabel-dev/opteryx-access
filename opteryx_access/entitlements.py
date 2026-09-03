"""Entitlements: authority over a workspace's OPERATIONS, scoped at the moment
the platform issues it.

A role measures DEPTH of access to rows -- reader, then writer, then owner,
each strictly containing the one before. That ordering is load-bearing:
`opteryx_access.roles.role_outranks_or_equals` uses it, and
`opteryx_access.grants.find_conflict` decides redundancy with it. Some
authority does not lie on that line at all. **Managing the operations of a
workspace is not a deeper form of access to its data; it is a different axis.**
An identity that may create, suspend and re-pin the tasks in a workspace need
not be able to read a row of it, and an owner who can read everything is not
thereby the right person to run its automation.

Inserting an `automator` into `ROLES` would mean scoring on the privilege
ladder something that has no place on it. So this is a different kind of
object: a set of ACTIONS on a pattern.

## The shape of a name

The platform's identity system issues named entitlements to accounts --
`platform_admin`, `data_admin`, `user_admin`, and now these. An entitlement
this package recognizes is a KIND and a SCOPE, joined by `::`:

    automation_admin::public
    automation_admin::platform
    automation_admin::acme
    automation_admin::acme.pipelines

The kind says what it confers (`ENTITLEMENT_KINDS`: `automation_admin` is
`AUTOMATE`, and nothing else). The scope says where: a workspace, or a
narrower prefix within one, and the entitlement covers everything beneath it.
So `automation_admin::acme` is `AUTOMATE` on `acme.*`, and the account holding
it can run every task and trigger in `acme` without being able to read a row
of it.

The scope is in the NAME, decided when the entitlement is issued, and not in
this package. That is the point. The situation this exists for -- a workspace
whose data belongs to a pipeline, run by bots, with no human owner, whose
operations still need a human -- is not special to `public` and `platform`. It
is any customer whose workspace works that way, and the platform, not this
package, is where "which workspace" is known. A design with the two platform
namespaces hardcoded here would have answered the first two instances and
required a code change for every one after; this answers the general case,
and `public` and `platform` are just its first two uses.

The price is that the identity system carries a workspace name inside an
entitlement string. That is accepted: it is a runtime decision by the
platform, and a runtime decision belongs in the system that makes runtime
decisions, not in a table that changes by pull request.

## What this package does and does not do

- **Assignment stays where it already is.** Nothing here creates, stores or
  revokes an entitlement -- there is no store and no `assign_entitlement`,
  because there is already a system that assigns these and audits doing so. A
  second mechanism for the same concept would mean two places to look when
  answering "why can this person do that".
- **A token carries a NAME, never a permission.** What a kind confers is
  declared here in `ENTITLEMENT_KINDS`, in code, reviewable as a diff. A
  token can name a scope, because that is the platform's to decide; it cannot
  name an action, because that is not.
- **Names this package does not recognize are ignored**, not rejected. A
  session holding `user_admin` gets nothing here and no error; that name is
  someone else's to interpret. A name of a RECOGNIZED kind whose scope is
  unusable (`automation_admin` with no scope, `automation_admin::$x`) is
  also skipped in a permission check -- a check is not the place to object to
  a misconfigured account -- but `parse_entitlement_name` raises on it, so an
  issuing path can refuse to mint one.

## Why one is needed at all

Consider `public.*`:

- no policy can confer anything there -- `validate_pattern` refuses a reserved
  workspace outright;
- the implicit grant caps everyone at `reader`, and the cap is consulted
  before issued grants, so a policy claiming otherwise would never be reached;
- even the platform identities hold only `writer`, and `writer` is not in
  `AUTOMATE`'s set.

So `AUTOMATE` inside `public.*` had no holder at all: the platform's own tasks
and triggers could not be created, suspended, re-pinned or dropped by anybody,
and `information_schema.tasks`/`.triggers` -- which show a row only where
`AUTOMATE` holds -- showed nothing to anyone.

`platform.*` is the same need arriving from the opposite direction. It is an
ordinary workspace, so policies over it are perfectly legal -- but it is run
by bots, and no human holds owner there. And `acme.*` is the same again for a
customer.

**On an owned workspace this deliberately reaches past the owner.** An
entitlement is consulted before issued grants, so `automation_admin::acme`
confers `AUTOMATE` on `acme.*` whatever `acme`'s owners have granted. That is
the intent, not a leak -- it is the platform saying who runs the operations of
a namespace, which is a decision above any one workspace's owner, and it is
issued by the platform's identity system, which is the platform's to run.

## What one can never do

`GRANT` and `REVOKE` are not entitleable (see `ENTITLEABLE_ACTIONS`), checked
when `ENTITLEMENT_KINDS` is declared and again in `entitlement_permits`. An
entitlement is authority granted outside the ownership model; letting it
confer authority OVER that model would let a non-owner mint ownership and make
every other check in this package advisory. Engine-private (`$`) names are
refused on the same basis, and `information_schema` cannot be a scope for the
same reason it cannot be a pattern.
"""

from collections.abc import Iterable
from typing import Any

from opteryx_access.actions import ACTION_ROLES
from opteryx_access.actions import DATA_ACTIONS
from opteryx_access.exceptions import InvalidActionError
from opteryx_access.exceptions import InvalidPatternError
from opteryx_access.models import Entitlement
from opteryx_access.patterns import is_engine_private
from opteryx_access.patterns import normalize
from opteryx_access.patterns import resource_matches
from opteryx_access.patterns import validate_entitlement_pattern

# What joins a kind to its scope in an entitlement name.
SCOPE_SEPARATOR = "::"

# The actions an entitlement may confer: every data action, and never policy
# administration.
#
# Derived from `DATA_ACTIONS` rather than listed, so a data action added to
# `ACTION_ROLES` later is entitleable from the moment it exists -- which is the
# intended default, since a kind confers only the actions declared for it.
#
# The exclusion of `GRANT`/`REVOKE` is the one rule here, and it is absolute:
# an entitlement is authority granted outside the ownership model, so letting
# it confer authority OVER the ownership model would let a non-owner mint
# ownership and make every other check in this package advisory.
ENTITLEABLE_ACTIONS: frozenset[str] = DATA_ACTIONS

# The kinds of entitlement this package recognizes, and what each confers.
#
# A kind is the part of a name before `::`. Names come from the platform's
# identity system, which issues plenty this package has no opinion about
# (`user_admin`, `data_admin`, ...); only kinds that confer authority over
# DATA belong here. Keep it short: every kind is authority that reaches past
# what a workspace's own owners decided, so a kind earning its place is one
# whose reason can be written in a sentence.
ENTITLEMENT_KINDS: dict[str, frozenset[str]] = {
    # Operations, not data: run the standing automation in a scope -- create,
    # drop, suspend, resume and re-pin its tasks and triggers -- without
    # being able to read a row of it. Deliberately AUTOMATE alone.
    "automation_admin": frozenset({"AUTOMATE"}),
}


def validate_entitlement_actions(actions: Iterable[str]) -> frozenset[str]:
    """Check `actions` are all entitleable, returning them as a frozenset.

    Actions are spelled exactly as `ACTION_ROLES` spells them, uppercase.
    Nothing casefolds an action anywhere in this package
    (`action_allowed_for_role("owner", "drop")` is False), so this does not
    either: a name that is not spelled the way the table spells it is
    rejected rather than quietly repaired.

    Raises:
        InvalidActionError: if `actions` is empty, names something that is not
            an action at all, or names `GRANT`/`REVOKE` -- which are actions,
            but not ones an entitlement may confer. The two cases get
            different messages: one is a typo, the other is an attempt at
            something the model forbids.
    """
    requested = frozenset(actions)
    if not requested:
        raise InvalidActionError("an entitlement must name at least one action to confer")

    unknown = sorted(action for action in requested if action not in ACTION_ROLES)
    if unknown:
        raise InvalidActionError(
            f"unknown action(s) {', '.join(repr(action) for action in unknown)}; actions are "
            f"spelled as in ACTION_ROLES: {', '.join(sorted(ACTION_ROLES))}"
        )

    forbidden = sorted(action for action in requested if action not in ENTITLEABLE_ACTIONS)
    if forbidden:
        raise InvalidActionError(
            f"{', '.join(repr(action) for action in forbidden)} cannot be conferred by an "
            "entitlement: administering policy is the owner's, and an entitlement that "
            "granted it would let a non-owner mint ownership"
        )

    return requested


def _validate_kinds() -> None:
    """Check every kind in `ENTITLEMENT_KINDS` at import time.

    A malformed entry is a mistake in this file, so it should stop the process
    that imports it rather than surface later as one permission check quietly
    answering the wrong thing.
    """
    for kind, actions in ENTITLEMENT_KINDS.items():
        if SCOPE_SEPARATOR in kind or kind != normalize(kind):
            raise InvalidActionError(
                f"ENTITLEMENT_KINDS[{kind!r}]: a kind is a bare, lowercase name; the scope is "
                "added when the entitlement is issued"
            )
        try:
            validate_entitlement_actions(actions)
        except InvalidActionError as error:
            raise InvalidActionError(f"ENTITLEMENT_KINDS[{kind!r}]: {error}") from error


_validate_kinds()


def entitlement_kinds() -> frozenset[str]:
    """The entitlement kinds this package recognizes.

    For a caller that wants to show, or lint, which of an account's names have
    any meaning here -- everything else it holds is another system's.
    """
    return frozenset(ENTITLEMENT_KINDS)


def scope_pattern(scope: str) -> str:
    """The pattern an entitlement scope covers: everything beneath it.

    `acme` -> `acme.*`; `acme.pipelines` -> `acme.pipelines.*`. A scope that
    already ends in `*` is taken as written. Validated as an entitlement
    pattern, so a reserved workspace is allowed and an engine-private or
    `information_schema` scope is not.

    Raises:
        InvalidPatternError: if the scope is empty or not a usable pattern.
    """
    normalized = normalize(scope)
    if not normalized:
        raise InvalidPatternError("an entitlement must name the scope it applies to")
    if not normalized.endswith("*"):
        normalized = f"{normalized}.*"
    return validate_entitlement_pattern(normalized)


def parse_entitlement_name(name: str) -> tuple[str, str] | None:
    """Split an entitlement name into `(kind, pattern)`.

    Returns None for a name whose kind this package does not recognize --
    `user_admin`, `platform_admin` -- since those are other services' to
    interpret and are not an error. Raises for a name whose kind IS
    recognized but which cannot be used: no scope at all, or a scope that is
    not a valid pattern. That split lets a permission check skip the bad name
    (see `resolve_entitlements`) while an issuing path refuses to mint it.

    Names are casefolded, so `AUTOMATION_ADMIN::Acme` is `automation_admin`
    on `acme.*` -- matching how every other identifier here is compared.

    Raises:
        InvalidPatternError: if the kind is recognized and the scope is
            missing or unusable.
    """
    normalized = normalize(name)
    kind, separator, scope = normalized.partition(SCOPE_SEPARATOR)
    kind = kind.strip()
    if kind not in ENTITLEMENT_KINDS:
        return None
    if not separator:
        raise InvalidPatternError(
            f"entitlement {name!r} names no scope: it must be written "
            f"{kind}{SCOPE_SEPARATOR}<workspace>"
        )
    return kind, scope_pattern(scope)


def resolve_entitlements(names: Iterable[str], *, principal: str = "") -> list[Entitlement]:
    """What `names` confer over data, as `Entitlement`s.

    `names` are the entitlement names the identity system issued to an
    account, straight off a token or an account record. Names this package
    does not recognize resolve to nothing and are SKIPPED, never raised on: an
    account legitimately holds names that mean something to other services,
    and a permission check is not the place to object to them. A name of a
    recognized kind with an unusable scope is skipped too, for the same
    reason; `parse_entitlement_name` is where it raises.

    `principal` is stamped onto the returned entitlements for the benefit of
    anything that reports them; it takes no part in deciding what they confer.
    """
    resolved: list[Entitlement] = []
    for name in names:
        if not isinstance(name, str):
            continue
        try:
            parsed = parse_entitlement_name(name)
        except InvalidPatternError:
            continue
        if parsed is None:
            continue
        kind, pattern = parsed
        resolved.append(
            Entitlement(principal=principal, actions=ENTITLEMENT_KINDS[kind], pattern=pattern)
        )
    return resolved


def parse_entitlement_claim(claims: dict, *, principal: str = "") -> list[Entitlement]:
    """Resolve the `entitlements` claim of a decoded JWT.

    The entitlement counterpart to
    `opteryx_access.models.parse_policy_claim`, and deliberately a much
    smaller job than that one. The claim is a list of NAMES -- the account's
    entitlements exactly as the identity system issued them -- so there is no
    permission-shaped payload to validate: a token can name a kind and a
    scope, and what a kind confers is declared in `ENTITLEMENT_KINDS`. A
    forged or stale token can therefore claim `automation_admin::acme`; it
    cannot claim `GRANT` on anything.

    Anything in the claim that is not a string, and any name this package does
    not recognize, is skipped -- as `parse_policy_claim` skips an entry it
    cannot read, and for the same reason.
    """
    raw: Iterable[Any] = claims.get("entitlements") or ()
    if isinstance(raw, str):
        # A single name sent unwrapped: iterating it would resolve one
        # character at a time and silently find nothing.
        raw = (raw,)
    return resolve_entitlements(raw, principal=principal)


def _permits(actions: frozenset[str], pattern: str, resource: str, action: str) -> bool:
    """The one place an entitlement's authority is evaluated.

    Both guards are re-applied here rather than left to the kind check: these
    functions are public and an `Entitlement` can be constructed by a caller
    directly, so nothing that reaches this point is assumed to have come from
    `resolve_entitlements`.
    """
    if is_engine_private(resource) or is_engine_private(pattern):
        return False
    if action not in ENTITLEABLE_ACTIONS or action not in actions:
        return False
    return resource_matches(resource, pattern)


def entitlement_permits(entitlement: Entitlement, resource: str, action: str) -> bool:
    """Whether `entitlement` permits `action` on `resource`."""
    return _permits(entitlement.actions, entitlement.pattern, resource, action)


def entitlement_permits_workspace_action(
    entitlement: Entitlement, workspace: str, action: str
) -> bool:
    """Whether `entitlement` permits `action` on `workspace` as a whole.

    The rule `can_perform_workspace_action` applies to a grant, applied to an
    entitlement: the pattern counts only if it covers the workspace in FULL,
    so `acme.*` (and the bare `acme`) qualify and `acme.pipelines.*` does not.
    Deliberately the same rule rather than a laxer one -- an entitlement is
    narrower authority than a role, so it must not reach a whole workspace
    from a pattern a role could not have reached it from.
    """
    return _permits(
        entitlement.actions,
        normalize(entitlement.pattern).removesuffix(".*"),
        workspace,
        action,
    )
