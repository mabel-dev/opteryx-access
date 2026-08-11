"""Resource-pattern matching and the invariants a pattern must satisfy.

Ported from `policy.opteryx`/`control.opteryx`'s `app/models/policy.py` and
`app/routes/v1/access.py` (identical in both -- see that repo's
`docs/design/consolidation.md`), which is where these rules previously lived
as the only copy.

Resource names and patterns are dot-separated (`workspace.collection.dataset`)
and matched with shell-style globs (`analytics.*`, `analytics.sales.q1`).
"""

import fnmatch

from opteryx_access.exceptions import InvalidPatternError

# Principal matching any authenticated user.
WILDCARD_PRINCIPAL = "*"

# Characters that make a pattern segment match more than one resource.
_GLOB_CHARACTERS = "*?["

# Workspaces that are never grantable through a policy -- access to them is
# decided by a mechanism other than the access-policy documents this package
# manages (a hardcoded anonymous allowlist for "public", owner-only hardcoding
# for "personal" -- see odata.opteryx).
RESERVED_WORKSPACES: tuple[str, ...] = ("public", "personal")

# Synthetic per-workspace collection generated on the fly for whoever already
# has access to that workspace. It has no real catalog entry of its own, so it
# can't be granted as an independent resource.
INFORMATION_SCHEMA_COLLECTION = "information_schema"


def resource_matches(resource: str, pattern: str) -> bool:
    """Whether `pattern` covers `resource`.

    Case-sensitive (`fnmatch.fnmatchcase`), not the platform's `fnmatch.fnmatch`.
    Plain `fnmatch` folds case per the OS it runs on, so the same policy would
    decide differently on macOS versus Linux -- some existing call sites (e.g.
    opteryx-core's `ACTION_MAP` enforcement) use plain `fnmatch` for this reason
    unaddressed; this is the corrected, deterministic behavior and the one new
    integrations should use.
    """
    return fnmatch.fnmatchcase(resource, pattern)


def validate_wildcard_rule(principal: str, pattern: str) -> None:
    """Reject policies that are wildcarded in both principal and pattern.

    A policy may say "everyone, on this exact resource" or "this person, on
    anything matching a pattern" -- but "everyone, on anything" is a grant
    nobody would write on purpose and which no listing surfaces as unusual.
    Requiring the wildcard principal to name its resource exactly keeps the
    blast radius of "*" bounded and reviewable.

    Raises:
        InvalidPatternError: if both sides are wildcarded, or a wildcard
            principal has no pattern.
    """
    if principal != WILDCARD_PRINCIPAL:
        return

    if not pattern:
        raise InvalidPatternError(
            "a policy for the wildcard principal '*' must specify an exact resource pattern"
        )

    if any(ch in pattern for ch in _GLOB_CHARACTERS):
        raise InvalidPatternError(
            f"pattern {pattern!r} is not allowed for the wildcard principal '*': a policy "
            "may use a wildcard principal or a wildcard pattern, not both. Specify a "
            "fully-qualified resource."
        )


def validate_pattern_does_not_target_reserved_resource(
    pattern: str, reserved_workspaces: tuple[str, ...] = RESERVED_WORKSPACES
) -> None:
    """Reject patterns that grant access to a reserved, non-grantable resource.

    A workspace segment that merely *could* match a reserved name via a
    wildcard (e.g. "*" or "pub*") is rejected too, not just an exact match --
    otherwise the restriction is trivial to route around.

    Case-sensitive (`fnmatchcase`), same as `resource_matches` -- see that
    function for why plain `fnmatch` is not used here either: it would let
    the reserved-workspace check itself decide differently by platform.

    Raises:
        InvalidPatternError: if the pattern targets a reserved resource.
    """
    parts = pattern.split(".", 2)
    workspace = parts[0] if parts else ""
    collection = parts[1] if len(parts) > 1 else None

    for reserved in reserved_workspaces:
        if workspace and fnmatch.fnmatchcase(reserved, workspace):
            raise InvalidPatternError(
                f"pattern {pattern!r} is not allowed: the {reserved!r} workspace cannot be "
                "granted through a policy"
            )

    if collection == INFORMATION_SCHEMA_COLLECTION:
        raise InvalidPatternError(
            f"pattern {pattern!r} is not allowed: {INFORMATION_SCHEMA_COLLECTION!r} is a "
            "synthetic per-workspace resource and cannot be granted independently"
        )


def pattern_segments(pattern: str) -> tuple[str, str | None, str | None]:
    """Split a dot-separated resource pattern into (workspace, collection, dataset)."""
    parts = pattern.split(".", 2)
    workspace = parts[0] if parts else ""
    collection = parts[1] if len(parts) > 1 else None
    dataset = parts[2] if len(parts) > 2 else None
    return workspace, collection, dataset


def is_literal_segment(segment: str | None) -> bool:
    """True if `segment` is present and names an exact resource (no glob chars)."""
    return bool(segment) and not any(ch in segment for ch in _GLOB_CHARACTERS)
