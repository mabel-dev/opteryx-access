"""Resource patterns: what they may look like, and how they match.

A pattern names data as `workspace[.collection[.dataset[...]]]`. Segments are
dot-separated, and each one written is either a literal name or `*`. The
workspace segment must always be literal: a policy has to say which workspace
it applies to, so there is no such thing as a grant over everything.

A `*` matches EVERYTHING BELOW IT, not one segment: `analytics.*` covers
`analytics.sales` and `analytics.sales.q1` alike. That is the intent -- a
grant over a workspace is a grant over what is in it -- but it means a pattern
is a subtree, and reading `*` as "one level" understates what a policy confers.

Names are lowercase. Patterns are normalized when validated and both sides
are normalized again when matched, so matching is case-insensitive and
decided identically on every platform -- unlike `fnmatch.fnmatch`, which
folds case according to the OS it runs on.

Because a segment is either `*` or a fully literal name, there are no partial
globs (`pub*`) to reason about: a pattern either names a workspace exactly or
is rejected. That is what lets the reserved-workspace check below be a plain
membership test rather than a match against every reserved name.
"""

import fnmatch
import re

from opteryx_access.exceptions import InvalidPatternError

# A segment that stands for any single name.
WILDCARD_SEGMENT = "*"

# A literal segment: lowercase alphanumerics and underscores, starting with a
# letter. Anything else -- leading digits, punctuation, spaces, glob
# metacharacters other than a whole-segment `*` -- is not a name we issue.
_LITERAL_SEGMENT = re.compile(r"^[a-z][a-z0-9_]*$")

# Characters that would make a principal match more than one identity.
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


def normalize(value: str) -> str:
    """Casefold and trim `value` for comparison or storage."""
    return value.strip().lower()


def escape_glob(value: str) -> str:
    """Neutralize glob metacharacters in `value` so it matches literally.

    Used when a pattern is built around something that is not itself a
    pattern -- an identity, say -- so that metacharacters in it cannot widen
    what the resulting pattern covers.
    """
    return value.replace("[", "[[]").replace("*", "[*]").replace("?", "[?]")


def resource_matches(resource: str, pattern: str) -> bool:
    """Whether `pattern` covers `resource`, case-insensitively.

    Both sides are normalized first, then compared with `fnmatchcase` -- the
    case-sensitive matcher over already-casefolded values, which is how the
    result stays identical across platforms.
    """
    return fnmatch.fnmatchcase(normalize(resource), normalize(pattern))


def validate_principal(principal: str) -> str:
    """Check `principal` names one individual, returning it normalized.

    Policies are issued to named individuals. There is no wildcard principal
    and no group principal: a grant everyone holds is not something any
    listing surfaces as unusual, and groups are a thing we may add later as
    their own concept rather than by overloading this field with a pattern.

    Identities are casefolded, so `XB500` and `xb500` are one principal rather
    than two people who each hold half the access. Everything that stores or
    looks up a principal goes through here or `normalize`, so the write side
    and the read side agree on the spelling -- normalizing on write alone
    would mean a lookup for `xb500` silently missing a stored `XB500`.

    Raises:
        InvalidPatternError: if `principal` is empty or is not a single
            named identity.
    """
    identity = normalize(principal)
    if not identity:
        raise InvalidPatternError("a policy must name the principal it is granted to")

    if any(character in identity for character in _GLOB_CHARACTERS):
        raise InvalidPatternError(
            f"principal {principal!r} is not allowed: a policy is granted to one named "
            "individual, not to a pattern matching several"
        )

    return identity


def validate_pattern(pattern: str) -> str:
    """Check `pattern` is a usable resource pattern, returning it normalized.

    Enforces, in order: a non-empty pattern; every segment either `*` or a
    literal name (which rejects empty segments like `a..b`, leading digits,
    and stray punctuation); a literal workspace segment; a workspace that is
    not reserved; and no grant over `information_schema`.

    Raises:
        InvalidPatternError: with a message naming which rule was broken.
    """
    normalized = normalize(pattern)
    if not normalized:
        raise InvalidPatternError("a policy must name the resources it applies to")

    segments = normalized.split(".")
    for segment in segments:
        if segment == WILDCARD_SEGMENT:
            continue
        if not _LITERAL_SEGMENT.match(segment):
            raise InvalidPatternError(
                f"pattern {pattern!r} is not allowed: {segment!r} is not a usable name -- each "
                "part must be '*' or start with a letter and use only letters, digits, and "
                "underscores"
            )

    workspace = segments[0]
    if workspace == WILDCARD_SEGMENT:
        raise InvalidPatternError(
            f"pattern {pattern!r} is not allowed: a policy must name the workspace it applies "
            "to, so the first part cannot be '*'"
        )

    if workspace in RESERVED_WORKSPACES:
        raise InvalidPatternError(
            f"pattern {pattern!r} is not allowed: the {workspace!r} workspace cannot be "
            "granted through a policy"
        )

    if len(segments) > 1 and segments[1] == INFORMATION_SCHEMA_COLLECTION:
        raise InvalidPatternError(
            f"pattern {pattern!r} is not allowed: {INFORMATION_SCHEMA_COLLECTION!r} is a "
            "virtual per-workspace resource and cannot be granted independently"
        )

    return normalized


def pattern_segments(pattern: str) -> tuple[str, str | None, str | None]:
    """Split a pattern into (workspace, collection, dataset)."""
    parts = normalize(pattern).split(".", 2)
    workspace = parts[0] if parts else ""
    collection = parts[1] if len(parts) > 1 else None
    dataset = parts[2] if len(parts) > 2 else None
    return workspace, collection, dataset


def is_literal_segment(segment: str | None) -> bool:
    """True if `segment` names one resource exactly rather than standing for any."""
    return bool(segment) and segment != WILDCARD_SEGMENT
