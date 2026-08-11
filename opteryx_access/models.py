"""The two shapes a grant of access takes in this platform.

`Grant` is the lightweight form carried inside a JWT's `policies` claim (see
`authenticate.opteryx/app/policies.py::fetch_policies_for_principal`) -- just
enough to answer "can this role, on this pattern, do that action", with the
principal and any storage metadata already stripped out to keep the token
small.

`Policy` is the administrative form used when listing, creating, updating, or
revoking policies -- it also carries who it applies to and (once stored) an
id and audit timestamps.
"""

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class Grant:
    """A (role, pattern) pair as it appears in a caller's JWT claims."""

    role: str
    pattern: str


@dataclass
class Policy:
    """A stored access-policy document."""

    principal: str
    role: str
    pattern: str
    policy_id: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
    updated_by: str | None = None

    def as_grant(self) -> Grant:
        """This policy's (role, pattern), discarding principal and metadata."""
        return Grant(role=self.role, pattern=self.pattern)


def parse_policy_claim(claims: dict) -> list[Grant]:
    """Parse the `policies` claim of a decoded JWT into a list of `Grant`.

    Accepts the two shapes seen across the fleet: a `[role, pattern]` pair
    (what `authenticate.opteryx` actually emits, to keep the token small) or a
    `{"role": ..., "pattern": ...}` dict (used by services that round-trip a
    `Policy`/`PolicyInfo`-shaped record through the claim instead). Any entry
    that matches neither shape is skipped rather than raising -- a malformed
    or unexpected entry should not deny every other grant the token carries.
    """
    raw: Iterable[Any] = claims.get("policies") or ()
    grants: list[Grant] = []

    for entry in raw:
        if isinstance(entry, (list, tuple)) and len(entry) == 2:
            role, pattern = entry
        elif isinstance(entry, dict):
            role, pattern = entry.get("role"), entry.get("pattern")
        else:
            continue

        if isinstance(role, str) and isinstance(pattern, str) and role and pattern:
            grants.append(Grant(role=role, pattern=pattern))

    return grants
