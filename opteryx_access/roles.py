"""The canonical set of grantable roles.

Single source of truth for what a policy can grant.

`admin` is NOT one of these roles. It exists only as `billing_admin`/`member`
on a *billing account* (the JWT's `billing_role` claim) -- a different system
this package has no notion of and enforces no checks for. Nothing in this
package's own vocabulary is named "admin".

Roles rank two different things, and they do NOT coincide:

- **Administrative authority** -- who can create/update/revoke policies, list
  them, or export the full effective-permissions map. `owner` is the only
  role with this authority; see `ADMINISTRATIVE_ROLES`.
- **Data-action authority** -- who can SELECT/INSERT/DELETE/DROP/etc. against
  a resource. See `opteryx_access.actions` for that mapping -- do not use
  `ROLE_RANK` to decide a data action.
"""

# Highest privilege first. Order matters: `ROLE_RANK` is derived from it, and
# it is safe to reference by index (routes validate role values against this
# list, and can publish it verbatim in OpenAPI schemas).
ROLES: tuple[str, ...] = ("owner", "writer", "reader")

# Ordinal rank, highest first -- `ROLES[0]` outranks everything after it.
# Used only for administrative-authority comparisons (see module docstring).
ROLE_RANK = {role: len(ROLES) - index for index, role in enumerate(ROLES)}

# The role that may create, update, or revoke policies; list a workspace's
# policies; or export its full effective-permissions map. A single role, not
# a rank threshold -- there is no second, lesser administrative tier.
ADMINISTRATIVE_ROLES = frozenset({"owner"})


def is_valid_role(role: str) -> bool:
    """Whether `role` is one of the grantable roles in `ROLES`."""
    return role in ROLES


def role_rank(role: str) -> int:
    """Ordinal rank of `role`, or 0 if it isn't a recognized role.

    For administrative-authority comparisons only -- see the module
    docstring for why this must not be used to decide a data action.
    """
    return ROLE_RANK.get(role, 0)


def role_outranks_or_equals(held: str, other: str) -> bool:
    """Whether `held` is at least as privileged as `other` on the
    administrative-authority scale (owner > writer > reader).

    Used by conflict detection: a broader policy already at an equal or
    higher rank makes a narrower new grant redundant.
    """
    return role_rank(held) >= role_rank(other)
