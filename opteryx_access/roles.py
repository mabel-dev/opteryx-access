"""The canonical set of grantable roles.

Single source of truth for what a policy can grant, replacing the identical
`ROLES` tuple previously copy-pasted between policy.opteryx and
control.opteryx (see those repos' `app/models/policy.py`).

Roles rank two different things, and they do NOT coincide:

- **Administrative authority** -- who can create/update/revoke policies, and
  who can list or export them. This ranks `owner` and `admin` above
  `writer`/`reader`; see `ADMINISTRATIVE_ROLES` and `OWNER_ONLY_ROLES`.
- **Data-action authority** -- who can SELECT/INSERT/DELETE/DROP/etc. against
  a resource. `admin` is deliberately NOT a superset of `writer` here: it is
  a grant-management tier, not a data-access tier. See `opteryx_access.actions`
  for that mapping -- do not use `ROLE_RANK` to decide a data action.

This `admin` is a WORKSPACE role -- unrelated to the `billing_admin`/`member`
distinction on a *billing account* (the JWT's `billing_role` claim). The two
share the word "admin" and nothing else; this package has no notion of
`billing_role` and enforces no billing checks. `bootstrap_workspace` in
`opteryx_access.store` takes an explicit list of (principal, role) pairs --
any rule about who is allowed to call it (e.g. requiring the caller be a
billing_admin) belongs to, and stays in, whichever service calls it.
"""

# Highest privilege first. Order matters: `ROLE_RANK` is derived from it, and
# it is safe to reference by index (routes validate role values against this
# list, and can publish it verbatim in OpenAPI schemas).
ROLES: tuple[str, ...] = ("owner", "admin", "writer", "reader")

# Ordinal rank, highest first -- `ROLES[0]` outranks everything after it.
# Used only for administrative-authority comparisons (see module docstring).
ROLE_RANK = {role: len(ROLES) - index for index, role in enumerate(ROLES)}

# Roles that may create, update, or revoke policies, and may list a
# workspace's policies. This is NOT "outranks writer" in the data-action
# sense -- it is its own, smaller tier.
ADMINISTRATIVE_ROLES = frozenset({"owner", "admin"})

# Roles that may export the full effective-permissions map for a workspace.
# Narrower than ADMINISTRATIVE_ROLES: exporting reveals who can reach every
# resource in the workspace in one document, a bigger blast radius than any
# single policy mutation, which owner *or* admin may already perform.
OWNER_ONLY_ROLES = frozenset({"owner"})


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
    administrative-authority scale (owner > admin > writer > reader).

    Used by conflict detection: a broader policy already at an equal or
    higher administrative rank makes a narrower new grant redundant.
    """
    return role_rank(held) >= role_rank(other)
