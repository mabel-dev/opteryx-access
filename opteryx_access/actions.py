"""SQL-shaped actions mapped to the roles that may perform them.

Single source of truth for "DELETE requires writer-or-owner", "DROP requires
owner", etc. -- ported from opteryx-core's `opteryx.managers.permissions.ACTION_MAP`
(the only place this mapping existed before), extended with GRANT/REVOKE so the
policy-administration actions this package itself exposes (see `opteryx_access.store`)
are declared in the same table instead of living as an implicit rule elsewhere.

Deliberately a `{action: set-of-roles}` map, not a minimum-rank comparison,
even though every entry today happens to be "top N roles by rank" and so
could be read as one. Rank is a data-role-only concept (owner > writer >
reader); an explicit per-action set stays correct if a future action's
requirement doesn't nest that way, and it keeps each action's requirement
self-documenting at its own definition rather than inferred from a number.
"""

from opteryx_access.roles import ADMINISTRATIVE_ROLES

ACTION_ROLES = {
    "READ": {"reader", "writer", "owner"},
    "DELETE": {"writer", "owner"},
    "WRITE": {"writer", "owner"},
    "UPDATE": {"writer", "owner"},
    # Creating a brand-new relation risks nothing existing; a writer may do it.
    "CREATE": {"writer", "owner"},
    # Rebuilding a materialized view from its own stored definition. Mechanically
    # a CREATE OR REPLACE, but the decision to have this relation at all was
    # taken -- and authorized -- when the view was created, and its contents
    # are derived rather than authored. So a refresh is a writer-tier act, not
    # the owner-tier one that replacing a hand-written table is.
    "REFRESH": {"writer", "owner"},
    # Dropping a relation destroys it and its history; a writer may change a
    # relation's contents but only an owner may remove the relation itself.
    "DROP": {"owner"},
    # ALTER changes a relation's physical layout (e.g. CLUSTER BY) rather than
    # its contents -- same tier as DROP.
    "ALTER": {"owner"},
    # SHOW MANIFEST FOR exposes file paths and layout (bucket/partition
    # structure), not just data -- stricter than a normal READ.
    "MANIFEST": {"owner"},
    # Policy administration: creating, updating, or revoking a grant.
    # Owner-only, same as ADMINISTRATIVE_ROLES.
    "GRANT": set(ADMINISTRATIVE_ROLES),
    "REVOKE": set(ADMINISTRATIVE_ROLES),
}


def allowed_roles(action: str) -> frozenset[str]:
    """The set of roles that may perform `action`. Empty if unrecognized."""
    return frozenset(ACTION_ROLES.get(action, ()))


def action_allowed_for_role(role: str, action: str) -> bool:
    """Whether `role` may perform `action`."""
    return role in ACTION_ROLES.get(action, ())
