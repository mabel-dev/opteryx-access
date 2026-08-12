"""Actions mapped to the roles that may perform them.

Single source of truth for "DELETE requires writer-or-owner", "DROP requires
owner", etc. -- ported from opteryx-core's `opteryx.managers.permissions.ACTION_MAP`
(the only place this mapping existed before), extended with GRANT/REVOKE so
policy administration is declared here alongside the data actions instead of
living as an implicit rule elsewhere.

An explicit set per action, rather than a minimum rank each action must
clear: the requirement is stated where the action is defined, and stays
correct for a future action whose requirement isn't simply "this rank and
above".
"""

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
    # Granting and revoking access to a resource is the owner's to do -- the
    # same tier as DROP, and for the same reason: it changes what the relation
    # fundamentally is to everyone else, not just what is in it.
    "GRANT": {"owner"},
    "REVOKE": {"owner"},
}


def allowed_roles(action: str) -> frozenset[str]:
    """The set of roles that may perform `action`. Empty if unrecognized."""
    return frozenset(ACTION_ROLES.get(action, ()))


def action_allowed_for_role(role: str, action: str) -> bool:
    """Whether `role` may perform `action`."""
    return role in ACTION_ROLES.get(action, ())
