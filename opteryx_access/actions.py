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
    # Standing automation on a relation: creating, dropping, suspending,
    # resuming, or re-pinning the identity of a task or trigger, and creating
    # a materialized view (which lands a refresh trigger on every source it
    # reads). An INSERT is over when it finishes; a trigger runs unattended,
    # indefinitely, as a pinned identity, on the owner's compute, and can write
    # to other relations and fire further triggers. That is a commitment about
    # what the relation DOES to the world, not what is in it -- far closer to
    # GRANT than to WRITE -- so it is the owner's to make. Every engine with
    # triggers puts creating one above plain write (Postgres and MySQL have a
    # separate TRIGGER privilege; Snowflake gates tasks on EXECUTE TASK).
    "AUTOMATE": {"owner"},
    # Firing a task's SIGNAL trigger once, from outside - the webhook surface
    # dispatch.opteryx exposes. The caller is the EVENT, not the context: the
    # run assumes the trigger's pinned identity, exactly as a commit-fired run
    # does, and the caller is only recorded as what fired it. So this is a
    # writer-tier act like REFRESH - kicking off work that was already
    # authorized when the trigger was armed - and deliberately not AUTOMATE,
    # which is the owner's decision to have the standing automation at all. A
    # low-privilege service account can signal a pipeline that runs as
    # somebody else without being able to create, repoint or drop it.
    "SIGNAL": {"writer", "owner"},
    # Granting and revoking access to a resource is the owner's to do -- the
    # same tier as DROP, and for the same reason: it changes what the relation
    # fundamentally is to everyone else, not just what is in it.
    "GRANT": {"owner"},
    "REVOKE": {"owner"},
}

# The actions that administer policy rather than touch data. Named here, next
# to the table, so a consumer that only handles one kind can say which it
# means instead of restating the pair. The query engine performs these too --
# its GRANT/REVOKE/SHOW GRANTS ON statements land on
# `opteryx_access.capability`'s apply_grant/apply_revoke/grants_on -- so its
# SHOW GRANTS reports them alongside the data actions.
POLICY_ADMINISTRATION_ACTIONS: frozenset[str] = frozenset({"GRANT", "REVOKE"})

# Everything else: the actions a query engine can be asked to perform.
DATA_ACTIONS: frozenset[str] = frozenset(ACTION_ROLES) - POLICY_ADMINISTRATION_ACTIONS


def allowed_roles(action: str) -> frozenset[str]:
    """The set of roles that may perform `action`. Empty if unrecognized."""
    return frozenset(ACTION_ROLES.get(action, ()))


def action_allowed_for_role(role: str, action: str) -> bool:
    """Whether `role` may perform `action`."""
    return role in ACTION_ROLES.get(action, ())
