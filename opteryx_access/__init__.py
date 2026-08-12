"""Permission checks and grant/revoke for the Opteryx platform.

An embedded library, not a service: every consumer imports this and calls it
in-process, against whatever policies it already has in hand (a JWT's
`policies` claim, or a `PolicyStore` it constructs). There is no
`opteryx-access` HTTP surface and this package makes no network calls itself
other than through the storage adapter a caller chooses to use.

Quick reference:

    from opteryx_access import Grant, action_allowed_for_role, can_perform_action

    grants = [Grant(role="writer", pattern="analytics.sales.*")]
    can_perform_action(grants, "analytics.sales.q1", "DELETE")  # True

    from opteryx_access import Policy, PolicyStore, grant, revoke, grants_for_principal
    from opteryx_access.adapters.firestore import FirestorePolicyStore

    store = FirestorePolicyStore(db)
    policy_id = grant(store, actor="alice", workspace="analytics",
                       principal="bob", role="writer", pattern="analytics.sales.*")
    revoke(store, actor="alice", workspace="analytics", policy_id=policy_id)

    # fetching what a principal holds, to hand to can_perform_action above:
    grants = grants_for_principal(store, workspace="analytics", identity="bob")

"May this identity administer grants here?" and "may this role perform this
action on this resource?" are separate questions -- see `opteryx_access.checks`,
which implements each over the input it needs.
"""

from opteryx_access.actions import ACTION_ROLES
from opteryx_access.actions import action_allowed_for_role
from opteryx_access.actions import allowed_roles
from opteryx_access.audit import AUDIT_LOGGER_NAME
from opteryx_access.audit import set_audit_sink
from opteryx_access.checks import can_administer_pattern
from opteryx_access.checks import can_perform_action
from opteryx_access.checks import can_perform_workspace_action
from opteryx_access.checks import has_workspace_access
from opteryx_access.checks import implicit_grants
from opteryx_access.exceptions import AccessDeniedError
from opteryx_access.exceptions import InvalidPatternError
from opteryx_access.exceptions import InvalidRoleError
from opteryx_access.exceptions import OpteryxAccessError
from opteryx_access.exceptions import PolicyConflictError
from opteryx_access.exceptions import PolicyNotFoundError
from opteryx_access.exceptions import SelfAccessError
from opteryx_access.exceptions import WorkspaceAlreadyBootstrappedError
from opteryx_access.grants import bootstrap_workspace
from opteryx_access.grants import find_conflict
from opteryx_access.grants import grant
from opteryx_access.grants import grants_for_principal
from opteryx_access.grants import owned_by
from opteryx_access.grants import revoke
from opteryx_access.grants import update_grant
from opteryx_access.models import Grant
from opteryx_access.models import Policy
from opteryx_access.models import parse_policy_claim
from opteryx_access.patterns import RESERVED_WORKSPACES
from opteryx_access.patterns import resource_matches
from opteryx_access.patterns import validate_pattern
from opteryx_access.patterns import validate_principal
from opteryx_access.roles import ROLES
from opteryx_access.roles import is_valid_role
from opteryx_access.roles import role_outranks_or_equals
from opteryx_access.store import PolicyStore

__all__ = [
    "ACTION_ROLES",
    "AUDIT_LOGGER_NAME",
    "RESERVED_WORKSPACES",
    "ROLES",
    "AccessDeniedError",
    "Grant",
    "InvalidPatternError",
    "InvalidRoleError",
    "OpteryxAccessError",
    "Policy",
    "PolicyConflictError",
    "PolicyNotFoundError",
    "PolicyStore",
    "SelfAccessError",
    "WorkspaceAlreadyBootstrappedError",
    "action_allowed_for_role",
    "allowed_roles",
    "bootstrap_workspace",
    "can_administer_pattern",
    "can_perform_action",
    "can_perform_workspace_action",
    "find_conflict",
    "grant",
    "grants_for_principal",
    "has_workspace_access",
    "implicit_grants",
    "is_valid_role",
    "owned_by",
    "parse_policy_claim",
    "resource_matches",
    "revoke",
    "role_outranks_or_equals",
    "set_audit_sink",
    "update_grant",
    "validate_pattern",
    "validate_principal",
]
