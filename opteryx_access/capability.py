"""The permissions capability opteryx-core asks for.

opteryx-core ships an intrinsic capability that allows everything: a CLI or
embedded engine has no workspaces to own and no policy service to have issued
anything, so access control is a property of a deployment rather than of the
engine. A deployment installs this one over it:

    import opteryx
    import opteryx_access

    opteryx.register_permissions_capability(opteryx_access.capability())

This module is the ONLY part of this package that knows opteryx-core exists,
and even here it does not import it: the engine hands over an execution
context and this reads two attributes off it. So the dependency points one way
only -- a deployment brings the two together, neither package requires the
other, and this file can be read as the full extent of the coupling.

The engine's own permission checks and `SHOW GRANTS` are both answered from
here, so what it enforces and what it reports come from one evaluation.
"""

from opteryx_access.actions import ACTION_ROLES
from opteryx_access.actions import DATA_ACTIONS
from opteryx_access.checks import can_perform_action
from opteryx_access.checks import can_perform_workspace_action
from opteryx_access.checks import implicit_grants
from opteryx_access.models import Grant
from opteryx_access.models import parse_policy_claim

__all__ = ("PermissionsCapability", "capability")


def _identity(execution_context) -> str | None:
    """The identity the session is running as, or None if anonymous."""
    return getattr(execution_context, "user", None)


def _grants(policies) -> list[Grant]:
    """The issued grants a session holds, as `Grant`s.

    Reuses `parse_policy_claim` rather than converting separately: an engine's
    `access_policies` is the same `{"role":..., "pattern":...}` shape a token's
    `policies` claim carries, and that parser already skips entries it cannot
    read instead of failing the whole list. One malformed policy must not
    decide the fate of the others, in either direction.
    """
    return parse_policy_claim({"policies": policies})


def _actions_for(role: str) -> str:
    """The data actions `role` confers, as `SHOW GRANTS` renders them.

    Derived from `ACTION_ROLES` rather than restated, so the column cannot
    describe a permission that is not the one enforced. Policy administration
    (`GRANT`/`REVOKE`) is excluded: those are real actions this package
    decides, but no SQL statement in opteryx performs them, so naming them in
    the engine's own output would advertise a capability its surface does not
    have.
    """
    return ", ".join(sorted(action for action in DATA_ACTIONS if role in ACTION_ROLES[action]))


class PermissionsCapability:
    """Answers opteryx-core's permission checks from issued access policies.

    Stateless: every answer is computed from the execution context handed in,
    so one instance serves every session and there is nothing to invalidate.

    The grants are rebuilt from `execution_context.access_policies` on each
    check rather than cached against the context. A cache would have to
    guess when that list changed, and a permission cache that answers from a
    stale list is a security bug in a way that a little repeated work is not.
    """

    name = "opteryx-access"

    def can_perform_action(self, execution_context, resource: str, action: str) -> bool:
        return can_perform_action(
            _grants(getattr(execution_context, "access_policies", None) or ()),
            resource,
            action,
            identity=_identity(execution_context),
        )

    def can_perform_workspace_action(self, execution_context, workspace: str, action: str) -> bool:
        return can_perform_workspace_action(
            _grants(getattr(execution_context, "access_policies", None) or ()),
            workspace,
            action,
        )

    def grants(self, identity: str, policies: list) -> list[dict]:
        """The rows behind `SHOW GRANTS`, in the order they are evaluated.

        Implicit grants come first because `can_perform_action` answers from
        them first and stops: read top-down, the table is the order the engine
        actually decides in, so a caller can see why `public.*` is read-only
        even where a broader policy appears below it.
        """
        held = implicit_grants(identity) + _grants(policies)
        return [
            {"pattern": grant.pattern, "role": grant.role, "actions": _actions_for(grant.role)}
            for grant in held
        ]


def capability() -> PermissionsCapability:
    """The capability to hand to `opteryx.register_permissions_capability`."""
    return PermissionsCapability()
