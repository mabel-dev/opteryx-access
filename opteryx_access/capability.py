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

Most checks are answered from that context alone. One is not:
`can_principal_perform_action` is asked about somebody who is not the caller,
whose policies this process was never issued, so a capability that has to
answer it is constructed with a `PolicyStore` to read them from:

    opteryx.register_permissions_capability(opteryx_access.capability(store))

The engine's own permission checks and `SHOW GRANTS` are both answered from
here, so what it enforces and what it reports come from one evaluation.
"""

from opteryx_access.actions import ACTION_ROLES
from opteryx_access.actions import DATA_ACTIONS
from opteryx_access.checks import can_perform_action
from opteryx_access.checks import can_perform_workspace_action
from opteryx_access.checks import implicit_grants
from opteryx_access.exceptions import PolicyStoreRequiredError
from opteryx_access.grants import grants_for_principal
from opteryx_access.models import Grant
from opteryx_access.models import parse_policy_claim
from opteryx_access.patterns import normalize
from opteryx_access.store import PolicyStore

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

    Holds no session state: every answer is computed from the execution context
    handed in, so one instance serves every session and there is nothing to
    invalidate. The `PolicyStore` it may be constructed with is not session
    state either -- it is read through, never read from a cache.

    The grants are rebuilt from `execution_context.access_policies` on each
    check rather than cached against the context. A cache would have to
    guess when that list changed, and a permission cache that answers from a
    stale list is a security bug in a way that a little repeated work is not.
    The same applies to what is read from the store.
    """

    name = "opteryx-access"

    def __init__(self, store: PolicyStore | None = None) -> None:
        self._store = store

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

    def can_principal_perform_action(self, principal: str, resource: str, action: str) -> bool:
        """Whether `principal` may perform `action` on `resource`.

        Asked about somebody who is not the caller. There is no execution
        context because that principal has no session here, and the asking
        session's policies say nothing about what they hold -- so their grants
        are read from the store rather than handed over.

        The engine needs this wherever a statement names an identity to act AS
        rather than acting as its author. `ALTER MATERIALIZED VIEW ... OWNER TO`
        pins the identity a view's refresh runs as, and has to establish that
        the incoming owner can read the view's sources before pinning them
        there: a caller's own authority is not transferable by naming somebody
        else.

        Evaluated by the same `can_perform_action` the session-scoped check
        uses, so a principal is judged by exactly the rules that would judge
        them if they ran the query themselves -- implicit grants included,
        since those are theirs whatever any store holds.

        Raises:
            PolicyStoreRequiredError: no store was supplied at construction, so
                another principal's policies cannot be read.
        """
        if resource.count(".") == 0:
            # `can_perform_action`'s rule, for the same reason: a name with no
            # dot is a local, in-session table, and there is no workspace to
            # look a policy up in.
            return action == "READ"

        if self._store is None:
            raise PolicyStoreRequiredError(
                f"cannot decide whether {principal!r} may {action} {resource!r}: this "
                "capability was built by capability() with no PolicyStore, so it can "
                "only answer about the session that is asking. Build it as "
                "capability(store) to answer about other principals."
            )

        workspace = normalize(resource).split(".", 1)[0]
        return can_perform_action(
            grants_for_principal(self._store, workspace=workspace, identity=principal),
            resource,
            action,
            identity=principal,
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


def capability(store: PolicyStore | None = None) -> PermissionsCapability:
    """The capability to hand to `opteryx.register_permissions_capability`.

    `store` is needed only by `can_principal_perform_action`; the rest are
    answered from the execution context the engine hands over. A deployment
    running statements that name another principal -- `ALTER MATERIALIZED VIEW
    ... OWNER TO` -- must supply one, and without it that check raises rather
    than guessing at an answer it has no way to reach.
    """
    return PermissionsCapability(store)
