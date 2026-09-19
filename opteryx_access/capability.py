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

Most checks are answered from that context alone. The exceptions:
`can_principal_own_materialized_view` is asked about a named principal and
answered from this package's own list of platform identities;
`can_principal_perform_action` is asked about somebody who is not the caller,
whose policies this process was never issued; and grant administration
(`apply_grant`/`apply_revoke`/`grants_on`/`effective_grants_on`/
`effective_grants_in`, behind the engine's `GRANT`/`REVOKE`/`SHOW GRANTS ON`/
`SHOW EFFECTIVE GRANTS ON` statements and its `information_schema.grants`
table) reads and writes live policy state. A capability that has to answer any of those is constructed with a
`PolicyStore`:

    opteryx.register_permissions_capability(opteryx_access.capability(store))

The engine's own permission checks, its `SHOW GRANTS`, and its grant
mutations are all answered from here, so what it enforces, what it reports,
and what it changes come from one evaluation.
"""

from opteryx_access.actions import ACTION_ROLES
from opteryx_access.checks import PLATFORM_IDENTITIES
from opteryx_access.checks import maintenance_identity
from opteryx_access.checks import can_administer_pattern
from opteryx_access.checks import can_perform_action
from opteryx_access.checks import can_perform_workspace_action
from opteryx_access.checks import implicit_grants
from opteryx_access.entitlements import parse_entitlement_claim
from opteryx_access.entitlements import resolve_entitlements
from opteryx_access.exceptions import AccessDeniedError
from opteryx_access.exceptions import InvalidPatternError
from opteryx_access.exceptions import PolicyStoreRequiredError
from opteryx_access.grants import grant
from opteryx_access.grants import grants_for_principal
from opteryx_access.grants import revoke_grant
from opteryx_access.models import Grant
from opteryx_access.models import parse_policy_claim
from opteryx_access.patterns import is_engine_private
from opteryx_access.patterns import normalize
from opteryx_access.patterns import pattern_level
from opteryx_access.patterns import resource_matches
from opteryx_access.patterns import validate_pattern
from opteryx_access.store import PolicyStore

__all__ = ("PermissionsCapability", "capability")


def _identity(execution_context) -> str | None:
    """The identity the session is running as, or None if anonymous."""
    return getattr(execution_context, "user", None)


def _entitlements(execution_context) -> list:
    """What the session's entitlement NAMES confer, as `Entitlement`s.

    Read with `getattr(..., None)`, like `access_policies`: an engine that
    does not carry the claim yet simply has none, and the deployment behaves
    exactly as it did before entitlements existed rather than failing on a
    missing attribute.

    The context carries the names the identity system issued
    (`["platform_admin", "automation_admin::acme"]`), not permissions. What a
    kind confers is declared in `opteryx_access.entitlements.ENTITLEMENT_KINDS`
    and its scope is in the name; names this package does not recognize
    resolve to nothing -- an account holds plenty that mean something to other
    services.
    """
    return parse_entitlement_claim(
        {"entitlements": getattr(execution_context, "entitlements", None) or ()},
        principal=_identity(execution_context) or "",
    )


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
    """The actions `role` confers, as `SHOW GRANTS` renders them.

    Derived from `ACTION_ROLES` rather than restated, so the column cannot
    describe a permission that is not the one enforced. Policy administration
    (`GRANT`/`REVOKE`) is included: opteryx performs them as SQL statements
    (`GRANT`/`REVOKE`/`SHOW GRANTS ON`), so an owner's row advertises exactly
    what an owner may do. Before that surface existed they were deliberately
    hidden here; the surface and this line changed together.
    """
    return ", ".join(sorted(action for action in ACTION_ROLES if role in ACTION_ROLES[action]))


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
            entitlements=_entitlements(execution_context),
        )

    def can_perform_workspace_action(self, execution_context, workspace: str, action: str) -> bool:
        return can_perform_workspace_action(
            _grants(getattr(execution_context, "access_policies", None) or ()),
            workspace,
            action,
            entitlements=_entitlements(execution_context),
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

        ENTITLEMENTS ARE NOT INCLUDED, and cannot be: a principal's
        entitlement names live in the identity system, which this package does
        not talk to, and there is no execution context here to read them off.
        So this answers from policies and implicit grants -- narrower than the
        truth for a principal who holds one. It matters little for what the
        engine asks this: entitlements confer operational actions, and the
        statements naming another principal ask whether they can READ.

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

    def can_principal_own_materialized_view(self, principal: str) -> bool:
        """Whether `principal` may be pinned as a materialized view's `runs-as`.

        Refused for the platform identities (`PLATFORM_IDENTITIES`) and nobody
        else. This is a COSTING rule, not an access one, which is why it is not
        answerable from grants: those identities can read a great deal - they
        hold writer on `public.*` and maintain what is in it - but they are
        identities rather than accounts. Nothing bills them, because nothing
        sells them. A materialized view refreshes as its owner, on a schedule,
        forever, so a view a user could point at one would be standing compute
        billed to nobody.

        Every other principal is permitted. A human account and a service
        account both sit behind a billing account (a service account cannot be
        created without claiming a seat on one), so both are costed when they
        run, and neither needs distinguishing here.

        No store is consulted: a platform identity is refused whatever policies
        it holds, and holding none would not make it billable.
        """
        return normalize(principal) not in PLATFORM_IDENTITIES

    def grants(self, identity: str, policies: list, entitlements: list | None = None) -> list[dict]:
        """The rows behind `SHOW GRANTS`, in the order they are evaluated.

        Implicit grants come first because `can_perform_action` answers from
        them first and stops: read top-down, the table is the order the engine
        actually decides in, so a caller can see why `public.*` is read-only
        even where a broader policy appears below it.

        Entitlements come first, ahead even of the implicit grants, for the
        same reason: `can_perform_action` consults them first. Their `role`
        column reads `entitlement` -- not a role, and deliberately not one of
        `ROLES`, so a row conferring `AUTOMATE` on `public.*` cannot be
        mistaken for a role that was granted. Their `actions` column is what
        the entitlement actually confers, not what a role would.

        `entitlements` is the session's entitlement NAMES, as the token
        carries them. It is optional so that an engine which does not pass
        them gets exactly the listing it got before entitlements existed,
        rather than an error -- but a deployment whose tokens carry names and
        whose `SHOW GRANTS` omits them reports less than it enforces.

        `level` labels each pattern the way the SQL surface speaks
        (workspace/collection/dataset, via `pattern_level`); a pattern that
        addresses no single object carries an empty label rather than a
        guessed one.
        """
        rows = [
            {
                "pattern": entitlement.pattern,
                "level": pattern_level(entitlement.pattern) or "",
                "role": "entitlement",
                "actions": ", ".join(sorted(entitlement.actions)),
            }
            for entitlement in resolve_entitlements(entitlements or (), principal=identity)
        ]

        held = implicit_grants(identity) + _grants(policies)
        rows.extend(
            {
                "pattern": held_grant.pattern,
                "level": pattern_level(held_grant.pattern) or "",
                "role": held_grant.role,
                "actions": _actions_for(held_grant.role),
            }
            for held_grant in held
        )
        return rows

    def _administration_store(self, doing: str) -> PolicyStore:
        """The store, or the refusal to guess without one.

        Grant administration is a write against live policy state; the
        session's own token says nothing about what other principals hold.
        Raising mirrors `can_principal_perform_action`: no store is "cannot
        answer", never "denied" and never "allowed".
        """
        if self._store is None:
            raise PolicyStoreRequiredError(
                f"cannot {doing}: this capability was built by capability() with no "
                "PolicyStore, so it can only answer about the session that is asking. "
                "Build it as capability(store) to administer grants."
            )
        return self._store

    def _acting_identity(self, execution_context) -> str:
        """The identity administering grants, refused for anonymous sessions.

        Every grant rule downstream reasons about a named actor -- authority,
        self-service, audit attribution -- so a session with no identity has
        nothing those rules can hold to account.
        """
        identity = _identity(execution_context)
        if not identity:
            raise AccessDeniedError("an anonymous session cannot administer grants")
        return normalize(identity)

    def apply_grant(self, execution_context, pattern: str, role: str, principal: str) -> str:
        """Add ONE policy: `role` on `pattern` to `principal`. Returns its id.

        The engine's `GRANT <role> ON <object> TO USER <principal>`, with the
        object already mapped to its pattern by the binder (`WORKSPACE w` ->
        `w.*`, `COLLECTION w.c` -> `w.c.*`, `DATASET w.c.d` -> `w.c.d`).
        Every rule -- owner authority covering the pattern, the no-self-service
        rule, validation, conflict/redundancy refusal, the audit record --
        lives in `opteryx_access.grants.grant`, which this delegates to whole.
        There is no upgrade path: changing an existing grant is REVOKE then
        GRANT, by the caller.
        """
        store = self._administration_store(f"grant {role!r} on {pattern!r}")
        actor = self._acting_identity(execution_context)
        pattern = validate_pattern(pattern)
        workspace = pattern.split(".", 1)[0]
        return grant(
            store,
            actor=actor,
            workspace=workspace,
            principal=principal,
            role=role,
            pattern=pattern,
        )

    def apply_revoke(self, execution_context, pattern: str, role: str, principal: str) -> str:
        """Delete ONE policy: the exact (`principal`, `pattern`, `role`) match.

        The engine's `REVOKE <role> ON <object> FROM USER <principal>`.
        Resolution and every rule live in `opteryx_access.grants.revoke_grant`:
        strictly 1:1 -- access held through a policy at a different level is
        reported (naming that policy and its level), never narrowed or
        silently left in place. Returns the revoked policy's id.
        """
        store = self._administration_store(f"revoke {role!r} on {pattern!r}")
        actor = self._acting_identity(execution_context)
        pattern = validate_pattern(pattern)
        workspace = pattern.split(".", 1)[0]
        return revoke_grant(
            store,
            actor=actor,
            workspace=workspace,
            principal=principal,
            role=role,
            pattern=pattern,
        )

    # -- maintenance ---------------------------------------------------
    #
    # `ALTER WORKSPACE <ws> SET maintenance TO ON|OFF` is a setting in the
    # statement and a GRANT in the store: what it names is whether the
    # platform's compactor may WRITE here, and that is a policy like any other.
    #
    # It exists because the alternative is what the platform did before it:
    # to have a workspace compacted, its owner added an identity they had
    # never heard of to their access list at `writer`, with nothing on that
    # screen saying what it was for or that revoking it turned maintenance off.
    # The mechanism was sound and the surface was backwards. Nothing about the
    # authority changes here - the same policy, checked by the same rules,
    # written by the same `grant()` - only who has to know it is a policy.
    #
    # One piece of state, deliberately: the setting IS the grant's existence,
    # never a flag stored beside it. A flag could disagree with the policy that
    # actually decides, and the disagreement would be invisible until a
    # compaction that everyone believed was running turned out not to be.

    MAINTENANCE_ROLE = "writer"

    @staticmethod
    def _maintenance_pattern(workspace: str) -> str:
        """The pattern maintenance is held at: the whole workspace.

        Workspace-wide and not narrower, because that is the level the setting
        is offered at. A dataset inside an enabled workspace shows the setting
        as INHERITED and cannot manage it - exactly as it shows an inherited
        grant, which is what it is.
        """
        return f"{normalize(workspace)}.*"

    def set_workspace_maintenance(self, execution_context, workspace: str, enabled: bool) -> None:
        """Turn platform maintenance on or off for `workspace`.

        Idempotent in both directions. `grant()` refuses a policy that already
        exists and `revoke_grant()` refuses one that does not, both correctly
        for a caller who asked for a change - but a SETTING set to what it
        already says is not an error, it is a no-op. So the current state is
        read first and a call that would change nothing writes nothing.

        Everything else is `apply_grant`/`apply_revoke`: the same store, the
        same actor, the same owner-authority check, the same audit record. A
        caller who lacks owner authority over the workspace is refused here
        exactly as they would be for the GRANT spelled out longhand.
        """
        store = self._administration_store(
            f"{'enable' if enabled else 'disable'} maintenance on {workspace!r}"
        )
        actor = self._acting_identity(execution_context)
        principal = maintenance_identity()
        workspace = normalize(workspace)
        pattern = validate_pattern(self._maintenance_pattern(workspace))

        if self._maintenance_policy(store, workspace, principal, pattern) is not None:
            if enabled:
                return
            revoke_grant(
                store,
                actor=actor,
                workspace=workspace,
                principal=principal,
                role=self.MAINTENANCE_ROLE,
                pattern=pattern,
            )
            return

        if not enabled:
            return

        grant(
            store,
            actor=actor,
            workspace=workspace,
            principal=principal,
            role=self.MAINTENANCE_ROLE,
            pattern=pattern,
        )

    def workspace_maintenance(self, execution_context, workspace: str) -> bool:
        """Whether platform maintenance is on for `workspace`.

        Derived from the policy, never from a stored flag, so what this
        reports is what the compactor's own permission check will decide.

        Deliberately NOT gated on owner authority the way the grant listings
        are: this answers "is my data being maintained", which is a property of
        the workspace rather than a fact about who holds access to it, and it
        names no principal. The listings stay owner-only.
        """
        store = self._store
        if store is None:
            return False
        workspace = normalize(workspace)
        principal = maintenance_identity()
        pattern = self._maintenance_pattern(workspace)
        return self._maintenance_policy(store, workspace, principal, pattern) is not None

    def _maintenance_policy(self, store, workspace: str, principal: str, pattern: str):
        """The stored policy that IS the maintenance setting, or None.

        Matched on all three of principal, pattern and role. A `writer` grant
        the identity holds at some other level is somebody else's arrangement
        and not this setting - turning maintenance off must not delete it, and
        turning it on must not be fooled into writing nothing by it.
        """
        for policy in store.list_policies_for_principal(workspace, principal):
            if (
                normalize(policy.pattern) == normalize(pattern)
                and policy.role == self.MAINTENANCE_ROLE
            ):
                return policy
        return None

    def _policy_rows(
        self, execution_context, pattern: str, doing: str, covering: bool
    ) -> list[dict]:
        """The shared body of the two grant listings: gate, select, render.

        `covering` is the ONLY difference between them, and it is one line: an
        attached listing keeps the policies stored at exactly `pattern`, an
        effective one keeps every policy whose own pattern covers it. Sharing
        the rest is deliberate -- the gate, the ordering and the four columns
        must be identical, so that the two statements can be read side by side
        and the console can render both with one renderer.

        A workspace pattern (`w.*`) skips the filter entirely in both modes:
        the workspace listing is already every policy at every level, which is
        also every policy that covers the workspace. The two statements
        therefore agree there by construction rather than by coincidence.
        """
        store = self._administration_store(doing)
        actor = self._acting_identity(execution_context)
        pattern = validate_pattern(pattern)
        workspace = pattern.split(".", 1)[0]

        if not can_administer_pattern(
            store.list_policies_for_principal(workspace, actor), actor, pattern
        ):
            raise AccessDeniedError("insufficient permissions to list the grants on this pattern")

        policies = store.list_policies(workspace)
        if pattern != f"{workspace}.*":
            if covering:
                # `resource_matches` is the matcher `can_perform_action` decides
                # real queries with, asked here with the object as the resource.
                # Reusing it is the whole value of the effective listing: a
                # private covering test would drift and start reporting access
                # that does not exist, or hiding access that does.
                policies = [
                    policy for policy in policies if resource_matches(pattern, policy.pattern)
                ]
            else:
                policies = [policy for policy in policies if normalize(policy.pattern) == pattern]

        policies.sort(key=lambda policy: (normalize(policy.principal), normalize(policy.pattern)))
        return [
            {
                "user": policy.principal,
                "pattern": policy.pattern,
                "level": pattern_level(policy.pattern) or "",
                "role": policy.role,
            }
            for policy in policies
        ]

    def grants_on(self, execution_context, pattern: str) -> list[dict]:
        """The rows behind `SHOW GRANTS ON <object>`: stored policies, one row
        per policy, `(user, pattern, level, role)`, ordered by user then
        pattern.

        `SHOW GRANTS ON WORKSPACE w` arrives as `w.*` and lists EVERY policy
        in the workspace, whatever level each is scoped to -- the access-list
        screen, as SQL. A narrower object (`w.c.*`, `w.c.d`) lists only the
        policies at exactly that object: 1:1 with what GRANT and REVOKE there
        would act on. A broader policy that merely covers the object is not
        that object's to show -- it is `effective_grants_on` that answers who
        can reach the object, and the workspace listing that shows the lot.

        Gated on the same authority a mutation needs (`can_administer_pattern`:
        owner, covering the pattern) -- deliberately not the weaker
        `has_workspace_access`, and deliberately identical for reading and
        writing: who may see the grants is who may change them.
        """
        return self._policy_rows(
            execution_context, pattern, f"list the grants on {pattern!r}", covering=False
        )

    def effective_grants_on(self, execution_context, pattern: str) -> list[dict]:
        """The rows behind `SHOW EFFECTIVE GRANTS ON <object>`: every stored
        policy that COVERS the object, one row per policy, in the same four
        columns and the same order as `grants_on`.

        The other question about an object. `grants_on` answers what is stored
        AT it -- 1:1 with what GRANT and REVOKE there act on -- and returns
        nothing for a dataset whose only reachable-by policy is the workspace
        owner's `w.*`. This answers who can reach the object at all, that
        owner included, and says why: the `pattern` and `level` columns carry
        the covering policy, so a row reading `(bob, w.*, workspace, owner)`
        against a dataset explains itself without a fifth column.

        One row per COVERING POLICY, not per user, and no highest-role-wins
        collapse: a user may reach an object through more than one policy, and
        which policy grants it is exactly what has to change to take it away.
        A consumer wanting one effective role per user collapses the rows
        itself.

        `SHOW EFFECTIVE GRANTS ON WORKSPACE w` returns what `SHOW GRANTS ON
        WORKSPACE w` returns -- a workspace listing is already every policy at
        every level. The two statements differ only for a COLLECTION or a
        DATASET.

        The covering test is `resource_matches`, the matcher that decides real
        queries, never a second implementation of it. Gated identically to
        `grants_on`: owner authority covering the object.
        """
        return self._policy_rows(
            execution_context,
            pattern,
            f"list the effective grants on {pattern!r}",
            covering=True,
        )

    def effective_grants_in(self, execution_context, workspace: str, objects: list) -> list[dict]:
        """The rows behind the engine's `information_schema.grants`: for each
        object in `objects`, every stored policy in `workspace` that covers
        it -- `effective_grants_on` asked once per object, over ONE read of
        the policy store.

        `objects` are object patterns as the SQL surface speaks them (`w.*`,
        `w.c.*`, `w.c.d`), built by the engine from its catalog listing. That
        listing is why this member exists: `effective_grants_on` reads the
        store twice per call, so walking a workspace of a hundred datasets
        through it would read the same policy documents two hundred times.
        Here the actor's policies and the workspace's are each read once.

        Every stored policy is ALSO reported at its own pattern, whether or
        not the engine asked about it. A policy on a dataset that has since
        been dropped, or a collection nobody has created yet, names no
        catalog object the engine could have enumerated -- and a listing of
        what is granted that omits exactly the grants pointing at nothing is
        the one an administrator most needs to be complete. `SHOW GRANTS ON
        WORKSPACE` lists them; so does this.

        Rows carry the four columns of the two SHOW statements plus `object`
        (the pattern the row answers for, normalized, so the engine can join
        it back to what it asked) and `explicit`: True when the policy is
        stored AT the object -- the same exact-pattern test `grants_on`
        applies -- and False when it merely covers the object from above.
        One row per covering policy, as for the statements, and for the same
        reason: which policy grants the access is what has to change to take
        it away.

        Gated per object with `can_administer_pattern`, exactly as the two
        statements are gated. Unlike them, an object the actor may not
        administer is SKIPPED rather than refused: a statement names one
        object and refusing it is the answer, while a listing over a
        workspace shows what the actor may see, as every information_schema
        table does. An anonymous session may see none of it and gets no
        rows. The store is still required -- no store is "cannot answer",
        never an empty table.

        For a collection or a dataset the rows are `effective_grants_on`'s
        exactly. For the WORKSPACE object they are not: the statement lists
        every policy in the workspace, whatever level it is held at, while
        here the workspace row holds only the policies that cover the
        workspace as an object (`w.*`). Every other policy is reported at its
        own pattern instead, once, as explicit -- so "everything stored in the
        workspace" is the explicit rows, and a narrower policy is never shown
        as if it reached the workspace above it.

        Object patterns are normalized, not validated. They name what the
        catalog holds rather than what a policy may be issued over: a dataset
        whose name no policy could spell exactly is still covered by `w.*`,
        and `can_perform_action` would say so for a real query. Engine-private
        names are the exception, refused here as they are everywhere. Objects
        outside `workspace` are a caller error, not a silent miss.
        """
        store = self._administration_store(f"list the effective grants in {workspace!r}")
        workspace = normalize(workspace)
        if not workspace:
            raise InvalidPatternError("effective_grants_in needs the workspace to list")

        asked: list[str] = []
        for pattern in objects:
            normalized = normalize(pattern)
            if not normalized or is_engine_private(normalized):
                continue
            if normalized.split(".", 1)[0] != workspace:
                raise InvalidPatternError(
                    f"effective_grants_in lists one workspace at a time: {pattern!r} is not "
                    f"in {workspace!r}"
                )
            if normalized not in asked:
                asked.append(normalized)

        identity = _identity(execution_context)
        if not identity:
            return []
        actor = normalize(identity)

        actor_policies = store.list_policies_for_principal(workspace, actor)
        policies = sorted(
            store.list_policies(workspace),
            key=lambda policy: (normalize(policy.principal), normalize(policy.pattern)),
        )

        # What was asked about, in the order asked, then every stored pattern
        # not already among them -- so nothing granted goes unlisted.
        for policy in policies:
            held_at = normalize(policy.pattern)
            if held_at not in asked and not is_engine_private(held_at):
                asked.append(held_at)

        rows = []
        for object_pattern in asked:
            if not can_administer_pattern(actor_policies, actor, object_pattern):
                continue
            for policy in policies:
                if not resource_matches(object_pattern, policy.pattern):
                    continue
                rows.append(
                    {
                        "object": object_pattern,
                        "user": policy.principal,
                        "pattern": policy.pattern,
                        "level": pattern_level(policy.pattern) or "",
                        "role": policy.role,
                        "explicit": normalize(policy.pattern) == object_pattern,
                    }
                )
        return rows


def capability(store: PolicyStore | None = None) -> PermissionsCapability:
    """The capability to hand to `opteryx.register_permissions_capability`.

    `store` is needed only by `can_principal_perform_action`; the rest are
    answered from the execution context the engine hands over. A deployment
    running statements that name another principal -- `ALTER MATERIALIZED VIEW
    ... OWNER TO` -- must supply one, and without it that check raises rather
    than guessing at an answer it has no way to reach.

    Entitlements need no store at all: a session's entitlement names arrive
    on the execution context, scoped by the platform that issued them, and
    what each kind confers is declared in
    `opteryx_access.entitlements.ENTITLEMENT_KINDS`.
    """
    return PermissionsCapability(store)
