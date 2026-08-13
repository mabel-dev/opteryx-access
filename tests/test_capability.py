"""The opteryx-core permissions capability.

These exercise the adapter against a stand-in for the engine's execution
context -- the two attributes it reads, and nothing else. That stand-in is the
whole contract: if it stops resembling `opteryx.models.ExecutionContext`, this
adapter is what breaks.
"""

from dataclasses import dataclass
from dataclasses import field

import pytest
from fakes import FakePolicyStore

from opteryx_access.actions import ACTION_ROLES
from opteryx_access.actions import DATA_ACTIONS
from opteryx_access.actions import POLICY_ADMINISTRATION_ACTIONS
from opteryx_access.capability import PermissionsCapability
from opteryx_access.capability import capability
from opteryx_access.exceptions import PolicyStoreRequiredError
from opteryx_access.models import Policy
from opteryx_access.roles import ROLES


@dataclass
class FakeExecutionContext:
    """The slice of `opteryx.models.ExecutionContext` the capability reads."""

    user: str | None = None
    access_policies: list = field(default_factory=list)


def test_capability_provides_the_four_members_the_engine_requires():
    # Mirrors opteryx-core's _REQUIRED_MEMBERS check at registration.
    cap = capability()
    for member in (
        "can_perform_action",
        "can_perform_workspace_action",
        "can_principal_perform_action",
        "grants",
    ):
        assert getattr(cap, member, None) is not None, member


def test_capability_returns_a_permissions_capability():
    assert isinstance(capability(), PermissionsCapability)


# --- can_perform_action


def test_writer_may_delete_but_not_drop():
    context = FakeExecutionContext(
        user="alice", access_policies=[{"pattern": "analytics.*", "role": "writer"}]
    )
    cap = capability()
    assert cap.can_perform_action(context, "analytics.sales.q1", "DELETE")
    assert not cap.can_perform_action(context, "analytics.sales.q1", "DROP")


def test_a_pattern_confers_nothing_outside_itself():
    context = FakeExecutionContext(
        user="alice", access_policies=[{"pattern": "analytics.*", "role": "owner"}]
    )
    assert not capability().can_perform_action(context, "billing.invoices.q1", "READ")


def test_no_policies_confers_nothing_beyond_the_implicit_grants():
    context = FakeExecutionContext(user="alice")
    cap = capability()
    assert not cap.can_perform_action(context, "analytics.sales.q1", "READ")
    # ...but the implicit ones still apply.
    assert cap.can_perform_action(context, "public.security", "READ")
    assert cap.can_perform_action(context, "personal.alice.notes", "DROP")


def test_personal_namespace_is_the_session_identity_not_another():
    context = FakeExecutionContext(user="alice")
    cap = capability()
    assert cap.can_perform_action(context, "personal.alice.notes", "DROP")
    assert not cap.can_perform_action(context, "personal.bob.notes", "READ")


def test_public_stays_read_only_even_under_an_owner_policy():
    context = FakeExecutionContext(
        user="alice", access_policies=[{"pattern": "public.*", "role": "owner"}]
    )
    cap = capability()
    assert cap.can_perform_action(context, "public.security", "READ")
    assert not cap.can_perform_action(context, "public.security", "DELETE")


def test_an_anonymous_session_holds_only_public_read():
    context = FakeExecutionContext(user=None)
    cap = capability()
    assert cap.can_perform_action(context, "public.security", "READ")
    assert not cap.can_perform_action(context, "public.security", "WRITE")
    assert not cap.can_perform_action(context, "analytics.sales.q1", "READ")


def test_malformed_policies_are_skipped_not_fatal():
    # One unreadable entry must not decide the fate of the others -- in either
    # direction. The valid grant still applies; the junk confers nothing.
    context = FakeExecutionContext(
        user="alice",
        access_policies=[
            None,
            "nonsense",
            {"role": "owner"},
            {"pattern": "analytics.*", "role": "writer"},
        ],
    )
    cap = capability()
    assert cap.can_perform_action(context, "analytics.sales.q1", "WRITE")
    assert not cap.can_perform_action(context, "analytics.sales.q1", "DROP")


def test_missing_attributes_are_treated_as_an_unprivileged_session():
    class Bare:
        pass

    cap = capability()
    assert not cap.can_perform_action(Bare(), "analytics.sales.q1", "READ")


# --- can_perform_workspace_action


def test_whole_workspace_ownership_clears_a_workspace_action():
    context = FakeExecutionContext(
        user="alice", access_policies=[{"pattern": "analytics.*", "role": "owner"}]
    )
    assert capability().can_perform_workspace_action(context, "analytics", "ALTER")


def test_partial_ownership_does_not_clear_a_workspace_action():
    context = FakeExecutionContext(
        user="alice", access_policies=[{"pattern": "analytics.sales.*", "role": "owner"}]
    )
    assert not capability().can_perform_workspace_action(context, "analytics", "ALTER")


def test_a_writer_over_the_whole_workspace_still_cannot_alter_it():
    context = FakeExecutionContext(
        user="alice", access_policies=[{"pattern": "analytics.*", "role": "writer"}]
    )
    assert not capability().can_perform_workspace_action(context, "analytics", "ALTER")


# --- can_principal_perform_action
#
# The one check with no execution context: it is asked about somebody who is
# not the caller, so their grants come from the store rather than from a
# session that was issued them. The engine needs it where a statement names an
# identity to act AS -- `ALTER MATERIALIZED VIEW ... OWNER TO`.


def _store_holding(principal: str, role: str, pattern: str) -> FakePolicyStore:
    store = FakePolicyStore()
    store.seed(pattern.split(".", 1)[0], Policy(principal=principal, role=role, pattern=pattern))
    return store


def test_a_principal_is_judged_on_their_own_stored_policies():
    cap = capability(_store_holding("ginny", "reader", "analytics.*"))
    assert cap.can_principal_perform_action("ginny", "analytics.sales.q1", "READ")
    assert not cap.can_principal_perform_action("ginny", "analytics.sales.q1", "DELETE")


def test_a_principal_holding_nothing_is_permitted_nothing():
    cap = capability(FakePolicyStore())
    assert not cap.can_principal_perform_action("ginny", "analytics.sales.q1", "READ")


def test_one_principals_authority_does_not_answer_for_another():
    """The reason this check exists. alice owning the workspace says nothing
    about ginny, and must not be allowed to stand in for her."""
    cap = capability(_store_holding("alice", "owner", "analytics.*"))
    assert cap.can_principal_perform_action("alice", "analytics.sales.q1", "READ")
    assert not cap.can_principal_perform_action("ginny", "analytics.sales.q1", "READ")


def test_a_principal_keeps_their_implicit_grants():
    """Judged by the same rules that would judge them running the query, so
    `public.*` and their own `personal.` namespace come with them."""
    cap = capability(FakePolicyStore())
    assert cap.can_principal_perform_action("ginny", "public.gdelt.events", "READ")
    assert cap.can_principal_perform_action("ginny", "personal.ginny.scratch", "DROP")
    assert not cap.can_principal_perform_action("ginny", "personal.alice.scratch", "READ")


def test_each_resources_own_workspace_decides_the_lookup():
    """Grants are per-workspace, so the workspace is taken from the resource
    being asked about rather than from wherever the caller happens to be.

    This is what lets one statement ask about sources in several workspaces and
    get each judged against the policies that actually govern it.
    """
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="ginny", role="reader", pattern="analytics.*"))
    store.seed("billing", Policy(principal="alice", role="reader", pattern="billing.*"))
    cap = capability(store)

    assert cap.can_principal_perform_action("ginny", "analytics.sales.q1", "READ")
    assert not cap.can_principal_perform_action("ginny", "billing.invoices.q1", "READ")
    assert cap.can_principal_perform_action("alice", "billing.invoices.q1", "READ")
    assert not cap.can_principal_perform_action("alice", "analytics.sales.q1", "READ")


def test_a_principal_is_normalized_like_any_other_identity():
    cap = capability(_store_holding("ginny", "reader", "analytics.*"))
    assert cap.can_principal_perform_action("GINNY", "analytics.sales.q1", "READ")


def test_a_local_relation_needs_no_store():
    """The dotless-name rule `can_perform_action` applies, and it is reached
    before the store is, so a name with no workspace needs none."""
    cap = capability()
    assert cap.can_principal_perform_action("ginny", "scratch_table", "READ")
    assert not cap.can_principal_perform_action("ginny", "scratch_table", "DROP")


def test_without_a_store_the_check_raises_rather_than_denying():
    """A check that could not run is not a check that ran and said no."""
    with pytest.raises(PolicyStoreRequiredError):
        capability().can_principal_perform_action("ginny", "analytics.sales.q1", "READ")


# --- grants (SHOW GRANTS)


def test_grants_lists_implicit_first_then_issued():
    rows = capability().grants("alice", [{"pattern": "analytics.*", "role": "writer"}])
    assert [(r["pattern"], r["role"]) for r in rows] == [
        ("personal.alice.*", "owner"),
        ("public.*", "reader"),
        ("analytics.*", "writer"),
    ]


def test_grants_for_an_anonymous_session_has_no_personal_namespace():
    rows = capability().grants("", [])
    assert [(r["pattern"], r["role"]) for r in rows] == [("public.*", "reader")]


def test_grants_actions_are_derived_from_the_enforced_table():
    rows = capability().grants("alice", [{"pattern": "analytics.*", "role": "writer"}])
    reported = {r["role"]: {a.strip() for a in r["actions"].split(", ")} for r in rows}
    for role, actions in reported.items():
        assert actions == {a for a in DATA_ACTIONS if role in ACTION_ROLES[a]}, role


def test_grants_never_reports_policy_administration_actions():
    # GRANT/REVOKE are real actions this package decides, but opteryx has no
    # statement that performs them -- reporting them would advertise a
    # capability the SQL surface does not have.
    rows = capability().grants("alice", [{"pattern": "analytics.*", "role": "owner"}])
    for row in rows:
        reported = {a.strip() for a in row["actions"].split(", ")}
        assert not (reported & POLICY_ADMINISTRATION_ACTIONS), row


def test_owner_reports_strictly_more_than_writer():
    owner = capability().grants("x", [{"pattern": "ws.*", "role": "owner"}])[-1]
    writer = capability().grants("x", [{"pattern": "ws.*", "role": "writer"}])[-1]
    owner_actions = {a.strip() for a in owner["actions"].split(", ")}
    writer_actions = {a.strip() for a in writer["actions"].split(", ")}
    assert writer_actions < owner_actions
    assert "DROP" in owner_actions and "DROP" not in writer_actions


def test_reported_grants_agree_with_what_is_enforced():
    """The drift guard: every action the table reports against a pattern must
    be one `can_perform_action` actually permits on a resource it covers."""
    cap = capability()
    context = FakeExecutionContext(
        user="olive", access_policies=[{"pattern": "ws.*", "role": "writer"}]
    )
    probes = {
        "personal.olive.*": "personal.olive.tbl",
        "public.*": "public.coll.tbl",
        "ws.*": "ws.coll.tbl",
    }
    for row in cap.grants(context.user, context.access_policies):
        reported = {a.strip() for a in row["actions"].split(", ")}
        for action in DATA_ACTIONS:
            assert cap.can_perform_action(context, probes[row["pattern"]], action) == (
                action in reported
            ), (row["pattern"], action)


def test_grants_skips_malformed_policies():
    rows = capability().grants("alice", [None, {"pattern": "ws.*", "role": "writer"}])
    assert [r["pattern"] for r in rows] == ["personal.alice.*", "public.*", "ws.*"]


# ---------------------------------------------------------------------------
# Escalation attempts through the engine-facing surface.
#
# `can_perform_action` here is reached with values the caller influences: the
# session identity and whatever patterns are stored on their policies. Neither
# is re-validated at read time -- validation happens when a policy is written --
# so these pin what the read path does with input it did not vet.
# ---------------------------------------------------------------------------


def test_glob_metacharacters_in_an_identity_do_not_widen_its_namespace():
    """The implicit personal grant is built AROUND the identity, so an identity
    of `a*` would otherwise own `personal.anything.*`. It is escaped first."""
    cap = capability()
    attacker = FakeExecutionContext(user="a*")

    assert not cap.can_perform_action(attacker, "personal.anything.notes", "DROP")
    assert not cap.can_perform_action(attacker, "personal.alice.notes", "READ")
    # It still owns its own literal namespace.
    assert cap.can_perform_action(attacker, "personal.a*.notes", "DROP")


def test_an_identity_that_looks_like_a_pattern_cannot_read_another_namespace():
    cap = capability()
    assert not cap.can_perform_action(FakeExecutionContext(user="?"), "personal.x.n", "READ")
    assert not cap.can_perform_action(FakeExecutionContext(user="[a-z]"), "personal.a.n", "READ")


def test_a_legacy_bare_wildcard_pattern_covers_everything():
    """`validate_pattern` refuses to WRITE a bare `*`, but a policy stored
    before that rule still reads as a grant over every workspace. This is the
    migration hazard the README's audit section names -- pinned so the blast
    radius is visible rather than inferred."""
    context = FakeExecutionContext(
        user="alice", access_policies=[{"pattern": "*", "role": "owner"}]
    )
    cap = capability()
    assert cap.can_perform_action(context, "anything.at.all", "DROP")
    assert cap.can_perform_action(context, "someone_elses.workspace.table", "DROP")


def test_matching_is_case_insensitive_end_to_end():
    context = FakeExecutionContext(
        user="alice", access_policies=[{"pattern": "analytics.*", "role": "reader"}]
    )
    cap = capability()
    assert cap.can_perform_action(context, "Analytics.Sales", "READ")
    assert cap.can_perform_action(context, "ANALYTICS.SALES.Q1", "READ")


def test_a_grant_covers_every_level_below_it():
    context = FakeExecutionContext(
        user="alice", access_policies=[{"pattern": "analytics.*", "role": "writer"}]
    )
    cap = capability()
    assert cap.can_perform_action(context, "analytics.sales", "WRITE")
    assert cap.can_perform_action(context, "analytics.sales.q1", "WRITE")
    assert not cap.can_perform_action(context, "billing.sales.q1", "READ")


# --- the contract the engine relies on for local and internal relations


def test_a_dotless_relation_is_readable_and_nothing_more():
    """`$grants`, `$planets`, a local table: no workspace, so no policy can
    name them. The engine asks anyway, and READ is the only answer that keeps
    `SHOW GRANTS` reachable without conferring anything."""
    cap = capability()
    context = FakeExecutionContext(user="alice")
    assert cap.can_perform_action(context, "$grants", "READ")
    assert cap.can_perform_action(context, "orders", "READ")
    for action in ("WRITE", "DELETE", "DROP", "ALTER", "CREATE", "MANIFEST"):
        assert not cap.can_perform_action(context, "$grants", action), action


def test_the_full_role_by_action_matrix_holds_through_the_capability():
    """Every role against every data action, answered through the adapter
    rather than by calling `checks` directly -- the engine only ever sees this
    path, so this is the one that has to be right."""
    cap = capability()
    for role in ROLES:
        context = FakeExecutionContext(
            user="alice", access_policies=[{"pattern": "ws.*", "role": role}]
        )
        for action in DATA_ACTIONS:
            expected = role in ACTION_ROLES[action]
            assert cap.can_perform_action(context, "ws.coll.tbl", action) == expected, (
                role,
                action,
            )


def test_an_unrecognised_role_on_a_stored_policy_confers_nothing():
    context = FakeExecutionContext(
        user="alice", access_policies=[{"pattern": "ws.*", "role": "superuser"}]
    )
    cap = capability()
    for action in DATA_ACTIONS:
        assert not cap.can_perform_action(context, "ws.coll.tbl", action), action
