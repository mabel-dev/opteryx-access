from opteryx_access.checks import can_administer_pattern
from opteryx_access.checks import can_perform_action
from opteryx_access.checks import can_perform_workspace_action
from opteryx_access.checks import has_workspace_access
from opteryx_access.checks import implicit_grants
from opteryx_access.models import Grant
from opteryx_access.models import Policy


def test_local_table_is_read_only():
    assert can_perform_action([], "orders", "READ")
    assert not can_perform_action([], "orders", "DELETE")


def test_writer_grant_permits_delete_not_drop():
    grants = [Grant(role="writer", pattern="analytics.sales.*")]
    assert can_perform_action(grants, "analytics.sales.q1", "DELETE")
    assert not can_perform_action(grants, "analytics.sales.q1", "DROP")


def test_no_matching_grant_denies():
    grants = [Grant(role="writer", pattern="analytics.sales.*")]
    assert not can_perform_action(grants, "billing.invoices.q1", "READ")


def test_implicit_personal_namespace_owner():
    grants = implicit_grants("alice")
    assert Grant(role="owner", pattern="personal.alice.*") in grants
    assert can_perform_action([], "personal.alice.private", "DROP", identity="alice")
    assert not can_perform_action([], "personal.bob.private", "DROP", identity="alice")


def test_implicit_public_is_read_only_regardless_of_issued_policy():
    # public.* is capped read-only by the implicit grant even if an issued
    # policy claims otherwise -- implicit grants short-circuit and never fall
    # through to `grants`.
    grants = [Grant(role="owner", pattern="public.*")]
    assert can_perform_action(grants, "public.security", "READ")
    assert not can_perform_action(grants, "public.security", "DELETE")


def test_anonymous_has_no_personal_namespace():
    grants = implicit_grants(None)
    assert all(not g.pattern.startswith("personal.") for g in grants)


def test_can_perform_workspace_action_requires_whole_workspace_coverage():
    grants = [Grant(role="owner", pattern="analytics.*")]
    assert can_perform_workspace_action(grants, "analytics", "ALTER")

    narrower = [Grant(role="owner", pattern="analytics.sales.*")]
    assert not can_perform_workspace_action(narrower, "analytics", "ALTER")


def test_can_perform_workspace_action_filters_by_role_not_just_coverage():
    # Coverage of the whole workspace is necessary but not sufficient -- the
    # role held still has to be allowed to perform the action (ALTER is
    # owner-only; a reader covering the whole workspace must not clear it).
    grants = [Grant(role="reader", pattern="analytics.*")]
    assert not can_perform_workspace_action(grants, "analytics", "ALTER")


def test_can_perform_workspace_action_bare_pattern_matches_bare_workspace():
    grants = [Grant(role="owner", pattern="analytics")]
    assert can_perform_workspace_action(grants, "analytics", "ALTER")


def test_can_administer_pattern_empty_pattern_denied():
    policies = [Policy(principal="alice", role="owner", pattern="analytics.*")]
    assert not can_administer_pattern(policies, "alice", "")


def test_can_administer_pattern_no_policies_denied():
    assert not can_administer_pattern([], "alice", "analytics.*")


def test_has_workspace_access_owner_grants_access():
    policies = [Policy(principal="alice", role="owner", pattern="analytics.*")]
    assert has_workspace_access(policies, "alice")


def test_has_workspace_access_no_matching_policy_denied():
    policies = [Policy(principal="bob", role="owner", pattern="analytics.*")]
    assert not has_workspace_access(policies, "alice")
    assert not has_workspace_access([], "alice")


def test_has_workspace_access_writer_is_insufficient():
    policies = [Policy(principal="alice", role="writer", pattern="analytics.*")]
    assert not has_workspace_access(policies, "alice")


def test_can_administer_pattern_requires_coverage_not_just_workspace_presence():
    policies = [Policy(principal="alice", role="owner", pattern="billing.*")]
    assert can_administer_pattern(policies, "alice", "billing.invoices.*")
    assert not can_administer_pattern(policies, "alice", "ops.servers.*")


def test_can_administer_pattern_writer_is_insufficient():
    policies = [Policy(principal="alice", role="writer", pattern="analytics.*")]
    assert not can_administer_pattern(policies, "alice", "analytics.sales.*")


def test_a_policy_only_applies_to_the_principal_it_names():
    policies = [Policy(principal="alice", role="owner", pattern="analytics.*")]
    assert can_administer_pattern(policies, "alice", "analytics.sales.q1")
    assert not can_administer_pattern(policies, "bob", "analytics.sales.q1")
    # Including "*", which is no longer a principal that means anyone.
    assert not can_administer_pattern(
        [Policy(principal="*", role="owner", pattern="analytics.*")],
        "anyone",
        "analytics.sales.q1",
    )
