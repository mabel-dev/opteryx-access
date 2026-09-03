"""Scoped entitlements: a kind and a scope in the name the identity system
issues, and what that authority can and cannot reach.
"""

import pytest
from fakes import FakePolicyStore

from opteryx_access.checks import can_perform_action
from opteryx_access.checks import can_perform_workspace_action
from opteryx_access.entitlements import ENTITLEABLE_ACTIONS
from opteryx_access.entitlements import ENTITLEMENT_KINDS
from opteryx_access.entitlements import entitlement_kinds
from opteryx_access.entitlements import entitlement_permits
from opteryx_access.entitlements import parse_entitlement_claim
from opteryx_access.entitlements import parse_entitlement_name
from opteryx_access.entitlements import resolve_entitlements
from opteryx_access.entitlements import scope_pattern
from opteryx_access.entitlements import validate_entitlement_actions
from opteryx_access.exceptions import InvalidActionError
from opteryx_access.exceptions import InvalidPatternError
from opteryx_access.exceptions import InvalidRoleError
from opteryx_access.grants import grant
from opteryx_access.models import Entitlement
from opteryx_access.models import Grant
from opteryx_access.models import Policy
from opteryx_access.patterns import validate_entitlement_pattern
from opteryx_access.patterns import validate_pattern
from opteryx_access.roles import ROLES

PLATFORM_OPS = resolve_entitlements(["automation_admin::public", "automation_admin::platform"])
ACME_OPS = resolve_entitlements(["automation_admin::acme"])


# --- the hole this closes -------------------------------------------------


def test_automate_on_public_is_unreachable_without_an_entitlement():
    # The premise. No policy may be issued over a reserved workspace, the
    # implicit grant caps everyone at reader, and even a platform identity
    # holds only writer -- so `AUTOMATE` in `public.*` had no holder at all.
    assert not can_perform_action([], "public.ops.nightly", "AUTOMATE", identity="alice")
    assert not can_perform_action(
        [Grant(role="owner", pattern="public.*")],
        "public.ops.nightly",
        "AUTOMATE",
        identity="alice",
    )
    assert not can_perform_action([], "public.ops.nightly", "AUTOMATE", identity="federator")


def test_the_platform_namespaces_are_two_ordinary_uses_of_the_scope():
    for resource in ("public.ops.nightly", "platform.ingest.hourly"):
        assert can_perform_action(
            [], resource, "AUTOMATE", identity="alice", entitlements=PLATFORM_OPS
        )


def test_a_customer_workspace_is_the_same_case():
    # The opportunity, not just the problem: any workspace run by bots whose
    # operations need a human. Scoped when issued, no code change here.
    assert can_perform_action(
        [], "acme.pipelines.nightly", "AUTOMATE", identity="ops", entitlements=ACME_OPS
    )
    assert not can_perform_action(
        [], "public.ops.nightly", "AUTOMATE", identity="ops", entitlements=ACME_OPS
    )


def test_it_confers_operations_and_not_data():
    # The whole point of the axis: manage the automation, read nothing extra.
    for action in ("READ", "WRITE", "DELETE", "DROP", "ALTER", "MANIFEST", "CREATE"):
        assert not can_perform_action(
            [], "acme.pipelines.nightly", action, identity="ops", entitlements=ACME_OPS
        )
    # `public` stays readable, but from the implicit grant everyone has, not
    # from the entitlement.
    assert can_perform_action(
        [], "public.ops.nightly", "READ", identity="alice", entitlements=PLATFORM_OPS
    )


def test_it_reaches_past_the_owner_of_an_ordinary_workspace():
    # `acme` is an ordinary workspace -- policies over it are legal -- but the
    # entitlement is consulted before issued grants, so it confers AUTOMATE
    # whatever those say. That is the platform deciding who runs a
    # namespace's operations, above any one workspace's owners.
    validate_pattern("acme.*")
    assert can_perform_action(
        [Grant(role="reader", pattern="acme.*")],
        "acme.pipelines.nightly",
        "AUTOMATE",
        identity="ops",
        entitlements=ACME_OPS,
    )


def test_it_can_be_scoped_narrower_than_a_workspace():
    narrow = resolve_entitlements(["automation_admin::acme.pipelines"])
    assert can_perform_action(
        [], "acme.pipelines.nightly", "AUTOMATE", identity="ops", entitlements=narrow
    )
    assert not can_perform_action(
        [], "acme.reports.weekly", "AUTOMATE", identity="ops", entitlements=narrow
    )


def test_it_covers_the_workspace_as_an_object():
    assert can_perform_workspace_action([], "acme", "AUTOMATE", entitlements=ACME_OPS)
    assert not can_perform_workspace_action([], "analytics", "AUTOMATE", entitlements=ACME_OPS)
    # And only from a scope covering the workspace in full.
    narrow = resolve_entitlements(["automation_admin::acme.pipelines"])
    assert not can_perform_workspace_action([], "acme", "AUTOMATE", entitlements=narrow)


# --- the shape of a name ---------------------------------------------------


def test_parse_entitlement_name():
    assert parse_entitlement_name("automation_admin::acme") == ("automation_admin", "acme.*")
    assert parse_entitlement_name("automation_admin::acme.pipelines") == (
        "automation_admin",
        "acme.pipelines.*",
    )
    assert parse_entitlement_name("automation_admin::acme.*") == ("automation_admin", "acme.*")
    # Casefolded, like every other identifier in the package.
    assert parse_entitlement_name("AUTOMATION_ADMIN::Acme") == ("automation_admin", "acme.*")
    assert parse_entitlement_name(" automation_admin :: acme ") == ("automation_admin", "acme.*")


def test_unrecognized_kinds_are_none_not_errors():
    # An account holds names that mean something to other services. This
    # package has an opinion about `automation_admin` and about nothing else.
    for name in ("platform_admin", "data_admin", "user_admin", "data_admin::acme"):
        assert parse_entitlement_name(name) is None
    assert resolve_entitlements(["platform_admin", "data_admin", "user_admin"]) == []
    assert entitlement_kinds() == frozenset({"automation_admin"})


def test_a_recognized_kind_with_a_bad_scope_raises_when_parsed():
    # ...so an issuing path can refuse to mint it.
    with pytest.raises(InvalidPatternError, match="names no scope"):
        parse_entitlement_name("automation_admin")
    with pytest.raises(InvalidPatternError, match="name the scope"):
        parse_entitlement_name("automation_admin::")
    with pytest.raises(InvalidPatternError, match="engine-private"):
        parse_entitlement_name("automation_admin::$internal")
    with pytest.raises(InvalidPatternError, match="information_schema"):
        parse_entitlement_name("automation_admin::acme.information_schema")
    with pytest.raises(InvalidPatternError, match="not a usable name"):
        parse_entitlement_name("automation_admin::acme;drop")
    with pytest.raises(InvalidPatternError, match="cannot be '\\*'"):
        parse_entitlement_name("automation_admin::*")


def test_and_is_skipped_when_resolved():
    # ...while a permission check just sees nothing, rather than failing the
    # query over a misconfigured account.
    assert resolve_entitlements(["automation_admin", "automation_admin::$x", 7, None]) == []
    # An unscoped name confers nothing anywhere -- never something somewhere
    # by default.
    assert not can_perform_action(
        [],
        "public.ops.nightly",
        "AUTOMATE",
        identity="alice",
        entitlements=resolve_entitlements(["automation_admin"]),
    )


def test_scope_pattern():
    assert scope_pattern("acme") == "acme.*"
    assert scope_pattern("acme.pipelines") == "acme.pipelines.*"
    assert scope_pattern("acme.*") == "acme.*"
    assert scope_pattern("public") == "public.*"  # reserved is fine for an entitlement
    with pytest.raises(InvalidPatternError):
        scope_pattern("")


def test_resolve_stamps_the_principal_without_it_deciding_anything():
    held = resolve_entitlements(["automation_admin::acme"], principal="alice")
    assert {entry.principal for entry in held} == {"alice"}
    assert can_perform_action(
        [], "acme.pipelines.nightly", "AUTOMATE", identity="bob", entitlements=held
    )


def test_parse_entitlement_claim_reads_names():
    parsed = parse_entitlement_claim(
        {"entitlements": ["user_admin", "automation_admin::acme", "automation_admin::public", 7]},
        principal="alice",
    )
    assert sorted(entry.pattern for entry in parsed) == ["acme.*", "public.*"]
    assert parse_entitlement_claim({}) == []
    # A single name sent unwrapped, rather than iterated character by
    # character into nothing.
    assert parse_entitlement_claim({"entitlements": "automation_admin::acme"}) == ACME_OPS


def test_a_token_cannot_claim_a_permission_only_a_name():
    # The claim carries names, so there is no action in it to forge. A
    # permission-shaped entry resolves to nothing at all.
    assert parse_entitlement_claim({"entitlements": [{"actions": ["GRANT"], "pattern": "*"}]}) == []


# --- what an entitlement can never reach ----------------------------------


def test_no_kind_confers_policy_administration():
    assert "GRANT" not in ENTITLEABLE_ACTIONS
    assert "REVOKE" not in ENTITLEABLE_ACTIONS
    for actions in ENTITLEMENT_KINDS.values():
        assert not actions & {"GRANT", "REVOKE"}


def test_an_entitlement_built_by_hand_still_cannot_confer_grant():
    # `ENTITLEMENT_KINDS` is validated at import, but `entitlement_permits`
    # is public and does not assume its input came from there.
    forged = Entitlement(principal="", actions=frozenset({"GRANT"}), pattern="acme.*")
    assert not entitlement_permits(forged, "acme.pipelines.nightly", "GRANT")
    assert not can_perform_action(
        [], "acme.pipelines.nightly", "GRANT", identity="alice", entitlements=[forged]
    )


def test_engine_private_names_stay_unreachable():
    assert not can_perform_action(
        [], "acme.$internal.state", "AUTOMATE", identity="ops", entitlements=ACME_OPS
    )
    assert not entitlement_permits(
        Entitlement(principal="", actions=frozenset({"AUTOMATE"}), pattern="acme.$x.*"),
        "acme.$x.state",
        "AUTOMATE",
    )


def test_a_local_table_is_still_read_only():
    assert not can_perform_action([], "orders", "AUTOMATE", identity="ops", entitlements=ACME_OPS)


# --- the kinds table -------------------------------------------------------


def test_every_declared_kind_is_valid():
    # The same check that runs at import, asserted explicitly so a bad entry
    # fails as a named test rather than as a collection error.
    for kind, actions in ENTITLEMENT_KINDS.items():
        assert "::" not in kind
        validate_entitlement_actions(actions)


def test_entitleable_actions_exclude_policy_administration():
    validate_entitlement_actions(["AUTOMATE", "READ"])
    with pytest.raises(InvalidActionError, match="mint ownership"):
        validate_entitlement_actions(["GRANT"])
    with pytest.raises(InvalidActionError, match="unknown action"):
        validate_entitlement_actions(["AUTOMATE", "TELEPORT"])
    with pytest.raises(InvalidActionError, match="at least one action"):
        validate_entitlement_actions([])


def test_action_names_are_not_casefolded():
    # Consistent with `action_allowed_for_role`, which is also exact.
    with pytest.raises(InvalidActionError, match="unknown action"):
        validate_entitlement_actions(["automate"])


def test_an_entitlement_is_not_a_role():
    # It cannot be granted as one: `grant()` validates against ROLES.
    assert "automation_admin" not in ROLES
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="root", role="owner", pattern="analytics.*"))
    with pytest.raises(InvalidRoleError):
        grant(
            store,
            actor="root",
            workspace="analytics",
            principal="alice",
            role="automation_admin",
            pattern="analytics.*",
        )


def test_entitlement_patterns_may_name_a_reserved_workspace():
    # This is what separates an entitlement pattern from a policy pattern, and
    # `automation_admin::public` depends on it.
    validate_entitlement_pattern("public.*")
    with pytest.raises(InvalidPatternError):
        validate_pattern("public.*")
