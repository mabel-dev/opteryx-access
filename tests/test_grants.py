import pytest
from fakes import FakePolicyStore

from opteryx_access.exceptions import AccessDeniedError
from opteryx_access.exceptions import InvalidPatternError
from opteryx_access.exceptions import InvalidRoleError
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


def _owner_store(workspace="analytics", owner="alice", pattern="analytics.*"):
    store = FakePolicyStore()
    store.seed(workspace, Policy(principal=owner, role="owner", pattern=pattern))
    return store


def test_grant_happy_path_creates_policy():
    store = _owner_store()
    policy_id = grant(
        store,
        actor="alice",
        workspace="analytics",
        principal="bob",
        role="writer",
        pattern="analytics.sales.*",
    )
    policy = store.get_policy("analytics", policy_id)
    assert policy.principal == "bob"
    assert policy.role == "writer"
    assert policy.updated_by == "alice"


def test_grant_rejects_invalid_role():
    store = _owner_store()
    with pytest.raises(InvalidRoleError):
        grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="bob",
            role="superadmin",
            pattern="analytics.sales.*",
        )


def test_grant_rejects_self_grant():
    store = _owner_store()
    with pytest.raises(SelfAccessError):
        grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="alice",
            role="writer",
            pattern="analytics.sales.*",
        )


def test_grant_rejects_insufficient_authority():
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="alice", role="writer", pattern="analytics.*"))
    with pytest.raises(AccessDeniedError):
        grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="bob",
            role="reader",
            pattern="analytics.sales.*",
        )


def test_grant_rejects_authority_outside_owned_pattern():
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="alice", role="owner", pattern="billing.*"))
    with pytest.raises(AccessDeniedError):
        grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="bob",
            role="reader",
            pattern="analytics.sales.*",
        )


def test_grant_rejects_reserved_resource():
    store = _owner_store(pattern="public.*")
    with pytest.raises(InvalidPatternError):
        grant(
            store,
            actor="alice",
            workspace="public",
            principal="bob",
            role="reader",
            pattern="public.security",
        )


def test_grant_rejects_a_wildcard_principal():
    store = _owner_store()
    with pytest.raises(InvalidPatternError):
        grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="*",
            role="reader",
            pattern="analytics.sales.*",
        )


def test_grant_rejects_exact_duplicate():
    store = _owner_store()
    store.seed("analytics", Policy(principal="bob", role="reader", pattern="analytics.sales.q1"))
    with pytest.raises(PolicyConflictError):
        grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="bob",
            role="writer",
            pattern="analytics.sales.q1",
        )


def test_grant_rejects_redundant_narrower_grant():
    store = _owner_store()
    store.seed("analytics", Policy(principal="bob", role="writer", pattern="analytics.*"))
    with pytest.raises(PolicyConflictError):
        grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="bob",
            role="reader",
            pattern="analytics.sales.q1",
        )


def test_grant_allows_more_privileged_narrower_grant():
    store = _owner_store()
    store.seed("analytics", Policy(principal="bob", role="reader", pattern="analytics.*"))
    policy_id = grant(
        store,
        actor="alice",
        workspace="analytics",
        principal="bob",
        role="writer",
        pattern="analytics.sales.q1",
    )
    assert store.get_policy("analytics", policy_id) is not None


def test_grant_normalizes_the_stored_principal():
    store = _owner_store()
    policy_id = grant(
        store,
        actor="alice",
        workspace="analytics",
        principal="XB500",
        role="writer",
        pattern="analytics.sales.*",
    )
    assert store.get_policy("analytics", policy_id).principal == "xb500"


def test_grant_to_a_differently_cased_self_is_still_a_self_grant():
    # The actor is normalized before the comparison, so casing is not a way
    # around the rule that nobody grants themselves access.
    store = _owner_store()
    with pytest.raises(SelfAccessError):
        grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="Alice",
            role="reader",
            pattern="analytics.sales.q1",
        )


def test_differently_cased_identities_are_one_principal_end_to_end():
    # Granting as "XB500" and reading back as "xb500" must find the grant --
    # the write side and the read side have to agree on the spelling.
    store = _owner_store()
    grant(
        store,
        actor="Alice",
        workspace="analytics",
        principal="XB500",
        role="writer",
        pattern="analytics.sales.*",
    )
    assert grants_for_principal(store, workspace="analytics", identity="xb500") == [
        Grant(role="writer", pattern="analytics.sales.*")
    ]
    assert grants_for_principal(store, workspace="analytics", identity="Xb500") == [
        Grant(role="writer", pattern="analytics.sales.*")
    ]


def test_conflict_detection_sees_a_differently_cased_existing_grant():
    store = _owner_store()
    store.seed("analytics", Policy(principal="xb500", role="writer", pattern="analytics.sales.*"))
    with pytest.raises(PolicyConflictError):
        grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="XB500",
            role="writer",
            pattern="analytics.sales.*",
        )


def test_find_conflict_returns_none_when_clear():
    policies = [Policy(principal="alice", role="owner", pattern="analytics.*")]
    assert find_conflict(policies, "bob", "analytics.sales.q1", "reader") is None


def test_revoke_happy_path():
    store = _owner_store()
    policy_id = store.seed(
        "analytics", Policy(principal="bob", role="writer", pattern="analytics.sales.*")
    )
    revoke(store, actor="alice", workspace="analytics", policy_id=policy_id)
    assert store.get_policy("analytics", policy_id) is None


def test_revoke_rejects_self_revoke():
    store = FakePolicyStore()
    policy_id = store.seed(
        "analytics", Policy(principal="alice", role="owner", pattern="analytics.*")
    )
    with pytest.raises(SelfAccessError):
        revoke(store, actor="alice", workspace="analytics", policy_id=policy_id)


def test_revoke_missing_policy_raises_not_found():
    store = _owner_store()
    with pytest.raises(PolicyNotFoundError):
        revoke(store, actor="alice", workspace="analytics", policy_id="does-not-exist")


def test_revoke_rejects_insufficient_authority():
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="alice", role="owner", pattern="billing.*"))
    policy_id = store.seed(
        "analytics", Policy(principal="bob", role="writer", pattern="analytics.sales.*")
    )
    with pytest.raises(AccessDeniedError):
        revoke(store, actor="alice", workspace="analytics", policy_id=policy_id)


def test_update_grant_missing_policy_raises_not_found():
    store = _owner_store()
    with pytest.raises(PolicyNotFoundError):
        update_grant(
            store,
            actor="alice",
            workspace="analytics",
            policy_id="does-not-exist",
            role="writer",
            pattern="analytics.sales.*",
        )


def test_update_grant_rejects_self_modify():
    store = FakePolicyStore()
    policy_id = store.seed(
        "analytics", Policy(principal="alice", role="owner", pattern="analytics.*")
    )
    with pytest.raises(SelfAccessError):
        update_grant(
            store,
            actor="alice",
            workspace="analytics",
            policy_id=policy_id,
            role="writer",
            pattern="analytics.*",
        )


def test_update_grant_happy_path():
    store = _owner_store()
    policy_id = store.seed(
        "analytics", Policy(principal="bob", role="reader", pattern="analytics.sales.*")
    )
    update_grant(
        store,
        actor="alice",
        workspace="analytics",
        policy_id=policy_id,
        role="writer",
        pattern="analytics.sales.*",
    )
    policy = store.get_policy("analytics", policy_id)
    assert policy.role == "writer"
    assert policy.updated_by == "alice"


def test_update_grant_rejects_moving_under_unowned_pattern():
    store = _owner_store()
    policy_id = store.seed(
        "analytics", Policy(principal="bob", role="reader", pattern="analytics.sales.*")
    )
    with pytest.raises(AccessDeniedError):
        update_grant(
            store,
            actor="alice",
            workspace="analytics",
            policy_id=policy_id,
            role="reader",
            pattern="billing.invoices.*",
        )


def test_update_grant_rejects_an_unusable_new_pattern():
    store = _owner_store()
    policy_id = store.seed(
        "analytics", Policy(principal="bob", role="reader", pattern="analytics.sales.*")
    )
    with pytest.raises(InvalidPatternError):
        update_grant(
            store,
            actor="alice",
            workspace="analytics",
            policy_id=policy_id,
            role="reader",
            pattern="analytics..sales",
        )


def test_update_grant_cannot_widen_a_policy_to_every_workspace():
    store = _owner_store()
    policy_id = store.seed(
        "analytics", Policy(principal="bob", role="reader", pattern="analytics.sales.*")
    )
    with pytest.raises(InvalidPatternError):
        update_grant(
            store,
            actor="alice",
            workspace="analytics",
            policy_id=policy_id,
            role="reader",
            pattern="*",
        )


def test_update_grant_normalizes_the_stored_pattern():
    store = _owner_store()
    policy_id = store.seed(
        "analytics", Policy(principal="bob", role="reader", pattern="analytics.sales.*")
    )
    update_grant(
        store,
        actor="alice",
        workspace="analytics",
        policy_id=policy_id,
        role="writer",
        pattern="Analytics.Sales.Q1",
    )
    assert store.get_policy("analytics", policy_id).pattern == "analytics.sales.q1"


def test_bootstrap_workspace_creates_scoped_grants():
    store = FakePolicyStore()
    ids = bootstrap_workspace(
        store, actor="alice", workspace="newspace", grants=[("alice", "owner"), ("bob", "writer")]
    )
    assert len(ids) == 2
    policies = store.list_policies("newspace")
    assert {p.principal for p in policies} == {"alice", "bob"}
    assert all(p.pattern == "newspace.*" for p in policies)


def test_bootstrap_workspace_asks_only_whether_any_policy_exists():
    # The emptiness check must not read the workspace to answer a yes/no.
    class RecordingStore(FakePolicyStore):
        def __init__(self):
            super().__init__()
            self.listed_whole_workspace = False

        def list_policies(self, workspace):
            self.listed_whole_workspace = True
            return super().list_policies(workspace)

    store = RecordingStore()
    bootstrap_workspace(store, actor="alice", workspace="newspace", grants=[("alice", "owner")])
    assert not store.listed_whole_workspace


def test_bootstrap_workspace_refuses_if_already_bootstrapped():
    store = _owner_store(workspace="newspace")
    with pytest.raises(WorkspaceAlreadyBootstrappedError):
        bootstrap_workspace(store, actor="alice", workspace="newspace", grants=[("bob", "writer")])


def test_bootstrap_workspace_rejects_reserved_workspace():
    store = FakePolicyStore()
    with pytest.raises(InvalidPatternError):
        bootstrap_workspace(store, actor="alice", workspace="public", grants=[("alice", "owner")])


def test_grants_for_principal_returns_only_the_matching_identity():
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))
    store.seed("analytics", Policy(principal="bob", role="writer", pattern="analytics.sales.*"))
    assert grants_for_principal(store, workspace="analytics", identity="bob") == [
        Grant(role="writer", pattern="analytics.sales.*")
    ]


def test_grants_for_principal_excludes_a_stored_wildcard_principal():
    # "*" is not a principal meaning everyone -- a policy left over from when
    # it was must not be handed to whoever happens to be asking.
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="*", role="reader", pattern="analytics.dashboard"))
    store.seed("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))
    assert grants_for_principal(store, workspace="analytics", identity="bob") == []


def test_grants_for_principal_pushes_the_filter_to_the_store():
    # The store is asked for one principal's policies, not handed the whole
    # workspace to filter in Python.
    class RecordingStore(FakePolicyStore):
        def __init__(self):
            super().__init__()
            self.listed_whole_workspace = False

        def list_policies(self, workspace):
            self.listed_whole_workspace = True
            return super().list_policies(workspace)

    store = RecordingStore()
    store.seed("analytics", Policy(principal="bob", role="writer", pattern="analytics.sales.*"))
    store.seed("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))

    assert grants_for_principal(store, workspace="analytics", identity="bob") == [
        Grant(role="writer", pattern="analytics.sales.*")
    ]
    assert not store.listed_whole_workspace


def test_grants_for_principal_drops_principal_and_metadata():
    store = FakePolicyStore()
    store.seed(
        "analytics",
        Policy(principal="bob", role="writer", pattern="analytics.sales.*", updated_by="alice"),
    )
    [only] = grants_for_principal(store, workspace="analytics", identity="bob")
    assert only == Grant(role="writer", pattern="analytics.sales.*")


def test_grants_for_principal_empty_when_nothing_matches():
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))
    assert grants_for_principal(store, workspace="analytics", identity="bob") == []


def test_grants_for_principal_empty_workspace():
    store = FakePolicyStore()
    assert grants_for_principal(store, workspace="analytics", identity="bob") == []


def test_grants_for_principal_is_ready_to_pass_to_can_perform_action():
    # The point of this function: its output is directly usable by the
    # data-plane checks, no further conversion needed.
    from opteryx_access.checks import can_perform_action

    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="bob", role="writer", pattern="analytics.sales.*"))
    grants = grants_for_principal(store, workspace="analytics", identity="bob")
    assert can_perform_action(grants, "analytics.sales.q1", "DELETE")
    assert not can_perform_action(grants, "analytics.sales.q1", "DROP")


def test_owned_by_finds_ownership_across_workspaces():
    # The offboarding question: what would become unowned if this identity
    # went away.
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="xb500", role="owner", pattern="analytics.*"))
    store.seed("billing", Policy(principal="xb500", role="owner", pattern="billing.invoices.*"))
    store.seed("ops", Policy(principal="alice", role="owner", pattern="ops.*"))

    owned = owned_by(store, identity="xb500")
    assert {(p.workspace, p.pattern) for p in owned} == {
        ("analytics", "analytics.*"),
        ("billing", "billing.invoices.*"),
    }


def test_owned_by_excludes_non_owning_roles():
    # "What can this user read" is not the question -- only ownership, which
    # is the part that has to be reassigned before an identity is removed.
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="xb500", role="writer", pattern="analytics.*"))
    store.seed("billing", Policy(principal="xb500", role="reader", pattern="billing.*"))
    assert owned_by(store, identity="xb500") == []


def test_owned_by_normalizes_the_identity():
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="xb500", role="owner", pattern="analytics.*"))
    assert len(owned_by(store, identity="XB500")) == 1


def test_owned_by_is_empty_for_an_unknown_identity():
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))
    assert owned_by(store, identity="nobody") == []
