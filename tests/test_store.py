import pytest
from fakes import FakePolicyStore

from opteryx_access.exceptions import AccessDeniedError
from opteryx_access.exceptions import InvalidPatternError
from opteryx_access.exceptions import InvalidRoleError
from opteryx_access.exceptions import PolicyConflictError
from opteryx_access.exceptions import PolicyNotFoundError
from opteryx_access.exceptions import SelfAccessError
from opteryx_access.exceptions import WorkspaceAlreadyBootstrappedError
from opteryx_access.models import Policy
from opteryx_access.store import bootstrap_workspace
from opteryx_access.store import find_conflict
from opteryx_access.store import grant
from opteryx_access.store import revoke
from opteryx_access.store import update_grant


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


def test_grant_rejects_wildcard_principal_with_glob_pattern():
    store = _owner_store()
    with pytest.raises(InvalidPatternError):
        grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="*",
            role="reader",
            pattern="analytics.*",
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
            role="admin",
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


def test_update_grant_preserves_wildcard_rule_against_stored_principal():
    store = _owner_store()
    policy_id = store.seed(
        "analytics", Policy(principal="*", role="reader", pattern="analytics.public")
    )
    with pytest.raises(InvalidPatternError):
        update_grant(
            store,
            actor="alice",
            workspace="analytics",
            policy_id=policy_id,
            role="reader",
            pattern="analytics.*",
        )


def test_bootstrap_workspace_creates_scoped_grants():
    store = FakePolicyStore()
    ids = bootstrap_workspace(
        store, actor="alice", workspace="newspace", grants=[("alice", "owner"), ("bob", "admin")]
    )
    assert len(ids) == 2
    policies = store.list_policies("newspace")
    assert {p.principal for p in policies} == {"alice", "bob"}
    assert all(p.pattern == "newspace.*" for p in policies)


def test_bootstrap_workspace_refuses_if_already_bootstrapped():
    store = _owner_store(workspace="newspace")
    with pytest.raises(WorkspaceAlreadyBootstrappedError):
        bootstrap_workspace(store, actor="alice", workspace="newspace", grants=[("bob", "writer")])


def test_bootstrap_workspace_rejects_reserved_workspace():
    store = FakePolicyStore()
    with pytest.raises(InvalidPatternError):
        bootstrap_workspace(store, actor="alice", workspace="public", grants=[("alice", "owner")])
