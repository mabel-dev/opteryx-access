from fake_firestore import FakeFirestoreClient

from opteryx_access.adapters.firestore import FirestorePolicyStore
from opteryx_access.models import Policy


def _store():
    return FirestorePolicyStore(FakeFirestoreClient())


def test_create_then_get_round_trips_fields():
    store = _store()
    policy_id = store.create_policy(
        "analytics",
        Policy(principal="bob", role="writer", pattern="analytics.sales.*", updated_by="alice"),
    )
    policy = store.get_policy("analytics", policy_id)
    assert policy.principal == "bob"
    assert policy.role == "writer"
    assert policy.pattern == "analytics.sales.*"
    assert policy.policy_id == policy_id
    assert policy.updated_by == "alice"
    assert policy.created_at is not None
    assert policy.updated_at is not None


def test_get_missing_policy_returns_none():
    store = _store()
    assert store.get_policy("analytics", "does-not-exist") is None


def test_list_policies_returns_every_document():
    store = _store()
    store.create_policy("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))
    store.create_policy(
        "analytics", Policy(principal="bob", role="writer", pattern="analytics.sales.*")
    )
    policies = store.list_policies("analytics")
    assert {p.principal for p in policies} == {"alice", "bob"}


def test_list_policies_is_scoped_to_its_own_workspace():
    store = _store()
    store.create_policy("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))
    store.create_policy("billing", Policy(principal="bob", role="owner", pattern="billing.*"))
    assert [p.principal for p in store.list_policies("analytics")] == ["alice"]
    assert [p.principal for p in store.list_policies("billing")] == ["bob"]


def test_list_policies_for_principal_filters_server_side():
    # Exercises the real FieldFilter the adapter builds -- the fake applies it
    # rather than reimplementing the predicate, so a wrong field name or
    # operator here would fail rather than silently pass.
    store = _store()
    store.create_policy("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))
    store.create_policy(
        "analytics", Policy(principal="bob", role="writer", pattern="analytics.sales.*")
    )
    policies = store.list_policies_for_principal("analytics", "bob")
    assert [(p.principal, p.role) for p in policies] == [("bob", "writer")]


def test_has_any_policies():
    store = _store()
    assert not store.has_any_policies("analytics")
    store.create_policy("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))
    assert store.has_any_policies("analytics")
    # Scoped per workspace, like everything else on the store.
    assert not store.has_any_policies("billing")


def test_list_policies_for_principal_is_empty_when_none_match():
    store = _store()
    store.create_policy("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))
    assert store.list_policies_for_principal("analytics", "nobody") == []


def test_update_policy_changes_role_and_pattern_and_updated_by():
    store = _store()
    policy_id = store.create_policy(
        "analytics",
        Policy(principal="bob", role="reader", pattern="analytics.sales.*", updated_by="alice"),
    )
    store.update_policy(
        "analytics", policy_id, role="writer", pattern="analytics.sales.q1", updated_by="carol"
    )
    policy = store.get_policy("analytics", policy_id)
    assert policy.role == "writer"
    assert policy.pattern == "analytics.sales.q1"
    assert policy.updated_by == "carol"
    # principal must survive an update untouched -- update_policy only
    # touches role/pattern/updated_at/updated_by, never who the policy is for.
    assert policy.principal == "bob"


def test_delete_policy_removes_it():
    store = _store()
    policy_id = store.create_policy(
        "analytics", Policy(principal="bob", role="reader", pattern="analytics.*")
    )
    store.delete_policy("analytics", policy_id)
    assert store.get_policy("analytics", policy_id) is None
    assert store.list_policies("analytics") == []


def test_delete_missing_policy_is_a_no_op():
    store = _store()
    store.delete_policy("analytics", "does-not-exist")  # must not raise


def test_created_at_is_stable_but_updated_at_changes_on_update():
    store = _store()
    policy_id = store.create_policy(
        "analytics", Policy(principal="bob", role="reader", pattern="analytics.*")
    )
    before = store.get_policy("analytics", policy_id)
    store.update_policy(
        "analytics", policy_id, role="writer", pattern="analytics.*", updated_by="alice"
    )
    after = store.get_policy("analytics", policy_id)
    assert after.created_at == before.created_at


def test_to_policy_confers_nothing_for_malformed_data():
    # Defensive fallback for a document written by something other than this
    # adapter (or corrupted): must not raise KeyError just because a field is
    # missing, and the fallback values must confer nothing -- an empty role
    # permits no action and an empty principal matches no identity. Defaulting
    # the role to "reader" would turn "we don't know what this grants" into
    # read access.
    store = _store()
    store._db.collection("analytics").document("$policies").collection("access").document(
        "raw-doc"
    ).set({})
    policy = store.get_policy("analytics", "raw-doc")
    assert policy.principal == ""
    assert policy.role == ""
    assert policy.pattern == ""


def test_reads_carry_the_workspace():
    store = _store()
    policy_id = store.create_policy(
        "analytics", Policy(principal="alice", role="owner", pattern="analytics.*")
    )
    assert store.get_policy("analytics", policy_id).workspace == "analytics"
    assert store.list_policies("analytics")[0].workspace == "analytics"
    assert store.list_policies_for_principal("analytics", "alice")[0].workspace == "analytics"


def test_list_owner_policies_spans_workspaces_and_derives_each_workspace():
    # A real collection-group query across every workspace's `access`
    # collection, with the workspace read back off the document path.
    store = _store()
    store.create_policy("analytics", Policy(principal="xb500", role="owner", pattern="analytics.*"))
    store.create_policy("billing", Policy(principal="xb500", role="owner", pattern="billing.*"))
    store.create_policy("ops", Policy(principal="alice", role="owner", pattern="ops.*"))

    owned = store.list_owner_policies("xb500")
    assert {(p.workspace, p.pattern) for p in owned} == {
        ("analytics", "analytics.*"),
        ("billing", "billing.*"),
    }


def test_list_owner_policies_excludes_non_owning_roles():
    store = _store()
    store.create_policy(
        "analytics", Policy(principal="xb500", role="writer", pattern="analytics.*")
    )
    store.create_policy("billing", Policy(principal="xb500", role="reader", pattern="billing.*"))
    assert store.list_owner_policies("xb500") == []


def test_store_requires_exactly_one_of_db_and_factory():
    import pytest

    from opteryx_access.adapters.firestore import FirestorePolicyStore

    with pytest.raises(ValueError):
        FirestorePolicyStore()
    with pytest.raises(ValueError):
        FirestorePolicyStore(object(), db_factory=lambda: object())


def test_factory_is_consulted_per_access_so_config_changes_take_effect():
    from fake_firestore import FakeFirestoreClient

    from opteryx_access.adapters.firestore import FirestorePolicyStore
    from opteryx_access.grants import bootstrap_workspace

    first, second = FakeFirestoreClient(), FakeFirestoreClient()
    current = {"db": first}
    store = FirestorePolicyStore(db_factory=lambda: current["db"])

    bootstrap_workspace(store, actor="root", workspace="ws", grants=[("alice", "owner")])
    assert store.has_any_policies("ws")

    # The "configuration" now names a different database: the same store
    # object speaks to it immediately -- nothing was frozen at construction.
    current["db"] = second
    assert not store.has_any_policies("ws")


def test_factory_returning_none_raises_not_denies():
    import pytest

    from opteryx_access.adapters.firestore import FirestorePolicyStore
    from opteryx_access.exceptions import PolicyStoreUnavailableError

    store = FirestorePolicyStore(db_factory=lambda: None)
    with pytest.raises(PolicyStoreUnavailableError):
        store.has_any_policies("ws")
