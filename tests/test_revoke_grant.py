"""revoke_grant: the by-value, strictly-1:1 form of revoke.

REVOKE = delete exactly one stored policy, resolved by (principal, pattern,
role). Everything else is an error that says why -- most importantly the
level-mismatch case: access held through a broader policy is never revocable
by naming something narrower, and never silently narrowed.
"""

import pytest
from fakes import FakePolicyStore

from opteryx_access.exceptions import AccessDeniedError
from opteryx_access.exceptions import InvalidRoleError
from opteryx_access.exceptions import PolicyNotFoundError
from opteryx_access.exceptions import SelfAccessError
from opteryx_access.grants import revoke_grant
from opteryx_access.models import Policy
from opteryx_access.patterns import pattern_level


def _store():
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))
    return store


def test_revoke_grant_deletes_the_exact_match():
    store = _store()
    seeded = store.seed(
        "analytics", Policy(principal="bob", role="writer", pattern="analytics.sales.*")
    )
    revoked = revoke_grant(
        store,
        actor="alice",
        workspace="analytics",
        principal="bob",
        role="writer",
        pattern="analytics.sales.*",
    )
    assert revoked == seeded
    assert store.get_policy("analytics", seeded) is None


def test_revoke_grant_deletes_only_the_named_policy():
    store = _store()
    kept = store.seed(
        "analytics", Policy(principal="bob", role="reader", pattern="analytics.ops.audit_log")
    )
    gone = store.seed(
        "analytics", Policy(principal="bob", role="writer", pattern="analytics.sales.*")
    )
    revoke_grant(
        store,
        actor="alice",
        workspace="analytics",
        principal="bob",
        role="writer",
        pattern="analytics.sales.*",
    )
    assert store.get_policy("analytics", gone) is None
    assert store.get_policy("analytics", kept) is not None


def test_revoke_grant_same_pattern_wrong_role_names_the_held_role():
    store = _store()
    store.seed("analytics", Policy(principal="bob", role="writer", pattern="analytics.sales.*"))
    with pytest.raises(PolicyNotFoundError, match="'writer'"):
        revoke_grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="bob",
            role="reader",
            pattern="analytics.sales.*",
        )
    # Nothing was deleted or narrowed.
    assert len(store.list_policies_for_principal("analytics", "bob")) == 1


def test_revoke_grant_at_the_wrong_level_names_the_covering_policy():
    # bob's read comes from a workspace-level policy; revoking it at dataset
    # level must refuse, naming that policy and its level -- never narrow it,
    # never no-op.
    store = _store()
    store.seed("analytics", Policy(principal="bob", role="reader", pattern="analytics.*"))
    with pytest.raises(PolicyNotFoundError, match="workspace-level.*analytics\\.\\*"):
        revoke_grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="bob",
            role="reader",
            pattern="analytics.sales.q1",
        )
    assert len(store.list_policies_for_principal("analytics", "bob")) == 1


def test_revoke_grant_collection_level_mismatch_is_named_too():
    store = _store()
    store.seed("analytics", Policy(principal="bob", role="writer", pattern="analytics.sales.*"))
    with pytest.raises(PolicyNotFoundError, match="collection-level"):
        revoke_grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="bob",
            role="writer",
            pattern="analytics.sales.q1",
        )


def test_revoke_grant_nothing_held_is_a_plain_not_found():
    store = _store()
    with pytest.raises(PolicyNotFoundError, match="no policy grants"):
        revoke_grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="bob",
            role="reader",
            pattern="analytics.sales.*",
        )


def test_revoke_grant_rejects_self_revoke():
    store = _store()
    with pytest.raises(SelfAccessError):
        revoke_grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="ALICE",
            role="owner",
            pattern="analytics.*",
        )


def test_revoke_grant_checks_authority_before_disclosing_anything():
    # mallory owns nothing here; the refusal must be AccessDenied, not a
    # diagnostic describing what bob holds.
    store = _store()
    store.seed("analytics", Policy(principal="bob", role="reader", pattern="analytics.*"))
    with pytest.raises(AccessDeniedError):
        revoke_grant(
            store,
            actor="mallory",
            workspace="analytics",
            principal="bob",
            role="reader",
            pattern="analytics.sales.q1",
        )


def test_revoke_grant_rejects_an_invalid_role():
    store = _store()
    with pytest.raises(InvalidRoleError):
        revoke_grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="bob",
            role="admin",
            pattern="analytics.sales.*",
        )


def test_revoke_grant_resolves_a_differently_cased_grant():
    store = _store()
    store.seed("analytics", Policy(principal="bob", role="writer", pattern="analytics.sales.*"))
    revoked = revoke_grant(
        store,
        actor="alice",
        workspace="Analytics",
        principal="BOB",
        role="writer",
        pattern="Analytics.Sales.*",
    )
    assert store.get_policy("analytics", revoked) is None


def test_pattern_level_labels_the_canonical_shapes():
    assert pattern_level("w") == "workspace"
    assert pattern_level("w.*") == "workspace"
    assert pattern_level("w.c") == "collection"
    assert pattern_level("w.c.*") == "collection"
    assert pattern_level("w.c.d") == "dataset"


def test_pattern_level_refuses_to_guess():
    assert pattern_level("*") is None
    assert pattern_level("w.*.d") is None
    assert pattern_level("w.c.d.e") is None
