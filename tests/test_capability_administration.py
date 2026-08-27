"""The capability's grant-administration surface: apply_grant, apply_revoke,
grants_on -- the members behind opteryx's GRANT / REVOKE / SHOW GRANTS ON.

Thin delegations by design: the rules are tested where they live
(test_grants.py, test_revoke_grant.py). What is pinned here is the seam --
identity extraction, the store requirement, the workspace derived from the
pattern, the listing's gate and shape.
"""

from dataclasses import dataclass
from dataclasses import field

import pytest
from fakes import FakePolicyStore

from opteryx_access.capability import capability
from opteryx_access.exceptions import AccessDeniedError
from opteryx_access.exceptions import PolicyConflictError
from opteryx_access.exceptions import PolicyNotFoundError
from opteryx_access.exceptions import PolicyStoreRequiredError
from opteryx_access.exceptions import SelfAccessError
from opteryx_access.models import Policy


@dataclass
class FakeExecutionContext:
    user: str | None = None
    access_policies: list = field(default_factory=list)


def _store():
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))
    return store


def _alice():
    return FakeExecutionContext(user="alice")


# --- apply_grant


def test_apply_grant_creates_the_policy():
    store = _store()
    policy_id = capability(store).apply_grant(_alice(), "analytics.sales.*", "writer", "bob")
    policy = store.get_policy("analytics", policy_id)
    assert (policy.principal, policy.role, policy.pattern) == (
        "bob",
        "writer",
        "analytics.sales.*",
    )
    assert policy.updated_by == "alice"


def test_apply_grant_requires_a_store():
    with pytest.raises(PolicyStoreRequiredError):
        capability().apply_grant(_alice(), "analytics.sales.*", "writer", "bob")


def test_apply_grant_refuses_an_anonymous_session():
    with pytest.raises(AccessDeniedError):
        capability(_store()).apply_grant(
            FakeExecutionContext(user=None), "analytics.sales.*", "writer", "bob"
        )


def test_apply_grant_on_an_existing_exact_policy_is_refused_not_upgraded():
    # No ALTER for grants: changing a role is REVOKE then GRANT, by the caller.
    store = _store()
    cap = capability(store)
    cap.apply_grant(_alice(), "analytics.sales.*", "reader", "bob")
    with pytest.raises(PolicyConflictError):
        cap.apply_grant(_alice(), "analytics.sales.*", "writer", "bob")
    [held] = store.list_policies_for_principal("analytics", "bob")
    assert held.role == "reader"


def test_apply_grant_enforces_the_self_service_rule():
    with pytest.raises(SelfAccessError):
        capability(_store()).apply_grant(_alice(), "analytics.sales.*", "writer", "alice")


# --- apply_revoke


def test_apply_revoke_deletes_the_exact_policy():
    store = _store()
    cap = capability(store)
    policy_id = cap.apply_grant(_alice(), "analytics.sales.*", "writer", "bob")
    revoked = cap.apply_revoke(_alice(), "analytics.sales.*", "writer", "bob")
    assert revoked == policy_id
    assert store.get_policy("analytics", policy_id) is None


def test_apply_revoke_reports_a_level_mismatch():
    store = _store()
    store.seed("analytics", Policy(principal="bob", role="reader", pattern="analytics.*"))
    with pytest.raises(PolicyNotFoundError, match="workspace-level"):
        capability(store).apply_revoke(_alice(), "analytics.sales.q1", "reader", "bob")


def test_apply_revoke_requires_a_store():
    with pytest.raises(PolicyStoreRequiredError):
        capability().apply_revoke(_alice(), "analytics.sales.*", "writer", "bob")


# --- grants_on


def test_grants_on_workspace_lists_every_policy_at_every_level():
    store = _store()
    store.seed(
        "analytics", Policy(principal="ginny", role="reader", pattern="analytics.ops.audit_log")
    )
    store.seed("analytics", Policy(principal="bob", role="writer", pattern="analytics.ops.*"))
    rows = capability(store).grants_on(_alice(), "analytics.*")
    assert [(r["user"], r["pattern"], r["level"], r["role"]) for r in rows] == [
        ("alice", "analytics.*", "workspace", "owner"),
        ("bob", "analytics.ops.*", "collection", "writer"),
        ("ginny", "analytics.ops.audit_log", "dataset", "reader"),
    ]


def test_grants_on_a_narrower_object_lists_only_exact_policies():
    # 1:1 with what GRANT/REVOKE there would act on; the broader covering
    # policies are the workspace listing's to show.
    store = _store()
    store.seed("analytics", Policy(principal="bob", role="writer", pattern="analytics.ops.*"))
    store.seed(
        "analytics", Policy(principal="ginny", role="reader", pattern="analytics.ops.audit_log")
    )
    rows = capability(store).grants_on(_alice(), "analytics.ops.audit_log")
    assert [(r["user"], r["role"]) for r in rows] == [("ginny", "reader")]


def test_grants_on_is_gated_on_owner_authority_covering_the_object():
    store = _store()
    store.seed("analytics", Policy(principal="bob", role="writer", pattern="analytics.*"))
    with pytest.raises(AccessDeniedError):
        capability(store).grants_on(FakeExecutionContext(user="bob"), "analytics.*")


def test_grants_on_authority_must_cover_the_pattern_not_just_the_workspace():
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="carol", role="owner", pattern="analytics.sales.*"))
    store.seed("analytics", Policy(principal="bob", role="reader", pattern="analytics.ops.*"))
    cap = capability(store)
    context = FakeExecutionContext(user="carol")
    # carol owns analytics.sales.* -- she may list there, but not the whole
    # workspace and not a sibling collection.
    assert cap.grants_on(context, "analytics.sales.*") == [
        {"user": "carol", "pattern": "analytics.sales.*", "level": "collection", "role": "owner"}
    ]
    with pytest.raises(AccessDeniedError):
        cap.grants_on(context, "analytics.*")
    with pytest.raises(AccessDeniedError):
        cap.grants_on(context, "analytics.ops.*")


def test_grants_on_requires_a_store():
    with pytest.raises(PolicyStoreRequiredError):
        capability().grants_on(_alice(), "analytics.*")


def test_grants_on_refuses_an_anonymous_session():
    with pytest.raises(AccessDeniedError):
        capability(_store()).grants_on(FakeExecutionContext(user=None), "analytics.*")
