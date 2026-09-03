"""The capability's grant-administration surface: apply_grant, apply_revoke,
grants_on, effective_grants_on, effective_grants_in -- the members behind
opteryx's GRANT / REVOKE / SHOW [EFFECTIVE] GRANTS ON and its
information_schema.grants table.

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


# --- effective_grants_on


def test_effective_grants_on_a_dataset_surfaces_the_covering_workspace_owner():
    # The reported case: a dataset with nothing stored at it is still reachable
    # by the workspace owner, and the attached listing says nothing about it.
    store = _store()
    cap = capability(store)
    context = _alice()
    assert cap.grants_on(context, "analytics.ops.audit_log") == []
    assert cap.effective_grants_on(context, "analytics.ops.audit_log") == [
        {"user": "alice", "pattern": "analytics.*", "level": "workspace", "role": "owner"}
    ]


def test_effective_grants_on_a_dataset_includes_the_covering_collection():
    store = _store()
    store.seed("analytics", Policy(principal="bob", role="writer", pattern="analytics.ops.*"))
    # A sibling collection covers nothing here and must not appear.
    store.seed("analytics", Policy(principal="ginny", role="reader", pattern="analytics.sales.*"))
    rows = capability(store).effective_grants_on(_alice(), "analytics.ops.audit_log")
    assert [(r["user"], r["pattern"], r["level"], r["role"]) for r in rows] == [
        ("alice", "analytics.*", "workspace", "owner"),
        ("bob", "analytics.ops.*", "collection", "writer"),
    ]


def test_effective_grants_on_reports_one_row_per_covering_policy():
    # No highest-role-wins collapse: which policy grants the access is what an
    # administrator has to change to take it away.
    store = _store()
    store.seed("analytics", Policy(principal="bob", role="reader", pattern="analytics.*"))
    store.seed("analytics", Policy(principal="bob", role="writer", pattern="analytics.ops.*"))
    rows = capability(store).effective_grants_on(_alice(), "analytics.ops.audit_log")
    assert [(r["user"], r["pattern"], r["role"]) for r in rows] == [
        ("alice", "analytics.*", "owner"),
        ("bob", "analytics.*", "reader"),
        ("bob", "analytics.ops.*", "writer"),
    ]


def test_effective_grants_on_includes_what_is_attached_at_the_object():
    store = _store()
    store.seed(
        "analytics", Policy(principal="ginny", role="reader", pattern="analytics.ops.audit_log")
    )
    rows = capability(store).effective_grants_on(_alice(), "analytics.ops.audit_log")
    assert [(r["user"], r["pattern"]) for r in rows] == [
        ("alice", "analytics.*"),
        ("ginny", "analytics.ops.audit_log"),
    ]


def test_effective_grants_on_a_collection_covers_at_and_above_it():
    store = _store()
    store.seed("analytics", Policy(principal="bob", role="writer", pattern="analytics.ops.*"))
    # Below the collection: a dataset policy does not cover the collection.
    store.seed(
        "analytics", Policy(principal="ginny", role="reader", pattern="analytics.ops.audit_log")
    )
    rows = capability(store).effective_grants_on(_alice(), "analytics.ops.*")
    assert [(r["user"], r["pattern"]) for r in rows] == [
        ("alice", "analytics.*"),
        ("bob", "analytics.ops.*"),
    ]


def test_effective_grants_on_a_workspace_matches_the_attached_listing():
    # A workspace listing is already every policy at every level, so the two
    # statements agree there by construction.
    store = _store()
    store.seed("analytics", Policy(principal="bob", role="writer", pattern="analytics.ops.*"))
    store.seed(
        "analytics", Policy(principal="ginny", role="reader", pattern="analytics.ops.audit_log")
    )
    cap = capability(store)
    assert cap.effective_grants_on(_alice(), "analytics.*") == cap.grants_on(
        _alice(), "analytics.*"
    )


def test_effective_grants_on_is_gated_exactly_as_the_attached_listing_is():
    store = _store()
    store.seed("analytics", Policy(principal="bob", role="writer", pattern="analytics.*"))
    with pytest.raises(AccessDeniedError):
        capability(store).effective_grants_on(
            FakeExecutionContext(user="bob"), "analytics.ops.audit_log"
        )


def test_effective_grants_on_requires_a_store_and_an_identity():
    with pytest.raises(PolicyStoreRequiredError):
        capability().effective_grants_on(_alice(), "analytics.*")
    with pytest.raises(AccessDeniedError):
        capability(_store()).effective_grants_on(FakeExecutionContext(user=None), "analytics.*")


def test_effective_grants_on_agrees_with_what_can_perform_action_decides():
    # The listing and enforcement must not drift: every row it reports is a
    # policy that would in fact let its holder read the dataset.
    from opteryx_access.checks import can_perform_action
    from opteryx_access.models import Grant

    store = _store()
    store.seed("analytics", Policy(principal="bob", role="reader", pattern="analytics.ops.*"))
    store.seed("analytics", Policy(principal="ginny", role="reader", pattern="analytics.sales.*"))
    rows = capability(store).effective_grants_on(_alice(), "analytics.ops.audit_log")
    for row in rows:
        assert can_perform_action(
            [Grant(role=row["role"], pattern=row["pattern"])],
            "analytics.ops.audit_log",
            "READ",
            identity=row["user"],
        )
    assert "ginny" not in {row["user"] for row in rows}


# --- effective_grants_in


def _seeded_workspace():
    store = _store()
    store.seed("analytics", Policy(principal="bob", role="writer", pattern="analytics.ops.*"))
    store.seed(
        "analytics", Policy(principal="ginny", role="reader", pattern="analytics.ops.audit_log")
    )
    store.seed("analytics", Policy(principal="ginny", role="reader", pattern="analytics.sales.*"))
    return store


def _shape(rows):
    return [
        (r["object"], r["user"], r["pattern"], r["level"], r["role"], r["explicit"]) for r in rows
    ]


def test_effective_grants_in_answers_a_collection_or_dataset_as_effective_grants_on_would():
    store = _seeded_workspace()
    cap = capability(store)
    objects = ["analytics.ops.*", "analytics.ops.audit_log", "analytics.sales.q1"]

    rows = cap.effective_grants_in(_alice(), "analytics", objects)

    for object_pattern in objects:
        per_object = [
            {k: r[k] for k in ("user", "pattern", "level", "role")}
            for r in rows
            if r["object"] == object_pattern
        ]
        assert per_object == cap.effective_grants_on(_alice(), object_pattern), object_pattern


def test_effective_grants_in_reports_the_workspace_as_an_object_not_as_the_whole_listing():
    # `SHOW EFFECTIVE GRANTS ON WORKSPACE` lists every policy at every level.
    # Here the workspace row is the policies that cover the workspace itself;
    # the narrower ones are each reported at their own pattern instead.
    rows = capability(_seeded_workspace()).effective_grants_in(
        _alice(), "analytics", ["analytics.*"]
    )
    at_the_workspace = [r for r in rows if r["object"] == "analytics.*"]
    assert _shape(at_the_workspace) == [
        ("analytics.*", "alice", "analytics.*", "workspace", "owner", True),
    ]
    assert ("analytics.ops.*", "bob", "analytics.ops.*", "collection", "writer", True) in _shape(
        rows
    )


def test_effective_grants_in_says_whether_each_policy_is_stored_at_the_object():
    rows = capability(_seeded_workspace()).effective_grants_in(
        _alice(), "analytics", ["analytics.ops.audit_log"]
    )
    at_the_dataset = [r for r in rows if r["object"] == "analytics.ops.audit_log"]
    assert _shape(at_the_dataset) == [
        ("analytics.ops.audit_log", "alice", "analytics.*", "workspace", "owner", False),
        ("analytics.ops.audit_log", "bob", "analytics.ops.*", "collection", "writer", False),
        ("analytics.ops.audit_log", "ginny", "analytics.ops.audit_log", "dataset", "reader", True),
    ]


def test_effective_grants_in_reads_the_store_once_however_many_objects():
    class CountingStore(FakePolicyStore):
        reads = 0

        def list_policies(self, workspace):
            CountingStore.reads += 1
            return super().list_policies(workspace)

        def list_policies_for_principal(self, workspace, principal):
            CountingStore.reads += 1
            return super().list_policies_for_principal(workspace, principal)

    store = CountingStore()
    store.seed("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))
    objects = [f"analytics.ops.dataset_{i}" for i in range(50)]

    capability(store).effective_grants_in(_alice(), "analytics", objects)

    assert CountingStore.reads == 2


def test_effective_grants_in_lists_every_stored_policy_at_its_own_pattern():
    # A grant on something the catalog no longer holds is exactly the grant a
    # listing must not lose. Nothing asked about `analytics.sales.*`, and
    # ginny's policy there is still reported, explicitly, at itself.
    rows = capability(_seeded_workspace()).effective_grants_in(
        _alice(), "analytics", ["analytics.ops.audit_log"]
    )
    assert (
        "analytics.sales.*",
        "ginny",
        "analytics.sales.*",
        "collection",
        "reader",
        True,
    ) in _shape(rows)
    # And the workspace owner's own policy, at the workspace.
    assert ("analytics.*", "alice", "analytics.*", "workspace", "owner", True) in _shape(rows)


def test_effective_grants_in_keeps_the_asked_order_then_appends_stored_patterns():
    rows = capability(_seeded_workspace()).effective_grants_in(
        _alice(), "analytics", ["analytics.ops.audit_log", "analytics.*"]
    )
    seen = []
    for row in rows:
        if row["object"] not in seen:
            seen.append(row["object"])
    assert seen[:2] == ["analytics.ops.audit_log", "analytics.*"]
    assert set(seen[2:]) == {"analytics.ops.*", "analytics.sales.*"}


def test_effective_grants_in_skips_objects_the_actor_may_not_administer():
    # bob owns only `analytics.ops.*`: he sees the ops collection and what is
    # under it, and nothing about the workspace or its other collections --
    # skipped, not refused, because this is a listing and not a statement.
    store = _store()
    store.seed("analytics", Policy(principal="bob", role="owner", pattern="analytics.ops.*"))
    store.seed("analytics", Policy(principal="ginny", role="reader", pattern="analytics.sales.*"))
    rows = capability(store).effective_grants_in(
        FakeExecutionContext(user="bob"),
        "analytics",
        ["analytics.*", "analytics.ops.*", "analytics.ops.audit_log", "analytics.sales.*"],
    )
    assert {r["object"] for r in rows} == {"analytics.ops.*", "analytics.ops.audit_log"}
    assert "ginny" not in {r["user"] for r in rows}


def test_effective_grants_in_gives_an_anonymous_session_nothing():
    rows = capability(_seeded_workspace()).effective_grants_in(
        FakeExecutionContext(user=None), "analytics", ["analytics.*"]
    )
    assert rows == []


def test_effective_grants_in_still_requires_a_store():
    with pytest.raises(PolicyStoreRequiredError):
        capability().effective_grants_in(_alice(), "analytics", ["analytics.*"])


def test_effective_grants_in_refuses_an_object_from_another_workspace():
    from opteryx_access.exceptions import InvalidPatternError

    with pytest.raises(InvalidPatternError):
        capability(_seeded_workspace()).effective_grants_in(
            _alice(), "analytics", ["analytics.*", "billing.*"]
        )


def test_effective_grants_in_does_not_validate_object_names_only_normalizes():
    # A dataset the catalog holds under a name no policy could spell exactly
    # is still reached by the workspace owner's `analytics.*`, and a real
    # query would let alice read it; the listing says the same.
    rows = capability(_seeded_workspace()).effective_grants_in(
        _alice(), "analytics", ["Analytics.ops.Odd-Name"]
    )
    assert (
        "analytics.ops.odd-name",
        "alice",
        "analytics.*",
        "workspace",
        "owner",
        False,
    ) in _shape(rows)


def test_effective_grants_in_never_lists_an_engine_private_object():
    rows = capability(_seeded_workspace()).effective_grants_in(
        _alice(), "analytics", ["analytics.ops.$secrets", "analytics.ops.audit_log"]
    )
    assert not any(r["object"].startswith("analytics.ops.$") for r in rows)


def test_effective_grants_in_agrees_with_what_can_perform_action_decides():
    from opteryx_access.checks import can_perform_action
    from opteryx_access.models import Grant

    rows = capability(_seeded_workspace()).effective_grants_in(
        _alice(), "analytics", ["analytics.ops.audit_log", "analytics.sales.q1"]
    )
    for row in rows:
        if row["object"].endswith(".*"):
            continue
        assert can_perform_action(
            [Grant(role=row["role"], pattern=row["pattern"])],
            row["object"],
            "READ",
            identity=row["user"],
        ), row
