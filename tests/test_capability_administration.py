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


# --- maintenance: the setting that is a grant


def _maintenance_policies(store, workspace="analytics", principal="federator"):
    return [p for p in store.list_policies_for_principal(workspace, principal)]


def test_maintenance_on_grants_the_identity_writer_on_the_workspace():
    """The setting IS the policy. Workspace-wide, because that is the level it
    is offered at - a dataset inside shows it inherited and cannot manage it."""
    store = _store()
    capability(store).set_workspace_maintenance(_alice(), "analytics", True)

    policies = _maintenance_policies(store)
    assert [(p.principal, p.role, p.pattern) for p in policies] == [
        ("federator", "writer", "analytics.*")
    ]


def test_maintenance_off_revokes_it():
    store = _store()
    cap = capability(store)
    cap.set_workspace_maintenance(_alice(), "analytics", True)
    cap.set_workspace_maintenance(_alice(), "analytics", False)

    assert _maintenance_policies(store) == []


def test_turning_it_on_twice_is_a_no_op_not_a_conflict():
    """`grant()` refuses a policy that already exists, correctly for a caller
    asking for a change. A setting set to what it already says is not a change
    and not an error."""
    store = _store()
    cap = capability(store)
    cap.set_workspace_maintenance(_alice(), "analytics", True)
    cap.set_workspace_maintenance(_alice(), "analytics", True)

    assert len(_maintenance_policies(store)) == 1


def test_turning_it_off_when_it_is_already_off_is_a_no_op():
    store = _store()
    capability(store).set_workspace_maintenance(_alice(), "analytics", False)

    assert _maintenance_policies(store) == []


def test_reading_it_back_comes_from_the_policy():
    """Derived, never a stored flag: what this reports is what the compactor's
    own permission check will decide."""
    store = _store()
    cap = capability(store)
    assert cap.workspace_maintenance(_alice(), "analytics") is False

    cap.set_workspace_maintenance(_alice(), "analytics", True)
    assert cap.workspace_maintenance(_alice(), "analytics") is True

    cap.set_workspace_maintenance(_alice(), "analytics", False)
    assert cap.workspace_maintenance(_alice(), "analytics") is False


def test_maintenance_needs_owner_authority_over_the_workspace():
    """The same refusal the GRANT spelled out longhand would get. Phrasing it
    as a setting does not weaken it: what it turns on is a standing WRITE grant
    over everything in the workspace."""
    store = _store()
    stranger = FakeExecutionContext(user="mallory")

    with pytest.raises(AccessDeniedError):
        capability(store).set_workspace_maintenance(stranger, "analytics", True)

    assert _maintenance_policies(store) == []


def test_maintenance_requires_a_store():
    with pytest.raises(PolicyStoreRequiredError):
        capability().set_workspace_maintenance(_alice(), "analytics", True)


def test_reading_maintenance_without_a_store_is_off_not_an_error():
    """A read has no policy store to consult, so it reports the only thing it
    can stand behind. A raise here would make "is my data maintained" fail
    closed and noisily on a deployment that simply has no policies."""
    assert capability().workspace_maintenance(_alice(), "analytics") is False


def test_an_anonymous_session_cannot_change_it():
    store = _store()
    with pytest.raises(AccessDeniedError):
        capability(store).set_workspace_maintenance(FakeExecutionContext(), "analytics", True)


def test_turning_it_off_leaves_the_identitys_other_grants_alone():
    """A `writer` grant the identity holds at another level is somebody else's
    arrangement. Maintenance owns exactly one policy and must not delete a
    second one on its way out."""
    store = _store()
    # Seeded directly: the SQL surface refuses a grant naming a platform
    # identity, so a policy like this is one the platform put there - which is
    # exactly the kind maintenance must not delete on its way out.
    store.seed("analytics", Policy(principal="federator", role="writer", pattern="analytics.ops.*"))
    cap = capability(store)
    cap.set_workspace_maintenance(_alice(), "analytics", True)

    cap.set_workspace_maintenance(_alice(), "analytics", False)

    assert [p.pattern for p in _maintenance_policies(store)] == ["analytics.ops.*"]


def test_a_collection_grant_does_not_read_as_maintenance_being_on():
    """The mirror of the test above: a narrower grant is not this setting, so
    the setting must still read as off and turning it on must write the real
    policy rather than deciding there is nothing to do."""
    store = _store()
    store.seed("analytics", Policy(principal="federator", role="writer", pattern="analytics.ops.*"))
    cap = capability(store)

    assert cap.workspace_maintenance(_alice(), "analytics") is False

    cap.set_workspace_maintenance(_alice(), "analytics", True)
    assert sorted(p.pattern for p in _maintenance_policies(store)) == [
        "analytics.*",
        "analytics.ops.*",
    ]


# --- platform identities are not grantable through the SQL surface


def test_granting_a_platform_identity_is_refused():
    """A GRANT here would mint standing platform-wide authority that no setting
    reflects and no screen shows - the access list does not render these
    identities at all."""
    store = _store()
    with pytest.raises(AccessDeniedError, match="maintenance"):
        capability(store).apply_grant(_alice(), "analytics.*", "writer", "federator")


def test_revoking_a_platform_identity_is_refused():
    """The direction that matters more: a REVOKE would turn maintenance off by
    a route that leaves the setting reading ON. Refusing it is what lets
    set_workspace_maintenance be the only writer, and so the only thing the
    setting can disagree with (nothing)."""
    store = _store()
    capability(store).set_workspace_maintenance(_alice(), "analytics", True)

    with pytest.raises(AccessDeniedError, match="maintenance"):
        capability(store).apply_revoke(_alice(), "analytics.*", "writer", "federator")

    assert len(_maintenance_policies(store)) == 1


def test_the_refusal_names_both_routes_a_caller_might_want():
    """Somebody reaching for GRANT here wants either maintenance or public
    read, and neither is obvious from a bare refusal."""
    store = _store()
    with pytest.raises(AccessDeniedError) as refusal:
        capability(store).apply_grant(_alice(), "analytics.*", "writer", "xb500")

    message = str(refusal.value)
    assert "ALTER WORKSPACE" in message
    assert "public" in message


def test_an_ordinary_principal_is_unaffected():
    store = _store()
    policy_id = capability(store).apply_grant(_alice(), "analytics.*", "writer", "bob")

    assert store.get_policy("analytics", policy_id).principal == "bob"


def test_maintenance_still_writes_the_policy_the_sql_surface_refuses():
    """The refusal is on the SQL surface, not in `grant()`. If it sat lower
    this setting could not write its own policy either."""
    store = _store()
    capability(store).set_workspace_maintenance(_alice(), "analytics", True)

    assert [p.principal for p in _maintenance_policies(store)] == ["federator"]
