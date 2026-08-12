"""Adversarial tests for the invariants this package exists to hold the line
on. Each test below encodes a specific escalation attempt and asserts it is
denied -- these are the properties that matter most on this surface, more
than line coverage of the happy path.
"""

import pytest
from fakes import FakePolicyStore

from opteryx_access.actions import ACTION_ROLES
from opteryx_access.actions import action_allowed_for_role
from opteryx_access.checks import can_administer_pattern
from opteryx_access.checks import can_perform_action
from opteryx_access.checks import has_workspace_access
from opteryx_access.exceptions import AccessDeniedError
from opteryx_access.exceptions import InvalidPatternError
from opteryx_access.exceptions import InvalidRoleError
from opteryx_access.exceptions import SelfAccessError
from opteryx_access.grants import bootstrap_workspace
from opteryx_access.grants import grant
from opteryx_access.models import Grant
from opteryx_access.models import Policy
from opteryx_access.patterns import validate_pattern
from opteryx_access.roles import ROLES

# ---------------------------------------------------------------------------
# ACTION_ROLES: exhaustive role x action matrix, not spot checks.
# ---------------------------------------------------------------------------


def test_action_roles_matrix_matches_declared_sets_exactly():
    # Guards against a future edit widening/narrowing ACTION_ROLES silently:
    # every (role, action) pair is checked against the map directly, so a
    # change to ACTION_ROLES is a change to this test's expectation too.
    for action, allowed in ACTION_ROLES.items():
        for role in ROLES:
            expected = role in allowed
            assert action_allowed_for_role(role, action) == expected, (role, action)


def test_no_role_can_perform_an_action_it_is_not_explicitly_listed_for():
    # Belt-and-suspenders on the matrix test above: nobody may DROP/ALTER/
    # MANIFEST without being exactly "owner".
    for action in ("DROP", "ALTER", "MANIFEST"):
        for role in ROLES:
            if role != "owner":
                assert not action_allowed_for_role(role, action), (role, action)


# ---------------------------------------------------------------------------
# Pattern-authority containment: administering a pattern must never let an
# actor reach outside the exact scope they were handed.
# ---------------------------------------------------------------------------


def test_cannot_grant_a_broader_pattern_than_you_administer():
    # Holding owner on the narrow "analytics.sales.*" must not let you mint a
    # grant on the broader "analytics.*" -- that would let a scoped owner
    # silently widen their own effective reach by handing the broad pattern
    # to an accomplice (or to themselves under a second identity).
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="alice", role="owner", pattern="analytics.sales.*"))
    with pytest.raises(AccessDeniedError):
        grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="bob",
            role="reader",
            pattern="analytics.*",
        )


def test_glob_characters_in_the_requested_pattern_are_not_expanded():
    # A requested pattern is matched as a literal string against the actor's
    # held (glob) pattern -- its own "*"/"?"/"[...]" must not be interpreted
    # as wildcards that could make an unrelated pattern look covered.
    policies = [Policy(principal="alice", role="owner", pattern="analytics.sales.q1")]
    assert not can_administer_pattern(policies, "alice", "analytics.sales.*")
    assert not can_administer_pattern(policies, "alice", "analytics.sales.q?")
    assert not can_administer_pattern(policies, "alice", "analytics.sales.[q]1")


def test_administering_one_workspace_grants_nothing_in_another():
    store = FakePolicyStore()
    store.seed("billing", Policy(principal="alice", role="owner", pattern="billing.*"))
    with pytest.raises(AccessDeniedError):
        grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="bob",
            role="reader",
            pattern="analytics.sales.*",
        )


def test_principal_matching_is_exact_not_glob():
    # A policy's stored `principal` is compared with `==`/`in`, never
    # fnmatch -- an identity that happens to contain glob metacharacters
    # (however implausible) must not match a differently-named principal's
    # policy.
    policies = [Policy(principal="alice.*", role="owner", pattern="analytics.*")]
    assert not can_administer_pattern(policies, "alice.anything", "analytics.sales.*")
    assert can_administer_pattern(policies, "alice.*", "analytics.sales.*")


# ---------------------------------------------------------------------------
# Reserved resources: not bypassable by case, and not by a glob that merely
# could match the reserved name.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "pattern", ["public.security", "Public.security", "PUBLIC.security", "PeRsOnAl.alice.*"]
)
def test_reserved_workspace_check_is_case_insensitive(pattern):
    # Names are normalized before anything looks at them, so a reserved
    # workspace cannot be reached by changing case -- and the answer is the
    # same on every platform, unlike plain `fnmatch`, which folds case per-OS.
    with pytest.raises(InvalidPatternError):
        validate_pattern(pattern)


@pytest.mark.parametrize("pattern", ["pub*.security", "p*.security", "*.security"])
def test_reserved_workspace_cannot_be_reached_by_a_partial_glob(pattern):
    # A workspace segment is either a literal name or nothing -- there are no
    # partial globs to evade the reserved list with.
    with pytest.raises(InvalidPatternError):
        validate_pattern(pattern)


def test_reserved_workspace_cannot_be_granted_even_by_a_pattern_owner():
    store = FakePolicyStore()
    # Contrived: even if an owner grant somehow existed scoped to "public.*",
    # granting *through* it must still be rejected.
    store.seed("public", Policy(principal="alice", role="owner", pattern="public.*"))
    with pytest.raises(InvalidPatternError):
        grant(
            store,
            actor="alice",
            workspace="public",
            principal="bob",
            role="reader",
            pattern="public.security",
        )


# ---------------------------------------------------------------------------
# Self-service: the only rule that isn't about scope, but about who is
# asking.
# ---------------------------------------------------------------------------


def test_self_grant_denied_even_with_full_administrative_authority():
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))
    with pytest.raises(SelfAccessError):
        grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="alice",
            role="owner",
            pattern="analytics.sales.*",
        )


def test_cannot_grant_to_everyone():
    # There is no wildcard principal: a grant everyone holds is not something
    # any listing surfaces as unusual, so it cannot be written at all.
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))
    with pytest.raises(InvalidPatternError):
        grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="*",
            role="reader",
            pattern="analytics.dashboard",
        )


def test_a_stored_wildcard_principal_confers_nothing():
    # Defence in depth for the migration: if a "*" policy predates the rule
    # above, it must not act as a grant to whoever happens to be asking.
    policies = [Policy(principal="*", role="owner", pattern="analytics.*")]
    assert not can_administer_pattern(policies, "anyone", "analytics.sales.q1")


def test_principal_is_matched_exactly_not_by_pattern():
    # Patterns are normalized and glob-matched; principals are neither. A
    # policy belongs to exactly the identity string it names.
    policies = [Policy(principal="alice", role="owner", pattern="analytics.*")]
    assert can_administer_pattern(policies, "alice", "analytics.sales.q1")
    assert not can_administer_pattern(policies, "alice.anything", "analytics.sales.q1")


# ---------------------------------------------------------------------------
# Implicit grants: public/personal must cap at their declared role no matter
# what an issued policy claims, in both directions (a stronger AND a weaker
# issued policy must not change the outcome).
# ---------------------------------------------------------------------------


def test_implicit_public_read_only_survives_a_conflicting_owner_grant():
    grants = [Grant(role="owner", pattern="public.*")]
    for action in ("WRITE", "DELETE", "DROP", "CREATE", "ALTER"):
        assert not can_perform_action(grants, "public.security", action)


def test_implicit_personal_owner_survives_a_conflicting_reader_grant():
    # The opposite direction: an issued policy that would be *weaker* than
    # the implicit grant must not narrow it either -- implicit grants are
    # answered before `grants` is even consulted.
    grants = [Grant(role="reader", pattern="personal.alice.*")]
    assert can_perform_action(grants, "personal.alice.notes", "DROP", identity="alice")


def test_implicit_grant_prefix_match_does_not_leak_across_identities():
    # "personal.alice2.x" must not be treated as covered by alice's implicit
    # "personal.alice.*" via a naive substring check -- the prefix compared
    # is "personal.alice." (dot included), not "personal.alice".
    assert not can_perform_action([], "personal.alice2.notes", "READ", identity="alice")


# ---------------------------------------------------------------------------
# A role outside `ROLES` is inert at every enforcement point -- it grants
# nothing and cannot be stored. The property is general; the values below are
# chosen to cover the ways one realistically shows up: "admin" is still a
# live role in the not-yet-migrated services, so it is the stale value most
# likely to appear in an existing stored policy, and "Owner" would pass a
# case-insensitive comparison if one ever crept in.
# ---------------------------------------------------------------------------

UNRECOGNIZED_ROLES = ("admin", "superuser", "Owner", "")


@pytest.mark.parametrize("role", UNRECOGNIZED_ROLES)
def test_unrecognized_role_permits_no_action(role):
    grants = [Grant(role=role, pattern="analytics.*")]
    for action in ACTION_ROLES:
        assert not can_perform_action(grants, "analytics.sales.q1", action), action


@pytest.mark.parametrize("role", UNRECOGNIZED_ROLES)
def test_unrecognized_role_carries_no_administrative_authority(role):
    policies = [Policy(principal="alice", role=role, pattern="analytics.*")]
    assert not can_administer_pattern(policies, "alice", "analytics.sales.*")
    assert not has_workspace_access(policies, "alice")


@pytest.mark.parametrize("role", UNRECOGNIZED_ROLES)
def test_unrecognized_role_cannot_be_granted(role):
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))
    with pytest.raises(InvalidRoleError):
        grant(
            store,
            actor="alice",
            workspace="analytics",
            principal="bob",
            role=role,
            pattern="analytics.sales.*",
        )


@pytest.mark.parametrize("role", UNRECOGNIZED_ROLES)
def test_unrecognized_role_cannot_bootstrap_a_workspace(role):
    store = FakePolicyStore()
    with pytest.raises(InvalidRoleError):
        bootstrap_workspace(store, actor="alice", workspace="newspace", grants=[("bob", role)])


def test_owner_may_grant_owner_to_a_third_party():
    # Known, intentional platform behavior worth pinning explicitly: owner's
    # grant-management authority lets it grant *any* role, including owner,
    # to a third party -- there is no rule limiting a grant to at most the
    # actor's own role.
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))
    policy_id = grant(
        store,
        actor="alice",
        workspace="analytics",
        principal="bob",
        role="owner",
        pattern="analytics.sales.*",
    )
    assert store.get_policy("analytics", policy_id).role == "owner"
