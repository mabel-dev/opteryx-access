"""`demo` is the one workspace readable without signing in.

It holds what the public demo site, the docs' "try it" panels and the
notebooks read with no token, so that `public` -- the curated data every
signed-in account sees in its catalog -- is not also the open internet's
surface. Like `samples` it is reached only through an implicit grant, which is
what keeps it out of every catalog tree (see `test_samples_workspace`).

Also pinned here: the policy labels a service reports for an implicit read,
and the helpers that let a service list and decide from this package instead
of keeping its own copy of these rules.
"""

import pytest

from opteryx_access import AUTHENTICATED_READ_POLICY
from opteryx_access import GLOBAL_UNAUTHENTICATED_READ_POLICY
from opteryx_access import PERSONAL_POLICY
from opteryx_access import PLATFORM_MAINTENANCE_POLICY
from opteryx_access import UNAUTHENTICATED_WORKSPACE
from opteryx_access import Grant
from opteryx_access import can_perform_action
from opteryx_access import implicit_access
from opteryx_access import implicit_grants
from opteryx_access import implicitly_readable_workspaces
from opteryx_access import workspace_roles
from opteryx_access.exceptions import InvalidPatternError
from opteryx_access.patterns import RESERVED_WORKSPACES
from opteryx_access.patterns import validate_pattern

DEMO = "demo.security.cisa_kev"


def _can(resource, action, identity, grants=()):
    return can_perform_action(list(grants), resource, action, identity=identity)


# --------------------------------------------------------------------------
# 1. Who can read what
# --------------------------------------------------------------------------


def test_demo_is_the_unauthenticated_workspace():
    assert UNAUTHENTICATED_WORKSPACE == "demo"


@pytest.mark.parametrize("identity", [None, "alice"])
def test_everyone_can_read_demo(identity):
    assert _can(DEMO, "READ", identity)
    assert _can("demo.security", "READ", identity)


@pytest.mark.parametrize(
    "resource",
    ["public.astronomy.planets", "public.astronomy", "samples.tpch_sf1.lineitem"],
)
def test_an_anonymous_session_reads_neither_public_nor_samples(resource):
    assert not _can(resource, "READ", None)


@pytest.mark.parametrize(
    "resource", ["public.astronomy.planets", "samples.tpch_sf1.lineitem", DEMO]
)
def test_any_signed_in_identity_reads_public_samples_and_demo(resource):
    assert _can(resource, "READ", "alice")


@pytest.mark.parametrize(
    "resource",
    [
        "public.security.cisa_kev",
        "public.security",
        "public.geopolitics.countries",
        "public.geopolitics",
    ],
)
def test_transitional_anonymous_collections_stay_readable(resource):
    # Until every anonymous consumer reads `demo`. Delete this test with
    # `_TRANSITIONAL_ANONYMOUS_PATTERNS`.
    assert _can(resource, "READ", None)
    assert not _can(resource, "WRITE", None)


# --------------------------------------------------------------------------
# 2. Read-only, for everyone except the platform
# --------------------------------------------------------------------------


@pytest.mark.parametrize("identity", [None, "alice"])
@pytest.mark.parametrize("action", ["WRITE", "CREATE", "DELETE", "DROP", "AUTOMATE"])
def test_nobody_can_change_demo(identity, action):
    assert not _can(DEMO, action, identity)


def test_an_issued_policy_cannot_widen_demo():
    issued = [Grant(role="owner", pattern="demo.*")]
    assert not _can(DEMO, "WRITE", "alice", issued)
    assert not _can(DEMO, "WRITE", None, issued)


def test_xb500_owns_demo():
    # The demo is rebuilt by `CREATE OR REPLACE TABLE demo... AS SELECT` copies,
    # and replacing an existing table is the DROP tier.
    assert _can(DEMO, "WRITE", "xb500")
    assert _can(DEMO, "REFRESH", "xb500")
    assert _can(DEMO, "DROP", "xb500")
    assert _can(DEMO, "AUTOMATE", "xb500")


def test_federator_only_writes_demo():
    # Its credential is shipped to every committing service: no drop rights over
    # anything standing.
    assert _can(DEMO, "WRITE", "federator")
    assert not _can(DEMO, "DROP", "federator")


def test_owning_demo_confers_no_policy_administration():
    # Owner includes GRANT, but no policy can be issued over a reserved workspace.
    with pytest.raises(InvalidPatternError):
        validate_pattern("demo.security.*")


def test_no_policy_may_be_written_over_demo():
    assert "demo" in RESERVED_WORKSPACES
    with pytest.raises(InvalidPatternError, match="demo"):
        validate_pattern("demo.*")


@pytest.mark.parametrize("pattern", ["dem*.*", "*.security.*", "d?mo.*"])
def test_a_wildcard_cannot_reach_a_reserved_workspace(pattern):
    # control.opteryx kept its own fnmatch check for this; the shape rule here
    # (a literal workspace segment) already refuses every such pattern, which
    # is what lets control call `validate_pattern` instead.
    with pytest.raises(InvalidPatternError):
        validate_pattern(pattern)


# --------------------------------------------------------------------------
# 3. Not listed
# --------------------------------------------------------------------------


def test_the_demo_grant_is_implicit_not_issued():
    # Implicit grants never reach a token's `policies` claim, which is what the
    # service document -- and so the catalog tree -- is drawn from.
    assert "demo.*" in [g.pattern for g in implicit_grants("alice")]
    assert "demo.*" in [g.pattern for g in implicit_grants(None)]


# --------------------------------------------------------------------------
# 4. Reporting and listing helpers
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("resource", "identity", "role", "label"),
    [
        (DEMO, None, "reader", GLOBAL_UNAUTHENTICATED_READ_POLICY),
        (DEMO, "alice", "reader", GLOBAL_UNAUTHENTICATED_READ_POLICY),
        ("public.astronomy.planets", "alice", "reader", AUTHENTICATED_READ_POLICY),
        ("samples.tpch_sf1.lineitem", "alice", "reader", AUTHENTICATED_READ_POLICY),
        ("public.security.cisa_kev", None, "reader", GLOBAL_UNAUTHENTICATED_READ_POLICY),
        ("personal.alice.notes", "alice", "owner", PERSONAL_POLICY),
        ("public.astronomy.planets", "xb500", "writer", PLATFORM_MAINTENANCE_POLICY),
        (DEMO, "xb500", "owner", PLATFORM_MAINTENANCE_POLICY),
        (DEMO, "federator", "writer", PLATFORM_MAINTENANCE_POLICY),
    ],
)
def test_implicit_access_reports_the_rule_that_applied(resource, identity, role, label):
    held, reported = implicit_access(resource, identity)
    assert (held.role, reported) == (role, label)


@pytest.mark.parametrize(
    ("resource", "identity"),
    [
        ("analytics.sales.q1", "alice"),
        ("public.astronomy.planets", None),
        ("personal.bob.notes", "alice"),
        ("demo.$private.thing", "alice"),
        ("local_table", "alice"),
    ],
)
def test_implicit_access_is_none_where_no_implicit_grant_decides(resource, identity):
    assert implicit_access(resource, identity) is None


def test_implicit_access_agrees_with_enforcement():
    # The label must name the grant that is actually enforced, so the two can
    # never be read off different lists.
    for identity in (None, "alice", "xb500"):
        for resource in (DEMO, "public.astronomy.planets", "samples.tpch_sf1.x"):
            found = implicit_access(resource, identity)
            assert (found is not None and found[0].role is not None) == _can(
                resource, "READ", identity
            ), (resource, identity)


def test_implicitly_readable_workspaces():
    # A starting point for listing, not a decision: `public` is here for an
    # anonymous caller only because of the transitional collections.
    assert implicitly_readable_workspaces(None) == {"demo", "public"}
    assert implicitly_readable_workspaces("alice") == {"personal", "public", "samples", "demo"}


def test_workspace_roles_puts_implicit_first_then_issued():
    issued = [
        Grant(role="writer", pattern="analytics.*"),
        Grant(role="owner", pattern="analytics.x.y"),
    ]
    assert workspace_roles("analytics", "alice", issued) == ["writer", "owner"]
    assert workspace_roles("public", "alice", issued) == ["reader"]
    assert workspace_roles("public", "xb500") == ["writer", "reader"]
    assert workspace_roles("demo", None) == ["reader"]
    assert workspace_roles("samples", None) == []
    assert workspace_roles("personal", "alice") == ["owner", "owner"]
    assert workspace_roles("ANALYTICS", "alice", issued) == ["writer", "owner"]
