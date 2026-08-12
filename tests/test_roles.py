from opteryx_access.roles import ADMINISTRATIVE_ROLES
from opteryx_access.roles import ROLES
from opteryx_access.roles import is_valid_role
from opteryx_access.roles import role_outranks_or_equals
from opteryx_access.roles import role_rank


def test_roles_ordered_highest_first():
    assert ROLES == ("owner", "writer", "reader")


def test_admin_is_not_a_role():
    # "admin" belongs exclusively to billing_role ("billing_admin"/"member")
    # on a billing account -- nothing in this package's own vocabulary is
    # named "admin".
    assert "admin" not in ROLES
    assert not is_valid_role("admin")


def test_role_rank_strictly_decreasing():
    ranks = [role_rank(role) for role in ROLES]
    assert ranks == sorted(ranks, reverse=True)
    assert len(set(ranks)) == len(ranks)


def test_is_valid_role():
    assert is_valid_role("owner")
    assert not is_valid_role("superadmin")


def test_role_outranks_or_equals():
    assert role_outranks_or_equals("owner", "writer")
    assert role_outranks_or_equals("writer", "writer")
    assert not role_outranks_or_equals("reader", "writer")


def test_unknown_role_ranks_lowest():
    assert role_rank("nonsense") == 0
    assert not role_outranks_or_equals("nonsense", "reader")
    # "admin" specifically -- a stray value from the billing vocabulary must
    # rank exactly like any other unrecognized string, not specially.
    assert role_rank("admin") == 0


def test_administrative_roles_is_owner_only():
    assert ADMINISTRATIVE_ROLES == {"owner"}
