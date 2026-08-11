from opteryx_access.roles import ADMINISTRATIVE_ROLES
from opteryx_access.roles import OWNER_ONLY_ROLES
from opteryx_access.roles import ROLES
from opteryx_access.roles import is_valid_role
from opteryx_access.roles import role_outranks_or_equals
from opteryx_access.roles import role_rank


def test_roles_ordered_highest_first():
    assert ROLES == ("owner", "admin", "writer", "reader")


def test_role_rank_strictly_decreasing():
    ranks = [role_rank(role) for role in ROLES]
    assert ranks == sorted(ranks, reverse=True)
    assert len(set(ranks)) == len(ranks)


def test_is_valid_role():
    assert is_valid_role("owner")
    assert not is_valid_role("superadmin")


def test_role_outranks_or_equals():
    assert role_outranks_or_equals("owner", "admin")
    assert role_outranks_or_equals("admin", "admin")
    assert not role_outranks_or_equals("writer", "admin")


def test_unknown_role_ranks_lowest():
    assert role_rank("nonsense") == 0
    assert not role_outranks_or_equals("nonsense", "reader")


def test_administrative_roles_are_owner_and_admin_only():
    assert ADMINISTRATIVE_ROLES == {"owner", "admin"}


def test_owner_only_roles():
    assert OWNER_ONLY_ROLES == {"owner"}
