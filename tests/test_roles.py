from opteryx_access.roles import ROLES
from opteryx_access.roles import is_valid_role
from opteryx_access.roles import role_outranks_or_equals


def test_roles_are_exactly_owner_writer_reader_in_privilege_order():
    assert ROLES == ("owner", "writer", "reader")


def test_is_valid_role():
    assert is_valid_role("owner")
    assert not is_valid_role("superuser")


def test_role_outranks_or_equals():
    assert role_outranks_or_equals("owner", "writer")
    assert role_outranks_or_equals("owner", "reader")
    assert role_outranks_or_equals("writer", "writer")
    assert not role_outranks_or_equals("writer", "owner")
    assert not role_outranks_or_equals("reader", "writer")


def test_every_role_outranks_or_equals_itself():
    for role in ROLES:
        assert role_outranks_or_equals(role, role)


def test_unrecognized_role_never_outranks_a_real_one():
    for role in ROLES:
        assert not role_outranks_or_equals("nonsense", role)


def test_a_real_role_never_outranks_an_unrecognized_one():
    # Not symmetry for its own sake: an unrecognized role confers nothing, so
    # it must not be treated as a rung on the ladder at either end. Scoring it
    # and comparing numerically would answer True here.
    for role in ROLES:
        assert not role_outranks_or_equals(role, "nonsense")


def test_two_unrecognized_roles_do_not_compare_equal():
    # The defect a sentinel score reintroduces: both land on the same number,
    # so `>=` calls them equal and one junk role is reported as making another
    # redundant.
    assert not role_outranks_or_equals("nonsense", "nonsense")
    assert not role_outranks_or_equals("bob", "admin")
