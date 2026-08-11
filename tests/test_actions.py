from opteryx_access.actions import ACTION_ROLES
from opteryx_access.actions import action_allowed_for_role
from opteryx_access.actions import allowed_roles
from opteryx_access.roles import ROLES


def test_admin_excluded_from_every_data_action():
    # admin is an administrative (grant-management) tier, not a data-access
    # tier -- see opteryx_access.roles. Confirm no data action was accidentally
    # opened up to admin.
    data_actions = set(ACTION_ROLES) - {"GRANT", "REVOKE"}
    for action in data_actions:
        assert "admin" not in ACTION_ROLES[action], action


def test_admin_and_owner_may_grant_and_revoke():
    assert action_allowed_for_role("admin", "GRANT")
    assert action_allowed_for_role("owner", "GRANT")
    assert action_allowed_for_role("admin", "REVOKE")
    assert not action_allowed_for_role("writer", "GRANT")


def test_drop_and_alter_are_owner_only():
    assert allowed_roles("DROP") == {"owner"}
    assert allowed_roles("ALTER") == {"owner"}


def test_reader_may_only_read():
    for action in ACTION_ROLES:
        expected = action == "READ"
        assert action_allowed_for_role("reader", action) == expected, action


def test_unknown_action_permits_nobody():
    assert allowed_roles("TRUNCATE") == frozenset()
    for role in ROLES:
        assert not action_allowed_for_role(role, "TRUNCATE")


def test_every_action_role_is_a_recognized_role_or_administrative():
    from opteryx_access.roles import ADMINISTRATIVE_ROLES

    for action, roles in ACTION_ROLES.items():
        for role in roles:
            assert role in ROLES or role in ADMINISTRATIVE_ROLES, (action, role)
