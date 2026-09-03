from opteryx_access.actions import ACTION_ROLES
from opteryx_access.actions import action_allowed_for_role
from opteryx_access.actions import allowed_roles
from opteryx_access.roles import ROLES


def test_role_outside_roles_permits_nothing():
    for action in ACTION_ROLES:
        assert not action_allowed_for_role("superuser", action), action


def test_only_owner_may_grant_and_revoke():
    assert action_allowed_for_role("owner", "GRANT")
    assert action_allowed_for_role("owner", "REVOKE")
    assert not action_allowed_for_role("writer", "GRANT")
    assert not action_allowed_for_role("reader", "GRANT")


def test_drop_and_alter_are_owner_only():
    assert allowed_roles("DROP") == {"owner"}
    assert allowed_roles("ALTER") == {"owner"}


def test_automation_is_owner_only():
    # A task or trigger is a standing commitment that runs unattended as a
    # pinned identity on the owner's compute; a writer may fill a relation but
    # may not decide what it does on its own.
    assert allowed_roles("AUTOMATE") == {"owner"}
    assert not action_allowed_for_role("writer", "AUTOMATE")
    assert not action_allowed_for_role("reader", "AUTOMATE")


def test_writer_tier_is_exactly_the_artefact_actions():
    # The line between writer and owner, pinned: a writer creates and fills
    # artefacts; everything that changes what a relation IS to others -- its
    # shape, its existence, its layout, who may read it, what it does on its
    # own -- is the owner's.
    writer_actions = {action for action in ACTION_ROLES if "writer" in ACTION_ROLES[action]}
    assert writer_actions == {"READ", "WRITE", "UPDATE", "DELETE", "CREATE", "REFRESH", "SIGNAL"}


def test_signalling_is_writer_tier_and_not_automation():
    # A signal fires work that was authorized when its trigger was armed; the
    # caller is recorded as the event and the run carries the trigger's own
    # identity. A writer may kick it off; only an owner may decide the
    # automation exists (AUTOMATE), and a reader may do neither.
    assert allowed_roles("SIGNAL") == {"writer", "owner"}
    assert not action_allowed_for_role("reader", "SIGNAL")
    assert allowed_roles("SIGNAL") != allowed_roles("AUTOMATE")


def test_reader_may_only_read():
    for action in ACTION_ROLES:
        expected = action == "READ"
        assert action_allowed_for_role("reader", action) == expected, action


def test_unknown_action_permits_nobody():
    assert allowed_roles("TRUNCATE") == frozenset()
    for role in ROLES:
        assert not action_allowed_for_role(role, "TRUNCATE")


def test_every_action_role_is_a_recognized_role():
    for action, roles in ACTION_ROLES.items():
        for role in roles:
            assert role in ROLES, (action, role)
