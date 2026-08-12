"""The roles a policy can grant, and their privilege ordering.

These are data roles: they say what an identity may do to workspaces,
collections, and datasets. Billing-account roles are a separate vocabulary
belonging to a separate system -- see the README's "Scope" section.

Which roles may perform which action lives in `opteryx_access.actions`, not
here. This module owns the role vocabulary and its ordering; ordering is used
only to decide whether one grant makes another redundant.
"""

# Most privileged first. Routes may publish this tuple verbatim in OpenAPI
# schemas as the accepted values.
ROLES: tuple[str, ...] = ("owner", "writer", "reader")

# Privilege as a comparable number, higher being more privileged. Private on
# purpose: exposing it invites `.get(role, 0)`, and a default of 0 both reads
# as "first place" to anyone taking "rank" in the ordinal sense and makes two
# unrecognized roles compare equal. Comparison goes through
# `role_outranks_or_equals`, which refuses to score an unrecognized role at
# all.
_ROLE_PRIVILEGE = {role: len(ROLES) - index for index, role in enumerate(ROLES)}


def is_valid_role(role: str) -> bool:
    """Whether `role` is one of the grantable roles in `ROLES`."""
    return role in ROLES


def role_outranks_or_equals(held: str, other: str) -> bool:
    """Whether `held` is at least as privileged as `other` (owner > writer > reader).

    False unless both are recognized roles. An unrecognized role confers
    nothing, so it must not take part in the comparison in either direction:
    it neither outranks a real role nor stands equal to another unrecognized
    one.

    Used by conflict detection: a broader policy at an equal or higher
    privilege makes a narrower new grant redundant.
    """
    if held not in _ROLE_PRIVILEGE or other not in _ROLE_PRIVILEGE:
        return False
    return _ROLE_PRIVILEGE[held] >= _ROLE_PRIVILEGE[other]
