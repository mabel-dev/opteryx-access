"""Exceptions raised by permission checks and grant/revoke operations.

Deliberately not `HTTPException` or anything else framework-shaped: this
library is embedded into services with different transports (FastAPI routes,
the query engine's execution phase), so it raises plain exceptions and lets
each caller translate to whatever its own boundary expects.
"""


class OpteryxAccessError(Exception):
    """Base class for every exception this package raises."""


class InvalidRoleError(OpteryxAccessError):
    """A role outside `opteryx_access.roles.ROLES` was supplied."""


class InvalidPatternError(OpteryxAccessError):
    """A resource pattern violates the wildcard-principal or reserved-resource rule."""


class SelfAccessError(OpteryxAccessError):
    """An actor tried to grant, modify, or revoke their own access.

    Self-service changes to one's own policy aren't auditable the same way a
    second party approving them is -- this is a deliberate platform rule, not
    an accident of the reference implementation it was ported from.
    """


class AccessDeniedError(OpteryxAccessError):
    """The actor lacks administrative authority over the pattern in question."""


class PolicyConflictError(OpteryxAccessError):
    """The requested grant duplicates or is made redundant by an existing policy."""


class PolicyNotFoundError(OpteryxAccessError):
    """No policy exists with the given id in the given workspace."""


class WorkspaceAlreadyBootstrappedError(OpteryxAccessError):
    """`bootstrap_workspace` was called on a workspace that already has policies."""


class PolicyStoreRequiredError(OpteryxAccessError):
    """A check about another principal was asked of a capability with no store.

    Raised rather than answered `False`. The caller asked whether somebody may
    do something and got no answer at all, which is not the same as being told
    no -- and a permission check that quietly returns "denied" because it could
    not read anything is how a check stops meaning what it says.
    """
