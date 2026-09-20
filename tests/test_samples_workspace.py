"""`samples` is universally readable and never listed.

Two properties, and they are held by ONE mechanism rather than two, which is
why they are tested together:

* everyone can READ `samples.*` and nobody can write it, so anyone can query a
  sample or fork one with `CREATE TABLE ... CLONE` without a policy being
  issued to them;
* it is not in anyone's catalog tree, because the grant is IMPLICIT - implicit
  grants never reach a token's `policies` claim, and odata.opteryx draws the
  service document (which is what draws the tree) from that claim. `public` is
  listed only because the service document unions it in by name.

The second is a property of an absence, so the test that protects it is the one
asserting the grant does not appear where a listable grant would.
"""

import pytest

from opteryx_access.checks import can_perform_action
from opteryx_access.checks import implicit_grants
from opteryx_access.exceptions import InvalidPatternError
from opteryx_access.patterns import RESERVED_WORKSPACES
from opteryx_access.patterns import validate_pattern

SAMPLE = "samples.tpch_sf1.lineitem"
SAMPLE_COLLECTION = "samples.tpch_sf1"


def _grants(identity):
    return implicit_grants(identity)


# --------------------------------------------------------------------------
# 1. Universally readable
# --------------------------------------------------------------------------


def test_any_identity_can_read_a_sample():
    assert can_perform_action(_grants("alice"), SAMPLE, "READ", identity="alice")


def test_an_anonymous_session_can_read_a_sample():
    # Forking needs READ on the upstream, and an account that has just been
    # created holds no issued policy at all.
    assert can_perform_action(_grants(None), SAMPLE, "READ", identity=None)


def test_the_collection_is_readable_too():
    # `CREATE COLLECTION ... CLONE` checks the two-part name, so a grant that
    # only covered datasets would refuse the collection-level clone that
    # Studio's sample dialog writes.
    assert can_perform_action(_grants("alice"), SAMPLE_COLLECTION, "READ", identity="alice")


# --------------------------------------------------------------------------
# 2. Read-only, for everyone except the platform
# --------------------------------------------------------------------------


@pytest.mark.parametrize("action", ["WRITE", "ALTER", "CREATE"])
def test_nobody_can_change_a_sample(action):
    assert not can_perform_action(_grants("alice"), SAMPLE, action, identity="alice")


def test_an_issued_policy_cannot_widen_it():
    # The implicit grant CAPS: a resource inside `samples.` is answered there
    # and never falls through to an issued policy. Without the cap, anyone who
    # could get a policy written could make the shared samples writable for
    # everyone who forks them.
    issued = [type(_grants("alice")[0])(role="owner", pattern="samples.*")]
    assert not can_perform_action(issued, SAMPLE, "WRITE", identity="alice")


def test_the_platform_identities_may_maintain_it():
    # Something has to be able to stage and compact the bundles.
    assert can_perform_action(_grants("xb500"), SAMPLE, "WRITE", identity="xb500")


def test_no_policy_may_be_written_over_samples():
    assert "samples" in RESERVED_WORKSPACES
    with pytest.raises(InvalidPatternError, match="samples"):
        validate_pattern("samples.*")


# --------------------------------------------------------------------------
# 3. Not listed
# --------------------------------------------------------------------------


def test_the_sample_grant_is_implicit_not_issued():
    # THE LISTING PROPERTY. odata.opteryx builds the service document from the
    # token's `policies` claim, and implicit grants are never in it - so a
    # namespace reachable only this way is readable and invisible. Five scale
    # factors of TPC-H would otherwise be forty datasets in the catalog tree of
    # every account on the platform, forever, to be forked once.
    patterns = [grant.pattern for grant in _grants("alice")]
    assert "samples.*" in patterns, "the implicit read is gone; samples became unforkable"


def test_reading_a_sample_needs_no_issued_policy():
    # The same statement from the other side: an identity with an empty policy
    # set still reads it, which is what "not listed" costs nothing.
    assert can_perform_action([], SAMPLE, "READ", identity="alice")
