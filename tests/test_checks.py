from opteryx_access.checks import PLATFORM_IDENTITIES
from opteryx_access.checks import can_administer_pattern
from opteryx_access.checks import can_perform_action
from opteryx_access.checks import can_perform_workspace_action
from opteryx_access.checks import has_workspace_access
from opteryx_access.checks import implicit_grants
from opteryx_access.models import Grant
from opteryx_access.models import Policy


def test_local_table_is_read_only():
    assert can_perform_action([], "orders", "READ")
    assert not can_perform_action([], "orders", "DELETE")


def test_writer_grant_permits_delete_not_drop():
    grants = [Grant(role="writer", pattern="analytics.sales.*")]
    assert can_perform_action(grants, "analytics.sales.q1", "DELETE")
    assert not can_perform_action(grants, "analytics.sales.q1", "DROP")


def test_no_matching_grant_denies():
    grants = [Grant(role="writer", pattern="analytics.sales.*")]
    assert not can_perform_action(grants, "billing.invoices.q1", "READ")


def test_implicit_personal_namespace_owner():
    grants = implicit_grants("alice")
    assert Grant(role="owner", pattern="personal.alice.*") in grants
    assert can_perform_action([], "personal.alice.private", "DROP", identity="alice")
    assert not can_perform_action([], "personal.bob.private", "DROP", identity="alice")


def test_implicit_personal_namespace_covers_the_collection_itself():
    # `personal.alice.*` does not fnmatch `personal.alice` -- the trailing `.`
    # is a literal the bare collection name has nothing to match. The engine's
    # collection-level statements (CREATE COLLECTION, DROP COLLECTION, LOAD
    # SAMPLE) all check that two-part name, so without the exact-name pattern
    # an identity owns every dataset in their personal collection while being
    # refused the collection.
    grants = implicit_grants("alice")
    assert Grant(role="owner", pattern="personal.alice") in grants

    assert can_perform_action([], "personal.alice", "CREATE", identity="alice")
    assert can_perform_action([], "personal.alice", "DROP", identity="alice")
    assert can_perform_action([], "personal.alice", "READ", identity="alice")


def test_personal_collection_of_another_identity_is_refused():
    assert not can_perform_action([], "personal.bob", "CREATE", identity="alice")
    assert not can_perform_action([], "personal.bob", "READ", identity="alice")


def test_personal_collection_exact_name_does_not_match_a_prefix_neighbour():
    # The same trap the `.*` pattern has: `personal.alice2` must not be read as
    # covered by alice's exact-name grant.
    assert not can_perform_action([], "personal.alice2", "READ", identity="alice")


def test_anonymous_holds_no_personal_collection():
    assert not can_perform_action([], "personal.alice", "READ", identity=None)


def test_personal_collection_grant_does_not_reach_the_personal_workspace():
    # Stripped of a trailing `.*` the exact-name pattern reduces to itself, so
    # it cannot clear a whole-workspace check on `personal` -- which would hand
    # every identity authority over everyone else's namespace.
    grants = implicit_grants("alice")
    assert not can_perform_workspace_action(grants, "personal", "ALTER")
    assert not can_perform_workspace_action(grants, "personal", "DROP")


def test_personal_collection_pattern_is_glob_escaped():
    # As with the `.*` pattern, metacharacters in an identity must not widen
    # the collection the caller owns.
    assert not can_perform_action([], "personal.alice", "READ", identity="*")
    assert not can_perform_action([], "personal.alice", "READ", identity="?????")
    assert not can_perform_action([], "personal.alice", "READ", identity="[a-z]*")


def test_engine_private_personal_collection_is_still_refused():
    # The `$` deny runs before implicit grants, and the new exact-name pattern
    # is decided in that same pass.
    assert not can_perform_action([], "personal.$system", "READ", identity="$system")


def test_implicit_public_is_read_only_regardless_of_issued_policy():
    # public.* is capped read-only by the implicit grant even if an issued
    # policy claims otherwise -- implicit grants short-circuit and never fall
    # through to `grants`.
    grants = [Grant(role="owner", pattern="public.*")]
    assert can_perform_action(grants, "public.security", "READ")
    assert not can_perform_action(grants, "public.security", "DELETE")


def test_platform_identities_may_write_public():
    # The platform's own automation loads and compacts what is in `public`;
    # `public` is reserved, so this access cannot be issued as a policy and is
    # declared as an implicit grant instead.
    for identity in PLATFORM_IDENTITIES:
        assert can_perform_action([], "public.security.cves", "READ", identity=identity)
        assert can_perform_action([], "public.security.cves", "WRITE", identity=identity)
        assert can_perform_action([], "public.gdelt.events", "CREATE", identity=identity)


def test_platform_identities_do_not_own_public():
    # Writer, not owner: loading and compacting is theirs, dropping a public
    # dataset or granting anyone access to one is not.
    assert not can_perform_action([], "public.security.cves", "DROP", identity="federator")
    assert not can_perform_action([], "public.security.cves", "GRANT", identity="federator")
    assert not can_perform_action([], "public.security.cves", "ALTER", identity="federator")


def test_platform_write_precedes_the_public_reader_cap():
    # `can_perform_action` answers from the first matching implicit grant, so
    # the writer grant is worthless unless it is ordered ahead of the reader
    # one covering the same pattern.
    grants = implicit_grants("federator")
    public = [g.role for g in grants if g.pattern == "public.*"]
    assert public == ["writer", "reader"]


def test_platform_identity_match_is_case_insensitive():
    # Identities are casefolded everywhere else; a token minted with `XB500`
    # must not silently drop to reader.
    assert can_perform_action([], "public.gdelt.events", "WRITE", identity="XB500")


def test_platform_identities_get_no_wider_than_public():
    # The exception is scoped to the workspace it exists for. Everywhere else a
    # platform identity holds exactly what it was granted, like anyone else.
    assert not can_perform_action([], "analytics.sales.q1", "WRITE", identity="federator")


def test_ordinary_identity_still_capped_read_only_on_public():
    assert not can_perform_action(
        [Grant(role="owner", pattern="public.*")], "public.security", "WRITE", identity="alice"
    )


def test_anonymous_has_no_personal_namespace():
    grants = implicit_grants(None)
    assert all(not g.pattern.startswith("personal.") for g in grants)
    assert [g.role for g in grants if g.pattern == "public.*"] == ["reader"]


def test_can_perform_workspace_action_requires_whole_workspace_coverage():
    grants = [Grant(role="owner", pattern="analytics.*")]
    assert can_perform_workspace_action(grants, "analytics", "ALTER")

    narrower = [Grant(role="owner", pattern="analytics.sales.*")]
    assert not can_perform_workspace_action(narrower, "analytics", "ALTER")


def test_can_perform_workspace_action_filters_by_role_not_just_coverage():
    # Coverage of the whole workspace is necessary but not sufficient -- the
    # role held still has to be allowed to perform the action (ALTER is
    # owner-only; a reader covering the whole workspace must not clear it).
    grants = [Grant(role="reader", pattern="analytics.*")]
    assert not can_perform_workspace_action(grants, "analytics", "ALTER")


def test_can_perform_workspace_action_bare_pattern_matches_bare_workspace():
    grants = [Grant(role="owner", pattern="analytics")]
    assert can_perform_workspace_action(grants, "analytics", "ALTER")


def test_can_administer_pattern_empty_pattern_denied():
    policies = [Policy(principal="alice", role="owner", pattern="analytics.*")]
    assert not can_administer_pattern(policies, "alice", "")


def test_can_administer_pattern_no_policies_denied():
    assert not can_administer_pattern([], "alice", "analytics.*")


def test_has_workspace_access_owner_grants_access():
    policies = [Policy(principal="alice", role="owner", pattern="analytics.*")]
    assert has_workspace_access(policies, "alice")


def test_has_workspace_access_no_matching_policy_denied():
    policies = [Policy(principal="bob", role="owner", pattern="analytics.*")]
    assert not has_workspace_access(policies, "alice")
    assert not has_workspace_access([], "alice")


def test_has_workspace_access_writer_is_insufficient():
    policies = [Policy(principal="alice", role="writer", pattern="analytics.*")]
    assert not has_workspace_access(policies, "alice")


def test_can_administer_pattern_requires_coverage_not_just_workspace_presence():
    policies = [Policy(principal="alice", role="owner", pattern="billing.*")]
    assert can_administer_pattern(policies, "alice", "billing.invoices.*")
    assert not can_administer_pattern(policies, "alice", "ops.servers.*")


def test_can_administer_pattern_writer_is_insufficient():
    policies = [Policy(principal="alice", role="writer", pattern="analytics.*")]
    assert not can_administer_pattern(policies, "alice", "analytics.sales.*")


def test_a_policy_only_applies_to_the_principal_it_names():
    policies = [Policy(principal="alice", role="owner", pattern="analytics.*")]
    assert can_administer_pattern(policies, "alice", "analytics.sales.q1")
    assert not can_administer_pattern(policies, "bob", "analytics.sales.q1")
    # Including "*", which is no longer a principal that means anyone.
    assert not can_administer_pattern(
        [Policy(principal="*", role="owner", pattern="analytics.*")],
        "anyone",
        "analytics.sales.q1",
    )


# --- engine-private storage is denied, not merely ungranted ------------------


def test_engine_private_storage_is_denied_to_a_workspace_owner():
    """A covering grant is the whole point of this check.

    `validate_pattern` refuses to issue a policy naming `$system`, but nobody
    would need one: `analytics.*` matches `analytics.$system.relationships`
    already. Without the deny, every workspace owner reads the relationship
    store.
    """
    grants = [Grant(role="owner", pattern="analytics.*")]
    assert can_perform_action(grants, "analytics.sales.q1", "READ")
    for action in ("READ", "WRITE", "ALTER", "DROP", "CREATE", "GRANT"):
        assert not can_perform_action(grants, "analytics.$system.relationships", action)


def test_engine_private_storage_is_denied_inside_a_personal_namespace():
    """Implicit grants are checked before issued ones, so the deny precedes both."""
    assert not can_perform_action(
        [], "personal.alice.$system.relationships", "READ", identity="alice"
    )


def test_engine_private_storage_is_denied_to_platform_identities():
    assert not can_perform_action([], "public.$system.relationships", "READ", identity="xb500")


def test_engine_private_storage_cannot_be_administered():
    policies = [Policy(principal="alice", role="owner", pattern="analytics.*")]
    assert not can_administer_pattern(policies, "alice", "analytics.$system.relationships")


def test_dollar_prefixed_local_relations_are_unaffected():
    """`$planets`, `$grants` and friends carry no dot and are session-local
    reads, decided before the deny is reached."""
    assert can_perform_action([], "$planets", "READ")
    assert not can_perform_action([], "$planets", "WRITE")
