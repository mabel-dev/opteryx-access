import pytest

from opteryx_access.exceptions import InvalidPatternError
from opteryx_access.patterns import escape_glob
from opteryx_access.patterns import is_literal_segment
from opteryx_access.patterns import normalize
from opteryx_access.patterns import pattern_segments
from opteryx_access.patterns import resource_matches
from opteryx_access.patterns import validate_pattern
from opteryx_access.patterns import validate_principal

# --- matching ---------------------------------------------------------------


def test_resource_matches_exact():
    assert resource_matches("analytics.sales.q1", "analytics.sales.q1")
    assert not resource_matches("analytics.sales.q2", "analytics.sales.q1")


def test_resource_matches_wildcard_segment():
    assert resource_matches("analytics.sales.q1", "analytics.*")
    assert not resource_matches("billing.sales.q1", "analytics.*")


def test_resource_matches_is_case_insensitive_both_ways():
    assert resource_matches("Analytics.Sales.Q1", "analytics.*")
    assert resource_matches("analytics.stuff.here", "Analytics.*")
    assert resource_matches("ANALYTICS.SALES.Q1", "analytics.sales.q1")


def test_resource_matches_ignores_surrounding_whitespace():
    assert resource_matches("  analytics.sales.q1  ", "analytics.*")


# --- principals -------------------------------------------------------------


def test_validate_principal_accepts_a_named_individual():
    assert validate_principal("alice@example.com") == "alice@example.com"
    assert validate_principal("  alice  ") == "alice"


def test_validate_principal_rejects_the_wildcard():
    # Policies are issued to named individuals; groups will be their own
    # concept rather than a pattern smuggled into this field.
    with pytest.raises(InvalidPatternError):
        validate_principal("*")


@pytest.mark.parametrize("principal", ["al*ce", "alic?", "alice[1]", "", "   "])
def test_validate_principal_rejects_anything_matching_more_than_one(principal):
    with pytest.raises(InvalidPatternError):
        validate_principal(principal)


# --- patterns ---------------------------------------------------------------


def test_validate_pattern_normalizes():
    assert validate_pattern("  Analytics.Sales.*  ") == "analytics.sales.*"


@pytest.mark.parametrize(
    "pattern",
    ["analytics", "analytics.*", "analytics.sales.*", "analytics.*.q1", "a1.b_2.c3"],
)
def test_validate_pattern_accepts_usable_patterns(pattern):
    assert validate_pattern(pattern) == pattern


def test_validate_pattern_requires_a_named_workspace():
    # A policy always says which workspace it applies to -- there is no grant
    # over everything.
    with pytest.raises(InvalidPatternError):
        validate_pattern("*")
    with pytest.raises(InvalidPatternError):
        validate_pattern("*.sales.q1")


@pytest.mark.parametrize(
    "pattern",
    [
        "",
        "   ",
        "a....*.bob11",  # empty segments
        "analytics..sales",
        ".analytics",
        "analytics.",
        "1analytics.sales",  # must start with a letter
        "analytics.2sales",
        "analytics.sa les",  # no spaces
        "analytics.sa-les",  # no punctuation beyond . and _
        "analytics.sales!",
        "pub*.security",  # partial globs are not patterns we issue
        "analytics.sale?",
        "analytics.[abc]",
    ],
)
def test_validate_pattern_rejects_unusable_patterns(pattern):
    with pytest.raises(InvalidPatternError):
        validate_pattern(pattern)


@pytest.mark.parametrize("pattern", ["public.security", "personal.alice.*", "Public.security"])
def test_validate_pattern_rejects_reserved_workspaces(pattern):
    with pytest.raises(InvalidPatternError):
        validate_pattern(pattern)


def test_validate_pattern_rejects_information_schema():
    with pytest.raises(InvalidPatternError):
        validate_pattern("analytics.information_schema.*")


# --- helpers ----------------------------------------------------------------


def test_normalize():
    assert normalize("  Analytics.Sales  ") == "analytics.sales"


def test_escape_glob_makes_metacharacters_literal():
    assert resource_matches("a*b", escape_glob("a*b"))
    assert not resource_matches("axb", escape_glob("a*b"))
    assert resource_matches("a[b", escape_glob("a[b"))
    assert not resource_matches("ab", escape_glob("a?b"))


def test_pattern_segments():
    assert pattern_segments("analytics.sales.q1") == ("analytics", "sales", "q1")
    assert pattern_segments("analytics.*") == ("analytics", "*", None)
    assert pattern_segments("analytics") == ("analytics", None, None)


def test_is_literal_segment():
    assert is_literal_segment("sales")
    assert not is_literal_segment("*")
    assert not is_literal_segment(None)
    assert not is_literal_segment("")


# --- what a `*` actually covers
#
# The shape rule (a segment is `*` or a literal name) and the matching rule are
# different things, and conflating them understates a grant: `*` matches across
# dots, so a pattern is a subtree, not a level.


def test_a_wildcard_covers_every_level_below_it_not_just_one():
    assert resource_matches("analytics.sales", "analytics.*")
    assert resource_matches("analytics.sales.q1", "analytics.*")
    assert resource_matches("analytics.sales.q1.part", "analytics.*")


def test_a_wildcard_does_not_escape_the_workspace_it_names():
    assert not resource_matches("billing.sales.q1", "analytics.*")
    assert not resource_matches("analytics2.sales", "analytics.*")


def test_a_trailing_wildcard_does_not_match_the_bare_workspace():
    # `analytics.*` covers what is IN analytics; the workspace itself is a
    # workspace-level question -- see checks.can_perform_workspace_action.
    assert not resource_matches("analytics", "analytics.*")


def test_a_mid_pattern_wildcard_also_crosses_dots():
    assert resource_matches("analytics.sales.q1", "analytics.*.q1")
    assert resource_matches("analytics.a.b.q1", "analytics.*.q1")


def test_a_fully_literal_pattern_matches_only_itself():
    assert resource_matches("analytics.sales.q1", "analytics.sales.q1")
    assert not resource_matches("analytics.sales.q1x", "analytics.sales.q1")
    assert not resource_matches("analytics.sales", "analytics.sales.q1")
