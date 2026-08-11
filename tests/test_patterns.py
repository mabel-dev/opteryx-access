import pytest

from opteryx_access.exceptions import InvalidPatternError
from opteryx_access.patterns import is_literal_segment
from opteryx_access.patterns import pattern_segments
from opteryx_access.patterns import resource_matches
from opteryx_access.patterns import validate_pattern_does_not_target_reserved_resource
from opteryx_access.patterns import validate_wildcard_rule


def test_resource_matches_is_case_sensitive():
    assert resource_matches("analytics.sales.q1", "analytics.*")
    assert not resource_matches("Analytics.sales.q1", "analytics.*")


def test_resource_matches_exact():
    assert resource_matches("analytics.sales.q1", "analytics.sales.q1")
    assert not resource_matches("analytics.sales.q2", "analytics.sales.q1")


def test_wildcard_principal_requires_exact_pattern():
    validate_wildcard_rule("*", "analytics.sales.q1")  # no raise
    with pytest.raises(InvalidPatternError):
        validate_wildcard_rule("*", "analytics.*")
    with pytest.raises(InvalidPatternError):
        validate_wildcard_rule("*", "")


def test_non_wildcard_principal_may_use_glob_pattern():
    validate_wildcard_rule("alice", "analytics.*")  # no raise


def test_reserved_workspaces_rejected():
    with pytest.raises(InvalidPatternError):
        validate_pattern_does_not_target_reserved_resource("public.security")
    with pytest.raises(InvalidPatternError):
        validate_pattern_does_not_target_reserved_resource("personal.alice.*")


def test_reserved_workspace_rejected_even_via_glob():
    with pytest.raises(InvalidPatternError):
        validate_pattern_does_not_target_reserved_resource("*")
    with pytest.raises(InvalidPatternError):
        validate_pattern_does_not_target_reserved_resource("pub*.security")


def test_information_schema_rejected():
    with pytest.raises(InvalidPatternError):
        validate_pattern_does_not_target_reserved_resource("analytics.information_schema.*")


def test_ordinary_pattern_accepted():
    validate_pattern_does_not_target_reserved_resource("analytics.sales.*")  # no raise


def test_pattern_segments():
    assert pattern_segments("analytics.sales.q1") == ("analytics", "sales", "q1")
    assert pattern_segments("analytics.*") == ("analytics", "*", None)
    assert pattern_segments("analytics") == ("analytics", None, None)


def test_is_literal_segment():
    assert is_literal_segment("sales")
    assert not is_literal_segment("*")
    assert not is_literal_segment(None)
    assert not is_literal_segment("")
