from opteryx_access.models import Grant
from opteryx_access.models import Policy
from opteryx_access.models import parse_policy_claim


def test_parse_pair_shape():
    claims = {"policies": [["writer", "analytics.sales.*"], ["reader", "public.*"]]}
    assert parse_policy_claim(claims) == [
        Grant(role="writer", pattern="analytics.sales.*"),
        Grant(role="reader", pattern="public.*"),
    ]


def test_parse_tuple_shape():
    claims = {"policies": [("owner", "analytics.*")]}
    assert parse_policy_claim(claims) == [Grant(role="owner", pattern="analytics.*")]


def test_parse_dict_shape():
    claims = {"policies": [{"role": "writer", "pattern": "analytics.sales.*"}]}
    assert parse_policy_claim(claims) == [Grant(role="writer", pattern="analytics.sales.*")]


def test_parse_mixed_pair_and_dict_shapes():
    claims = {
        "policies": [
            ["writer", "analytics.sales.*"],
            {"role": "reader", "pattern": "public.*"},
        ]
    }
    assert parse_policy_claim(claims) == [
        Grant(role="writer", pattern="analytics.sales.*"),
        Grant(role="reader", pattern="public.*"),
    ]


def test_missing_policies_claim_returns_empty():
    assert parse_policy_claim({}) == []


def test_none_policies_claim_returns_empty():
    assert parse_policy_claim({"policies": None}) == []


def test_empty_policies_list_returns_empty():
    assert parse_policy_claim({"policies": []}) == []


def test_malformed_entries_are_skipped_not_raised():
    # A malformed or unexpected entry must not deny every other grant the
    # token carries by raising -- this is untrusted input off the wire.
    claims = {
        "policies": [
            ["writer", "analytics.sales.*"],  # valid
            "not-a-pair-or-dict",
            42,
            None,
            [],
            ["only-one-element"],
            ["too", "many", "elements"],
            {"role": "writer"},  # missing pattern
            {"pattern": "analytics.*"},  # missing role
            {"role": None, "pattern": "analytics.*"},
            [None, "analytics.*"],
            [123, "analytics.*"],
            ["writer", 123],
            ["", "analytics.*"],  # empty role
            ["writer", ""],  # empty pattern
        ]
    }
    assert parse_policy_claim(claims) == [Grant(role="writer", pattern="analytics.sales.*")]


def test_non_iterable_policies_claim_does_not_raise():
    assert parse_policy_claim({"policies": "not-a-list"}) == []


def test_grant_is_hashable_and_comparable():
    assert Grant(role="writer", pattern="a.*") == Grant(role="writer", pattern="a.*")
    assert len({Grant(role="writer", pattern="a.*"), Grant(role="writer", pattern="a.*")}) == 1


def test_policy_as_grant_drops_principal_and_metadata():
    policy = Policy(
        principal="bob",
        role="writer",
        pattern="analytics.sales.*",
        policy_id="abc123",
        updated_by="alice",
    )
    assert policy.as_grant() == Grant(role="writer", pattern="analytics.sales.*")
