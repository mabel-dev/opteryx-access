"""Every material change emits exactly one structured record, after it lands.

The point of these is that the record is machine-readable and complete: a
change that happens without a record, or a record whose fields drifted, is
invisible to whatever is monitoring policy changes.
"""

import json
import logging

import pytest
from fakes import FakePolicyStore

from opteryx_access.audit import AUDIT_LOGGER_NAME
from opteryx_access.audit import set_audit_sink
from opteryx_access.exceptions import AccessDeniedError
from opteryx_access.exceptions import SelfAccessError
from opteryx_access.grants import bootstrap_workspace
from opteryx_access.grants import grant
from opteryx_access.grants import revoke
from opteryx_access.grants import update_grant
from opteryx_access.models import Policy


@pytest.fixture
def audit(caplog):
    """The audit payloads emitted during a test, in order."""
    caplog.set_level(logging.INFO, logger=AUDIT_LOGGER_NAME)

    class _Captured:
        @property
        def payloads(self):
            return [
                record.json_fields
                for record in caplog.records
                if record.name == AUDIT_LOGGER_NAME and hasattr(record, "json_fields")
            ]

        @property
        def messages(self):
            return [
                record.getMessage() for record in caplog.records if record.name == AUDIT_LOGGER_NAME
            ]

    return _Captured()


@pytest.fixture(autouse=True)
def _no_leaked_sink():
    yield
    set_audit_sink(None)


def _owner_store():
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="alice", role="owner", pattern="analytics.*"))
    return store


def test_grant_records_the_change(audit):
    store = _owner_store()
    policy_id = grant(
        store,
        actor="alice",
        workspace="analytics",
        principal="bob",
        role="writer",
        pattern="analytics.sales.*",
    )

    [payload] = audit.payloads
    assert payload["event"] == "policy.created"
    assert payload["actor"] == "alice"
    assert payload["workspace"] == "analytics"
    assert payload["policy_id"] == policy_id
    assert payload["principal"] == "bob"
    assert payload["role"] == "writer"
    assert payload["pattern"] == "analytics.sales.*"
    assert payload["timestamp"].endswith("+00:00")
    # Nothing was replaced, so there is no previous state to report.
    assert "previous_role" not in payload
    assert "previous_pattern" not in payload


def test_update_records_both_the_new_and_previous_state(audit):
    store = _owner_store()
    policy_id = store.seed(
        "analytics", Policy(principal="bob", role="reader", pattern="analytics.sales.*")
    )
    update_grant(
        store,
        actor="alice",
        workspace="analytics",
        policy_id=policy_id,
        role="writer",
        pattern="analytics.sales.q1",
    )

    [payload] = audit.payloads
    assert payload["event"] == "policy.updated"
    assert payload["principal"] == "bob"
    assert (payload["role"], payload["pattern"]) == ("writer", "analytics.sales.q1")
    assert (payload["previous_role"], payload["previous_pattern"]) == (
        "reader",
        "analytics.sales.*",
    )


def test_revoke_records_what_was_removed(audit):
    store = _owner_store()
    policy_id = store.seed(
        "analytics", Policy(principal="bob", role="writer", pattern="analytics.sales.*")
    )
    revoke(store, actor="alice", workspace="analytics", policy_id=policy_id)

    [payload] = audit.payloads
    assert payload["event"] == "policy.deleted"
    assert payload["principal"] == "bob"
    assert (payload["previous_role"], payload["previous_pattern"]) == (
        "writer",
        "analytics.sales.*",
    )
    # The policy is gone, so there is no current role/pattern to report.
    assert "role" not in payload
    assert "pattern" not in payload


def test_bootstrap_records_one_change_per_policy_and_marks_them(audit):
    store = FakePolicyStore()
    bootstrap_workspace(
        store,
        actor="alice",
        workspace="newspace",
        grants=[("alice", "owner"), ("bob", "writer")],
    )

    payloads = audit.payloads
    assert len(payloads) == 2
    assert {p["principal"] for p in payloads} == {"alice", "bob"}
    assert all(p["event"] == "policy.created" for p in payloads)
    # Genesis grants clear none of the usual authority checks, so they are
    # distinguishable from an ordinary grant in the record.
    assert all(p["bootstrap"] is True for p in payloads)


def test_an_ordinary_grant_is_not_marked_as_bootstrap(audit):
    store = _owner_store()
    grant(
        store,
        actor="alice",
        workspace="analytics",
        principal="bob",
        role="writer",
        pattern="analytics.sales.*",
    )
    assert "bootstrap" not in audit.payloads[0]


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"principal": "alice", "role": "writer"}, SelfAccessError),
        ({"principal": "bob", "role": "reader"}, AccessDeniedError),
    ],
)
def test_a_refused_change_records_nothing(audit, kwargs, expected):
    # Only changes that actually happened are recorded -- a record of a grant
    # that was refused would be worse than no record at all.
    store = FakePolicyStore()
    store.seed("analytics", Policy(principal="alice", role="owner", pattern="billing.*"))
    with pytest.raises(expected):
        grant(
            store,
            actor="alice",
            workspace="analytics",
            pattern="analytics.sales.*",
            **kwargs,
        )
    assert audit.payloads == []


def test_the_record_is_also_parseable_json_on_the_message(audit):
    # Cloud Run promotes a JSON stdout line into jsonPayload by itself, so the
    # message has to carry the same content for a service that just prints.
    store = _owner_store()
    grant(
        store,
        actor="alice",
        workspace="analytics",
        principal="bob",
        role="writer",
        pattern="analytics.sales.*",
    )
    [message] = audit.messages
    assert json.loads(message) == audit.payloads[0]
    assert "\n" not in message


def test_recorded_values_are_the_normalized_ones(audit):
    # What is recorded must be what was stored, or the trail disagrees with
    # the policy it is describing.
    store = _owner_store()
    grant(
        store,
        actor="Alice",
        workspace="analytics",
        principal="XB500",
        role="writer",
        pattern="Analytics.Sales.*",
    )
    [payload] = audit.payloads
    assert payload["actor"] == "alice"
    assert payload["principal"] == "xb500"
    assert payload["pattern"] == "analytics.sales.*"


def test_a_sink_receives_the_payload(audit):
    received = []
    set_audit_sink(received.append)

    store = _owner_store()
    grant(
        store,
        actor="alice",
        workspace="analytics",
        principal="bob",
        role="writer",
        pattern="analytics.sales.*",
    )

    assert len(received) == 1
    assert received[0]["event"] == "policy.created"
    assert received[0] == audit.payloads[0]


def test_a_broken_sink_does_not_undo_or_fail_the_change(audit):
    def exploding_sink(payload):
        raise RuntimeError("sink is misconfigured")

    set_audit_sink(exploding_sink)

    store = _owner_store()
    policy_id = grant(
        store,
        actor="alice",
        workspace="analytics",
        principal="bob",
        role="writer",
        pattern="analytics.sales.*",
    )

    # The change stands -- it was already written when the sink ran.
    assert store.get_policy("analytics", policy_id) is not None
    # And the broken sink is itself reported rather than swallowed silently.
    assert any("audit sink raised" in message for message in audit.messages)


def test_removing_the_sink_stops_delivery(audit):
    received = []
    set_audit_sink(received.append)
    set_audit_sink(None)

    store = _owner_store()
    grant(
        store,
        actor="alice",
        workspace="analytics",
        principal="bob",
        role="writer",
        pattern="analytics.sales.*",
    )
    assert received == []
    assert len(audit.payloads) == 1
