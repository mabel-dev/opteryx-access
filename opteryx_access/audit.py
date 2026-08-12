"""Structured records of every change this package makes to a policy.

Granting, updating, and revoking access are the events an access-control
system has to be able to answer questions about after the fact -- who gave
whom what, when, and what it replaced. Every successful mutation in
`opteryx_access.grants` emits one record here, after the write has landed, so
nothing is reported that did not happen.

**Field names are a contract, not decoration.** They match what
policy.opteryx/control.opteryx already emit from their own
`_audit_policy_change`, which xb500.opteryx's log transforms parse into the
`opteryx.ops.policy_changes` dataset. A service that moves onto this package
therefore keeps producing records its existing consumer already understands,
with no transform to update:

    event             policy.created | policy.updated | policy.deleted
    actor             the identity that made the change
    workspace         the workspace the policy belongs to
    policy_id         the policy document
    principal         the identity the policy is about
    timestamp         ISO 8601, UTC
    role, pattern     what the policy grants now      (absent on delete)
    previous_role,    what it granted before          (update and delete only)
    previous_pattern
    bootstrap         true when the policy came from workspace genesis

Absent fields are omitted rather than emitted as null, matching the existing
producer.

**How it gets out.** Records go to the standard-library logger
``opteryx_access.audit`` at INFO. Being a library, this configures nothing --
no handlers, no formatters, no levels. A service that does not configure
logging for this logger will not see these records at all, which for an audit
trail is worth checking rather than assuming.

Each record is emitted two ways at once, so it survives whichever pipeline is
in front of it:

- as the log message, compact single-line JSON -- Cloud Run promotes a
  JSON-formatted stdout line into `jsonPayload` on its own, which is how these
  reach Cloud Logging from a service that just prints;
- via ``extra={"json_fields": ...}`` -- what google-cloud-logging's handlers
  read to build `jsonPayload` directly, and what a test or an in-process
  consumer can read off the `LogRecord` without parsing anything.

A service that would rather route these through its own audit channel (the
fleet's `logger.audit`, say) can call `set_audit_sink` and get the payload
dict handed to it directly.
"""

import datetime
import json
import logging
from collections.abc import Callable
from typing import Any

AUDIT_LOGGER_NAME = "opteryx_access.audit"

POLICY_CREATED = "policy.created"
POLICY_UPDATED = "policy.updated"
POLICY_DELETED = "policy.deleted"

_logger = logging.getLogger(AUDIT_LOGGER_NAME)

_sink: Callable[[dict[str, Any]], None] | None = None


def set_audit_sink(sink: Callable[[dict[str, Any]], None] | None) -> None:
    """Route audit payloads to `sink` as well as to the logger.

    For a service that already has an audit channel and would rather not go
    through `logging` formatting to get the same dict back. Pass None to
    remove it.

    The sink is called with the payload dict, after the change has been
    written. It runs in the caller's thread, so it should be cheap; a slow
    sink slows down every grant.
    """
    global _sink
    _sink = sink


def _emit(payload: dict[str, Any]) -> None:
    _logger.info(
        json.dumps(payload, sort_keys=True, default=str),
        extra={"json_fields": payload},
    )

    if _sink is None:
        return
    try:
        _sink(payload)
    except Exception:
        # A sink that raises must not turn a change that already succeeded
        # into a failed call: the policy has been written by the time we get
        # here, so propagating would report a failure that did not happen and
        # leave the caller's state wrong in the other direction. Report the
        # broken sink and carry on.
        _logger.exception("audit sink raised; the change itself was applied")


def record_change(
    event: str,
    *,
    actor: str,
    workspace: str,
    policy_id: str,
    principal: str,
    role: str | None = None,
    pattern: str | None = None,
    previous_role: str | None = None,
    previous_pattern: str | None = None,
    bootstrap: bool = False,
) -> None:
    """Record one policy change. Call only after the change has been written."""
    payload: dict[str, Any] = {
        "event": event,
        "actor": actor,
        "workspace": workspace,
        "policy_id": policy_id,
        "principal": principal,
        "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
    }
    if role is not None:
        payload["role"] = role
    if pattern is not None:
        payload["pattern"] = pattern
    if previous_role is not None:
        payload["previous_role"] = previous_role
    if previous_pattern is not None:
        payload["previous_pattern"] = previous_pattern
    if bootstrap:
        payload["bootstrap"] = True

    _emit(payload)
