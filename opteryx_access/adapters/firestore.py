"""A `PolicyStore` backed by Firestore, matching the layout policy.opteryx and
control.opteryx already use: one document per grant, at
`{workspace}/$policies/access/{policy_id}`, with a random hex id (the
identity lives in the `principal` field, not the document id, since a policy
document must be queryable by principal).

The `access` collection name is shared by every workspace, which is what makes
`list_owner_policies` possible as a single collection-group query rather than
a scan of every workspace in turn.

This module never imports `google.cloud.firestore` itself -- `FirestorePolicyStore`
only calls `.collection()`/`.document()`/`.get()`/`.set()`/`.update()`/`.delete()`/
`.stream()` on whatever `db` object it's given, so it works against a real
`firestore.Client` or any test double with the same shape. Install the
`opteryx-access[firestore]` extra to get the real client; nothing in this
package requires it to be present.
"""

import datetime
import uuid

from opteryx_access.actions import action_allowed_for_role
from opteryx_access.models import Policy


class FirestorePolicyStore:
    """`PolicyStore` implementation over a `google.cloud.firestore.Client`."""

    def __init__(self, db) -> None:
        self._db = db

    def _collection(self, workspace: str):
        return self._db.collection(workspace).document("$policies").collection("access")

    def list_policies(self, workspace: str) -> list[Policy]:
        return [
            self._to_policy(doc.id, doc.to_dict() or {}, workspace)
            for doc in self._collection(workspace).stream()
        ]

    def list_policies_for_principal(self, workspace: str, principal: str) -> list[Policy]:
        # Filtered server-side: the identity lives in the `principal` field
        # rather than the document id, so this is a field query, not a lookup.
        # `principal` is single-field, which Firestore indexes automatically --
        # no composite index needed.
        #
        # `FieldFilter` is imported here rather than at module level to keep
        # importing this module free of the google-cloud-firestore dependency
        # (see the module docstring); by the time a query runs, the caller has
        # necessarily supplied a real client.
        from google.cloud.firestore_v1.base_query import FieldFilter

        query = self._collection(workspace).where(filter=FieldFilter("principal", "==", principal))
        return [self._to_policy(doc.id, doc.to_dict() or {}, workspace) for doc in query.stream()]

    def list_owner_policies(self, principal: str) -> list[Policy]:
        # A collection-group query: every `access` collection in the database
        # at once, which is what makes this cross-workspace without walking
        # workspaces one at a time.
        #
        # Only `principal` is filtered server-side; the role is matched in
        # Python. Stacking a second equality filter would make this a
        # composite query, which Firestore rejects with FAILED_PRECONDITION
        # unless a matching composite index exists -- odata.opteryx avoids
        # this the same way (see its `_query_collection_group`). A
        # collection-group index on `principal` is still required; Firestore's
        # error names the exact index to create if it is missing.
        from google.cloud.firestore_v1.base_query import FieldFilter

        query = self._db.collection_group("access").where(
            filter=FieldFilter("principal", "==", principal)
        )

        owned = []
        for doc in query.stream():
            data = doc.to_dict() or {}
            if not action_allowed_for_role(data.get("role", ""), "GRANT"):
                continue
            owned.append(self._to_policy(doc.id, data, self._workspace_of(doc)))
        return owned

    @staticmethod
    def _workspace_of(doc) -> str | None:
        """The workspace a collection-group hit came from.

        The path is `{workspace}/$policies/access/{policy_id}`, so the
        workspace is its first segment -- there is nowhere else to read it
        from, since the document itself does not repeat it.
        """
        path = getattr(getattr(doc, "reference", None), "path", "") or ""
        segments = path.strip("/").split("/")
        return segments[0] if segments and segments[0] else None

    def has_any_policies(self, workspace: str) -> bool:
        # One row, not the workspace: this gates bootstrap, where the expected
        # answer is "no" and reading the whole collection to learn it would be
        # the most wasteful possible way to ask.
        return next(iter(self._collection(workspace).limit(1).stream()), None) is not None

    def get_policy(self, workspace: str, policy_id: str) -> Policy | None:
        doc = self._collection(workspace).document(policy_id).get()
        if not doc.exists:
            return None
        return self._to_policy(doc.id, doc.to_dict() or {}, workspace)

    def create_policy(self, workspace: str, policy: Policy) -> str:
        policy_id = uuid.uuid4().hex
        now = datetime.datetime.now(datetime.UTC)
        self._collection(workspace).document(policy_id).set(
            {
                "principal": policy.principal,
                "role": policy.role,
                "pattern": policy.pattern,
                "created_at": now,
                "updated_at": now,
                "updated_by": policy.updated_by,
            }
        )
        return policy_id

    def update_policy(
        self, workspace: str, policy_id: str, *, role: str, pattern: str, updated_by: str
    ) -> None:
        self._collection(workspace).document(policy_id).update(
            {
                "role": role,
                "pattern": pattern,
                "updated_at": datetime.datetime.now(datetime.UTC),
                "updated_by": updated_by,
            }
        )

    def delete_policy(self, workspace: str, policy_id: str) -> None:
        self._collection(workspace).document(policy_id).delete()

    @staticmethod
    def _to_policy(policy_id: str, data: dict, workspace: str | None = None) -> Policy:
        return Policy(
            principal=data.get("principal", policy_id),
            role=data.get("role", "reader"),
            pattern=data.get("pattern", ""),
            policy_id=policy_id,
            workspace=workspace,
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            updated_by=data.get("updated_by"),
        )
