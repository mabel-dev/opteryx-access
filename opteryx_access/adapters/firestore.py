"""A `PolicyStore` backed by Firestore, matching the layout policy.opteryx and
control.opteryx already use: one document per grant, at
`{workspace}/$policies/access/{policy_id}`, with a random hex id (the
identity lives in the `principal` field, not the document id, since a policy
document must be queryable by principal).

This module never imports `google.cloud.firestore` itself -- `FirestorePolicyStore`
only calls `.collection()`/`.document()`/`.get()`/`.set()`/`.update()`/`.delete()`/
`.stream()` on whatever `db` object it's given, so it works against a real
`firestore.Client` or any test double with the same shape. Install the
`opteryx-access[firestore]` extra to get the real client; nothing in this
package requires it to be present.
"""

import datetime
import uuid

from opteryx_access.models import Policy


class FirestorePolicyStore:
    """`PolicyStore` implementation over a `google.cloud.firestore.Client`."""

    def __init__(self, db) -> None:
        self._db = db

    def _collection(self, workspace: str):
        return self._db.collection(workspace).document("$policies").collection("access")

    def list_policies(self, workspace: str) -> list[Policy]:
        return [
            self._to_policy(doc.id, doc.to_dict() or {})
            for doc in self._collection(workspace).stream()
        ]

    def get_policy(self, workspace: str, policy_id: str) -> Policy | None:
        doc = self._collection(workspace).document(policy_id).get()
        if not doc.exists:
            return None
        return self._to_policy(doc.id, doc.to_dict() or {})

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
    def _to_policy(policy_id: str, data: dict) -> Policy:
        return Policy(
            principal=data.get("principal", policy_id),
            role=data.get("role", "reader"),
            pattern=data.get("pattern", ""),
            policy_id=policy_id,
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            updated_by=data.get("updated_by"),
        )
