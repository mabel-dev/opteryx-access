"""A minimal in-memory double for the slice of the `google.cloud.firestore`
client surface `FirestorePolicyStore` actually calls.

Not a general Firestore emulator -- just enough of `.collection()`,
`.document()`, `.get()`, `.set()`, `.update()`, `.delete()`, and `.stream()`
to exercise the adapter without the real dependency installed.
"""


class _FakeSnapshot:
    def __init__(self, doc_id, data):
        self.id = doc_id
        self._data = data

    @property
    def exists(self):
        return self._data is not None

    def to_dict(self):
        return dict(self._data) if self._data is not None else None


class _FakeDocument:
    def __init__(self, store, doc_id):
        self._store = store
        self._id = doc_id

    def collection(self, name):
        return self._store._subcollection(self._id, name)

    def get(self):
        return _FakeSnapshot(self._id, self._store._docs.get(self._id))

    def set(self, data):
        self._store._docs[self._id] = dict(data)

    def update(self, data):
        if self._id not in self._store._docs:
            raise KeyError(f"no such document: {self._id}")
        self._store._docs[self._id].update(data)

    def delete(self):
        self._store._docs.pop(self._id, None)


class _FakeCollection:
    def __init__(self):
        self._docs = {}
        self._subcollections = {}

    def document(self, doc_id):
        return _FakeDocument(self, doc_id)

    def _subcollection(self, doc_id, name):
        key = (doc_id, name)
        if key not in self._subcollections:
            self._subcollections[key] = _FakeCollection()
        return self._subcollections[key]

    def stream(self):
        return [_FakeSnapshot(doc_id, data) for doc_id, data in self._docs.items()]


class FakeFirestoreClient:
    """Stands in for `google.cloud.firestore.Client` -- top-level `.collection(name)`
    calls each get their own independent `_FakeCollection`, matching how
    `FirestorePolicyStore._collection` addresses `{workspace}/$policies/access`."""

    def __init__(self):
        self._collections = {}

    def collection(self, name):
        if name not in self._collections:
            self._collections[name] = _FakeCollection()
        return self._collections[name]
