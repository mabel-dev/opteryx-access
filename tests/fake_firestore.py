"""A minimal in-memory double for the slice of the `google.cloud.firestore`
client surface `FirestorePolicyStore` actually calls.

Not a general Firestore emulator -- just enough of `.collection()`,
`.collection_group()`, `.document()`, `.get()`, `.set()`, `.update()`,
`.delete()`, `.where()`, `.limit()`, and `.stream()` to exercise the adapter
without the real dependency installed.

Documents carry a `.reference.path` because the adapter derives a policy's
workspace from it on collection-group reads.
"""


class _FakeReference:
    def __init__(self, path):
        self.path = path


class _FakeSnapshot:
    def __init__(self, doc_id, data, path=None):
        self.id = doc_id
        self._data = data
        self.reference = _FakeReference(path or doc_id)

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
        return _FakeSnapshot(self._id, self._store._docs.get(self._id), self._store._path(self._id))

    def set(self, data):
        self._store._docs[self._id] = dict(data)

    def update(self, data):
        if self._id not in self._store._docs:
            raise KeyError(f"no such document: {self._id}")
        self._store._docs[self._id].update(data)

    def delete(self):
        self._store._docs.pop(self._id, None)


class _FakeQuery:
    """The result of `.where(...)` / `.limit(...)` -- only `.stream()` is called on it."""

    def __init__(self, snapshots):
        self._snapshots = list(snapshots)

    def stream(self):
        return list(self._snapshots)


class _FakeCollection:
    def __init__(self, name="", parent_path="", registry=None):
        self._docs = {}
        self._subcollections = {}
        self._name = name
        self._parent_path = parent_path
        # Shared across the whole client so `collection_group` can find every
        # collection of a given name without walking the tree.
        self._registry = registry if registry is not None else {}
        self._registry.setdefault(name, []).append(self)

    def _path(self, doc_id):
        base = f"{self._parent_path}/{self._name}".strip("/")
        return f"{base}/{doc_id}"

    def document(self, doc_id):
        return _FakeDocument(self, doc_id)

    def _subcollection(self, doc_id, name):
        key = (doc_id, name)
        if key not in self._subcollections:
            self._subcollections[key] = _FakeCollection(
                name=name, parent_path=self._path(doc_id), registry=self._registry
            )
        return self._subcollections[key]

    def stream(self):
        return [
            _FakeSnapshot(doc_id, data, self._path(doc_id)) for doc_id, data in self._docs.items()
        ]

    def limit(self, count):
        return _FakeQuery(self.stream()[:count])

    def where(self, filter=None):
        """Apply a real `FieldFilter`, so the adapter's query is exercised as
        written rather than against a signature invented here."""
        return _FakeQuery(_apply(filter, self.stream()))


def _apply(field_filter, snapshots):
    if field_filter is None or field_filter.op_string != "==":
        raise NotImplementedError(f"fake supports only '==' filters, got {field_filter!r}")
    return [
        snapshot
        for snapshot in snapshots
        if (snapshot.to_dict() or {}).get(field_filter.field_path) == field_filter.value
    ]


class _FakeCollectionGroup:
    def __init__(self, collections):
        self._collections = collections

    def _stream(self):
        for collection in self._collections:
            yield from collection.stream()

    def where(self, filter=None):
        return _FakeQuery(_apply(filter, self._stream()))


class FakeFirestoreClient:
    """Stands in for `google.cloud.firestore.Client`."""

    def __init__(self):
        self._collections = {}
        self._registry = {}

    def collection(self, name):
        if name not in self._collections:
            self._collections[name] = _FakeCollection(name=name, registry=self._registry)
        return self._collections[name]

    def collection_group(self, name):
        return _FakeCollectionGroup(self._registry.get(name, []))
