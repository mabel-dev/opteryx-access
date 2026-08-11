# opteryx-access

Permission checks and grant/revoke for the Opteryx platform, as an installable
library rather than a service. Every consumer imports `opteryx_access` and
calls it in-process against policies it already has in hand -- a JWT's
`policies` claim, or a `PolicyStore` backed by whatever it uses for storage
(Firestore, today). There is no `opteryx-access` HTTP surface, and this
package makes no network calls of its own beyond what a storage adapter does.

## Why this exists

Three independent, subtly incompatible implementations of "does this role
satisfy this requirement" already exist in the fleet:

- **policy.opteryx** / **control.opteryx** (`app/routes/v1/access.py`,
  `app/models/policy.py` -- byte-for-byte duplicated between the two repos):
  a rank-based `ROLES = ("owner", "admin", "writer", "reader")` used to
  decide who may create/update/revoke a policy, and whether a new grant is
  redundant against one the principal already holds.
- **opteryx-core** (`opteryx/managers/permissions/__init__.py`): a
  set-based `ACTION_MAP` deciding which roles may `READ`/`DELETE`/`DROP`/etc.
  a resource once a query actually runs. `admin` is deliberately absent from
  every entry -- it never grants data access, only grant-management
  authority. This is the piece the rank-based model above cannot replace: a
  naive `owner > admin > writer > reader` comparison would silently hand
  admins data-write access they've never had.
- **odata.opteryx** (`app/auth/permissions.py`): a binary
  `role_allows_read` used for listing/visibility, plus its own
  `fnmatch.fnmatchcase`-based pattern matcher -- deliberately case-sensitive,
  unlike the plain `fnmatch.fnmatch` used elsewhere, which folds case per-OS.

On top of that, `policy.opteryx`/`control.opteryx`/`odata.opteryx`/
`register.opteryx` each carry their own copy of "parse the `policies` claim
out of a decoded JWT." Comments in several of these point at an
`authorize.opteryx` service (`app.routes.v1.evaluate`) as the semantics every
copy is meant to mirror -- but no such repo exists anywhere in this
workspace. Whether it's a real service in another org/remote or was never
built, every consumer today reimplements its own understanding of "role +
pattern -> allowed" independently, which is exactly the drift this package
is meant to stop.

## What lives here

| Module | Ported from | Purpose |
|---|---|---|
| `roles.py` | `policy.opteryx/app/models/policy.py` | The canonical `ROLES` tuple. Two separate notions of "outranks": `ADMINISTRATIVE_ROLES` (owner/admin -- may manage grants) and rank (`ROLE_RANK`, used only for conflict detection). **Not** used to decide data actions. |
| `actions.py` | `opteryx-core/opteryx/managers/permissions/__init__.py` | `ACTION_ROLES`: which roles may perform `READ`/`WRITE`/`DELETE`/`CREATE`/`DROP`/`ALTER`/`REFRESH`/`MANIFEST`, plus `GRANT`/`REVOKE` (new -- makes policy-administration authority explicit in the same table instead of an implicit rule elsewhere). |
| `patterns.py` | `policy.opteryx/app/models/policy.py` + `app/routes/v1/access.py` | `resource_matches` (case-sensitive `fnmatchcase` -- see "Behavior changes" below), the wildcard-principal rule, and the reserved-workspace (`public`/`personal`/`information_schema`) rule. |
| `models.py` | `authenticate.opteryx/app/policies.py` | `Grant` (role+pattern, the JWT-carried shape) and `Policy` (principal+role+pattern+metadata, the stored shape), plus `parse_policy_claim` for the `[role, pattern]` pairs a token carries. |
| `checks.py` | `opteryx-core`'s `can_perform_action`/`can_perform_workspace_action` + `policy.opteryx`'s `_check_pattern_access`/`_check_workspace_access`/`_check_workspace_owner_access` | The evaluation layer: data-plane checks over `Grant`s, administrative-plane checks over `Policy` documents. |
| `store.py` | `policy.opteryx/app/routes/v1/access.py`'s `create_policy`/`update_policy`/`delete_policy`/`create_genesis_policies` | Where policies are actually granted, updated, and revoked: the `PolicyStore` protocol plus `grant()`/`update_grant()`/`revoke()`/`bootstrap_workspace()`, which enforce every invariant those routes did (self-grant prevention, pattern-authority, conflict detection, wildcard/reserved-resource validation) against any storage backend. |
| `adapters/firestore.py` | (new) | `FirestorePolicyStore`, matching the `{workspace}/$policies/access` layout policy.opteryx/control.opteryx already write to -- a drop-in for their inline Firestore calls. |
| `exceptions.py` | (new) | Plain exceptions (`SelfAccessError`, `AccessDeniedError`, `PolicyConflictError`, ...) instead of `HTTPException` -- each caller translates to its own transport. |

## Two axes, not one rank

`admin` sits between `owner` and `writer` on the grant-management axis
(`ADMINISTRATIVE_ROLES`) but is excluded from every entry in `ACTION_ROLES`.
That split is real, existing platform behavior (see opteryx-core's
`ACTION_MAP`), not an oversight this library introduces -- an admin can grant
and revoke other people's access but cannot themselves `SELECT`/`INSERT`/
`DELETE` against a resource they don't separately hold `writer`/`owner` on.
Anything built on top of this package should keep asking the right one of
the two questions:

- "May this identity administer grants on this pattern?" -> `checks.can_administer_pattern`
- "May this role perform this SQL-shaped action on this resource?" -> `checks.can_perform_action`

## Usage

```python
from opteryx_access import Grant, can_perform_action

grants = [Grant(role="writer", pattern="analytics.sales.*")]
can_perform_action(grants, "analytics.sales.q1", "DELETE")  # True
can_perform_action(grants, "analytics.sales.q1", "DROP")    # False -- writer, not owner
```

```python
from opteryx_access import grant, revoke, AccessDeniedError
from opteryx_access.adapters.firestore import FirestorePolicyStore

store = FirestorePolicyStore(db)  # db: google.cloud.firestore.Client
try:
    policy_id = grant(
        store, actor="alice", workspace="analytics",
        principal="bob", role="writer", pattern="analytics.sales.*",
    )
except AccessDeniedError:
    ...  # translate to a 403, same as the route used to do inline
```

## Behavior changes from the ported originals

Ported faithfully except for one deliberate fix, worth calling out before
anything is cut over:

- **`resource_matches` uses `fnmatch.fnmatchcase`, not `fnmatch.fnmatch`.**
  `policy.opteryx`/`control.opteryx`/opteryx-core's data-action check all use
  plain `fnmatch`, which folds case per the OS Python runs on -- the same
  policy would decide differently on macOS versus Linux. opteryx-core's own
  `can_perform_action` already avoids `fnmatch` for exactly this reason when
  matching its hardcoded implicit policies. odata.opteryx already uses
  `fnmatchcase` for its read check. This package standardizes on the
  deterministic, already-precedented behavior. If any live policy pattern
  relies on the OS case-folding today, cutting a service over to this
  package will change what that specific pattern matches -- worth an audit
  of stored patterns before cutover, not assumed to be a no-op.

## Suggested migration (not yet done)

This repo is the library only -- nothing outside it has been changed yet.
Suggested order, each independently shippable:

1. **opteryx-core**: replace `opteryx/managers/permissions/__init__.py`'s
   `ACTION_MAP`/`can_perform_action`/`can_perform_workspace_action`/
   `implicit_policies` with thin wrappers around `opteryx_access.actions`/
   `opteryx_access.checks` (converting `ExecutionContext.access_policies`
   dicts to `Grant`s at the boundary). Zero new dependencies -- this package
   has none by default.
2. **odata.opteryx**: replace `app/auth/permissions.py`'s
   `role_allows_read`/`read_grant_for_relation`/pattern matching with
   `opteryx_access.checks.can_perform_action` (action="READ"). Leaves
   `entitlements_from_claims`/`billing_account_from_claims` alone -- those
   are a different concern (entitlements/billing), not permissions.
3. **policy.opteryx** and **control.opteryx**: thin `app/routes/v1/access.py`
   down to request parsing, calling `opteryx_access.store.grant`/
   `update_grant`/`revoke`/`bootstrap_workspace` via `FirestorePolicyStore`,
   and mapping the typed exceptions to `HTTPException`. The
   resource-existence check (`_resource_exists`), user-status lookup
   (`_lookup_user_record`), age gate, and audit logging all stay where they
   are -- see `store.py`'s module docstring for why those are out of scope
   here. Given `control.opteryx` is the in-progress merge target for
   `policy.opteryx` (see its `docs/design/consolidation.md`), do this once,
   on `control.opteryx`, and let the `policy.opteryx` cutover carry it along
   rather than porting both routes separately.
4. **register.opteryx** and any other claims-parsing copy: swap to
   `opteryx_access.models.parse_policy_claim` for the `policies` claim
   specifically. Token *verification* (signature, issuer, JWKS) stays
   service-specific -- this package has no opinion on how a JWT gets from
   bytes to a trusted claims dict, only on what to do with the `policies`
   claim once you have one.

## Installing

```
pip install opteryx_access
pip install "opteryx_access[firestore]"  # for adapters.firestore
```

No hard dependencies. `google-cloud-firestore` is an optional extra;
`adapters/firestore.py` never imports it at all (it's duck-typed against
whatever `db` object it's handed), so importing `opteryx_access` itself never
requires it -- consistent with opteryx-core's zero-dependency convention.

## CI/CD

- `.github/workflows/tests.yaml` -- pytest (3.13, 3.14) + ruff lint/format,
  on every push to `main` and every PR.
- `.github/workflows/release.yaml` -- on a pushed tag matching `version-*`:
  runs the full test workflow, checks the tag matches `pyproject.toml`'s
  `version` (exactly, or with a `.`-delimited suffix), then builds and
  publishes to PyPI via
  [trusted publishing](https://docs.pypi.org/trusted-publishers/) (OIDC --
  no stored API token). The `opteryx_access` PyPI project needs this repo +
  the `release.yaml` workflow registered as a trusted publisher before the
  first tag push, or the publish step will fail with no valid credentials.

To cut a release: bump `version` in `pyproject.toml`, merge to `main`, then
`git tag version-X.Y.Z && git push origin version-X.Y.Z`.

## License

Apache 2.0. See [LICENSE](LICENSE) for details.
