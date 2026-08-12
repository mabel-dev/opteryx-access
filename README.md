# opteryx-access

Permission checks and grant/revoke for the Opteryx platform, as an installable
library rather than a service. Every consumer imports `opteryx_access` and
calls it in-process against policies it already has in hand -- a JWT's
`policies` claim, or a `PolicyStore` backed by whatever it uses for storage
(Firestore, today). There is no `opteryx-access` HTTP surface, and this
package makes no network calls of its own beyond what a storage adapter does.

## Scope: data access only

This package models exactly one thing: who can do what to *data* --
`owner`/`writer`/`reader` on workspaces, collections, and datasets. It has no
notion of billing-account roles (`admin`/`member`, minted separately on a
billing account and unrelated to data roles) and enforces no billing checks.

The one place these two systems touch is **workspace genesis**: creating a
workspace is a billing-gated action (the creator must already be a billing
admin -- checked by whatever service owns billing, not this one), and its
result is a data-permission fact -- the creator becomes the new workspace's
`owner`. That handoff is the entire intersection. `opteryx_access.grants.bootstrap_workspace`
implements the data-permission half of it (an explicit list of
`(principal, role)` pairs, `owner` among them) and knows nothing about
billing; the billing gate is the calling service's job, enforced before
`bootstrap_workspace` is ever reached.

## Why this exists

Three independent, subtly incompatible implementations of "does this role
satisfy this requirement" already exist in the fleet:

- **policy.opteryx** / **control.opteryx** (`app/routes/v1/access.py`,
  `app/models/policy.py` -- byte-for-byte duplicated between the two repos):
  a rank-based `ROLES` tuple used to decide who may create/update/revoke a
  policy, and whether a new grant is redundant against one the principal
  already holds.
- **opteryx-core** (`opteryx/managers/permissions/__init__.py`): a
  set-based `ACTION_MAP` deciding which roles may `READ`/`DELETE`/`DROP`/etc.
  a resource once a query actually runs.
- **odata.opteryx** (`app/auth/permissions.py`): a binary
  `role_allows_read` used for listing/visibility, plus its own pattern
  matcher -- `fnmatchcase` where the others use plain `fnmatch`, a difference
  that is latent today (see "Behavior changes") but means the three do not
  state the same rule even where they currently agree.

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
| `roles.py` | `policy.opteryx/app/models/policy.py` | The canonical `ROLES = ("owner", "writer", "reader")` and `role_outranks_or_equals`, the privilege ordering used only for redundancy detection. |
| `actions.py` | `opteryx-core/opteryx/managers/permissions/__init__.py` | `ACTION_ROLES`: which roles may perform `READ`/`WRITE`/`DELETE`/`CREATE`/`DROP`/`ALTER`/`REFRESH`/`MANIFEST`, plus `GRANT`/`REVOKE` (new -- makes policy-administration authority explicit in the same table instead of an implicit rule elsewhere). |
| `patterns.py` | `policy.opteryx/app/models/policy.py` + `app/routes/v1/access.py` | What a pattern and a principal may look like, and how a pattern matches: `validate_pattern`, `validate_principal`, `resource_matches` (see "Patterns and principals" below). |
| `models.py` | `authenticate.opteryx/app/policies.py` | `Grant` (role+pattern, the JWT-carried shape) and `Policy` (principal+role+pattern+metadata, the stored shape), plus `parse_policy_claim` for the `[role, pattern]` pairs a token carries. |
| `checks.py` | `opteryx-core`'s `can_perform_action`/`can_perform_workspace_action` + `policy.opteryx`'s `_check_pattern_access`/`_check_workspace_access` | The evaluation layer: data-plane checks over `Grant`s, administrative-plane checks over `Policy` documents. |
| `grants.py` | `policy.opteryx/app/routes/v1/access.py`'s `create_policy`/`update_policy`/`delete_policy`/`create_genesis_policies` | The write half: `grant()`/`update_grant()`/`revoke()`/`bootstrap_workspace()`, enforcing every rule those routes did (self-grant prevention, pattern authority, conflict detection, principal and pattern validation) before calling a store. Also the two reads that need a store: `grants_for_principal()` and `owned_by()`. |
| `store.py` | (new) | The `PolicyStore` protocol: the storage contract, and nothing else. No rules live here -- see "Layering" below. |
| `audit.py` | `policy.opteryx/app/routes/v1/access.py`'s `_audit_policy_change` | One structured record per policy change, on the same field contract the existing log transforms already parse -- see "Audit records" below. |
| `capability.py` | (new) | The permissions capability opteryx-core registers -- the one module that knows the engine exists. See "The opteryx-core capability" below. |
| `adapters/firestore.py` | (new) | `FirestorePolicyStore`, matching the `{workspace}/$policies/access` layout policy.opteryx/control.opteryx already write to -- a drop-in for their inline Firestore calls. |
| `exceptions.py` | (new) | Plain exceptions (`SelfAccessError`, `AccessDeniedError`, `PolicyConflictError`, ...) instead of `HTTPException` -- each caller translates to its own transport. |

## Layering

Rules and storage are separate, and the dependency only points one way:

```
roles / actions / patterns / models     the vocabulary  (no I/O, no deps)
                 |
              checks.py                 read-side rules (no store at all)
                 |
              grants.py                 write-side rules -- the only module
                 |                       that mutates a store
              store.py                  the storage contract (a Protocol)
                 |
       adapters/firestore.py            one backend
```

Two consequences worth relying on:

- **`checks.py` never touches a store.** It answers from grants handed to it,
  so opteryx-core can evaluate a query's permissions from a JWT with no
  storage, no credentials, and no network.
- **A store enforces nothing.** It translates to its backend and no more. A
  store that filtered out policies it thought invalid, or refused a write it
  thought unauthorized, would be enforcing policy somewhere none of the tests
  for those rules can see it. Every rule lives in `grants.py`, tested against
  an in-memory fake.

## Patterns and principals

A policy says **who** gets **what role** over **which resources**.

*Which resources* is a pattern: `workspace[.collection[.dataset]]`, where each
dot-separated segment written is either a literal name or `*`.

**A `*` covers everything below it, not one level.** `analytics.*` grants
`analytics.sales` and `analytics.sales.q1` alike -- a grant over a workspace is
a grant over what is in it. Worth stating plainly, because reading `*` as "one
segment" understates what a policy confers.

Rules, all enforced by `validate_pattern`:

- **Names are lowercase**, `a-z0-9_`, starting with a letter. Patterns and
  resource names are normalized before they are compared, so matching is
  case-insensitive and decided identically on every platform.
- **The workspace segment must be literal.** A policy always says which
  workspace it applies to -- `analytics.*` is fine, a bare `*` is not.
- **A segment is either `*` or a whole literal name** -- no partial globs like
  `pub*`. This is what makes the reserved-workspace check a plain membership
  test rather than a match against every reserved name, with no evasion to
  reason about.
- `public`, `personal`, and `information_schema` remain non-grantable.

## Implicit grants, and the `public` exception

Some access is held without a policy having been issued for it, declared once in
`checks.implicit_grants`:

| Who | Holds | Why |
|---|---|---|
| Any identity | `owner` on `personal.<identity>.*` | Your own namespace |
| Everyone | `reader` on `public.*` | Shared open data, readable by all |
| `PLATFORM_IDENTITIES` | `writer` on `public.*` | Something has to load and compact it |

These are checked **before** issued grants and **cap** what they cover: a
resource in `public.` or in your own `personal.` is answered there and never
falls through, which is what makes `public.` read-only however broad a policy
someone holds over it.

`public` is where curated open data lives -- GDELT, vulnerability feeds -- and
something has to write it and keep it compacted. Because `public` is a reserved
workspace, `validate_pattern` refuses to store a policy over it, so that access
cannot be issued as an ordinary grant to the identities that do the work. It is
declared instead as a third implicit grant, held by a short closed list of
platform identities (`federator`, `xb500`), ordered ahead of the reader grant it
would otherwise be capped by.

Three things worth being explicit about, since this is a carve-out:

- **Writer, not owner.** These identities load and compact `public`; dropping a
  public dataset or granting anyone access to one is not theirs to do.
- **It is visible.** `SHOW GRANTS` reports implicit grants first, in evaluation
  order, so a platform identity's write access over `public` is legible in the
  same place a policy row would have been.
- **It rests on identity issuance.** Nothing here can verify that a session
  claiming to be `federator` is the platform -- an identity arrives already
  authenticated. These names must be unregisterable wherever accounts are
  created, or the carve-out is a signup form away from anyone.

*Who* is a named individual, enforced by `validate_principal`. There is no
wildcard principal and no group principal: a grant everyone holds is not
something any listing surfaces as unusual, and groups will be their own
concept rather than a pattern smuggled into this field.

Identities are casefolded too, so `XB500` and `xb500` are one principal rather
than two people each holding half the access. Normalizing on write alone would
not be enough -- a lookup for `xb500` would silently miss a stored `XB500` --
so every read that filters by principal normalizes the same way.

## Audit records

Every successful change to a policy emits one structured record, after the
write lands. `grant`, `update_grant`, `revoke`, and `bootstrap_workspace` all
do this themselves -- not the caller -- because a trail assembled by whoever
remembers to assemble it is one refactor away from having a hole in it, and a
hole here is invisible until someone needs it.

Records go to the standard-library logger `opteryx_access.audit` at INFO.
**Being a library, this configures nothing** -- no handlers, no levels. A
service that does not configure logging for that logger will not see these at
all, which for an audit trail is worth confirming rather than assuming.

Each record is emitted twice over, so it survives whatever is in front of it:
as compact single-line JSON in the message (Cloud Run promotes a JSON stdout
line into `jsonPayload` on its own), and via `extra={"json_fields": ...}`
(what google-cloud-logging's handlers read directly). A service that would
rather route these through its own audit channel can call `set_audit_sink`
and be handed the payload dict.

```json
{"event": "policy.updated", "actor": "alice", "workspace": "analytics",
 "policy_id": "9f2c...", "principal": "xb500", "role": "writer",
 "pattern": "analytics.sales.q1", "previous_role": "reader",
 "previous_pattern": "analytics.sales.*",
 "timestamp": "2026-08-12T08:06:37.516307+00:00"}
```

`event` is `policy.created`, `policy.updated`, or `policy.deleted`. The field
names deliberately match what policy.opteryx/control.opteryx already emit, so
the transforms building `opteryx.ops.policy_changes` keep working unchanged
when a service moves onto this package. Absent fields are omitted rather than
null: no `previous_*` on a create, no `role`/`pattern` on a delete. Genesis
grants additionally carry `bootstrap: true`, since they clear none of the
usual authority checks and are worth telling apart from an ordinary grant.

Only changes that actually happened are recorded. A refused grant writes
nothing -- see "Not recorded" at the end of this file for what that leaves
out.

## Which check to call

- **"May this identity administer grants on this pattern?"** ->
  `checks.can_administer_pattern`, over stored `Policy` documents. Requires
  `owner`, and requires that ownership to *cover* the pattern in question.
- **"May this role perform this action on this resource?"** ->
  `checks.can_perform_action`, over `Grant`s. Answered from `ACTION_ROLES`.

They take different inputs because they need different things: a `Grant` is
role plus pattern, all a data action needs; a `Policy` also names the
principal it was issued to, which is what an administrative check reasons
about. Call the one that fits the question -- neither answer substitutes for
the other.

## The opteryx-core capability

opteryx-core allows everything on its own: a CLI or embedded engine has no
workspaces to own and no policy service to have issued anything, so access
control is a property of a deployment rather than of the engine. A deployment
installs this library over that intrinsic default at start-up:

```python
import opteryx
import opteryx_access

opteryx.register_permissions_capability(opteryx_access.capability())
```

From then on the engine's permission gates and its `SHOW GRANTS` are both
answered from here, so what it enforces and what it reports come from one
evaluation.

`opteryx_access.capability` is the **only** module in this package that knows
opteryx-core exists, and even it does not import it -- the engine hands over
an execution context and the adapter reads two attributes off it. Neither
package depends on the other; a deployment brings them together. That is what
keeps opteryx-core's zero-dependency contract intact, and it means the whole
extent of the coupling can be read in one file.

Two things it deliberately does not report through `SHOW GRANTS`:

- **`GRANT`/`REVOKE`** (`actions.POLICY_ADMINISTRATION_ACTIONS`). They are
  real actions this package decides, but no SQL statement in opteryx performs
  them, so naming them in the engine's output would advertise a capability
  its surface does not have. Only `actions.DATA_ACTIONS` are reported.
- **Registration is start-up only.** opteryx-core refuses a capability
  registered after a permission check has already been answered, rather than
  let one process decide the same question two ways.

## Usage

Every check function takes grants/policies already in hand -- it doesn't
fetch them itself. Where those come from depends on what you're holding:

- **A JWT**: `opteryx_access.models.parse_policy_claim(claims)` -- the token
  was already scoped to its own holder when it was minted, so nothing more
  to filter.
- **A `PolicyStore`** (live policy state, not a token): `opteryx_access.grants.grants_for_principal(store, workspace=..., identity=...)`
  -- fetches that identity's issued grants and converts them to the same
  `Grant` shape.

One question is asked across workspaces rather than within one:
`opteryx_access.grants.owned_by(store, identity=...)` returns every policy, in
any workspace, that makes an identity an **owner**. That is what offboarding
needs -- a workspace whose last owner is removed cannot be administered by
anyone, so those grants have to be reassigned before the identity goes. Each
returned `Policy` carries its `workspace`.

There is deliberately no "everywhere this identity can read" equivalent: it
would mostly return reader rows nobody acts on, while being the expensive
query shape and widening what a backend has to index. If a use for it turns
up, it should arrive as its own named operation with that use written down.

```python
from opteryx_access import Grant, can_perform_action

grants = [Grant(role="writer", pattern="analytics.sales.*")]
can_perform_action(grants, "analytics.sales.q1", "DELETE")  # True
can_perform_action(grants, "analytics.sales.q1", "DROP")    # False -- writer, not owner
```

```python
from opteryx_access.grants import grants_for_principal
from opteryx_access.adapters.firestore import FirestorePolicyStore

store = FirestorePolicyStore(db)
grants = grants_for_principal(store, workspace="analytics", identity="bob")
can_perform_action(grants, "analytics.sales.q1", "DELETE")
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

Ported faithfully except for the deliberate deviations below. Four of them are
stricter than what the originals accept, so each can reject a policy that exists
today -- audit stored policies before cutting a service over, rather than
assuming any of this is a no-op. Two grant *more* than the originals did
(case-insensitive matching, and the platform identities' write access over
`public`); both are called out as such:

- **`ROLES` is `("owner", "writer", "reader")` -- three roles, not four.**
  `policy.opteryx`/`control.opteryx`'s current `ROLES`/`VALID_WORKSPACE_ROLES`
  include a fourth, `admin`. This package intentionally drops it: `admin` is
  a billing-account concept, not a data-permission one (see "Scope" above),
  and never belonged in the data-role vocabulary.
- **Matching is case-insensitive. This is the one deviation that grants
  *more* than the originals -- read the note below before cutting over.** The
  originals use plain `fnmatch`, which delegates to `os.path.normcase`: that
  is the identity function on every platform this fleet runs (Linux in
  production, macOS in development), so the originals are effectively
  case-*sensitive* and `analytics.*` does **not** match `Analytics.sales`
  there. They would only fold case on Windows. Here both sides are lowercased
  before comparison, so `analytics.*` **does** match `Analytics.sales`. The
  gain is that the rule is stated rather than inherited from the host OS; the
  cost is that a stored pattern can now cover resources it did not cover
  before.
- **No wildcard principal.** The originals accept `principal: "*"` as "any
  authenticated user". Policies here name one individual.
- **Patterns must be usable and workspace-scoped.** The originals accept any
  string, including a bare `*`, partial globs (`pub*`), and malformed input
  (`a....*.bob11`). See "Patterns and principals" above for the rules.
- **Platform identities may write `public`. This is the second deviation that
  grants more than the originals.** `federator` and `xb500` hold `writer` on
  `public.*` as an implicit grant -- see "Implicit grants, and the `public`
  exception" above for why it cannot be an ordinary policy, and what it rests
  on. In the originals nothing could write `public` at all, which is why the
  jobs that maintain it bypassed permission checks entirely rather than
  clearing them.

## Suggested migration (not yet done)

This repo is the library only -- nothing outside it has been changed yet.

**Before step 3**, audit the existing policy documents under
`*/$policies/access`. Validation runs when a policy is *written*, not when it
is read, so nothing raises on already-stored data -- the behavior just
changes silently. Three of the deviations fail *closed* (the grant stops
conferring anything):

- `role: "admin"` -- no longer a role, so the grant becomes inert.
- `principal: "*"` -- no longer means "anyone", so the grant reaches nobody.
- patterns that are bare `*`, partially globbed, or malformed -- they can no
  longer be written, and are unlikely to match what they used to.
- **principals stored with any uppercase** (`XB500`) -- these need rewriting
  to lowercase, and are the one item here that is not merely inert. Lookups
  filter server-side on the exact stored string, so a query for `xb500` will
  not find a stored `XB500`: the grant is invisible to `grants_for_principal`
  and `owned_by` even though the document still exists. In-memory comparisons
  (`can_administer_pattern`, `has_workspace_access`) normalize both sides and
  so still resolve it, which means a mixed-case principal can behave
  *differently depending on which path reached it*. Rewrite them.

The fourth fails **open**, and needs looking at first:

- **case-insensitive matching widens every stored pattern.** A pattern only
  ever matched resources of identical case before; now it also matches those
  differing in case. If any workspace, collection, or dataset name in the
  catalog contains an uppercase character, a policy that did not reach it
  before now does. Enumerate mixed-case resource names before cutover -- if
  there are none, this deviation is inert and the migration is closed-only.

Decide what happens to each (revoke, or rewrite as an explicit grant); this
package does not migrate them for you. `tests/test_security.py` pins the
inert-on-read behavior for the closed-failing three if you want the exact
semantics.

Suggested order, each independently shippable:

1. **opteryx-core**: add a *permissions capability* seam rather than
   rewriting the engine's checks. `opteryx/managers/permissions/` keeps
   `can_perform_action` and `can_perform_workspace_action` as module-level
   functions, but they delegate to whichever capability is registered, so all
   28 existing call sites (21 in the binder, 7 in `information_schema`) stay
   as they are. The engine ships an intrinsic default that allows every
   action on every resource, and a deployment injects this library over it:

   ```python
   opteryx.register_permissions_capability(opteryx_access.capability())
   ```

   `ACTION_MAP` and `implicit_policies` leave the engine entirely. `public`
   and `personal` are cloud-deployment namespaces -- meaningless to CLI and
   embedded opteryx, which has no workspace service to have issued them --
   so they belong to the capability, not to the engine's intrinsic
   behaviour. `ACTION_ROLES` and `implicit_grants` already hold both here.

   This keeps opteryx-core's zero-dependency contract intact: the engine
   defines the interface and the default and never imports `opteryx_access`;
   the deploying service wires the two together, exactly as it already does
   for `opteryx-catalog` via `set_default_connector(..., catalog=...)`.

   The adapter this needs is `opteryx_access.capability` -- **done**; see
   "The opteryx-core capability" below.

   Both packages support Python 3.11+, so a deployment can run them together
   on any version opteryx-core supports.
2. **odata.opteryx**: replace `app/auth/permissions.py`'s
   `role_allows_read`/`read_grant_for_relation`/pattern matching with
   `opteryx_access.checks.can_perform_action` (action="READ"). Leaves
   `entitlements_from_claims`/`billing_account_from_claims` alone -- those
   are a different concern (entitlements/billing), not permissions.
3. **policy.opteryx** and **control.opteryx**: thin `app/routes/v1/access.py`
   down to request parsing, calling `opteryx_access.grants.grant`/
   `update_grant`/`revoke`/`bootstrap_workspace` via `FirestorePolicyStore`,
   and mapping the typed exceptions to `HTTPException`. The
   resource-existence check (`_resource_exists`), user-status lookup
   (`_lookup_user_record`), age gate, and audit logging all stay where they
   are -- see `grants.py`'s module docstring for why those are out of scope
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

- `.github/workflows/tests.yaml` -- pytest (3.11-3.14) + ruff lint/format,
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

## Not recorded

Refused attempts -- a grant denied for insufficient authority, a self-grant,
a rejected pattern -- raise and emit nothing. The records above are a log of
*changes*, and a refusal changes nothing.

That is a deliberate line, not an oversight, but it does mean this package
gives a monitoring system no visibility into someone repeatedly trying to
escalate. If that is wanted, it should be its own event kind (a
`policy.denied` at WARNING, carrying the actor, what was attempted, and which
rule refused it) rather than being folded into the change records, which
downstream treats as "this is now true".

## License

Apache 2.0. See [LICENSE](LICENSE) for details.
