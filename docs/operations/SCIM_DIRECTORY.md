# SCIM directory client interoperability

SOU-57, roadmap Phase 6. This is an internal synthetic interoperability fixture,
not certification of a customer identity provider or a product release.

## Supported profile

The independent open-source client is [python-scim/scim2-client](https://github.com/python-scim/scim2-client),
version 0.13.1, using its synchronous httpx2 engine and discovered resource models.
It serializes requests and validates server responses over a real loopback HTTP
listener running the production Soup Wall router and storage APIs. SQLite and
PostgreSQL use the same client lifecycle. No external IdP account is required.

All endpoints require the existing expiring organization-scoped SCIM credential.
A directory user or group grants no workspace role, identity binding or proxy
credential. Group names such as Owner never grant authority.

- `Users`: equality on `userName`, `externalId`, or `id`.
- `Groups`: equality on `displayName`, `externalId`, or `id`.
- Grammar: one attribute, whitespace, `eq`, whitespace, one JSON string. Attribute
  names and `eq` are ASCII case-insensitive. Values are case-sensitive, exact
  strings with no normalization or wildcard expansion, consistently across stores.
  Discovery advertises `caseExact: true` for this bounded profile. This is not a
  claim of every default comparison behavior in the full SCIM core schema.
- Filters are limited to 2048 bytes, decoded values to 512 bytes without control
  characters. Unsupported operators, compounds, paths, types or trailing content
  return HTTP 400 SCIM `invalidFilter`; a filter is never silently ignored.
- SQL columns come from a closed typed mapping; values are bound parameters.
  Both `totalResults` and the returned page use the organization and filter.
  `startIndex` is 1-based, at most 1,000,000; `count` is 0..100. `count=0` retains
  the filtered count and returns no resources. Sorting is explicitly unsupported.
- `ResourceTypes` and `Schemas` support list and individual discovery. Only User
  and Group attributes implemented here are advertised. Bulk, sorting, ETags and
  password changes remain unsupported in `ServiceProviderConfig`.
- User PATCH supports replace of `userName`, `displayName`, and `active`, including
  a pathless attribute object. Group PATCH supports displayName replace and
  members add/remove/replace, including pathless replace and
  `remove` with `members[value eq "principal-id"]` and no value.
- Patches are bounded to three User / two Group operations and distinct changed
  attributes. Repeated changes to one attribute, unknown fields, unsupported
  forms and extra selector syntax are rejected before mutation. A valid name
  change followed by invalid or cross-organization members leaves both unchanged.
- Group member replacement preserves retained members; duplicate add/remove and
  replacement retries are idempotent. Create duplicates are rejected by existing
  uniqueness checks; discover existing resources before retrying a lost create.
- `externalId` remains required at creation and immutable. User DELETE preserves
  the existing deactivation contract and directory ID; Group DELETE removes the
  group. No incompatible identity migration is introduced.

## Reproduce

On Linux with Docker and Rust installed, from the repository root:

```sh
python3 -m venv /tmp/soup-scim-client
/tmp/soup-scim-client/bin/python -m pip install -r scripts/scim-directory-requirements.txt
cargo test --locked -p llm-firewall scim
cargo build --locked -p llm-firewall --example scim-directory-fixture
/tmp/soup-scim-client/bin/python scripts/scim-directory-acceptance.py --backend sqlite --fixture target/debug/examples/scim-directory-fixture --out /tmp/scim-sqlite.json
/tmp/soup-scim-client/bin/python scripts/scim-directory-acceptance.py --backend postgres --fixture target/debug/examples/scim-directory-fixture --out /tmp/scim-postgres.json
```

Use a fresh output path for every attempt; earlier failure evidence is not
replaced. The `scim-directory` workflow runs both backends on the exact PR head.
Windows can run the SQLite command using the `.exe` fixture and native Python;
PostgreSQL acceptance uses the Linux disposable Docker fixture.

The helper refuses existing SQLite files and populated stores. PostgreSQL uses
an owned digest-pinned container, a random database/password and verified TLS
with a temporary CA, reusing the accepted fixture helper without modifying it.
HTTP credentials cross only private pipes and loopback in this fixture; production
SCIM must be deployed behind the documented HTTPS boundary. The child exposes
only fixed revoke/stop commands on its private stdin. Temporary files and created
containers are cleaned before a passing report; operator data is never a target.

Reports contain exact source hashes, source commit, fixture binary hash, client
versions, individual checks and cleanup outcome. They exclude credentials,
request/response bodies and exception strings. A failure report remains failed;
there is no hidden automatic retry. Inspect private local logs while the run is
active if diagnosis is needed, and rerun using a new evidence path.
