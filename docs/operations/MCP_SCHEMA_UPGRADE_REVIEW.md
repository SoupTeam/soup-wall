# Offline MCP schema upgrade review (SOU-204)

`agentfw mcp-schema-upgrade` compares two exact original MCP `tools/list`
snapshots with the current operator-owned declarations and writes review
material for semantic review and re-qualification **before** an upstream
server update is deployed.

## Purpose and non-goals

The analyzer reads only the files named on its command line (and the files an
identity document names) and writes one new output directory. It **never**:

- approves, accepts or installs a schema, profile, registry or policy;
- grants runtime permission or changes an accepted profile or declaration;
- launches an MCP server or any other process;
- performs network lookups, retrieves `$ref` targets or classifies with a model;
- infers action, resource or destination semantics from tool names,
  descriptions, titles or annotations.

**Invariant:** every after-side identity that differs from the before side is
reported as *new and unaccepted*. A finding's nature (even
`inert_metadata`) never changes that. Acceptance only happens through the
existing review, qualification and admission process.

## Inputs

| Flag | Required | Accepted format |
| --- | --- | --- |
| `--before`, `--after` | yes | A JSON-RPC 2.0 `tools/list` response (`{"jsonrpc","id","result":{"tools":[…]}}`, the format of the committed `upstream-tools-list.json` files) or `sw-mcp/operator-discovery/1` |
| `--before-identity` | no | The accepted identity of the before snapshot: `sw-mcp/filesystem-readonly-upstream/1` or the Git `upstream-identity.json` document |
| `--registry` | one of the two, unless `--snapshot-only` | Current operator registry `sw-native/1` (the installed `registry.json`), bound to the before snapshot |
| `--declarations` | | Current `sw-mcp/operator-declaration/1`, bound to an `sw-mcp/operator-discovery/1` before snapshot; exclusive with `--registry` |
| `--snapshot-only` | no | Explicitly compare snapshots **without** declarations; semantic review is then reported as unavailable. Exclusive with every declaration flag |
| `--proposed-registry` | no | A draft `sw-native/1` registry for the after snapshot; compared, never accepted |
| `--before-label`, `--after-label` | no | Operator-asserted provenance text (≤256 bytes), reported as untrusted |
| `--out` | yes | A new directory; its parent must exist; never inside the Agent home |

The semantic review requires the current operator-owned declarations. Without
`--registry`/`--declarations` the analyzer refuses (`missing_declarations`,
exit 2) unless `--snapshot-only` is given. A snapshot-only report sets
`summary.analysis_mode = snapshot_only` and
`summary.semantic_review = unavailable_snapshot_only`, keeps coverage
incomplete, and prints a banner in `report.txt` and `REVIEW_GUIDE.md`. It is
never a semantic upgrade review.

Every JSON input is parsed strictly: duplicate object members, `NaN`/`Infinity`,
trailing data and malformed UTF-8 are refused. Tool names must be unique and
match `[A-Za-z0-9_.:/-]{1,128}`; `inputSchema` must be an object. A paginated
response (`result.nextCursor`) is refused as an incomplete snapshot. Declarations
must bind the exact before identities: each declared tool's `schema_sha256` must
equal the before tool's schema identity (`declarations.snapshot_sha256` must equal
the before discovery identity). The proposed registry must bind the after
identities in the same way.

An identity document is verified completely: the filesystem format checks
`discoveryResultSha256` and, for **every** before tool, `inputSchemaSha256` and
`originalDefinitionSha256`; the Git format checks the raw SHA-256 pinned for
`upstream-tools-list.json`. Referenced files (`upstreamNotices[].path`, Git
`files`) must be plain relative paths inside the identity document's directory,
regular files of at most 1 MiB, and match their digests. `packageLockSha256` has
no declared path and is reported as `recorded_not_verified`.

### Invalid versus unsupported

- **Invalid input is refused** (exit 2, nothing written): malformed or duplicate
  JSON, wrong envelope or member types, duplicate or malformed tool names,
  exceeded bounds, incomplete or mismatching identities, invalid referenced
  paths, and declarations bound to other identities.
- **Valid but unsupported input is analyzed and reported** (exit 5): schema
  keywords outside the supported subset (`anyOf`, `oneOf`, `format`, `$ref`,
  `$defs`, `pattern`, …), type unions, schema-valued `additionalProperties`,
  tuple `items`, and tool members other than `name`, `title`, `description`,
  `inputSchema`, `outputSchema`, `annotations` and `execution`. They appear as
  `unsupported` findings when they change. They also appear as
  `unsupported_construct_added`/`unsupported_construct_removed` findings when
  they sit inside an added or removed field, item schema, result schema or
  tool, and always in `coverage.unsupported_constructs`; whole-schema support is checked with the
  runtime validator `InputSchema::read_selected`. Coverage is never reported
  complete while any gap exists.

## Supported schema subset

Identical to the runtime input profile in `crates/agentfw/src/mcp/input.rs`:
`type` (one of object, array, string, integer, number, boolean, null), `title`,
`description`, `default`, `enum`, `const`; objects with `properties`,
`required`, `additionalProperties`; arrays with object `items`, `minItems`,
`maxItems`; strings with `minLength`, `maxLength`; root `$schema`. The analyzer
does not claim general JSON Schema equivalence.

## Limits

| Limit | Value |
| --- | --- |
| Snapshot / declaration / identity bytes | 262,144 each (`server_profile::MAX_DISCOVERY_BYTES`) |
| Tools per snapshot | 64 (`server_profile::MAX_TOOLS`) |
| JSON nesting depth / values per document | 32 / 65,536 |
| Diff steps | 131,072 (exceeded → refusal) |
| Findings / coverage entries | 2,048 / 1,024 (exceeded → reported truncation, coverage incomplete) |
| Referenced files | 16, each ≤ 1 MiB |
| Value excerpt in findings | 1,024 bytes (larger values are reported by SHA-256 and length) |
| Review-pack records | 512 total, 4 per finding |
| Example strings / arrays / bytes | 64 characters / 4 items / 4,096 bytes |
| Total output | 16 MiB |

Schema bounds are untrusted `u64` values; the before schema is never
runtime-validated. Example edges use checked arithmetic and checked
conversion. An edge that cannot be represented or bounded, for example
`maxLength` = 18446744073709551615, yields an `unconstructible` record instead
of an example. An after schema with such a bound is also reported as outside
the runtime subset.

The runtime limits (`input::MAX_DEPTH`, `MAX_ITEMS`, `MAX_SCHEMA_NODES`) are
reported, unchanged and still enforced by the runtime.

## Identity, normalization and acceptance

| Concept | Definition | Use |
| --- | --- | --- |
| Raw file digest | SHA-256 of the exact input bytes | Artifact identity; the Git identity pins it |
| Exact schema identity | `profile_author::digest(inputSchema)` = SHA-256 of sorted-key compact JSON | Bound by `sw-native/1` `schema_sha256` and `inputSchemaSha256` |
| Exact definition identity | `profile_author::digest(tool)` | `originalDefinitionSha256`, admission `definition_sha256` |
| Discovery identity | `digest(result)` for JSON-RPC, `digest(document)` for operator discovery | `discoveryResultSha256`, `snapshot_sha256` |
| Analysis normalization | Sorted keys; `required`, `enum` and `type` compared as sets | Stable comparison and ids only, **never** an identity |

Reordering object keys leaves exact identities unchanged but creates a new raw
artifact identity. Reordering the tool list changes the discovery identity.
Both produce no per-tool finding and still exit 5. Exit 0 requires
byte-identical snapshots **and** no finding: identical snapshots with a
declaration-only change (for example a proposed registry that changes an
action class) report `byte_identical: true` as a snapshot fact,
`declaration_findings` > 0, outcome `review_required` and exit 5. Arrays are not sorted indiscriminately: `default`, `const`,
enum values, `items` tuples and the tool list keep their order in the exact
identities.

## Running

```sh
# Accepted Git snapshot against a candidate update.
agentfw mcp-schema-upgrade \
  --before profiles/mcp/git-readonly-v1/upstream-tools-list.json \
  --before-identity profiles/mcp/git-readonly-v1/upstream-identity.json \
  --registry /private/operator/git-profile/registry.json \
  --after /private/review/candidate-tools-list.json \
  --out /private/review/sou204-git-review
```

| Exit | Meaning |
| --- | --- |
| 0 | Analysis complete; snapshots are byte-identical and there is no finding. Nothing accepted. |
| 5 | Analysis complete; the after snapshot or the declarations differ (including declaration-only changes and unsupported constructs). Review and re-qualification are required. This is an expected product outcome, not an execution failure. |
| 2 | Invalid input or exceeded bound (also clap usage errors); nothing written. |
| 3 | An input could not be read (I/O); nothing written. |
| 4 | The output directory exists, is inside the Agent home or cannot be created. |

## Outputs

All outputs are deterministic for identical inputs and flags: no timestamps,
no absolute paths, sorted keys and content-derived ids (`F-…` findings,
`E-…` records).

- `report.json` (`sw-mcp/schema-upgrade-report/1`): inputs with raw digests,
  formats and verified identity checks; identity rules; limits; summary
  (`classification` = `byte_identical`, `raw_bytes_differ_identities_equal`,
  `inert_metadata_only`, `review_required` or `unsupported_present`); per-tool
  before/after identities, `after_identity_status` and runtime-subset support;
  findings; coverage gaps and unsupported constructs; explicit non-authority.
- `findings.csv`: one quoted row per finding. Control, bidi and invisible
  characters are escaped as `\u{…}`; a cell whose first non-space character is
  `= + - @ | %`, a full-width or minus variant, or a control character, is
  prefixed with `'`.
- `report.txt`: human-readable summary; untrusted values are escaped and
  truncated to 240 bytes.
- `review-pack.json` (`sw-mcp/schema-upgrade-review-pack/1`): proposals.
- `REVIEW_GUIDE.md`: the exact inputs and the required operator steps.

### Findings

Each finding has `tool`, `area` (`tool`, `input`, `result`, `declaration`,
`discovery`), an RFC 6901 `pointer` into the tool definition (`~0`/`~1`
escaping), an `argument_pointer` where applicable (`/0` addresses an array
item), `kind`, `nature`, bounded `before`/`after`, `detail`, reasons,
declaration references and linked example ids. Natures:

- `inert_metadata`: title/description wording, `required` or `enum` order,
  tool order; untrusted text, no validation effect.
- `review_required`: field/tool added or removed; required, type, nullable,
  enum, const, default, bounds, openness, item, dialect, hint, capability and
  result-shape changes; declared-selector, removed-tool and proposed-declaration
  differences.
- `unsupported`: changes outside the subset and after schemas the runtime
  validator does not support.
- `requalification_required`: `declaration_binding_stale`, meaning the current
  declaration binds the before schema identity. This is about acceptance, not
  the nature of the change, and it does not alter the classification.

With declarations, the analyzer maps each declared resource/destination
selector (registry `egress`, `resource_policy` selectors and bindings, or the
selectors implied by an operator-declaration authority) to the before and after
schema. It reports:

- unbound selectors;
- changed targets, including a scalar becoming an array;
- `declared_selector_requirement_relaxed`: a non-optional declared selector
  whose field is no longer required;
- new fields in tools that have declared selectors.

These findings cite the declaration in `declaration_refs`. Added subtrees list
their nested leaf pointers.

### Review pack

Records are `invocation_example`, `review_item`, `unsupported_case` or
`unconstructible`. Each carries `tool`, `finding_ids`, pointers, `arguments`
(or `null`), `check_category`, `rationale`, `source_rule`, declaration
references, `value_notes`, `limitations` and
`status: proposal_for_human_review`. Every record separates these statements:

| Field | Meaning |
| --- | --- |
| `schema_validity` | **Observed** verdict of `InputSchema::read_selected(after inputSchema).validate(arguments)` (selected-profile objects are closed): `schema_valid`, `schema_invalid` or `not_applicable` |
| `semantic_expectation` | Proposal, from one category table: `adverse_under_current_declaration` only with a stated `contradiction` of the cited declaration (today: several values through a declared single-value selector, or omission of a non-optional declared selector); `behavior_change_vs_before_schema` (a concrete schema change such as a new enum value, relaxed requirement or changed default); `unknown_requires_manual_review` (additions or shape changes whose meaning the declarations do not establish, including new fields in tools with declared selectors and new tools); `exercise_only`; `rejected_by_schema`; `unknown` (unsupported or unconstructible); `not_applicable` |
| `contradiction` | The identified contradiction with the cited declaration, otherwise `null` |
| `declaration_refs` | Relevance and traceability only; a reference alone never makes a record adverse |
| `semantic_basis` | The cited declarations, or an explicit statement that none applies |
| `runtime_enforcement` / `semantic_safety` / `human_approval` | Always `not_observed` / `not_established` / `none` |

For a declared destination that becomes an array, the pack proposes several
values through the one declared selector (schema-valid, adverse under the
declaration) and the before-schema scalar shape (observed schema-invalid).
Values are schema-shaped placeholders (`sw-review-placeholder…`), enum/const
members, or values copied from the snapshots. Values at declared selectors must
be replaced by the operator. When no bounded example exists, an
`unconstructible` or `unsupported_case` record says so.

A passing schema check establishes no semantic safety, approval or
enforcement. Records are not gold labels, training data, approvals,
permission, evidence of runtime enforcement or semantic-safety
determinations.

## Operator review before deployment

The analyzer performs none of these steps. Before any deployment, the operator
must review:

1. the exact before/after snapshots and their raw, schema, definition and
   discovery identities in `report.json`;
2. the current profile and semantic declarations, which remain bound to the
   before identities;
3. every finding, especially `review_required`, `unsupported` and
   `requalification_required`, and all coverage gaps;
4. the proposed examples, including unsupported and unconstructible records,
   against the actual upstream implementation;
5. the applicable existing workflow. For an operator profile that is
   [`agentfw mcp-profile import/validate/compile`](MCP_PROFILE_AUTHORING.md).
   For the selected filesystem/Git profiles it is their reviewed installer and
   [installed pilot qualification](INSTALLED_PILOT_QUALIFICATION.md). Use them
   for the new exact identities, followed by the existing admission process.

## Fixtures and demonstration

`crates/agentfw/tests/fixtures/schema_upgrade/` is generated by
`python scripts/schema-upgrade-fixtures.py` (`--check` verifies it). Each
upgrade fixture is a **synthetic mutation** of an accepted snapshot whose raw
digest is verified first. `MANIFEST.json` records the baseline, its digest, the
mutation and the expected outcome.

`filesystem-readonly-v1.registry.json` and `git-readonly-v1.registry.json` are
**reproduced**, not observed: they are the output of the accepted installer
functions `registry(manifest, …)` on the accepted snapshots, serialized as the
installers write them. Their MANIFEST entries record the installer path and
SHA-256, the explicit call parameters and the asserted accepted base revision.
The demonstration verifies those installers are byte-identical to the base
blobs. **No committed file holds an installed filesystem/Git operator
registry**: the installer generates it into the operator's private profile at
install time. The `fs-control-*` registries are labelled synthetic controls.

Fixture and evidence files are stored verbatim (`-text`): some derive from the
CRLF-terminated accepted Git snapshot, and the CSV uses CRLF rows, so
line-ending conversion would break their recorded digests.

```sh
cargo build --locked -p agentfw
python scripts/schema-upgrade-fixtures.py --check
cargo test --locked -p agentfw --lib schema_upgrade
cargo test --locked -p agentfw --test mcp_schema_upgrade_cli
python scripts/schema-upgrade-demo.py --agentfw target/debug/agentfw --out <new evidence directory>
# Windows x64 only: execution-level process/Winsock trace (no administrator rights).
python scripts/schema-upgrade-trace-windows.py --agentfw target/debug/agentfw.exe --out <evidence directory>/windows-trace.json
```

The committed evidence is in
[`evidence/sou-204-schema-upgrade-2026-11-03/`](evidence/sou-204-schema-upgrade-2026-11-03/README.md).

## Limitations

- Semantic equivalence is decided only inside the supported subset;
  everything else is `unsupported` and needs manual review.
- The analyzer cannot know valid resources, destinations or server behavior.
  Examples are placeholders and do not show runtime enforcement.
- Absence of network and process use is supported by three separate kinds of
  evidence:
  - source inspection (a source test);
  - an execution-level Windows trace (Win32 debugger: every process creation in
    the tree and the first call of each ws2_32 Winsock/name-resolution entry
    point, validated by positive controls);
  - filesystem observation.

  The trace does not see kernel-level or raw AFD networking, and no packet
  capture was possible without elevation. No Linux or macOS trace was run.
- Output-schema changes cannot be exercised by an invocation; they produce
  review items only.
