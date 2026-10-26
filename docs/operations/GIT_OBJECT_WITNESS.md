# Local Git object witness component (SOU-156)

The object-witness record below remains a local diagnostic component, not an
importable production attestation interface. The separate daemon-owned execution
path at the end of this document owns its real result pipe and uses the same
sealed image internally. Serialized claims never authorize result relief.

## Why result text cannot identify the object

The pinned original `mcp-server-git==2026.10.10` resolves `git_show.revision` with
GitPython. For a blob it returns the decoded raw payload; for a commit it formats
the commit and its diff. A blob can contain exactly that formatted text. The
original MCP responses can therefore be byte-identical even though the requested
full OIDs and Git object kinds differ. Headers, separators, displayed hashes and
the server's own kind claim cannot establish the formatter or object kind.

Run the owned synthetic control with an explicit original runtime and a wheel
whose SHA-256 is already in the accepted requirements lock:

```sh
python3 -B scripts/reproduce-sou156-git-object-confusion.py --run \
  --python /absolute/original-runtime/bin/python3 \
  --git /absolute/reviewed/git \
  --server-wheel /absolute/pinned/mcp_server_git.whl \
  --output /absolute/owned/new-evidence-directory
```

The command checks original initialization/discovery, pinned package bytes and
dependency versions, preserves the exact request/response lines, and compares a
commit read with a commit-looking blob read using the same request ID in separate
sessions. Both final reads occur after fixture construction; all subsequent reads
must leave the fixture's file contents and modes unchanged. An ordinary blob and
a missing full OID are independent controls. Output explicitly records the actual
Python/Git/platform and does not claim the accepted Linux runtime or confinement
was exercised merely because the package pins match.

## Component scope and boundary

Support `git_show` only, with its unchanged original arguments. Validate using the
selected existing profile grammar: `HEAD`, a full SHA-1, and literal local refs
only for the profile that already permits them. Abbreviated/ambiguous IDs and
revision expressions acquire no witness. Other operations, packed object stores,
unsupported view machinery and incomplete results remain baseline-only. Existing
profile identities, defaults, tool discovery, errors and result bytes stay intact.

Produce object facts from a descriptor-held, bounded sealed `.git` object and
metadata image which must be the **same image mounted for that execution**. This
is not a full immutable working-tree snapshot. Never
query the ambient repository later to repair or complete evidence. Hash and parse
the Git object header and payload from that image; validate the full SHA-1 before
using its kind. Record both the directly resolved object and the effective show
target, including a bounded annotated-tag peel chain when supported. A tag is not
silently relabelled as a commit. A raw or commit-looking blob remains a blob.
The pinned original/GitPython runtime also returns an original error for the
owned nonempty root-tree fixture resolved by a full OID (`path` unset). Its tree
kind is still a typed object fact; that error cannot yield a successful local
completion. The component preserves this behavior instead of supplying a listing.

The Linux adapter reuses accepted `server_profile/git/shallow_view/linux.rs`
capture/mount on the same retained `Arc<View>`. It reads the very sealed
descriptors used by that view's mount function, verifies their seals and retains
the existing leases and sticky withdrawal. It never reads from an ambient object
directory. Existing `SelectedView` selection/defaults are unchanged. A separate
additive capture entry point watches workspace entry changes and rechecks the
existing repository guards after that watch is installed. Configuration,
attributes, hooks and repository-indirection guards remain in force.

Inherited caps are **128 objects, 16 MiB image, 256 KiB per loose object,
64 refs, 256 watches, 128 directories, reference traversal depth 10 and 8 tag
peels**. No accepted cap is widened. Existing shallow/packed profile behavior
stays intact; this first witness refuses any captured packed-object image.
The local ledger allows 8 pending/completed slots and a 30-second lifetime.
These are provisional component resource limits, not Ask/grant TTL or daemon
policy. No shell, network, helpers, filters, ambient PATH or Git subprocess is
used for resolution. Original-server execution must retain the accepted
`server_sandbox.rs` launcher, confinement and budgets; this component implements
no launcher or daemon execution path.

Hold the same opened source descriptors/read leases throughout capture, pending
Ask, execution and completion. Watch relevant directories before traversal.
Mapped writers, ref movement, rename/substitution, lock files, missing entries,
watch overflow or broken proof permanently withdraw this snapshot; restoring the
old bytes cannot revive it. Unsupported filesystems/platforms fail closed for the
witness while ordinary unattested paths retain their baseline behavior.

## Implemented local record and digest domains

The local diagnostic record is `sw-mcp/git-object-witness/1`.
The following fields describe the current in-process component, not an agreed
daemon wire contract. Interface proposals and unsent coordination drafts remain
outside public documentation.
`Claim` is serializable for diagnostics but has no wire import/deserialization
API. A serialized claim cannot create a snapshot, invocation or local authority.

| Field | Bounded source and meaning |
| --- | --- |
| operation, revision | Literal `git_show`; original UTF-8 revision, at most 255 bytes, under the selected existing grammar |
| requested object | Lowercase 40-hex SHA-1 and enum `commit`, `blob`, `tree` or `tag`, derived from sealed bytes |
| effective show target | Same typed OID/kind, plus at most 8 typed tag entries; a tag ending at blob/tree refuses completion because original `repo.commit(revision)` fails |
| view identity | 32-byte image digest and distinct 32-byte generation, backed by the retained private snapshot capability |
| selected profile/schema | Existing finite profile format; nonzero 32-byte operator profile digest; raw SHA-256 of the shipped original tools-list asset |
| selected runtime closure | Nonzero opaque 32-byte reference to the closure SOU-155 will authenticate |
| invocation binding | Nonzero opaque 32-byte daemon/session/process generations supplied by the execution owner; local random 32-byte one-use invocation slot; 32-byte exact-request digest |
| result binding | 32-byte exact-response digest; response length at most 1,048,576 bytes; original JSON-RPC ID matches the request |
| completion/lifetime | Successful original result only; monotonic local expiry, cancellation and sticky withdrawal; failure consumes the local slot |

Digest domains use SHA-256 of the concatenation:
`FORMAT || NUL || u64be(domain_length) || domain || u64be(byte_length) || bytes`.
Domains are `sealed-git-image`, `original-request-wire` and
`original-result-wire`. Request and response inputs include their exact final LF
and otherwise remain unmodified. Requests are bounded to 65,536 bytes, responses
to 1,048,576 bytes. The image input is the lexicographically sorted list of
captured relative `.git` file paths, each encoded as
`u64be(path_length) || path || u64be(file_length) || sealed_file_bytes`.
Profile/runtime references are opaque inputs; the schema asset digest is ordinary
raw SHA-256, explicitly separate from those domain-separated hashes.

For independently testable local composition, private producer state can reserve
a single-use invocation slot, retain the sealed view and consume the slot on
completion or cancellation. Verification compares the complete expected context,
including request and result bytes, then consumes the witness. Opaque local
correlation is not process authentication. A serialized witness alone is
untrusted; replay, copied context, concurrent-slot substitution and use after
cancellation/expiry must fail. SOU-155 supplies the authenticated custody and
daemon binding later. Production authentication/composition remains **disabled**
until that integration is independently reviewed. Legacy/native/1 and unattested
runtimes retain baseline inspection. No signature, policy, threshold, hard floor
or SOU-109 structural parser changes belong here.

## Required acceptance before any production integration

- Commit, plain blob, commit-looking blob, tree, annotated tag and missing target
  retain their actual typed identities. Ambiguous short OIDs and unsupported
  object/view forms never acquire a complete witness.
- Ref/HEAD movement, object replacement, directory substitution, mapped writes,
  mutation during pending Ask and validation-to-use races withdraw the source.
- Original request/result bytes and errors remain exact. A different result,
  request, view generation, profile/runtime closure, session or invocation fails
  verification, even when the response text is identical.
- Concurrent calls stay isolated; cancellation consumes only its call. Replayed,
  expired and cancelled evidence fails; a fresh subsequent valid read works.
- Native Linux controls run the actual pinned original runtime against that same
  sealed image. Independently calibrated outside-file, helper execution and
  network probes distinguish refusal from a broken probe; repository state stays
  unchanged. Missing native facilities are reported as NOT_RUN, never PASS.

Implementation locations:
`crates/agentfw/src/mcp/server_profile/git/object_witness.rs`, its Linux snapshot
adapter and focused tests, this boundary note, the original-server reproducer and
a native acceptance command. Changes to shared snapshot helpers must
preserve and recheck their existing consumers. No competing launcher, new trust
root or default-profile integration is proposed.

Focused component checks (the first command can test pure parser/ledger logic
on macOS; it does not qualify Linux capture or original-runtime confinement):

```sh
cargo test --locked --offline -p agentfw --lib object_witness -- --nocapture
python3 -B -m unittest discover -s scripts/tests \
  -p test_sou156_git_object_confusion.py -v
```

Native capture/mount and original-server confinement acceptance must run on
native Linux x86_64 with supported local filesystems and the accepted pinned
Git/Python/bubblewrap profile. Missing prerequisites or unexecuted native tests
remain NOT_RUN. No production runtime authentication, IPC integration or
structural-text relief is enabled by passing local component tests.

## Daemon-owned original Git result inspection (SOU-109)

Linux operators can explicitly select a separate execution boundary for the
pinned Git profile. This does not change the legacy native result protocol.
Add to the existing enforced daemon configuration:

~~~yaml
native:
  registry_path: /absolute/private/registry.json
  registry_sha256: <exact registry SHA-256>
  liveness:
    default_lease_seconds: 10
    max_lease_seconds: 60
    maintenance_interval_ms: 500
  git_execution:
    profile_path: /absolute/private/git-profile.json
    profile_sha256: <exact profile file SHA-256>
    server_id: git
~~~

The profile must contain the exact installed runtime/package/library pins and a
workspaceIdentity observation from the intended workspace. The profile file is
an owner-controlled regular file, with no symlink ancestors; group/other writes,
hard links, oversized files and changed bytes are refused. It selects one fixed
operator server ID and workspace. It is never supplied by an MCP response.

Use the normal selected Git collector with authenticated host/child authority
and liveness. For that server ID the collector and daemon must select identical
profile values. The collector automatically uses the configured execution path
for admitted git_show/git_diff; it does not also forward that tools/call to its
idle discovery server. Other calls and server IDs keep their existing paths.
Missing git_execution keeps the previous behavior. Unsupported platforms and
prepared-run aggregate budget bindings are refused explicitly; this feature
does not silently create an additional unbudgeted process in a prepared run.

The new POST /native/git-execute/v1 contract is sw-native-git-execute/1.
Its request contains only contract_version, registry_sha256, session_id,
call_id and binding_sha256. It requires the authenticated enrolled collector
identity. A native ingress token, submitted result, serialized object witness or
formatter flag cannot create a completion. The daemon consumes the exact final
Call before asynchronous execution, including an already redeemed Ask, then
launches the pinned original server inside the existing namespace owner and
read-only confinement. It owns the original input/output pipes and mounts the
same held sealed Git image that establishes the resolved object kind. The
current session epoch, lineage, policy and exact original result binding are
checked again at completion. Only the original inspected frame can be released.

Only a proved complete formatter OID in the first header can lose the weak
LONG_B64 contribution. git_show additionally requires a directly selected
commit object; a blob with byte-identical commit text stays on baseline.
git_diff covers only its fixed original header; its working-tree body remains
untrusted. No separators or body bytes are stripped. Independent imperatives,
signatures, secret/PII findings and positive result evidence preserve their
original coupled policy floors. No policy preset, threshold, label, registry or
resource grant is relaxed. ML input and invocation conditions remain unchanged.
This is structural attribution, not a semantic declaration that arbitrary
unmatched text is benign.

There are at most two native executions per daemon and eight owned workers per
process. The existing five-second collector/exchange deadline is not increased.
A runtime, transport, size, snapshot or cleanup failure spends the Call and
returns an audited incomplete refusal, with no original frame and no fabricated
Allow result. Host cancellation may withdraw delivery after a read occurred;
withholding cannot undo an effect. The separate legacy result endpoint cannot
import or replay the private execution completion.

Run the independent Linux qualification with an already-installed, operator
reviewed base Git profile. It creates only private synthetic repositories and
homes; it downloads nothing and makes no model calls:

~~~sh
python3 -B scripts/verify-sou109-original-git.py \
  --binary /absolute/current/agentfw \
  --template-profile /absolute/installed/git-profile.json \
  --expected-commit "$(git rev-parse HEAD)" \
  --output /absolute/private/sou109-original-git.json
~~~

The report separates actual original execution from incomplete failures, checks
a commit-looking blob built from the original formatter's exact commit body,
replays, matched attacks, the production collector with the real rule baseline,
faithful original content delivery and useful continuation after refusals.
It does not qualify a Claude model, arbitrary servers, Windows/macOS, the
prepared aggregate-budget path, or claim held-out attack effectiveness.
