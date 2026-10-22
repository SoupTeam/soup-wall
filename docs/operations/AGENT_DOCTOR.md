# Installed Agent doctor

`agentfw doctor` is a **read-only troubleshooting command** for an already installed,
operator-owned Linux Agent. It does not install, repair, apply policy, modify
Claude/MCP host settings, start/stop services, send telemetry, invoke tools or
models, or run a self-test. The optional pilot mode reads one explicitly selected
bounded private incident file; it never exports raw audit data.

The distinction to preserve in reports is:

- **Setup**: whether selected installed artifacts, local configuration, managed
  selection, authenticated daemon and (when explicitly selected) host MCP
  connection agree.
- **Active host-call protection**: always **unknown**. A running daemon,
  matched config pin, enabled enforcement, configured collector, recent contact
  or isolated `self-test` is not independent evidence of an actual protected
  live host call. Legacy Claude HTTP hooks fail open on timeout/error.

## From outside the source tree

Use the reviewed installed executable, not a binary found via `PATH`.

```sh
/opt/soup-wall/bin/agentfw doctor \
  --home /home/OPERATOR/.agentfw \
  --agent /opt/soup-wall/bin/agentfw \
  --json

/opt/soup-wall/bin/agentfw doctor \
  --home /home/OPERATOR/.agentfw \
  --agent /opt/soup-wall/bin/agentfw \
  --host-config /home/OPERATOR/.config/claude/settings.json \
  --server reviewed-stdio-server \
  --classifier-script /opt/soup-wall/classifier/rule_baseline.py \
  --classifier-sha256 REVIEWED_LOWERCASE_SHA256
```

The optional `--host-config` and `--server` pair passes through the existing
**read-only** `mcp-connection inspect` logic with no `--probe-tool`: only the
selected server is examined. The command refuses unverified selection.
There is no implicit server execution, synthetic test, repair or host rewrite.

The `--agent` hash is compared with the managed selected pin and with the
authenticated protection-status response. Missing or mismatched native registry
bytes, a shadow-mode daemon, foreign/occupied port, unexpected runtime identity,
unsafe token/configuration and an incomplete lifecycle transaction produce
separate reason codes and concrete next steps. The accepted production
`Config::from_yaml` validator and nonce-bound, bearer-authenticated
`protection_status::query` are reused.

`--classifier-script` with `--classifier-sha256` validates the explicit file,
**not** whether the running collector chose this classifier. Without selection,
that check is unknown. `rule-package` and non-Linux doctor profiles require
additional verification and are not claimed as covered.

## Output and exit codes

`--json` prints the versioned `sw-agent-doctor/1` record.
Otherwise a short human-readable summary prints a static reason code,
explanation and a scenario-appropriate operator command for each check.

Every check has `id`, `source`, `observed_at_ms`, `outcome` (ready, failed,
unknown, unsupported), `reason_code`, `explanation`, and `next_step`.
Unknown coverage is explicitly separate from setup readiness.

| Exit | Meaning |
|---|---|
| 0 | Selected required setup checks ready; **not** a claim of active protection |
| 3 | A required setup check failed |
| 4 | Required setup uncertain, or support export refused |
| 5 | Unsupported platform |
| 2 | Invalid CLI arguments (Clap) |

The doctor does not read an entire settings directory or discover arbitrary
host integrations; only explicitly selected installed paths are checked.
Corrections are operator decisions performed using existing commands, never
an automatic doctor mutation.

## Support bundle

Prepare an **existing, private (0700), user-owned parent directory** on Linux.
Select a **new** output directory name:

```sh
mkdir -m 700 "$HOME/agentfw-support-private"
/opt/soup-wall/bin/agentfw doctor \
  --home "$HOME/.agentfw" \
  --agent /opt/soup-wall/bin/agentfw \
  --json --support-bundle "$HOME/agentfw-support-private/case-1"
```

The command atomically publishes exactly two owner-private files to a new
directory with no replacement:

- `report.json`: allowlisted `sw-agent-doctor/1` metadata and stable reason codes.
- `manifest.json`: `sw-agent-doctor-support/1`, creation timestamp,
  report schema, SHA-256 and byte length of `report.json`.

Export uses descriptor-relative, no-follow directory traversal; private
staging, exclusive file creation, size caps, atomic no-replace rename and
cleanup of a failed stage. The input config/token files must be owned,
private, regular, single-linked and bounded. Symlinks, FIFOs, oversize inputs,
parent aliases and pre-existing support targets are refused. An output path is
printed nowhere inside the bundle.

### Bounded lifecycle inspection (review hardening)

The doctor-specific lifecycle snapshot uses the **same descriptor-relative,
no-follow, nonblocking, owner-private file reader** as diagnostic configuration
and token checks. It accepts at most 1 MiB of `versions/lifecycle.json`
then performs the normal structural validation in memory. The selected managed
binary is hashed in chunks with a strict 512 MiB limit and checked ownership,
file type, mode and single-link requirements; normal `lifecycle` operations
remain unchanged. The config SHA-256 is calculated from the **original bounded
`config.yaml` bytes** and supplied to lifecycle inspection; a rejected FIFO,
link or oversize config is never silently reopened through legacy `fs::read`.
An unsafe or missing config with a recorded process becomes
`managed_config_unverifiable`, never a verified running configuration.

Linux outside-checkout CLI regression controls use a valid recorded managed
process and inject FIFO, symlink and sparse oversized config, manifest and
managed binary inputs. Each diagnostic subprocess has an explicit three-second
timeout, confirms sanitized reason codes and checks that the manifest and
owner configuration were not rewritten. Cancellation is also covered by the
independent pre-publication private support bundle test.

**Excluded:** bearer tokens, approval grants/nonces, private keys, raw
prompts/arguments/results, full host settings or environment, raw forensic
audit fields, log archives, identifying hostnames and user file paths.
There is no upload or network delivery. Review the two exported files before
sharing: even allowlisted SHA-256 hashes, timestamps and reason codes can be
sensitive operational metadata.

## Troubleshooting recipes

| Reason code | Suggested operator response |
|---|---|
| `agent_not_installed`, `lifecycle_unverifiable` | Inspect `agentfw lifecycle status`, then select an already-reviewed installed Agent |
| `installed_binary_mismatch`, `binary_pin_mismatch` | Compare reviewed binary digest with lifecycle selection; do not execute an unknown artifact |
| `classifier_pin_mismatch` | Recheck the reviewed classifier digest and explicit path |
| `registry_pin_mismatch` | Inspect the operator-selected native registry and SHA-256; do not auto-correct the pin |
| `shadow_mode`, `runtime_shadow` | Review shadow diagnostics and follow the existing operator-controlled enforcement workflow |
| `daemon_unavailable`, `listener_unverifiable` | Inspect `agentfw lifecycle status` and `agentfw protection-status --query-only`; never adopt a listener based on port occupation |
| `runtime_identity_mismatch`, `runtime_not_managed_instance` | Resolve mismatch privately before any operator restart |
| `host_connection_unknown`, `host_connection_unsafe_or_invalid` | Run explicit `agentfw mcp-connection inspect` and review selected server/ownership state; never assume arbitrary MCP safety |
| `active_call_not_witnessed` | Use a separate operator-approved live host-call and independent audit/receiver witness |

Example versioned, synthetic (no user data) report:
[`doctor-sample.json`](evidence/sou74/doctor-sample.json).

## Verification and limitations

```sh
cargo test --locked -p agentfw --lib doctor
cargo test --locked -p agentfw --lib support_bundle
cargo test --locked -p agentfw --test doctor
cargo fmt --all -- --check
cargo clippy --locked -p agentfw --all-targets -- -D warnings
```

Tests run the compiled CLI from a temporary directory outside checkout, verify
config/classifier failures, owner settings unchanged, private no-clobber
publication, sentinel omission and unsafe input refusal. These checks do not
establish a protected live host-call witness. An owned Linux positive path
using actual installed daemon/host integration, interruption controls and
reviewed end-to-end witness remain required before final acceptance.


## Two-server Linux pilot diagnosis (SOU-114)

Use `doctor --pilot` with the installed `profile.json` files for both accepted
original read-only filesystem and Git servers and their common absolute
workspace. This is an additive mode of the same doctor. Legacy invocations and
`sw-agent-doctor/1` consumers remain valid; only selected pilot reports add a
`pilot` section with schema `sw-agent-doctor-pilot/1`. Pilot support manifests
add `pilot_schema`; the base support schema and two-file layout are unchanged.

The diagnostic reads the existing installer receipts, verifies original
schema/registry and profile-policy identities, hashes the pinned package tree
and runtime assets, and compares selected config, binary, policy and combined
registry with nonce-bound authenticated current daemon status. These are
operator-installed pins, not remote package or runtime attestation. An edited
receipt cannot authorize a new upstream schema. Classifier source selection is
checked separately; daemon status does not attest which classifier worker ran.

A selected profile/config/audit file must be owner-private, regular,
single-linked, bounded and link-free in every path component. System runtime
assets may be root-owned and readable, but cannot be group/other-writable.
Selected executable assets must also be single-linked. Cargo debug outputs can
be hard-linked to a build entry: the operator preparation workflow must stage a
private regular installation copy with the same reviewed digest before pinning
that path. Doctor refuses the build alias and never makes the copy itself.
Only the accepted installer's system-library list has an additional exception:
root-owned `/lib`, `/lib64`, `/usr/lib`, `/usr/lib64` loader aliases are resolved
through pinned Linux `O_PATH` descriptors, with at most 40 links, 1,024 steps,
128 components and 4,096 path bytes. Every ancestry/link owner must be root;
resolved directories/files cannot be group/other-writable, and the final
read descriptor must match the pinned inode and expected digest. This does
not allow a linked profile, private input or selected server executable.
The accepted package tree format includes internal relative symlinks: their
link text is hashed without opening a target. They cannot redirect a diagnostic
read. Selected profile, runtime and incident input paths themselves refuse links.
Both trees together have at most 65,536 entries, depth 32, 4,096-byte relative
paths, a 1.5 GiB total read budget and a 30-second hashing budget checked between
bounded reads. This is an I/O/byte budget, not a hard deadline for a stalled
filesystem syscall. No executable or discovery command is run.

### Reproducible operator sequence

Start with an existing reviewed installation; this sequence does not prepare it.
Substitute your private installed paths and the reviewed classifier digest.
Run it outside the checkout and workspace. The existing output parent must be
private; choose a new case name for each export.

```sh
AGENT="$HOME/.agentfw/versions/agentfw-REVIEWED_VERSION"
AGENT_HOME="$HOME/.agentfw"
FS_PROFILE="$HOME/soup-pilot/filesystem/profile.json"
GIT_PROFILE="$HOME/soup-pilot/git/profile.json"
WORKSPACE="$HOME/soup-pilot/workspace"
CLASSIFIER="$HOME/soup-pilot/classifier/rule_baseline.py"
CLASSIFIER_SHA256=REVIEWED_LOWERCASE_SHA256

"$AGENT" doctor --pilot --home "$AGENT_HOME" --agent "$AGENT" \
  --fs-profile "$FS_PROFILE" --git-profile "$GIT_PROFILE" --workspace "$WORKSPACE" \
  --classifier-script "$CLASSIFIER" --classifier-sha256 "$CLASSIFIER_SHA256"

# Explicit local export of one selected native audit event. SESSION_EPOCH and
# EVENT_SEQ are taken privately from the owned incident, never guessed from a
# current physical session ID. For retained audit, select one concrete segment.
mkdir -m 700 "$HOME/agentfw-pilot-support"
"$AGENT" doctor --pilot --home "$AGENT_HOME" --agent "$AGENT" \
  --fs-profile "$FS_PROFILE" --git-profile "$GIT_PROFILE" --workspace "$WORKSPACE" \
  --classifier-script "$CLASSIFIER" --classifier-sha256 "$CLASSIFIER_SHA256" \
  --incident-source native-audit --incident-file "$AGENT_HOME/audit.jsonl" \
  --incident-session SESSION_EPOCH --incident-seq EVENT_SEQ \
  --json --support-bundle "$HOME/agentfw-pilot-support/case-1"
```

Alternatively select `--incident-call-id NATIVE_CALL_ID` for a call/result pair.
This is the daemon call ID, not the host JSON-RPC ID. A refused invocation may
have no native call ID; use session epoch and event sequence in that case.
For a private collector JSONL report use `--incident-source collector-report
--incident-host-id-json '123' --incident-server filesystem` (or `git`). JSON
`123` and JSON `"123"` are different IDs. Collector IDs are scoped by server;
reused IDs within the selected file are ambiguous and produce unknown.

Incident lookup reads only the selected file: at most 8 MiB, 8,192 records and
64 KiB per record, strict JSON without duplicate keys, with a final newline.
It never discovers history or reads raw arguments/results into an export.
It projects only source kind, fixed boundary/reason/next-step codes, file and
selected-record digests, and completeness. Native records must match the
selected registry, original tool, epoch/reference, non-shadow verdict/release
and be within 24 hours (at most five seconds into the future). Malformed,
truncated, missing, rotated, stale, mismatched or ambiguous evidence produces
**unknown/incomplete**, never a guessed cause. Native call/result pairs remain
local assertions: the accepted audit format does not record authenticated
current instance identity. Collector classification records also lack a
trustworthy timestamp; their freshness and current-instance binding stay
unknown even when typed IDs and original schema/classifier digests match.

`setup` and the exit code describe installation readiness; an incomplete
incident lookup is reported separately in `pilot.incident`. A setup exit 0
cannot establish the incident cause or prove execution. A local result-withheld
record never implies that an already completed tool effect was undone.
Actual terminal `native_session_expired`/`native_session_ended` records can be
selected by epoch/sequence as local cleanup evidence, not a failed-call cause.
Schema/owner/transport errors returned before a native audit row exists cannot
be reconstructed from similarly named rule text: those causes stay unknown.
Current authenticated status is a separate observation. Model consumption and
active host-call execution remain unknown in every report.

| Reason | Next safe action |
|---|---|
| `pilot_runtime_unsupported` | Use the existing original profiles on Linux x86-64; do not use a fallback sandbox |
| `pilot_profile_missing_unsafe_or_invalid`, `pilot_receipt_missing_or_invalid` | Select the private original profile and inspect its existing adjacent installer receipt, registry and policy |
| `pilot_profile_workspace_mismatch` | Select the profile installed for the exact selected workspace |
| `pilot_original_identity_mismatch`, `two_server_registry_mismatch` | Compare accepted original schema/registry/policy pins; do not replace a digest merely to accept drift |
| `pilot_package_changed_or_unsafe` | Inspect the selected package, original entrypoint and lock against its receipt before launch |
| `pilot_runtime_asset_changed_or_unsafe` | Inspect the selected runtime/sandbox/Git executable pins using the existing preparation workflow |
| `pilot_git_launcher_changed_or_unsafe` | Verify the Git launcher digest and private single-linked installation copy; do not select a Cargo hard-linked build alias |
| `pilot_system_library_changed_or_unsafe` | Inspect system-library pins and root-owned loader aliases without relaxing ownership/path checks |
| `pilot_profile_changed_during_inspection` | Finish the operator installation change, then diagnose the stable selection |
| `installed_pilot_not_active` | Inspect lifecycle/enforcement configuration and use the existing operator activation workflow |
| `pilot_daemon_unavailable_or_unverifiable`, `pilot_runtime_identity_mismatch` | Query protection status and inspect lifecycle ownership; do not adopt an occupied port |
| `pilot_config_unavailable` | Inspect the private selected config before comparing current runtime identity; installed assets alone cannot establish readiness |
| `recorded_classifier_uncertainty` | Review original schema and reviewed classifier; use only the supported intended Ask workflow |
| `recorded_native_policy_refusal` | Review exact request and current action/resource policy privately; do not weaken the policy |
| `recorded_result_withheld` | Review result policy and independent effect witnesses; do not force release or claim rollback |
| `recorded_session_terminal_cleanup` | This is local session lifecycle evidence, not the cause of a call failure; use fresh authority for a new run without replay or risk reset |
| `incident_missing_or_rotated`, `incident_stale_or_future_record`, `incident_mismatched_or_ambiguous` | Select retained private original evidence explicitly; missing history remains incomplete |

The support report remains capped at **128 KiB**, with a separate manifest
below 8 KiB. Only explicit `--support-bundle` creates output, with the existing
private descriptor-safe no-clobber publisher; a pilot destination inside the
workspace is refused. No raw logs, prompts, arguments, results, authority,
credentials, environment, private paths or arbitrary exception messages are
published. No upload takes place. Review even sanitized operational metadata
before sharing it.

### Exact-source installed acceptance

`scripts/verify-sou114-pilot-doctor.py --run` is the focused acceptance driver
in the required Linux original-filesystem lane. It alone creates disposable
original filesystem/Git installations, starts its owned managed enforcing
daemon and generates a real refused request after a useful original read. Each
subsequent doctor run executes outside checkout. Independent `strace` process
observations must show only the diagnostic executable, and input/workspace
snapshots must remain unchanged. Healthy JSON/text and private export are
checked alongside changed assets, missing/stale/mismatched incidents,
malformed/oversized/linked/FIFO/public inputs and unsafe/existing export targets.
All published files and stdout/stderr are checked for planted canaries and
actual credentials; bounded raw authority/syscall/server failure witnesses stay in a separate private sibling directory and are never uploaded.
Missing assets, an unexecuted required case or an unavailable enforcing daemon
cannot yield a passing installed report. Parser fixtures and macOS unit tests
are regressions only; original installed pilot acceptance requires Linux x86-64.
