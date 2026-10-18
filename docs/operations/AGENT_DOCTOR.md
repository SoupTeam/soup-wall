# Installed Agent doctor (SOU-74)

`agentfw doctor` is a **read-only troubleshooting command** for an already installed,
operator-owned Linux Agent. It does not install, repair, apply policy, modify
Claude/MCP host settings, start/stop services, send telemetry, invoke tools or
models, read raw audit data, or run a self-test.

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
