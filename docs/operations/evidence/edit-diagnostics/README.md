# Installed edit-session diagnosis qualification

The actual installed run passed **23/23** existing edit-session controls and
**14/14** additional diagnostic cases on source
`a7ec2de899aa55726e7488f5d31bec5044b52307`, tree
`fc1336b4e9ed706d170e52ea181b2fc359f76cc5`. A subsequent evidence-only commit
does not acquire a separate runtime execution claim.

The environment was Ubuntu 24.04, Linux x86-64, UID 1000, kernel
`6.18.54.1-microsoft-standard-WSL2`, with the installed runtime outside the
checkout on the Linux filesystem. The genuinely installed Agent/component and
pinned Claude Code used the owned loopback scripted provider without paid
inference. This environment-specific development result does not establish
live-model effectiveness or acceptance on another platform.

## Retained evidence

[qualification.json](qualification.json) is a fixed typed projection of the
original qualification report. It binds source, component and executable
identities, every case outcome, independent target metadata/digests, native
result/publication counts and owned-process cleanup. All 13 supervised host
workflows recorded stopped owned descendants. Every diagnosis preserved its
target, unrelated sentinel and selected state. Live diagnoses additionally
preserved the exact owner process start identity; closed-run observations use
the preceding owned-run cleanup witness.
Closed audits were immutable; live observations allowed only bounded,
correlated append-only lease renewals.

[manifest.json](manifest.json) binds the byte lengths and SHA-256 values of
that projection and all 14 exact typed status-command JSON responses. Local
Git attributes preserve their bytes across platform line-ending settings.
The evidence excludes raw audit, run/context/profile/config state, provider inputs,
prompts, file contents, tokens, grants, raw stdout/stderr, component archives,
binaries or private paths. Original reports, failed attempts and private
captures remain retained locally. The successful harness checked text, JSON,
default output absence, private create-new support export, manifest integrity
and omission of actual test credentials, authority and content/path canaries.

| Identity | SHA-256 |
| --- | --- |
| Agent | `c62872d5721bda10939de9fcdd94a30fc2a7de746b482424e1a8d777a9112095` |
| Claude Code | `fd5f10ff0eb58daec04900466b143ea98aab50abf208a422bc008eaec13f61f7` |
| Component manifest / ID | `03686312bb036238da24519f294296f5700ac6348f07fbf07c33c89d6f4a86c4` |
| Component archive | `b8589880226ad5053cb28a2a58ca5e39446927d0b932123afca663a52c6fe0da` |
| Original private qualification report | `cc360a478b9a32b5fa79c293f503fbdd0be9a2ed92014aed9ffe525a6bb1c5ed` |

## Frozen diagnostic inventory

| Observation | Kind | Result |
| --- | --- | --- |
| [Create/read](create-read-status.json) | Actual installed runtime | Passed |
| [Replace/read](replace-read-status.json) | Actual installed runtime | Passed |
| [Pending Ask](pending-ask-status.json) | Actual installed runtime | Passed |
| [Rejected Ask](rejected-ask-status.json) | Actual installed runtime | Passed |
| [Cancellation](cancelled-status.json) | Actual installed runtime | Passed |
| [Daemon loss](daemon-loss-status.json) | Actual installed runtime | Passed |
| [Post-publication interruption](post-publication-interruption-status.json) | Actual installed runtime, after independently observed result delivery | Passed |
| [Canary-safe support export](secret-canary-export.json) | Actual installed runtime | Passed |
| [Stale instance](stale-instance-fixture.json) | Simulated retained-state change during a real run | Passed |
| [Missing audit](missing-audit-fixture.json) | Simulated retained state | Passed |
| [Truncated audit](truncated-audit-fixture.json) | Simulated retained state | Passed |
| [Missing result after publication gate](commit-before-result-loss-fixture.json) | Simulated retained state | Passed |
| [Tampered profile](tampered-state-fixture.json) | Simulated retained state | Passed |
| [Foreign run](foreign-run-fixture.json) | Simulated retained state | Passed |

The missing-result fixture is not an observed commit-before-result-loss event.
The actual interruption occurred after one independently observed successful
tool result and one replacement publication gate. Ordinary status correctly
retains unknown commit, host delivery and model consumption: a retained gate,
allowed result or matching current target cannot establish those boundaries.

## Failed attempts and checks

The subsequent integrated CI Stop-suite parser correction and its real installed
12/12 Stop plus 23/23 refresh follow-up are recorded separately in
[CI_JSON_FIX.md](CI_JSON_FIX.md), with original failed-artifact/report hashes.

The projection retains two distinct failed original reports and their hashes:

- `1df096f2`: 5/23 base controls and 0/14 diagnosis cases passed before the
  live diagnostic rejected mismatched policy digest formats. The correction
  now tests the actual authenticated status handler and keeps canonical profile
  hashes separate from `agent-policy-json/1` runtime hashes.
- `789a7fec`: 5/23 base controls and 2/14 diagnosis cases passed. Pending Ask
  and stale-instance observations worked, but the parser treated an ordinary
  server-level MCP handshake as a native session event. The correction validates
  that exact bounded metadata separately, with a producer-sequence regression;
  it never uses the handshake as admission, execution or result evidence.

The first interrupted failed attempt has no terminal record; later checks
observed its two recorded owner/host identities absent, without proving cleanup
of every unrecorded descendant. No failed attempt is promoted to a pass. A later
host WSL startup failure required an operator restart before the final run; no
runtime deadline, acceptance threshold or host setting was relaxed.

The final implementation passed 33 focused Rust edit-session controls, strict
Agent Clippy, formatting and 14 Python controls. The earlier doctor integration
passed 8/8. A broader library run passed 957 tests and ignored 21; its sole
task-runner umask-precondition failure passed separately with its expected
environment. Windows additionally passed 37 Python/CI controls, workflow
generator consistency and documentation/diff checks. Unsupported-platform
behavior was reviewed; no fresh Windows/macOS native build acceptance is claimed.

Reproduce using the [installed edit-session guide](../../INSTALLED_EDIT_SESSION.md)
and the existing explicit qualifier with `--run --diagnose`, exact selected
Agent/Claude paths and a new absolute output directory outside the checkout.
The qualifier is inert without `--run`. Final shared CI, admission and
main merge remain reviewer-owned.
