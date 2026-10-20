# Profile onboarding evidence (2026-10-20)

Acceptance of [`agentfw onboard --server-profile`](../ONBOARDING.md#original-filesystem-and-git-profiles)
with the accepted original filesystem (`filesystem-readonly-v1`) and Git
(`git-readonly-v1`) profiles, installed outside the source checkout and run as an
ordinary (non-root) user. No model, provider, private or held-out data was used.
No live-model effectiveness, arbitrary-server support, shared-host delegation or
release readiness is claimed.

## Source and assets

- Source: `main` `77a3b61` (a reviewed successor of the task base
  `bc1ab842da1e0b0362ca7adfa5a53214c7a38c59`) plus this change, measured from the
  clean tree at commit `b8e6080581c69d830a2fb29d1d7576d37300994f` (the change before
  this evidence was added). Source SHA-256 recorded by the runner:

  | File | SHA-256 |
  |---|---|
  | `crates/agentfw/src/onboarding/linux.rs` | `e52d8657d2004aed5dead3421e019a1950df11e1f61f783e31790a94e72b2469` |
  | `crates/agentfw/src/onboarding/mod.rs` | `e872d44cdb4be7666107774a87d04bc774dcb2695d8d1f9e66215402adc504d2` |
  | `crates/agentfw/src/mcp/connection.rs` | `1d9f6a0c305e4424246ec114bcf8638cb4057819c112b5470a3be25858ee8270` |
  | `crates/agentfw/src/mcp/server_sandbox.rs` | `ff6c9e304affe9d17d1490107a45f113c15446f4ec64c580fc095931a654dd7f` |
  | `scripts/onboarding-profile-acceptance.py` | `bf3529390066cb99872c8d6de479f42350a29b1553cb22ee92ec884e27d63549` |

- Agent: `cargo build --locked --release -p agentfw --bins` (rustc 1.97.0, Linux 6.18),
  `agentfw` SHA-256 `5e1ce027da02b9a839e47b50cc81f6eddaf707ca53f178020aef18659801256f`,
  `agentfw-git-sandbox` `c6016e5c993c855a0a7e90a0827411ddceea80d851bf00d39a9a07f766a8d4d6`.
- bubblewrap 0.13.1 built from the pinned archive
  (`0e85c870…217c4d`), executable `f56b4f9760efd35d6a5884735aba5c2f578a3473d721d5a0ef710089c356cc62`.
- Filesystem: official Node.js v22.22.0 `bin/node` `1bec56ef…3c7ce7c31` (the pinned
  runtime), original `server-filesystem` installed from the committed lock;
  installed package tree `da0df010dc8f5c78792f37b82e605919e34886a15edcda78e04d824743775043`;
  classifier `rule_baseline.py` `d2d43d6f…8e964676aebd`.
- Git: Git 2.51.2 built from tag `v2.51.2` (`bb5c6242…`), binary
  `aba0506da6f8c5aee0abd3e9f55e1abd95788274812b9f5f33cf69a0a15f8d45`; pinned CPython 3.11.14
  runtime `c65a77ee…c1d8c` and hash-locked `mcp-server-git` 2026.10.10; installed
  package tree `552dd921d804a308512956b7ebe457df7558bed349fd3a3217735319014f5fd1`;
  classifier `git_readonly_v1/rule_baseline.py` `8a57c58d…a068f97482d12b4a60e94302bad318474`.
- Per-installation profile, registry and policy digests are in [summary.json](profile_onboarding/summary.json).

## Result

```sh
python3 -B scripts/onboarding-profile-acceptance.py --agentfw <agentfw> --node <node> --npm <npm> \
  --bwrap <bwrap> --git <git> --git-sha256 <sha256> --git-launcher <agentfw-git-sandbox> --out <evidence>
```

**12/12 scenarios (6 per profile), 86 checks passed** in 174 s, as a non-root user;
all owned roots removed afterwards. Every report in
[`profile_onboarding/`](profile_onboarding) was checked to contain no raw path from
its root.

| Scenario | Filesystem | Git | Key observations |
|---|---|---|---|
| `full_cycle` | 15 | 15 | Calibration: the same original server, unprotected on a scratch copy, read and performed the change (`write_file` / `git_create_branch`). Preview read-only with `server_profile`, `profile_registry`, `profile_runtime` and `sandbox_support` ok. Apply `verified` through `verified_profile_witness`. The persisted entry is `/usr/bin/env -i` with exactly `PATH`, `HOME`, `USERPROFILE` and the five profile settings, then the original command and arguments, and no `env` field. The acceptance client independently read the original result (equal to the unprotected result), saw the change refused with an unchanged host workspace snapshot and continued. Retry re-verified; undo restored the original entry; purge left nothing |
| `changed_after_preview` | 5 | 5 | A changed installed dependency file (`profile_runtime`), a changed `profile.json` (`server_profile`) and a changed entry after preview each refused apply before any change |
| `missing_sandbox_support` | 4 | 4 | Inside a user namespace that forbids further namespaces, preview refused `sandbox_support`; nothing changed |
| `occupied_foreign_port` | 4 | 4 | An occupied port is a conflict; a listener that appeared after preview refused apply |
| `operator_edits` | 8 | 8 | A changed runtime after apply: `inspect` reports `unknown` and the entry fails closed (no discovery, no result, workspace unchanged). A changed `profile.json`: `unknown`. Restored: `configured`. An edited wrapped entry blocked undo (`rollback_conflict`, entry kept). Unrelated operator edits survived undo |
| `interrupted_and_retry` | 7 | 7 | SIGINT right after publication: `incomplete`, journal `interrupted`, the entry already carries the profile launch (`configured`); rerun resumed to `verified`. SIGKILL during the witness: rerun `verified`. An early interruption (after `lifecycle_install`) was undone with the entry untouched |

Timing (release build, `full_cycle` apply): filesystem 3.4 s (real-server witness
0.9 s, isolated self-test 1.0 s); Git 4.6 s (witness 2.0 s, self-test 1.1 s).

## Other checks

| Command | Result |
|---|---|
| `cargo test --locked -p agentfw --lib` | 543 passed (3 ignored, pre-existing) |
| `cargo test --locked -p agentfw --test onboarding` | 10 passed, including 3 profile refusal tests |
| `cargo clippy --locked -p agentfw --all-targets -- -D warnings` | clean |
| `cargo fmt --all -- --check` | clean |
| `python3 -m unittest discover -s scripts/tests -p 'test_*.py'` | OK (23 skipped, pre-existing) |
| `python3 scripts/onboarding-acceptance.py` (generic SOU-69 matrix) | 9/9 scenarios |
| `python3 scripts/check_docs.py` | 0 errors |

The real-server workflows (`mcp-real-filesystem.yml`, `mcp-real-git.yml`) now run
this acceptance for their profile on the exact candidate and retain its reports.

## Limits

- Linux x86-64 only; other platforms refuse `--server-profile`. One selected entry
  per transaction; no multi-server or shared-host session is configured.
- Only the two accepted read-only profiles. Resource-executor registries and other
  formats stay refused.
- The independent refusal witnesses are the profile's own unsupported-tool refusal
  and an unchanged host workspace; they do not measure live-model behavior.
- Known classifier gaps are unchanged (for example `directory_tree` remains
  unknown/Ask in the filesystem profile).
- Undo removes recorded entries and the connection's own manifest record. Other
  runtime files the Agent writes while it is used are preserved for review.
