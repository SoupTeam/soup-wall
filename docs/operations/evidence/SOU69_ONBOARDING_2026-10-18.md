# SOU-69 onboarding evidence (2026-10-18)

Acceptance of [`agentfw onboard`](../ONBOARDING.md) on owned clean Linux homes
outside the source checkout. No model, provider, network destination, package
download, real credential or private/held-out data was used. Phase 4 stays open.

## Source and assets

- Source: `main` `449bb38649b52b38cd1b6406e4f0553434b88f59` (a reviewed successor of
  the task base `fff8ba55a22f2d19b3a4554908571adc84a42fce`) with the SOU-69 changes
  in the working tree, including the review fix for PR #184 (inventory-based
  Agent-home cleanup). New source SHA-256:

  | File | SHA-256 |
  |---|---|
  | `crates/agentfw/src/onboarding/mod.rs` | `a3c0028b755037dccd22e2284afafa85277373e3d3c8463c0322dd19fb0730c4` |
  | `crates/agentfw/src/onboarding/linux.rs` | `16701f12fd87e7ee9513f696bacac4782aad1c7f18cf8e5de0783cf6c43e18ce` |
  | `crates/agentfw/tests/onboarding.rs` | `5b0906e1c6585c5f5ce3e4c85b44d0bb85e33e1feb5e8408bdaac85115bf7fa9` |
  | `scripts/onboarding-acceptance.py` | `66449810b9bcc4593ad269467a0ddf18382eeaaa08d1ed855b6ea9869cf0cd02` |

- Agent: `cargo build --locked --release -p agentfw` (rustc 1.97.0, Linux 6.18),
  SHA-256 `a3c036f7f5bb828b63d24b490372fad803656f1a6e451f6127792a8acd4588c7`, copied
  into each owned root.
- Classifier: `rule_baseline.py` `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd`,
  system Python 3.13.16.
- Reviewed server: the accepted admission fixture server
  (`81fc37feaf8109832106246e317801c7e9c49154286fd6133549751a0b328206`), its
  `notes-fixture-v1` registry generated from its own tool schemas, and the shipped default policy.

## Result

`python3 scripts/onboarding-acceptance.py --agentfw target/release/agentfw --out <evidence>`:
**9/9 scenarios, 54 checks passed** in 35 s. All owned roots were removed
afterwards ([summary](sou69/summary.json)). Every onboarding report in
[`sou69/`](sou69) was checked to contain no raw path from its root.

| Scenario | Checks | Key observations |
|---|---|---|
| `success_retry_undo` | 14 | Preview read-only; apply `verified` in 3.4 s (lifecycle start 0.8 s, self-test 1.4 s); identity, policy and registry matched; probe `verified_for_this_probe`; self-test 5/5 with its isolated scope stated; host coverage `unknown`; retry re-verified with `resumed: true`; undo restored the original entry and kept the audit log; purge removed the home and journal |
| `missing_or_wrong_classifier` | 4 | Missing source and wrong revision refused with actions; nothing created |
| `existing_active_config` | 4 | Existing Agent home is a conflict; apply refused; its files byte-identical |
| `occupied_port_foreign_listener` | 3 | Occupied port is a conflict; a listener added after preview refused apply at revalidation |
| `interrupted_and_killed_apply` | 6 | SIGINT after `lifecycle_install`: `incomplete`, journal `interrupted`, no rollback; rerun resumed to `verified`; SIGKILL during server verification, rerun `verified`; clean undo |
| `external_edit_conflicts` | 7 | Host edit after preview invalidated the plan; operator edit of the wrapped entry blocked undo (`rollback_conflict`, entry kept); apply refused while unresolved; edited `config.yaml` retained as a conflict; clean undo after resolution |
| `rollback_after_listener_race` | 4 | A listener bound while apply ran was not adopted (`incomplete`); rollback reversed lifecycle, config, registry, policy, token and the home; host config and sentinels unchanged |
| `foreign_files_in_agent_home` | 9 | Operator files in `grants/` and `onboarding/` after apply: undo `incomplete` with an `agent_home` conflict, bytes preserved, journal `rollback_conflict`, connection and lifecycle still reversed; `--purge-agent-home` also preserved them; after removal undo was clean. Files added while apply was interrupted survived the automatic rollback after a listener race (lifecycle and owned files reversed, conflict reported); undo then finished cleanly |
| `unsafe_host_config` | 3 | A `0644` host config refused; permissions unchanged |

Every scenario checks that the sentinel file, the unrelated `mcpServers`
entry, the unrelated `theme` setting and the workspace note survive, and that no
process referencing the owned root remains. The only retained files are the
documented `mcp-connection` recovery files beside the host config.

## Other checks

| Command | Result |
|---|---|
| `cargo test --locked -p agentfw --lib` | 503 passed (2 ignored, pre-existing), including 7 onboarding unit tests |
| `cargo test --locked -p agentfw --test onboarding` | 7 passed |
| `cargo clippy --locked -p agentfw --all-targets -- -D warnings` | clean |
| `cargo fmt --all -- --check` | clean |
| `python3 -m unittest discover -s scripts/tests -p 'test_*.py'` | 892 run, OK (23 skipped, pre-existing) |
| `python3 scripts/check_docs.py` | 0 errors |

## Limits

- Linux local-user profile without a service; other platforms are `unsupported`.
- The reviewed server is the accepted test fixture; real servers need their own
  reviewed registry. Profile-launched servers (for example the filesystem
  profile) are refused because the accepted connection does not configure them.
- No Claude Code session was observed: host session, hooks, other servers and
  model context are reported `unknown`.
- The self-test is isolated by design and does not prove that the configured host is protected.
