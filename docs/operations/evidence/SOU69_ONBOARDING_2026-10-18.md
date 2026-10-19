# SOU-69 onboarding evidence (2026-10-18)

Acceptance of [`agentfw onboard`](../ONBOARDING.md) on owned clean Linux homes
outside the source checkout. No model, provider, network destination, package
download, real credential or private/held-out data was used. Phase 4 stays open.

## Source and assets

- Source: PR #184 head `528d8d7c4ac557427940d831c321d8c696e09c0c` (SOU-69 merged with
  `main` `84e76c5`, a reviewed successor of the task base
  `fff8ba55a22f2d19b3a4554908571adc84a42fce`) plus the review fix that adopts only
  known outputs of each step into the Agent-home inventory. New source SHA-256:

  | File | SHA-256 |
  |---|---|
  | `crates/agentfw/src/onboarding/mod.rs` | `a3c0028b755037dccd22e2284afafa85277373e3d3c8463c0322dd19fb0730c4` |
  | `crates/agentfw/src/onboarding/linux.rs` | `0e9f7d73516a4dbdc9a643ffe7593311e13eda226d12e9ed5a5f5dbf98ab739b` |
  | `crates/agentfw/tests/onboarding.rs` | `5b0906e1c6585c5f5ce3e4c85b44d0bb85e33e1feb5e8408bdaac85115bf7fa9` |
  | `scripts/onboarding-acceptance.py` | `8dd5683d09d51be1c0ed09df26e3cecbd9811305935d1695e66f2d72efdc819e` |

- Agent: `cargo build --locked --release -p agentfw` (rustc 1.97.0, Linux 6.18),
  SHA-256 `0e3705ca8b4a07e7b113211da460d642cbd513f60b8b898359a8f727544799c2`, copied
  into each owned root.
- Classifier: `rule_baseline.py` `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd`,
  system Python 3.13.16.
- Reviewed server: the accepted admission fixture server
  (`81fc37feaf8109832106246e317801c7e9c49154286fd6133549751a0b328206`), its
  `notes-fixture-v1` registry generated from its own tool schemas, and the shipped default policy.

## Result

`python3 scripts/onboarding-acceptance.py --agentfw target/release/agentfw --out <evidence>`:
**9/9 scenarios, 56 checks passed** in 18 s. All owned roots were removed
afterwards ([summary](sou69/summary.json)). Every onboarding report in
[`sou69/`](sou69) was checked to contain no raw path from its root.

| Scenario | Checks | Key observations |
|---|---|---|
| `success_retry_undo` | 14 | Preview read-only; apply `verified` in 2.1 s (lifecycle start 0.3 s, self-test 1.0 s); identity, policy and registry matched; probe `verified_for_this_probe`; self-test 5/5 with its isolated scope stated; host coverage `unknown`; retry re-verified with `resumed: true`; undo restored the original entry and kept the audit log; purge removed the home and journal |
| `missing_or_wrong_classifier` | 4 | Missing source and wrong revision refused with actions; nothing created |
| `existing_active_config` | 4 | Existing Agent home is a conflict; apply refused; its files byte-identical |
| `occupied_port_foreign_listener` | 3 | Occupied port is a conflict; a listener added after preview refused apply at revalidation |
| `interrupted_and_killed_apply` | 6 | SIGINT after `lifecycle_install`: `incomplete`, journal `interrupted`, no rollback; rerun resumed to `verified`; SIGKILL during server verification, rerun `verified`; clean undo |
| `external_edit_conflicts` | 7 | Host edit after preview invalidated the plan; operator edit of the wrapped entry blocked undo (`rollback_conflict`, entry kept); apply refused while unresolved; edited `config.yaml` retained as a conflict; clean undo after resolution |
| `rollback_after_listener_race` | 4 | A listener bound while apply ran was not adopted (`incomplete`); rollback reversed lifecycle, config, registry, policy, token and the home; host config and sentinels unchanged |
| `foreign_files_in_agent_home` | 11 | An operator file written to `grants/` while `verify_server` ran was not recorded and survived undo. Operator files in `grants/` and `onboarding/` after apply: a retry stayed `verified` and did not record them; undo `incomplete` with an `agent_home` conflict, bytes preserved, journal `rollback_conflict`, connection and lifecycle still reversed; `--purge-agent-home` also preserved them; after removal undo was clean. Files added while apply was interrupted survived the automatic rollback after a listener race (lifecycle and owned files reversed, conflict reported); undo then finished cleanly |
| `unsafe_host_config` | 3 | A `0644` host config refused; permissions unchanged |

Every scenario checks that the sentinel file, the unrelated `mcpServers`
entry, the unrelated `theme` setting and the workspace note survive, and that no
process referencing the owned root remains. The only retained files are the
documented `mcp-connection` recovery files beside the host config.

## Other checks

| Command | Result |
|---|---|
| `cargo test --locked -p agentfw --lib` | 525 passed (3 ignored, pre-existing), including 11 onboarding unit tests |
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
