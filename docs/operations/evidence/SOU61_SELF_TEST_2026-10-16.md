# SOU-61 self-test evidence (2026-10-16)

Clean-directory demonstration of [`agentfw self-test`](../SELF_TEST.md) with
selected installed runtime assets, plus the check results. No model, provider,
network destination, real credential or sealed data was used. Phase 4 stays
open.

## Source and assets

- Source: `main` `dd3fb884c09000c0c4ffa6d9fbbfb46ec1de4501` (a reviewed successor of
  the task base `d75030eedc7d1c57f97c695387dd6f973f560b46`, including SOU-48, SOU-55
  and SOU-63) with the SOU-61 changes in the working tree. Re-verified on
  2026-10-17 after rebasing. New source SHA-256:

  | File | SHA-256 |
  |---|---|
  | `crates/agentfw/src/self_test/mod.rs` | `e86d21dcc0faa0f9c724cefe8bc5296577ad0b0e7629f0593d8c6b7c7f789cb2` |
  | `crates/agentfw/src/self_test/linux.rs` | `2e85b5f42c80768b2ed1f258355bb8dca22ff0ad40a00451dbea44add16e70c4` |
  | `crates/agentfw/src/self_test/fixture.rs` | `535431e670d9162b0755b6bd5bbaaed43bbef0cd26cd1e38c46535bf08dc71ec` |
  | `crates/agentfw/tests/self_test.rs` | `2d93627b1e3986360240c77adea118ad1f4ea44316543494fa908054cf630ba6` |

- Agent: `cargo build --locked --release -p agentfw` (rustc 1.97.0, Linux 6.18,
  2 CPUs), copied with `install -m 0755` to an install prefix outside the
  repository. SHA-256 `461216e4e41bad1f180f79bf593329f5a4ee5fbb0a4067b65d0dabae5209cc12`.
- Classifier: `rule_baseline/rule_baseline.py` copied to the same prefix,
  SHA-256 `d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd`,
  run by system Python 3.13.16.

## Clean-directory run

The command ran from a new empty directory, with the report written to a
separate output directory and the default system temporary directory as the
workspace parent:

```sh
cd <demo>/clean
<demo>/opt/soup-wall/bin/agentfw self-test --agent <demo>/opt/soup-wall/bin/agentfw \
  --classifier rule-baseline --classifier-script <demo>/opt/soup-wall/classifier/rule_baseline.py \
  --classifier-sha256 d2d43d6f67719921592bba4d52e73c0f0543c5b1f1b24c75b88e8d964676aebd \
  --classifier-python /usr/bin/python3 --report <demo>/out/self-test-report.json
```

Result: **passed, exit 0**, 0.96 s in total
([report](sou61/self-test-report.json), [console](sou61/stdout.txt)).

| Scenario | Witnessed |
|---|---|
| `allowed_read` | Exact 54 expected bytes; 1 MCP child execution with the original frame; result bytes unchanged; 0 deliveries |
| `adversarial_result` | 1 execution; result withheld (`ask-injection-in-result`); marker never reached the client |
| `protected_send_refused` | Refused (`deny-secret-egress`, native audit `deny`); 0 MCP child executions, 0 receiver connections |
| `useful_read_after_refusal` | Exact 55 expected bytes; 1 execution |
| `daemon_loss` | Owned daemon killed; collector closed; 0 executions, 0 receiver connections |

Classifier receipts for the first four scenarios show `rule-baseline/python`,
the pinned revision and `policy: reached`. The configured section records one
start attempt, health `enforce: true`, and authenticated status with the owned
daemon PID, mode `enforcing`, registry `sw-self-test-fixture-v1` (2 tools) and
the same binary SHA-256 as the Agent. Per-call latency (scripted client write
to reply, release build) was 45 to 51 ms. The opt-in SOU-48 Ask approval path
was not enabled, so Ask stays a correlated refusal.

Cleanup: collector and daemon reaped with empty process groups, receiver socket
closed, workspace removed. A probe before and after the run found no
`agentfw-self-test-*` temporary directory, no process referencing one, an
absent operator `~/.agentfw` both times, and the clean directory still empty.
The report contains no `/tmp`, `/root`, `/home` path, token, marker or
synthetic key.

## Actionable incomplete

The same command with a wrong `--classifier-sha256` stopped before starting
anything: **incomplete, exit 4**, every scenario `unavailable`, with the
explanation "the classifier source does not match --classifier-sha256 (wrong
revision)" ([report](sou61/self-test-wrong-revision.json),
[console](sou61/stdout-wrong.txt)).

## Checks

| Command | Result |
|---|---|
| `cargo test --locked -p agentfw --lib self_test` | 10 passed |
| `cargo test --locked -p agentfw --test self_test` | 6 passed (29 s, debug build) |
| `cargo clippy --locked -p agentfw --all-targets -- -D warnings` | clean |
| `cargo fmt --all -- --check` | clean |

The integration suite covers a full pass after a forced port collision (an
unrelated listener on the preferred port, which was left untouched), SIGINT
during startup (exit 4, `Interrupted`, workspace removed, no remaining
process), missing and wrong classifier revisions, a stand-in Agent whose daemon
cannot start (three `port_in_use` attempts, exit 4), refusal to replace an
existing report and the fixture server's destination check.

## Limits

- Scripted client frames: not Claude Code, model context or live-model effectiveness.
- One bundled fixture server with two tools; other servers need their own reviewed registry.
- Linux only. A debug daemon can need several seconds to become healthy on a
  small host (up to about 13 s observed on the earlier base); each start attempt
  allows 30 s. The release build was healthy in well under a second.
- No release or publication is part of this task.
