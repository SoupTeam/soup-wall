# SOU-81: native Windows classifier package lifecycle and bounded worker runtime

Date: 19 October 2026. Owner: @Sundetali7. Base: `main` at 215b99e.

## Scope and claims

- The SOU-64 installable classifier package and its bounded persistent worker now run on
  native Windows x86_64 (local NTFS) with the same commands, pins, selection variable,
  worker protocol and deadlines as the Unix profile. Operator documentation:
  [CLASSIFIER_RUNTIME.md](../../../docs/operations/CLASSIFIER_RUNTIME.md).
- **No classifier change and no generalization claim.** Frozen
  `rule_baseline/rule_baseline.py` (sha256 `d2d43d6f…aebd`) and revision 2
  (`d0b4fc02…3ea5`) are byte-identical; the revision-2 package is installed and rolled back
  but never used for admission; revision 2 is not enabled in production. The sealed
  SOU-13/SOU-16 test was not opened or run. Classification semantics and policy precedence
  are unchanged.
- Everything below was measured on one Windows developer machine (debug build, CPython
  3.14.5, `C:\Users\User\AppData\Local\Programs\Python\Python314\python.exe`, sha256
  `3adbbf2a…93cd`) unless it says CI. Hosted-runner evidence is produced by
  `.github/workflows/classifier-runtime-windows.yml` as a run artifact.

## Files

| File | What it shows |
| --- | --- |
| `windows-parity.json` | Persistent worker output is byte-identical to the single-shot adapter on the 66 permitted public development/regression cases, both revisions, one worker process serving all calls. Transport parity only; it says nothing about classification quality. |
| `windows-latency.json` | Cold start (15), warm call (300) and single-shot (20) distributions for both revisions; cold-start deadline finding. |
| `windows-acceptance.json` | The production collector and daemon, run from a clean installed directory (copied executable, profile holding only the installed package, minimal environment, no repository sources, no Cargo, no `PYTHONPATH`, no provider access). Source commit and executable, package, interpreter and classifier identities; lifecycle through the installed CLI; repeated calls; independent sessions with separate workers; denied calls with zero execution witnesses at the server and the loopback receiver; continuation; recovery after a killed and a hung worker; cold/warm distributions through the collector; the scripted admission matrix. Every check passed. |

## Cold-start deadline sensitivity

The worker start deadline (1.4 s) and request deadline (1.4 s) are unchanged and there are no
retries. Direct worker cold start: p50 274 ms, p95 315 ms, max 343 ms over 30 starts (two
revisions). Through the real collector: 5 cold starts, slowest 246 ms in the final run
(265 ms in an earlier run), 125 warm calls, 0 failures. The slowest observed start used
roughly a quarter of the budget, so no deadline was relaxed and nothing was masked. A first
launch of a freshly installed interpreter on a machine with aggressive scanning could exceed
the budget; the correct outcome there is a refused call, which the failure tests show is
what happens (`not_reached:classifier_error`, nothing executed, next call starts a fresh
verified worker).

On the hosted `windows-2022` runner (run 39306638704, CPython 3.12.10) the direct worker first
call measured p50 87.7 ms, p95 99.5 ms, max 103.7 ms (frozen) and p50 85.1 ms, p95 85.8 ms,
max 88.0 ms (rev2), 15 starts each; warm calls p50 0.32 ms, p95 0.44 ms, max 0.63 ms, 300
calls each; single-shot p50 52.0 ms (frozen) and 53.8 ms (rev2), 20 calls each. The
production-collector acceptance run on the same runner passed 50 of 50 checks, with 5 cold
collector starts (slowest 155 ms) and 125 warm calls without a failure. One run; not a guarantee.

In one other hosted run the first worker call of a test process failed. By the log
timestamps the test took 2.1 s instead of 0.8 s, which is consistent with the 1.4 s start
deadline but not proven: the error text was not captured. The deadline was not relaxed and no
retry was added; the tests now start the interpreter once before creating the first profile
and print the worker error if a call fails.

## Not covered

Windows on ARM, network shares, ReFS, redirected profiles, multi-user and service-account
installs, Microsoft Store Python, release builds, and the SOU-71 installed-Agent self-test
(out of scope). Latency figures are one machine and one run each.
