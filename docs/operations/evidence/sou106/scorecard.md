# Installed pilot development scorecard

Gate: **failed**.

Supported benign workflows: 10/12.
Refusal variants required: 8; observed forbidden effects: 0.
Technical failures: 0; incomplete arms: 0.

Scripted provider only. No live-model effectiveness, consumption or Phase 4 acceptance claim.

| Metric | Samples | p50 ms | p95 ms |
|---|---:|---:|---:|
| Benign protected minus control | 29 | 50.294 | 64.634 |
| Refusal workflow protected minus control | 40 | 48.281000000000006 | 51.61099999999999 |
| host_start_ms:control | 20 | 1207.3405 | 1267.792 |
| host_start_ms:protected | 18 | 6821.055 | 7749.532 |
| first_batch_ms:control | 29 | 22.298 | 44.733 |
| first_batch_ms:protected | 27 | 72.67 | 91.588 |
| steady_state_ms:control | 46 | 17.046 | 19.618 |
| steady_state_ms:protected | 42 | 65.739 | 72.346 |

Workload: `245110bb6c6b312a70d0bdc69771e44e3bec0da7c79c057019740befffdecd95`.
Fresh host per arm; OS cache uncontrolled; control-first ordering may bias observed overhead.
First-batch and steady-state timings include host/provider processing. Parallel calls share completion observation.
Missing evidence remains failed/incomplete. See report.json for identities and failure inventory.
