# Opt-in managed rollout reconciliation (SOU-226)

Console can evaluate persisted acknowledgement gates without an open browser,
Agent traffic or an Owner `advance` request. It is disabled by default.

```yaml
rollout_reconciliation:
  enabled: true
  interval_seconds: 5
  batch_size: 32
```

Enable only with `tenant_store.enabled: true`. Intervals are 1–300 seconds;
pages contain 1–100 plans. Startup scans immediately. Each tick reads one
ordered keyset page across active tenants, wraps after an empty page, and
attempts each plan independently. A blocked early plan cannot starve later
plans. Detection latency depends on the active fleet size and configured page
and interval; this is not an immediate-deadline guarantee.

Only persisted pilot, standard and rolling_back plans are discovered. Paused
plans stay paused. Before mutation the saved rollout identity is rechecked in
SQLite's immediate transaction or PostgreSQL's existing tenant lease. Manual
operations and ACKs use the same engine. A stale discovery result cannot advance
a replacement rollout. Frozen cohorts, policy digests, deadlines, supersession,
revocation and exact baseline ACK requirements remain authoritative. A timeout
never fabricates an applied acknowledgement.

Missing signing authority leaves issuance and transition rolled back together.
Database errors leave persisted work recoverable; later ticks retry. No new
persistent table or migration is introduced, and the strict recovery inventory
is unchanged. Process restarts rediscover work from persistence. SIGINT/SIGTERM
stop scheduling between transactions; an in-flight transaction finishes before
the worker joins. Abrupt termination relies on backend atomicity.

Read-only authenticated diagnostics:
`GET /admin/v1/tenants/:tenant/groups/:group/rollout/reconciliation`.
The response reports configuration, worker running state, last discovery time,
discovery availability and the latest cached observation for that exact scope.
A blocked observation contains a bounded reason code, never an exception,
credential or policy payload. The diagnostic cache holds at most 256 observations;
an absent observation means unknown, not healthy. Diagnostics are per process,
reset on restart, and never trigger reconciliation. Persisted rollout status and
Agent acknowledgements remain the outcome authority.

## Runnable acceptance

```sh
cargo test --locked -p llm-firewall --test managed_reconciliation
SOUP_RECONCILIATION_TEST_POSTGRES_URL="$OWNED_DISPOSABLE_DATABASE_URL" cargo test --locked -p llm-firewall --test managed_reconciliation postgres_reconciliation_controls -- --ignored
cargo build --locked -p llm-firewall -p agentfw
python3 -B scripts/managed-group-rollout-demo.py --no-build --reconciliation --output target/group-reconciliation-sqlite.json
```

The real-process witness waits 305 real seconds with Console and all four Agents
stopped, restarts Console without a browser or manual transition, observes the
same saved plan issue one rollback, and verifies rollback stays pending until
the real pilot applies the exact higher-sequence baseline and acknowledges it.
`--downtime-seconds` cannot be below 301. For PostgreSQL use `--backend postgres`
and the demo's existing explicitly owned disposable source/empty-restore database
variables. Never point the acceptance command at production. The existing
`managed-group-rollout.yml` workflow runs both backends and retains sanitized
successes and failures.
