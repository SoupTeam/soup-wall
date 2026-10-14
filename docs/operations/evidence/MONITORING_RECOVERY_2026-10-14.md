# Protected alert recovery evidence — 2026-10-14 (SOU-41)

The controlled Linux/arm64 slice passed **65 checks**, with six authenticated durable status identities across three correlated firing/resolved cycles. The raw [successful result](SOU41_linux-alert-98a7cf6.json) records source, image/binary/configuration hashes, runtime versions, observations and cleanup. This accepts the declared local notification/recovery slice; it does not establish production routing, staffed incident response, host-loss recovery, network egress denial or release eligibility.

## Exact source and reproduction

Verified clean commit: `98a7cf6f9ebfd96ac069d1d830eae2d67fa06d35`; tree `0ff5d5404d2d54954448b3c1ed48900b467ba49f`. Base main: `290e043bee52b7d97682577af2d3fd09e715e13e`. The Gateway was built from `git archive` of this commit using its locked Cargo dependencies. The local test image uses release opt-level 1, without LTO/debug information; this is not a published release image or performance benchmark. The later evidence commit changes only documentation/artifacts. The runtime JSON verifies unchanged source before and after the complete drill.

Run in a clean checkout of the verified commit with Python 3.12+, OpenSSL and a working Linux Docker daemon:

```sh
mkdir -p target
python3 scripts/linux-alert-acceptance.py --execute \
  --expected-commit 98a7cf6f9ebfd96ac069d1d830eae2d67fa06d35 \
  --out target/linux-alert-recovery.json
```

Use a fresh output path; the command refuses existing evidence. See the [Linux procedure](../LOCAL_MONITORING_ACCEPTANCE.md#current-source-linux-dependency-and-receiver-recovery) and [receiver ownership/retention instructions](../ALERT_RECEIVER.md). The [six-image inventory](../../../deploy/monitoring-images.json) pins official multi-platform manifests; the independent [architecture metadata check](SOU41_image-platform-review.json) confirms Linux amd64/arm64 entries, not execution on both architectures. Local actual execution used Linux/arm64 containers on macOS Docker Desktop (Engine 29.2.1, Compose 5.1.0). The dedicated [CI job](../../../.github/workflows/monitoring.yml) runs the same command on Linux/amd64; inspect its exact-head result before accepting that platform.

Rule evaluation remains 30 seconds, PostgreSQL/Gateway `for: 2m` and Redis `for: 1m`. The controlled fixture preserves `group_wait: 30s` but declares `group_interval: 15s` for notification scheduling; the production example remains 5 minutes. HTTPS used a fresh explicit per-run CA with strict chain/hostname verification and protected owner-only token/key/state files. The private standard Docker bridge publishes only owned loopback observer ports; PostgreSQL/Redis have no host ports.

## Raw outcomes and witnesses

| Actual fault | Wait to real rule firing | Wait to authenticated firing receipt | Wait to authenticated resolved receipt | Correlation |
| --- | ---: | ---: | ---: | --- |
| PostgreSQL | 130.073 s | 2.028 s | 24.286 s | same validated labels, startsAt and cycle ID |
| Redis | 89.458 s | 28.484 s | 28.277 s | same validated labels, startsAt and cycle ID |
| Gateway | 144.341 s | 30.364 s | 60.629 s | same validated labels, startsAt and cycle ID |

These waits cover each named polling phase, not total end-to-end alert latency or a production SLO. Raw UTC observation times and configuration hashes are in the JSON.

- PostgreSQL and Redis loss each produced readiness 503, the selected dependency gauge 0, the other dependency 1 and Prometheus `up=1`. A model request returned 503 with **zero** independent provider receipt delta for each fault. Gateway outage produced `up=0` and absent readiness rather than a fabricated readiness zero.
- Alertmanager recorded **3 failed HTTP notification attempts** while the receiver was stopped. The pinned counter is `alertmanager_notification_requests_failed_total`; whole-stage failure counts are not substituted for individual attempts.
- Restoring the receiver delivered the PostgreSQL firing notification. A second receiver restart preserved event/cycle identity; authenticated replay returned a duplicate and no new identity. The driver reinspects ownership and current loopback bindings after start/restart because ephemeral host ports can change.
- Missing/wrong credentials returned 401; malformed messages and unrelated targets returned 400. All four probes left zero durable receipts. Bearer possession and validated declared labels are distinct from proof of the sender's network identity.
- Four useful synthetic calls (before outages and after each recovery) returned the same benign response and independently appended exactly one provider record each. Each completed call also had a durable PostgreSQL audit-row witness before the next fault. This is **zero interruptions in four fixture calls**, not a general detection or availability rate.
- The final protected receipt inventory contained exactly six identities, firing/resolved for each declared alert, without truncation or unrelated rows. Only generated project services/volumes were stopped. Success cleanup was verified and its private profile removed; no paid model or real incident channel was contacted.

## Regressions and required checks

- Protected receiver: **28 passed**, including process interruption, restart/dedup, storage failure/capacity, declared source/type bounds and real TLS saturation/recovery. Pinned Alertmanager 0.34.1 `notification_reason` and `routeLabels` metadata are validated and discarded; they never authorize a source or change identity. Older payloads remain supported.
- Linux driver: **31 passed**, including actual lifecycle methods with changed external bindings, strict generated CA/leaf verification, incomplete/truncated evidence, source/ownership gates and useful/provider/audit witnesses. Both endpoint lifecycle regressions fail against the pre-fix driver.
- Pinned promtool: **7 rules validated; 18 fixture assertions passed** ([outcomes and baseline failure](SOU41_promtool-results.json)). The new brief-outage/recovery expectations fail against baseline main for the previous PostgreSQL `min_over_time` expression; the instantaneous readiness expression with unchanged `for: 2m` prevents stale firing after recovery.
- Rust: `cargo fmt --all -- --check`, locked workspace clippy with warnings denied, and locked workspace tests passed (**963 passed, 8 explicitly ignored**). No Rust code or Cargo lock changes are included.
- Python scripts: **433 run, 10 skipped, all 423 executed tests passed**. Skips are five optional Playwright fixtures and five native Windows launcher/ACL/DPAPI fixtures. Benchmark scripts: **44 tests run; 28 passed, 16 individual skips and 2 class-level skips** (explicit pinned checkout/runtime or disposable native Agent required). No skipped test is used as runtime acceptance.
- Documentation: local link check passed. Initial sandboxed suites could not bind local fixture sockets; authorized local-listener reruns passed. This was an execution-environment limitation, not successful protection evidence.

## Preserved development attempts

Incomplete attempts are retained rather than relabeled as passing. Every attempt below verified cleanup of its generated services; private failure profiles remain local and are not committed.

| Source | Raw outcome | Reason and resulting repair |
| --- | --- | --- |
| `e18edd2` | [incomplete](SOU41_linux-alert-e18edd2.json) | Internal-only Docker network suppressed published host ports; switched to an owned private standard bridge and strict actual binding inspection. No fault cycle reached. |
| `b046201` | [incomplete](SOU41_linux-alert-b046201.json) | Strict CA validation refused missing CA key usage; generated explicit CA/leaf extensions and real strict TLS regressions. No fault cycle reached. |
| `91d2635` | [incomplete](SOU41_linux-alert-91d2635.json) | Fixture omitted the Gateway admin Bearer prefix; aligned it with the existing authentication contract. No fault cycle reached. |
| `9fc65be` | [cancelled/incomplete](SOU41_linux-alert-9fc65be.json) | Stopped gracefully after actual PostgreSQL readiness/refusal checks when primary-source review identified the pinned webhook's new metadata fields and per-attempt metric. This is not a completed firing/resolved cycle. |
| `234e172` | [incomplete](SOU41_linux-alert-234e172.json) | Actual firing/retry succeeded, but the observer used the old ephemeral port after restart. A separate [read-only checkpointed SQLite witness](SOU41_independent-receiver-234e172.json) found one durable firing row after cleanup; it does not make this run complete. Refreshing owned endpoints fixed the observer. |

Acceptance requires this successful run, maintainer-reviewed code and passing exact-head CI. The local result does not mark the issue Done while external review/checks remain; earlier partial outcomes are preserved to explain actual failures. Production receiver operation still requires a declared operator, durable-disk/backup monitoring, coordinated credential/certificate renewal, retained deduplication horizon and verified incident-routing ownership.
