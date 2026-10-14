# Local monitoring acceptance

The original local checkpoint exercises the published Windows Gateway with real
Prometheus, promtool and Alertmanager, then receives authenticated firing and
resolved webhooks on a disposable loopback server. It stops and restarts only
the Gateway process that it started. It sends no model requests or external
notifications and does not require PostgreSQL or Redis.

The current-source Linux/Docker procedure is described below. Its persistent
receiver, real dependency failures and evidence are a separate acceptance slice;
the historical Windows procedure and result remain unchanged.

The [independent Windows evidence](evidence/LOCAL_MONITORING_2026-10-05.md)
records a complete 26/26 run against the published v0.4.0 Gateway, including
matched authenticated firing/resolved receipts and successful cleanup.

This establishes local scrape-outage detection and delivery. Managed TLS,
deployment routing, receiver ownership, staffed critical notifications and
dependency-specific alert delivery still require the
[staging drill](STAGING_DRILLS.md). The Gateway's separate `policy.deployed`
webhook is not a security alert and is not exercised by this procedure.

## The outage rule

`deploy/prometheus-alerts.yaml` now contains seven rules. The new
`LLMFirewallGatewayTargetDown` selects `up{job="soup-wall-gateway"} == 0` for
two minutes, with the existing 30-second rule-group evaluation interval.
Configure the matching named scrape job: changing its name without updating
the rule disables this coverage.

An unavailable Gateway stops exporting its readiness metric. A missing or
stale sample does not become zero; therefore the existing readiness rule
cannot replace scrape-target outage detection. The dependency rules inspect the
current readiness sample. Their pending intervals still apply; recovery must
resolve rather than preserve a historical failure sample. The evidence-loss rules remain
unchanged. See Prometheus's
[staleness semantics](https://prometheus.io/docs/prometheus/latest/querying/basics/#staleness)
and [rule-test format](https://prometheus.io/docs/prometheus/latest/configuration/unit_testing_rules/).

The regression fixture covers a healthy target, stopped target with a stale
readiness metric, an unrelated failed job, the two-minute pending interval,
recovery, and a genuine zero-readiness dependency failure while the target
remains reachable:

```text
promtool check rules deploy/prometheus-alerts.yaml
promtool test rules deploy/prometheus-alerts.test.yaml
```

The acceptance harness also runs this fixture against the exact pre-change
rules at `934653821f73dd702dfe5b8977c6c5ea751ad28a`. It requires the missing
target-down alert to fail that baseline, and the current rules to pass.
Keep that Git object available; a shallow checkout may need its history.

## Portable Windows reproduction

Use Python 3.12 or later. No Python packages, global services, Docker or
certificate-trust changes are needed. The current executable/archive check
is intentionally bound to the Windows AMD64 v0.4.0 Gateway release. It does
not claim execution coverage for other platforms or arbitrary source builds.

From a source checkout, fetch the official pinned portable archives:

```powershell
python scripts/fetch-monitoring-tools.py
```

The explicit command downloads Prometheus 3.15.0 (114,650,144 bytes) and
Alertmanager 0.34.1 (40,131,065 bytes), about 147.61 MiB total. It verifies
the pinned SHA-256 of each official archive and official checksum inventory
before extracting into this checkout's ignored `target/monitoring-tools`.
It keeps the original archives, LICENSE, NOTICE and a manifest. It refuses
different existing files, linked target directories and paths outside target.
Release sources are
[Prometheus 3.15.0](https://github.com/prometheus/prometheus/releases/tag/v3.15.0)
and [Alertmanager 0.34.1](https://github.com/prometheus/alertmanager/releases/tag/v0.34.1).

Obtain the published v0.4.0 Windows Gateway archive and extract it using the
[release verification procedure](LOCAL_RELEASE_ACCEPTANCE.md#gateway-and-sqlite-console). The harness checks
both the pinned archive SHA-256 and the selected Gateway's equality with
its archive member. Set the two paths below to those verified files:

```powershell
$gatewayArchive = 'C:/absolute/path/soup-wall-v0.4.0-x86_64-pc-windows-msvc.zip'
$gatewayBinary = 'C:/absolute/path/extracted/llm-firewall.exe'
python scripts/local-monitoring-acceptance.py
python scripts/local-monitoring-acceptance.py --execute `
  --gateway $gatewayBinary --gateway-archive $gatewayArchive --artifact-label v0.4.0 `
  --prometheus target/monitoring-tools/prometheus-3.15.0.windows-amd64/prometheus.exe `
  --promtool target/monitoring-tools/prometheus-3.15.0.windows-amd64/promtool.exe `
  --alertmanager target/monitoring-tools/alertmanager-0.34.1.windows-amd64/alertmanager.exe `
  --tools-manifest target/monitoring-tools/manifest.json `
  --out target/local-monitoring-evidence.json
```

The first command prints a manifest and starts no processes. `--execute`
reserves a fresh writable evidence output before running any executable;
an existing output is never overwritten. Use a new filename for each run.
Allow about three to five minutes: the real rule keeps its original two-minute
duration, and the harness waits for both firing and resolved delivery.

The harness verifies official archives, executable and license bytes, copies
the rule/test snapshots, validates configuration, scrapes the healthy Gateway,
stops it, observes `up=0` with readiness absent, verifies pending then firing,
and restarts it. The authenticated resolved receipt must match the firing
cycle's `startsAt`. The unchanged readiness rule must not be misreported as
firing from an invented zero. Receiver tests reject missing/wrong credentials,
unrelated targets and malformed payloads.

Generated tokens, SQLite state, child profiles and logs live in one fresh
private directory beneath this checkout's unlinked ignored target. Windows
uses a current-user DACL before writing credentials; POSIX permissions apply
to the free tests. Child environments omit inherited provider keys and proxies.
All listeners bind to numeric loopback. Alertmanager clustering is disabled;
HTTP requests and notification delivery reject redirects. The receiver's
random bearer token stays in its private credential file and memory. Evidence
contains source/archive/binary/configuration hashes, timings and aggregate
receipt metadata, without tokens or raw logs.

Normal completion stops owned processes and removes only the directory created
by that run. A process-stop or cleanup failure leaves `status=incomplete`,
records a sanitized error type and returns a nonzero exit code. Inspect any
retained owned runtime before manually removing it; the harness does not clean
unrelated or interrupted historical directories.

Free regressions run in the existing Python CI job without downloads or
monitoring executable startup:

```text
python -m unittest discover -s scripts/tests -p 'test_*.py' -v
```

## Operator configuration

[Prometheus example](../../deploy/prometheus.example.yaml) provides the exact
named scrape job and rule file. Reach `/metrics` through the private monitoring
network: the public Caddy example returns 404 for that path. Configure the
actual internal Gateway and Alertmanager targets and validate with the deployed
promtool version before rollout.

[Alertmanager example](../../deploy/alertmanager.example.yaml) uses a reserved
example receiver hostname and a protected bearer credential file. Replace both
with the selected owned receiver, preserve TLS verification, and test firing
and resolved routing. Review who receives each severity and whether the
critical route is staffed. Alertmanager's
[webhook configuration](https://prometheus.io/docs/alerting/latest/configuration/#webhook_config)
supports `send_resolved` and HTTP authentication; configure receiver retention
and deduplication explicitly. Examples are configuration guidance, not evidence
that a production receiver exists.

## Current-source Linux dependency and receiver recovery

This opt-in procedure runs Linux containers with a Gateway built from the
checkout's exact source, real PostgreSQL and Redis, Prometheus 3.15.0 and
Alertmanager 0.34.1. It uses the persistent [alert receiver](ALERT_RECEIVER.md)
with a private database and credential, an exact alert/target allowlist and a
per-run HTTPS certificate. Alertmanager trusts only that fixture CA for this
receiver; the drill does not modify the host trust store or disable certificate
verification.

Use Python 3.12 or later, Git, OpenSSL and Docker with a working Linux-container
daemon. Run from the repository root with enough Docker memory and disk for the
locked Gateway build. On macOS the processes under test are Linux containers,
not native macOS Gateway execution. WSL must use the Linux interpreter and its
Linux Docker engine. The first execution may download the declared images and
Rust dependencies; no paid service or production account is needed.

```sh
python3 scripts/linux-alert-acceptance.py
python3 scripts/linux-alert-acceptance.py --execute \
  --out target/linux-alert-recovery.json
```

The default command prints the declared execution scope and starts no services.
Execution requires a clean checkout; the Gateway is built from an archived Git
commit with the locked dependency graph. `--expected-commit <full-commit>` can
require a specific candidate. The source identity must remain unchanged through
verification. The image inventory is pinned by digest in
`deploy/monitoring-images.json`; selected runtime and binary hashes are recorded
separately.
`--execute` is the explicit fault-drill opt-in. Choose a fresh output filename;
existing evidence must not be overwritten. Keep the real one-minute Redis and
two-minute PostgreSQL/Gateway pending intervals. The complete sequence takes
longer than a simple health check because it waits for actual Prometheus rule
transitions and Alertmanager delivery. The drill preserves the 30-second rule
evaluation interval, 30-second notification `group_wait` and four-hour
`repeat_interval`. Its controlled routing sets `group_interval: 15s` to avoid an
extra grouping delay for resolved notifications; this is an explicit fixture
routing override. The production Alertmanager example retains
`group_interval: 5m`; rule pending durations and firing clocks are unchanged.

The drill must establish all of these independent observations:

1. A healthy reachable Gateway has working readiness, scrape and benign local
   behavior. The fixture sends no request to a real model provider.
2. Stopping the generated PostgreSQL service makes control-plane readiness fail
   while the Gateway remains scrapeable. The selected control-plane alert
   produces an authenticated durable firing receipt. Restoring PostgreSQL
   produces a resolved receipt for the same alert identity and `startsAt`.
3. Stopping the generated Redis service makes enabled shared-limit readiness
   fail while the Gateway remains scrapeable. Its firing and resolved cycle is
   separately witnessed after Redis recovery.
4. Stopping and restarting the generated Gateway establishes target-down firing
   and matching resolved delivery, including useful behavior after recovery.
5. A receiver outage prevents acknowledgment. Alertmanager retry after receiver
   restart is witnessed in the durable store. A duplicate authenticated replay
   and another receiver restart preserve the original deduplicated identity.
6. Missing/wrong authentication, unsupported messages and unrelated targets are
   refused without adding an accepted receipt. Only generated services and
   private fixture state are stopped or removed during cleanup.

Evidence records the source revision and file hashes, selected image/runtime
identities, configuration hashes, transition/receipt timings, rejected probes,
duplicate handling and cleanup outcome. Do not publish generated bearer tokens,
private keys, raw customer content or unredacted runtime logs. A dependency,
receiver, timeout or cleanup failure remains failed/incomplete evidence and
returns a failing command status; rerunning does not erase that result.

Run the focused free regressions before the complete fault drill:

```sh
python3 -m unittest discover -s scripts/tests -p 'test_*alert*.py' -v
```

The controlled fixture validates the stated notification and recovery boundary.
It does not establish managed PostgreSQL/Redis failover, certificate rotation,
public routing, a staffed human response or deployment acceptance. An operator
must configure the actual monitoring source and receiver ownership, preserve
retention and credentials, and collect evidence in the intended environment.
The separate policy-event outbox and historical Windows release drill are not
rerun by this procedure.
