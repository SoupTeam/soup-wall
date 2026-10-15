# Local release acceptance

The 2026-10-04 checkpoint tests released binaries and isolated services. It does
not establish a managed deployment, real-provider behavior, customer-IdP
interoperability or alert delivery. Keep those gates in the
[current roadmap](../ROADMAP.md#phases) open until their own evidence
exists.

The separate [local monitoring acceptance](LOCAL_MONITORING_ACCEPTANCE.md)
procedure exercises a real scrape-target outage and authenticated loopback
firing/resolved notifications. This additional local procedure does not close
managed deployment or staffed notification-channel gates.

## Gateway and SQLite Console

Verify a release archive against that release's `SHA256SUMS`, extract it, then
run Python 3 from the source checkout:

```sh
python scripts/self-hosted-local-acceptance.py --gateway /absolute/path/to/llm-firewall --artifact-label v0.4.0 --out target/local-gateway-evidence.json
```

Use `llm-firewall.exe` on Windows. Source builds should use their exact commit
as the artifact label. The runner creates and removes its own configuration,
SQLite database, tokens, provider fixture and processes. It verifies preflight
without database creation, readiness, Console authentication, permitted proxy
traffic, an injection blocked before forwarding and persistence across restart.
It sends no external model requests. Its 15-check Windows release result is
recorded in [Gateway evidence](evidence/local-gateway-release-2026-10-04.json).

## Windows Agent

Follow [Windows Agent acceptance](WINDOWS_AGENT_ACCEPTANCE.md). The native
runner uses a separate child profile and workspace; it never edits the user's
Claude Code settings. IPv4, IPv6 and localhost runs establish daemon, hook
protocol, shadow/enforce, authorization, audit, replay and outage behavior.
An unavailable IPv6 loopback must be reported as skipped, not passed.

## PostgreSQL, Redis and recovery

Use disposable services and distinct databases. The default ignored integration
tests are explicitly selected with environment variables:

```sh
cargo test --locked -p llm-firewall tenant_store::tests::postgres_control_plane_persists_tenants_tokens_policies_and_audit -- --ignored
cargo test --locked -p llm-firewall redis_limits::tests::redis_shares_rate_and_spend_windows -- --ignored
```

Set `LLM_FW_TEST_POSTGRES_URL` and `LLM_FW_TEST_REDIS_URL` in the operator shell
first. Do not point test or restore commands at an existing customer database.
The checkpoint used PostgreSQL 18.6 and Redis 8.0.5 extracted into separate WSL
directories, loopback listeners and distinct fixture databases; it did not
modify installed services. Docker Desktop was unavailable, and an existing
interrupted WSL package configuration prevented normal package installation.
No unrelated package repair was performed.

The v0.4.0 Windows Gateway then ran with those services. Its preflight and
PostgreSQL migrations passed. The existing acceptance and dependency scripts
were run with `-AllowHttpForLocal` through Baseline, PostgresDown, RedisDown and
Recovered. Each outage kept `/healthz` at 200 and changed `/readyz` to 503;
recovery restored readiness to 200. Wait for actual readiness after starting a
dependency before recording its recovery; a successful service start alone
does not establish that the Gateway has reconnected.

The [encrypted restore script](../../scripts/postgres-restore-drill.ps1) restored
a fixture with two tenants and two security events into a separate database.
Both counts and schema version 25 were retained. A second URL spelling for the
source database was refused before backup creation, proving the same-target
guard independently of string equality. The temporary age identity and
encrypted backup stay outside Git; plaintext restore files were cleaned by the
script. Webhook and service-account tables were empty in this fixture, so this
run does not establish preservation of nonempty records in those tables.

The timestamped [dependency and restore evidence](evidence/local-dependency-restore-2026-10-04.json)
records the observed transitions and exact binary hash. It used loopback HTTP,
not a managed TLS edge. Repeat the full
[staging and restore procedure](STAGING_DRILLS.md) against the chosen managed
environment and observe its alert routing before closing the external gate.


## Candidate preparation and promotion gate (SOU-26)

Preparation builds the four platform archives, six SBOMs and OCI archive for
one already authorized existing tag. It does not publish them. Its completed
release workflow run must have successful verification, platform builds,
SBOM, container and Prepare & Freeze Candidate jobs. Retain the run ID,
attempt, source SHA and immutable candidate-package artifact ID/digest.
Do not create a tag or dispatch publication merely to test this gate.

Before promotion, an operator must independently review the product,
operator and license evidence for that exact candidate. The JSON
acceptance_record contains:

- decision: approved only after that review;
- run_id, run_attempt, artifact_id: the accepted preparation identity;
- artifact_digest: the GitHub artifact archive SHA-256, without its
  sha256: prefix;
- source_sha: the reviewed source commit;
- checksums: the exact eleven checksum records from the frozen manifest;
- evidence_ref: the actual reviewed evidence reference;
- gates.product, gates.operator, gates.license: passed only for
  gates that have actually been accepted.

This is an operator approval/checksum record, not a cryptographic signature.
Synthetic fixture approvals do not establish product or license acceptance.

For an authorized no-publication rehearsal, use the existing tag,
promote_run_id equal to the accepted preparation run and dry_run=true.
Promotion checks the API workflow/repository/event/source/attempt and successful
preparation job before downloading the exact artifact. It checks the archive
digest, the manifest attempt and exact eleven-file inventory, then hashes
the files using the approved manifest. OCI inspection runs; registry push,
tag/latest changes and GitHub Release writes must be skipped in the dry run.
Missing, failed, skipped, stale or mismatched required inputs must stop the gate.

Retain the preparation and promotion run links, the approved artifact identity,
checksum output and both publication-skipped messages. The October 14 rehearsal
of source 1dbc0112d9cbe7c2d94cbea23942d5028921a47f used preparation
[38618098605](https://github.com/SoupTeam/soup-wall/actions/runs/38618098605)
and dry-run promotion
[38625274585](https://github.com/SoupTeam/soup-wall/actions/runs/38625274585).
Its fixture record points to PR #999; it is workflow evidence only, not real
product/operator/license approval. Later validator changes require affected
positive/negative checks again; these historical runs do not execute a later
validator revision.

Actual publication remains a separate explicit release decision after all
required roadmap, security, license and runtime gates are accepted.
