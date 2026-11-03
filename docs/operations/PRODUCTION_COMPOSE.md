# Verified production Compose inputs

The production template keeps PostgreSQL major 16 and Redis major 7. Its dependency
references include immutable OCI index digests; the lock also records the exact
Linux amd64 and arm64 child manifest and image-configuration digests. Architecture
comes from the selected Docker daemon, including Docker Desktop's Linux engine,
not from the operator's Windows/macOS host. Other architectures refuse.

`scripts/production-compose.py` reuses this template and its existing health
checks. It is a local deployment command, not a replacement orchestrator or a
license/advisory approval gate. It checks the image configuration ID actually
present in Docker, rather than trusting the readable version tag. The Gateway
must be selected by its independently reviewed local `sha256:` image ID.

Docker's legacy image store exposes configuration IDs. Its containerd image
store can expose an OCI index ID instead. The gate keeps these identities
distinct: legacy stores must match the exact locked config ID; modern stores
must match the immutable parent index, the daemon-platform child manifest
selected with `docker image inspect --platform`, and the actual container's
`ImageManifestDescriptor`. That reviewed child manifest content-addresses the
locked config blob. A matching index without a matching platform manifest is
insufficient. The Gateway's explicit local image ID likewise binds its selected
child manifest; reports distinguish the observed parent/selected IDs from the
lock's config digest. No network lookup or image-save fallback occurs during
this check.

## Stage inputs explicitly

Build from the accepted source through the existing Dockerfile. Keep a clean
build context; `.dockerignore` excludes runtime secrets and local data. For
example, from that source checkout:

```text
docker build --file deploy/Dockerfile --iidfile <new-image-id-file> --tag soup-wall:production .
```

Read and retain the resulting image ID with the source commit and build outcome.
The tag is a convenience for build management; the deployment command requires
the immutable ID, not the tag. This records a selected built image; it does not
prove source-to-binary reproducibility of the compiler or floating build bases.

Before an offline deployment, explicitly prefetch both `images.*.image` references
from `deploy/production-images.lock.json` on the selected supported daemon. Pass
the entire `repository:version@sha256:digest` reference to `docker pull`. Do not
replace it with `postgres:16-alpine` or `redis:7-alpine`. Normal startup has no
download/build fallback, including when an image is missing locally.

Prepare an operator-owned environment file outside Git, with the variables
required by the template: PostgreSQL database/user/password, Redis password,
Gateway admin/OIDC/webhook keys, and PostgreSQL/Redis URLs. Use the Compose service
names `postgres` and `redis` for this isolated single-host network. The
[production runbook](PRODUCTION_RUNBOOK.md#before-first-deployment) describes
runtime/migration roles and cross-host PostgreSQL TLS. Never print the file or
retain expanded `docker compose config`, `docker inspect` or environment output.

## Check and start

Use the same explicit project name for every command. Do not reuse somebody
else's Compose project. The output file, if requested, must not already exist.

```text
python3 scripts/production-compose.py check --project soup-wall-production --env-file <protected-file> --gateway-image-id sha256:<reviewed-image-id> --output <new-check.json>
python3 scripts/production-compose.py preflight --project soup-wall-production --env-file <protected-file> --gateway-image-id sha256:<reviewed-image-id>
python3 scripts/production-compose.py migrate --project soup-wall-production --env-file <protected-file> --gateway-image-id sha256:<reviewed-image-id>
python3 scripts/production-compose.py start --project soup-wall-production --env-file <protected-file> --gateway-image-id sha256:<reviewed-image-id> --output <new-start.json>
```

`check` verifies the local images and effective template/configuration; it does
not claim a running or healthy application. `preflight` runs the existing
Gateway preflight without starting dependencies. `migrate` starts and verifies
the pinned dependencies before invoking the existing one-shot migration.
`start` verifies healthy dependency containers before starting the Gateway with
`--no-deps`, then checks every actual container's image ID, project/service
ownership, process/environment configuration, data-volume identity, isolation
and health. Secret values are compared in memory and never included in reports.
No Gateway startup follows a wrong/missing image,
unsupported architecture, changed source/configuration or failed dependency
verification.

Every Compose command uses `pull_policy: never`; startup additionally specifies
`--pull never --no-build`. Dependency ports stay unexposed, and the Gateway stays
on `127.0.0.1:8080`, with a read-only root filesystem, all capabilities dropped
and no-new-privileges. Existing volumes, authentication, health checks and
fail-closed Gateway policy are preserved.

The wrapper renders the explicit template once, checks its images and isolation,
then passes that frozen resolved model to Compose through stdin. The resolved
model and secrets are not written to a configuration file or report. Literal
dollar characters are escaped for the second Compose parse. Inherited Compose
files/profiles and provider/deployment environment overrides are not forwarded.
Only the specified protected environment file supplies deployment values.

The nonsecret mounted policy is retained under ignored
`target/production-compose/<project>/<policy-sha256>.yaml`. Keep this file while
its container exists: a container restart needs the same host bind source. Each
invocation checks its bytes and the original source inputs. Earlier snapshots
are retained for an explicit rollback; they are not automatically deleted.

Reports contain selected image IDs, daemon platform and canonical-LF source
configuration/lock digests. They exclude credential values, resolved URLs,
environment-file contents and Docker inspect/configuration dumps. A failure
prints a fixed category; diagnose it privately without copying raw secret-bearing
tool output into a ticket. Earlier observations remain attributed to their actual
source and inputs.

## Update and rollback

1. Back up owned PostgreSQL and Redis data and drill restoration using the
   [existing recovery procedures](PRODUCTION_RUNBOOK.md#postgresql-backup-and-restore-drill).
   Save the accepted source, image ID, dependency lock and nonsecret policy
   snapshot. Do not change or delete live data volumes.
2. Review upstream release, security and license notes before selecting new
   same-major dependency artifacts. Retrieve the exact official index, child
   manifests and configuration blobs, verify their SHA256 digests and supported
   architecture, and update the template and lock together. The lock also binds
   the canonical-LF bytes of the template, production policy, Dockerfile and
   default policy. A stale lock fails; do not edit only a tag or waive the gate.
3. Explicitly prefetch the reviewed replacement references. Stop the existing
   owned services in a maintenance window. Existing wrong-image containers are
   refused even when stopped: remove only those owned containers (without
   `--volumes`) before starting a newly reviewed closure. Run check, preflight,
   migration and start, then the existing staging/dependency acceptance.
4. For rollback, stop the owned services and select the previous accepted source,
   lock, local image ID, protected environment and retained policy snapshot.
   Remove only changed owned containers, preserving volumes. Repeat the guarded
   sequence. PostgreSQL 16 minor releases retain the data-directory major; that
   fact does not make arbitrary database/application schema downgrades safe.
   If schema or storage format changed, restore the tested compatible backup
   instead. There is no automatic rollback or major migration here.

## Source and policy observations

The lock records the exact official PostgreSQL 16.15/Alpine 3.24 and
Redis 7.4.12/Alpine 3.21 recipes and source archive hashes. Their upstream notes are
retained: [PostgreSQL 16.15](https://www.postgresql.org/docs/release/16.15/) includes
security corrections and migration considerations;
[Redis 7.4.12](https://github.com/redis/redis/releases/tag/7.4.12) includes the
cluster-bus large-message security fix. Pinning these artifacts does not certify
all bundled Alpine packages or establish an absence of vulnerabilities.

Redis 7.4 uses the upstream choice of RSALv2 or SSPLv1, as recorded in its
[exact source license](https://github.com/redis/redis/blob/7.4.12/LICENSE.txt).
The manifest makes no license-policy change or legal/release approval. The
existing runtime inventory clearance and final publication gates stay separate.

## Bounded local validation

The no-Docker unit controls are:

```text
python3 -B -m unittest discover -s scripts/tests -p test_production_compose.py -v
```

They cover image/config/architecture mismatches, source drift, startup ordering,
existing container ownership, secret-safe output and frozen policy custody.
Mocks are not actual Compose acceptance. For an owned running stack, reuse
`scripts/staging-acceptance.ps1` and `scripts/local-compose-drill.ps1`, which
exercise readiness and PostgreSQL/Redis outage/recovery without provider traffic.
Their current project and fixture environment must identify the same owned stack.
Retain actual authenticated data/restart witnesses separately from structural
controls and distinguish skipped architectures from executed targets.

The reproducible owned-stack qualification uses an already-built image whose
`org.opencontainers.image.revision` label equals the supplied accepted Gateway
source. It creates a random project and disposable credentials, runs the existing
health/dependency drill, verifies admin and database authentication, writes
PostgreSQL/Redis witnesses and verifies those witnesses plus the tenant after a
three-container restart. It also checks missing-image and wrong-owned-container
refusal without replacement. Only that owned project's containers and volumes are
removed afterwards; no deployment or external database is reused.

```text
python3 scripts/qualify-production-compose.py --run --expected-commit <clean-full-qualification-source> --gateway-source-commit <full-reviewed-gateway-source> --gateway-image-id sha256:<reviewed-image-id> --output <new-qualification.json>
```

This command requires a clean source checkout, both prefetched dependency images,
the reviewed local Gateway image, Docker Compose and `pwsh` for the existing
PowerShell drill. It sends no model-provider requests. An unavailable prerequisite
or failed negative/control remains a failed observation, never a simulated pass.
