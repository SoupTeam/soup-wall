# Soup Wall documentation

The canonical repository is [SoupTeam/soup-wall](https://github.com/SoupTeam/soup-wall).
Start with the [project README](../README.md) for the Agent, Gateway and Console
overview. Choose a guide below for development, operation or evaluation.

## Development and project navigation

| Guide | Purpose |
| --- | --- |
| [Development](DEVELOPMENT.md) | Prerequisites, platform differences, first build, local baseline and focused checks |
| [Clean setup and status preparation](operations/CLEAN_SETUP_ACCEPTANCE.md) | Disposable Agent installation, truthful daemon-status evidence and read-only scanning audit |
| [Contributing](../CONTRIBUTING.md) | Pull request expectations, regression cases and compatibility rules |
| [Architecture](ARCHITECTURE.md) | Workspace source map and decision boundaries |
| [Source provenance](PROVENANCE.md) | License intake, attribution and the current dependency/advisory boundary |
| [Security](../SECURITY.md) | Threat limitations and private vulnerability reporting |
| [Changelog](../CHANGELOG.md) | Released changes |

## Product and operator guides

| Guide | Purpose |
| --- | --- |
| [Self-hosting](SELF_HOSTING.md) | Build and run the Agent, Gateway and optional Console |
| [Managed Agent lifecycle](operations/AGENT_LIFECYCLE.md) | Install, verify, upgrade, roll back and remove a user-scoped Agent |
| [Native Windows onboarding](operations/WINDOWS_ONBOARDING.md) | Preview, apply, verify, recover and remove one owned Windows MCP setup |
| [Upgrading](UPGRADING.md) | Existing deployment compatibility and migration guidance |
| [Production runbook](operations/PRODUCTION_RUNBOOK.md) | Readiness, operations, alerts and recovery |
| [TLS rotation and recovery](operations/TLS_ROTATION.md) | Disposable Caddy certificate rotation, verifying clients and recovery |
| [Encrypted Console recovery](operations/CONSOLE_RECOVERY.md) | Complete current-state inventory, isolated encrypted restore and live managed Agent recovery |
| [Staging drills](operations/STAGING_DRILLS.md) | Explicit dependency and restore acceptance procedures |
| [Guarded execution](operations/SANDBOX.md) | Supported process, file and retrieval boundaries |
| [Windows Agent acceptance](operations/WINDOWS_AGENT_ACCEPTANCE.md) | Native installation, ACLs, hook posture and loopback configuration |
| [Claude HTTP-hook acceptance](operations/CLAUDE_HOST_ACCEPTANCE.md) | Actual host behavior with deterministic local model fixtures |
| [Agent self-test](operations/SELF_TEST.md) | One Linux command: witnessed useful reads, a refused synthetic send, daemon loss and a versioned report |
| [Offline Agent audit explorer](operations/AGENT_AUDIT_EXPLORER.md) | Private Linux JSONL report generation, decision timeline, filters and evidence limits |
| [Bounded Agent audit retention](operations/AGENT_AUDIT_RETENTION.md) | Opt-in Linux segments, crash recovery, private verified export and loss-aware browsing |
| [Roadmap support and evidence report](operations/ROADMAP_SUPPORT_REPORT.md) | Offline exact-source support matrix, evidence validation, private report and review boundaries |
| [Opt-in stdio MCP admission](operations/MCP_STDIO_ADMISSION.md) | Reviewed schemas, pre-execution calls and result release to the MCP host |
| [Native MCP diagnostic output](operations/NATIVE_MCP_STDERR.md) | Bounded discarded child stderr, safe metadata, owned cleanup and required Linux evidence |
| [Sandboxed real filesystem MCP](operations/MCP_REAL_FILESYSTEM.md) | Explicit pinned Linux read-only server, bounded overlap/cancellation and required actual-host acceptance |
| [Linux MCP resource budgets](operations/MCP_LINUX_RESOURCE_BUDGETS.md) | Opt-in delegated aggregate memory, CPU and task limits, wall expiry and independent Linux witnesses |
| [Linux MCP crash supervision](operations/MCP_LINUX_CRASH_SUPERVISION.md) | Owned collector-loss cleanup, private PID 1 supervision, restart isolation and independent native witnesses |
| [Claude Code MCP connection](operations/CLAUDE_MCP_CONNECTION.md) | Selected-server preview, transactional setup, controlled verification and safe disconnect |
| [Native resource admission](operations/NATIVE_RESOURCE_ADMISSION.md) | Resource permissions, receipt integrity and unsupported executor boundary |
| [Provenance memory budgets](operations/PROVENANCE_MEMORY.md) | Retained-byte/context limits, saturation refusal, safe retirement and required owned Linux evidence |
| [Constrained MCP file creation](operations/MCP_CREATE_FILE.md) | Linux create-only workspace files, bound authority, effect accounting and actual stdio verification |
| [Constrained MCP HTTPS GET](operations/MCP_HTTPS_GET.md) | Exact URL/address authority, verified TLS, bounded responses and independent receiver witnesses |
| [Constrained Windows MCP reads](operations/MCP_WINDOWS_READ.md) | Handle-bound local document reads, explicit v4 authority and native standard-user verification |
| [Constrained Windows MCP file creation](operations/MCP_WINDOWS_CREATE.md) | Exact v5 create authority, retained parent handles, atomic no-overwrite publication and native verification |
| [Identity interoperability](operations/IDENTITY_INTEROPERABILITY.md) | Local identity fixtures, external metadata probes and pilot gates |
| [Keycloak SAML acceptance](operations/KEYCLOAK_SAML_ACCEPTANCE.md) | Pinned vendor-runtime setup and signed SAML checks |
| [Linux SAML lifecycle](operations/KEYCLOAK_SAML_LINUX.md) | Genuine browser login, PostgreSQL sessions and explicit signing-key rotation |
| [Keycloak OIDC Console acceptance](operations/KEYCLOAK_OIDC_ACCEPTANCE.md) | Real browser sign-in, local roles, sessions and Console logout |
| [SSO acceptance diagnostics](operations/SSO_ACCEPTANCE_DIAGNOSTICS.md) | Bounded evidence, cleanup, focused reruns and honest batch outcomes |
| [Local release acceptance](operations/LOCAL_RELEASE_ACCEPTANCE.md) | Downloaded binary and archive acceptance scope |
| [Classified read seam evidence](operations/CLASSIFIED_READ_EVIDENCE.md) | Reproduce the Task 2 test-double read through protected MCP admission |
| [Local monitoring acceptance](operations/LOCAL_MONITORING_ACCEPTANCE.md) | Historical Windows scrape outage and current Linux dependency/receiver recovery |
| [Persistent alert receiver](operations/ALERT_RECEIVER.md) | Authenticated durable receipts, retention, deduplication and operator recovery |

## Benchmarks and evaluation

| Guide | Purpose |
| --- | --- |
| [Methodology](methodology.md) | Corpus, classifier and evidence methods with claim limits |
| [Local learned classifier preparation](../experiments/local_classifier/README.md) | Masked-label training, separate calibration and approved-data shadow pilot commands |
| [Experimental classifiers](../experiments/classification/README.md) | Offline Jev adapter, shadow comparison, access limitations and adoption decision |
| [Generated scorecard](benchmarks/agent-security-scorecard.generated.md) | Exact output compared by CI; regenerate through the benchmark command |
| [Independent historical replay](benchmarks/independent-history-replay.md) | Pinned historical evidence and the original adapter's semantic limits |
| [AgentDojo runtime adapter](benchmarks/agentdojo-live-fallback.md) | Pinned runtime fixtures and explicit live-evaluation prerequisites |
| [AgentDojo matched protocol](benchmarks/agentdojo-matched-protocol.md) | SOU-36 frozen plan, live gate, pair validation and independent report (Phase 4 stays open) |
| [Task 3 resilience](benchmarks/task3_resilience.md) | Malformed events, unknown tools, daemon failures and independent execution witnesses |
| [SOU-17 verification](benchmarks/sou17_verification.md) | Failure, overlap, replay and native witnesses; exact-source reproduction and code-scanning triage |
| [Native admission](benchmarks/native-admission.md) | Installed tool semantics, invocation binding and result/context contracts |
| [Corpus documentation](../crates/bench/corpora/README.md) | Versioned synthetic agent-session labels and provenance |
| [SOU-13 family-held-out pilot](benchmarks/sou13/README.md) | Candidate CP1/CP2 source, public data-free checks, private validation procedure and acceptance status (no released data or gold labels) |

## Status and retained evidence

- [Read-only Git MCP profile](operations/GIT_MCP_PROFILE.md): original-server pins, bounded operations, private installation and exact-source Linux acceptance.

[ROADMAP](ROADMAP.md) records the tagged baseline, product principles,
dependency-ordered phases, open decisions and one final release gate. Internal
drafts and personal notes stay locally under ignored `local-notes/`.
Generated planning output under `docs/plans/`, `docs/superpowers/` and
`.superpowers/` also stays local. One-off review and alert-triage notes are kept
in `local-notes/reviews/`; public aggregate evidence remains versioned.
Dated evidence records refer to their original source commit and environment
and may mention historical paths. They are not automatic claims about the latest
checkout.

Reviewed aggregates and explanatory records are retained under
[operation evidence](operations/evidence) and
[benchmark evidence](benchmarks/evidence). Useful entry points include the
[Claude Code stdio MCP proof (2026-10-05)](benchmarks/evidence/CLAUDE_MCP_STDIO_2026-10-05.md),
[actual Claude Code host acceptance proof (2026-10-11, SOU-8)](benchmarks/evidence/CLAUDE_MCP_STDIO_2026-10-11.md),
[native runtime checkpoint](benchmarks/evidence/agentdojo-native-fixture-2026-10-05.md),
[Windows AWS-LC and Keycloak checkpoint](operations/evidence/SAML_PROVIDER_2026-10-06.md),
[historical Keycloak checkpoint](operations/evidence/KEYCLOAK_SAML_2026-10-05.md) and
[populated restore checkpoint](operations/evidence/POPULATED_RESTORE_2026-10-05.md).
Keep these records separate from onboarding instructions so their versions,
failures and limitations remain reviewable.

- [SCIM directory client interoperability](operations/SCIM_DIRECTORY.md): bounded discovery/filter/PATCH profile and genuine client lifecycle on SQLite/PostgreSQL.
