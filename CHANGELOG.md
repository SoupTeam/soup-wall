# Changelog

Changes to the public Soup Wall source distribution are recorded here. Release artifacts and their checksums are published on [GitHub Releases](https://github.com/SoupTeam/soup-wall/releases).

## Unreleased

- Added accepted original-server profiles to `agentfw onboard` and
  `mcp-connection` (Linux): `--server-profile` selects the installed
  filesystem-readonly-v1 or git-readonly-v1 profile. Preview verifies the profile,
  runtime/dependency/sandbox pins, registry compatibility, the original entry and
  Linux sandbox prerequisites, and binds them to the plan digest. Connect persists
  only five validated launch settings, and verification requires an original useful
  read, a refused change with an independent workspace witness and a useful
  continuation through the connected entry. Recovery and undo cover the owned
  classifier copy and the connection's manifest record. A generic connect of a
  profile registry is refused.

- Added `agentfw onboard` (Linux, SOU-69): a read-only `preview` with the exact
  plan, conflicts, prerequisites and a plan digest; an explicit `apply` of that
  digest that journals each step through the accepted install, lifecycle,
  mcp-connection, protection-status and self-test commands and rolls back only
  its proven changes; and `undo`. Cleanup removes only Agent-home entries the
  journal recorded for this operation: untracked or changed files, including files
  inside runtime directories, are preserved and reported as a conflict. Reports keep configured identity separate from
  witnessed behavior, mark unobserved host coverage unknown and contain no
  tokens, payloads or raw paths. Phase 4 stays open.

- Added explicit Linux owned MCP connection profile preview/apply/status/recover/rollback
  (SOU-78), using reviewed immutable bundles and retained atomic host publication.
  Generation-checked launchers, current-daemon child authority and approval epoch
  retirement reject stale execution; authenticated provenance checkpoints retain host
  risk across restarts. Host reload remains pending until independently exercised.
  macOS/Windows profile upgrades remain unsupported. See
  [MCP_PROFILE_LIFECYCLE.md](docs/operations/MCP_PROFILE_LIFECYCLE.md) for scope and limits.

- Added native macOS `agentfw self-test` profile (SOU-77): delivered the
  `macos-stdio-mcp-admission-v1` profile with independent prevention witnesses,
  process group management, and verified process cleanup. It exercises an
  installed Agent on macOS end to end, verifying exact note reads, withheld
  adversarial injections, refused secret egress, useful read resumption, and
  fail-closed daemon loss, with process audit ensuring no orphaned child
  processes retain the temporary workspace path.

- Added `agentfw self-test` (Linux, SOU-61): one operator command that checks an
  installed Agent with an explicitly selected local classifier in an owned
  temporary workspace. It witnesses exact allowed reads, a withheld injected
  result, a refused synthetic-key send that never reaches the MCP child or an
  owned loopback receiver, and fail-closed daemon loss, then writes a versioned
  privacy-safe JSON report. Exit codes separate passed (0), failed (3),
  incomplete (4) and unsupported (5). Scripted client frames only: not Claude
  Code, model-context or live-model evidence.

- Added the AgentDojo matched evaluation protocol (SOU-36): versioned frozen
  plans with original tasks/attacks, development and fresh sets, repetitions,
  identities, budgets and separate proposed/approved limits; a live gate that
  refuses missing access, budget or identity before any credential is read; and
  an offline report command that validates pair identity and evaluator outputs
  and aggregates attack success, utility, interruptions, incomplete runs,
  uncertainty, latency and resources. Controlled fixture evidence only; Phase 4
  stays open and historical results are unchanged.

- Added opt-in sequential stdio MCP admission with reviewed schema/argument
  validation, pre-execution call gates and original text-result release to the
  MCP host. The legacy manifest proxy and Claude hooks retain their behavior.
  A scripted Claude Code check compares a real synthetic-secret send with its
  prevention and independently verifies useful completion; it is not live
  model or general MCP effectiveness evidence.

- Added opt-in operator-installed native admission with immutable tool semantics,
  separate authentication, single-use invocation bindings, and result/context
  gates. The AgentDojo adapter preserves the original runtime and formatter;
  native semantic coverage and model effectiveness require separate evidence.
  Fixed post-result hooks consuming pending action grants.
- Added Gateway scrape-target outage detection, Prometheus rule regressions,
  monitoring configuration examples and an isolated real monitoring drill.
  The published Windows Gateway passed 26 checks with authenticated firing
  and resolved delivery; managed TLS and staffed notification routing remain
  independent acceptance gates.
- Added an opt-in AgentDojo native-runtime fallback adapter, pinned runtime
  contract checks, explicit provider budgets and atomic aggregate evidence.
  The shipped policy is unchanged; independent live-model effectiveness and
  native semantic coverage remain separate acceptance gates.
- Added a manual portable Keycloak SAML login/ACS driver and offline isolation
  regressions. The first local vendor checkpoint is explicitly incomplete:
  functional observations preceded a cleanup failure, and the reviewed driver
  awaits a fresh full run. Managed IdP acceptance and issue #19 remain open.
- Fixed OIDC discovery for issuers with paths, including Keycloak realms.
  The well-known configuration path now follows the issuer path as required
  by OpenID Connect Discovery 1.0 section 4.1; exact issuer validation remains
  required.
- Fixed Windows Agent installation instructions and honored IPv4, IPv6, and
  localhost binds consistently across daemon clients. Added disposable Windows
  ACL, enforcement, shadow, and outage acceptance checks.
- Added an isolated Gateway binary acceptance command covering SQLite Console,
  authentication, provider forwarding, blocked requests, and restart persistence.
  Recorded published v0.4.0 binary checks and local PostgreSQL/Redis recovery and
  encrypted restore evidence.
- Added native Claude Code HTTP-hook acceptance using deterministic loopback
  model fixtures. Corrected outage guidance: connection failure can return
  immediately; the configured timeout is a ceiling, not a mandatory delay.
- Added agent evaluation JSON with immutable input snapshots, exact hashes,
  interruption outcomes, replay latency, and atomic output. Failed candidate
  gates retain evidence in CI. Added a pinned independent AgentDojo historical
  importer and recorded the current native-tool coverage gap without claiming
  live effectiveness.
- Added a checkpointed roadmap execution record. Managed staging, real-IdP,
  live-model evaluation, and shadow soaking remain open acceptance gates.
- Updated the SAML stack to `saml-rs 0.5.3`, `bergshamra 0.9.2`, and the `kryptering 0.6.0` security backport. Linux and macOS use AWS-LC; Windows retains RustCrypto because upstream's AWS-LC provider still rejects Windows. The `rsa` advisory remains in the complete release lock and [issue #19](https://github.com/SoupTeam/soup-wall/issues/19) stays open.
- Added SAML signature and metadata tampering checks and CI verification on all four archive targets. Encrypted assertions remain rejected and the SP does not advertise assertion encryption. Real-IdP acceptance still requires operator evidence.

## v0.4.0 — full-source Soup Wall

- Added the Gateway and self-hosted Console source to the public Apache-2.0 workspace. This is a reviewed source snapshot; the former private repository's Git history is not part of the public history.
- Added OpenAI Chat Completions and Responses, Anthropic Messages, tenant policy and identity, usage evidence, read-only invoice previews, and the associated deployment and operations templates to the public distribution.
- Unified the Soup Wall mark and visual identity across the README and browser pages. Existing `llm-firewall` executable, `LLM_FW_*` settings, headers, token prefixes, and stored identifiers remain for compatibility; release archives also carry a `soup-wall-gateway` executable alias.
- Expanded CI, advisory scanning, SBOM generation, and the release workflow to the complete workspace and Gateway container. Added self-hosting, upgrade, architecture, provenance, and security guidance.
- Updated `rustls` for the TLS handshake advisory and incorporated the reviewed `clap` and `rand` patch updates.

See the [roadmap](docs/ROADMAP.md) for field validation work and the [upgrade guide](docs/UPGRADING.md) for existing installations. Release artifacts and checksums are published with the v0.4.0 release after verification.

## [v0.3.0](https://github.com/SoupTeam/soup-wall/releases/tag/v0.3.0) — Agent release

First public binary release of Soup Wall Agent, including the local `agentfw` daemon and CLI, Claude Code hooks, MCP proxy, policy and audit path, guarded execution, and the `soup-wall-bench` regression corpus. Its default was shadow mode. The Gateway and Console source were not in that tag.
