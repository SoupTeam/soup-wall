# Soup Wall architecture

Soup Wall has two enforcement paths and one optional self-hosted control plane. The paths share detection and policy code, but they do not require a Soup Wall service or account.

```mermaid
flowchart LR
    Host[Claude Code or MCP host] --> Hook[Agent hook / MCP proxy]
    Hook --> Agent[agentfw daemon]
    Agent --> Policy[soup-wall-agent policy]
    Policy --> Core[soup-wall-core detectors]
    App[AI application] --> Gateway[Soup Wall Gateway]
    Gateway --> Core
    Gateway --> Provider[OpenAI / Anthropic upstream]
    Gateway --> Console[Optional Console and tenant store]
    Console --> Store[(SQLite or PostgreSQL)]
    Console -. optional .-> Redis[(Redis limits)]
    Console -. optional .-> IdP[OIDC / SAML IdP]
```

## Source map

| Directory | Responsibility |
| --- | --- |
| `crates/core` | Detection, normalization, findings, scoring, text policy and masking |
| `crates/agent` | Agent events, taint, action class, egress, authority and decision policy |
| `crates/agentfw` | Local daemon, Claude Code hooks, MCP proxy, grants, audit and guarded execution |
| `crates/proxy` | HTTP data plane for Chat Completions, Responses and Messages, plus the self-hosted Console and tenant store |
| `crates/adapter` | Versioned local decision and audit types for future integrations |
| `crates/bench` | Reproducible regression corpora and policy gates |
| `policies` | Built-in text policy; the agent default is under `crates/agent/policies` |
| `deploy` | Container, Compose, Kubernetes and edge examples |

The Gateway and Console currently live in one `crates/proxy` package. A local Gateway can run without a tenant store; enabling `tenant_store` adds the Console, tenant authentication and optional identity services. This is a configuration boundary today. Splitting the package for a smaller local install is a future refactor, not a prerequisite for accessing any source.

## Decision boundaries

The Agent computes verdicts for tool actions and records them locally. Its default is shadow mode. The Claude Code hook depends on host behavior and fails open when the daemon is unavailable. The guarded execution commands own process creation and fail closed. See [SECURITY.md](../SECURITY.md) before treating a hook verdict as an execution boundary.

The legacy MCP proxy checks manifests. Opt-in [stdio MCP admission](operations/MCP_STDIO_ADMISSION.md)
uses the reviewed native registry to gate supported calls before server execution
and original text results before release to the MCP host. It fails closed and
supports a bounded sequential contract; host release is not attestation of
the host's later model-context serialization.

The Gateway inspects request and response traffic and applies its text policy. Agent inspection and capability policy in the Gateway are separate opt-in controls. A provider request deliberately leaves the host for the configured upstream. With the Console enabled, audit and usage data can also be written to the configured local or external store.

The Console does not currently distribute Agent policy automatically. `soup-wall-adapter` defines a versioned contract for that integration, and the [roadmap](ROADMAP.md) tracks the work. Keep Agent and Gateway policies explicit until a tested rollout path exists.

## Incomplete session provenance

The [taint tracker](../crates/agent/src/taint.rs) retains at most `cap`
fingerprint entries and `cap` distinctive URL/path entries per active session,
with independently bounded FIFO queues. Eviction from either index sets a
sticky `incomplete` boolean. With `cap = 0`, any recorded untrusted input sets
it immediately, including input too short to fingerprint. Trusted input does
not set or clear it. This marker adds one boolean per session, with no discarded
text, fabricated source, eviction list or growing counter. Existing retained
literal/provenance string sizes and the number of active sessions are not a
global byte bound; hosts must bound input sizes and close ended sessions.

`TaintTracker::is_incomplete`, `AgentFirewall::provenance_incomplete`,
`Signals::provenance_incomplete` and `Outcome::provenance_incomplete` expose
the state. `check()` still reports only retained, matching evidence; `None`
does not establish clean provenance. `is_empty()` is false while history is
incomplete, even with zero retained entries. This does not claim perfect
provenance below capacity: existing extraction/fingerprint limits remain.

After ordinary policy evaluation, incomplete history imposes an **Ask floor**
on tool calls classified at least `SideEffecting` (including Network,
PrivilegeChanging and Destructive) or touching a sensitive path, even if
classified ReadOnly. Allow and Escalate become Ask, with no judge fallback and
reason `taint-history-incomplete`; an existing Ask or hard Deny keeps its
original verdict and reason. A retained mark can still trigger a stronger Deny.
The floor applies to both normal and native inspection, including custom Allow
policies. It does not synthesize a taint source for discarded evidence. Ordinary
nonsensitive ReadOnly calls and unrelated sessions keep their policy behavior.

An Ask is not an execution grant: consumers retain their existing confirmation
and enforcement requirements. Confirming one action does not clear the marker.
Native result preview does not record withheld content; admitting an untrusted
result does. A repeated SessionStart on the same active session does not reset
history. SessionEnd deletes that session's evidence and marker; a new session
starts empty. A safe reset requires the host to discard the old model context,
pending calls and derived plans before ending it and starting a fresh session.
Renaming a session, restarting a daemon or emitting SessionEnd while reusing the
old context is not a safe reset. This component cannot attest host context disposal.

### Focused reproduction

```sh
cargo test --locked -p soup-wall-agent incomplete_marker -- --nocapture
cargo test --locked -p soup-wall-agent zero_capacity_marks -- --nocapture
cargo test --locked -p soup-wall-agent --test provenance_overflow -- --nocapture
cargo test --locked -p soup-wall-agent
```

The [synthetic regressions](../crates/agent/tests/provenance_overflow.rs) cover
early prose/URL/path reuse after eviction, zero capacity, benign below-capacity
work, unaffected peer sessions, trusted input, duplicate starts, end/new-session
behavior, withheld/admitted native results and hard-Deny/judge precedence.
Tracker unit tests assert both map and queue bounds through repeated overflow.
These are component checks, not certification of the complete Phase 2 runtime.
The existing CI test job retains the focused test log as an artifact.

## Where to work next

Add a detector in `crates/core`, an agent decision rule in `crates/agent`, or a provider adapter in `crates/proxy`. For every enforcement change, add a test for the unsafe action and a benign case that should still succeed. Run the [full workspace checks](../CONTRIBUTING.md) and the relevant policy regression corpus before changing a default.
