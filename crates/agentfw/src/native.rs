// SPDX-License-Identifier: Apache-2.0
//! Opt-in native admission. Semantics come only from an immutable startup registry.
//! Legacy native/1 trusts the collector and does not attest runtime origin.
//! The separate opt-in git-execute contract owns its actual original process pipes.

use crate::hashing::sha256_hex;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use soup_wall_agent::{ActionClass, AgentEvent, EventKind, Outcome, Provenance, Trust, Verdict};

use crate::config::NativeCfg;
use crate::handlers::Shared;

pub mod analysis_purpose;
pub mod approval;
pub mod child_authority;
pub mod continuity;
pub mod execution;
mod invocation;
// SOU-218 executable contract experiment. No shipped endpoint or release path.
pub mod consumer;
// Share the two 256 KiB corpus originals across all test codegen units.
#[cfg(test)]
mod large_fixtures {
    pub(super) static G12_A: &str = include_str!("../../../eval/sou123/payloads/g12-a.txt");
    pub(super) static F12_A: &str = include_str!("../../../eval/sou123/payloads/f12-a.txt");
}

pub mod liveness;
pub mod pilot_cleanup;
pub mod pilot_stop;
#[cfg(test)]
mod purpose_prototype;
mod quarantine;
pub mod resource;
pub mod resource_approval;
mod timing;
pub(crate) mod verified_git;
pub mod workspace;

pub const CONTRACT: &str = "sw-native/1";
pub const MAX_BODY: usize = 1024 * 1024;
pub const MAX_CONTENT: usize = 262_144;
/// A selected original-server result frame, as received on the wire. Only a
/// `result` event with `mcp_host` delivery may use it; every other request,
/// argument and registry limit is unchanged.
pub const MAX_MCP_RESULT_CONTENT: usize = crate::mcp::server_profile::RESULT_FRAME_BYTES;
/// Request body for such a result: the frame re-escaped as a JSON string
/// (at most twice its size), bounded arguments and fixed fields.
pub const MAX_MCP_RESULT_BODY: usize = 2 * MAX_MCP_RESULT_CONTENT + MAX_CONTENT + 65_536;
const MAX_SESSIONS: usize = 64;
const MAX_CALLS: usize = 256;
const MAX_SESSION_CALLS: usize = 64;
pub(crate) const MAX_SPENT_AUTHORITIES: usize = MAX_SESSIONS * 8;
pub(crate) const TTL: Duration = Duration::from_secs(300);

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub contract_version: String,
    pub registry_id: String,
    pub tools: Vec<Tool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    pub name: String,
    pub schema_sha256: String,
    pub action_class: ActionClass,
    pub result_provenance: ResultProvenance,
    pub egress: Vec<Egress>,
    #[serde(default)]
    pub resource_policy: Option<resource::Policy>,
    /// Explicit operator opt-in to inspecting the selected real server's two
    /// original text result channels. Absent preserves strict legacy parsing.
    #[serde(default)]
    pub mcp_result_profile: Option<String>,
    /// Reviewed original AgentDojo workspace semantics; absent keeps schema-1 behavior.
    #[serde(default)]
    pub workspace_profile: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResultProvenance {
    Untrusted,
    LocalSystem,
    LocalProject,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Egress {
    pub pointer: String,
    pub kind: EgressKind,
    pub optional: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressKind {
    UrlHost,
    EmailDomain,
}

pub fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

pub(crate) fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-.:/".contains(&c))
}

fn json_pointer(value: &str) -> bool {
    crate::mcp::resources::valid_pointer(value)
}

fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => serde_json::to_value(
            map.iter()
                .map(|(k, v)| (k, canonical(v)))
                .collect::<BTreeMap<_, _>>(),
        )
        .expect("JSON values serialize"),
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

fn args_hash(value: &Value) -> String {
    sha256_hex(canonical(value).to_string().as_bytes())
}

pub fn canonical_digest(value: &Value) -> String {
    sha256_hex(canonical(value).to_string().as_bytes())
}

fn binding(
    registry: &str,
    epoch: &str,
    tool: &str,
    schema: &str,
    args: &Value,
    admission: Option<&resource::Admission>,
) -> String {
    let mut h = Sha256::new();
    h.update(b"sw-native/call/1\0");
    for field in [registry, epoch, tool, schema, &canonical(args).to_string()] {
        h.update((field.len() as u64).to_be_bytes());
        h.update(field.as_bytes());
    }
    if let Some(admission) = admission {
        h.update(admission.contract().as_bytes());
        h.update(b"\0");
        let context =
            canonical(&serde_json::to_value(admission).expect("context serializes")).to_string();
        h.update((context.len() as u64).to_be_bytes());
        h.update(context.as_bytes());
    }
    format!("{:x}", h.finalize())
}

fn selected_host_id(value: &Value) -> bool {
    const MAX_SAFE: u64 = 9_007_199_254_740_991;
    value.as_u64().is_some_and(|n| n <= MAX_SAFE)
        || value.as_i64().is_some_and(|n| n.unsigned_abs() <= MAX_SAFE)
        || value
            .as_str()
            .is_some_and(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control))
}

fn selected_host_binding(legacy: &str, host_id: &Value) -> String {
    let mut hash = Sha256::new();
    hash.update(b"sw-native/mcp-host-call/1\0");
    for field in [legacy, &canonical(host_id).to_string()] {
        hash.update((field.len() as u64).to_be_bytes());
        hash.update(field.as_bytes());
    }
    format!("{:x}", hash.finalize())
}

fn source(registry: &Registry, tool: &Tool) -> Provenance {
    match tool.result_provenance {
        ResultProvenance::Untrusted => Provenance::Native {
            registry: registry.registry_id.clone(),
            tool: tool.name.clone(),
        },
        ResultProvenance::LocalSystem => Provenance::LocalSystem,
        ResultProvenance::LocalProject => Provenance::LocalProject,
    }
}

fn declared_hosts(tool: &Tool, args: &Value) -> Result<Vec<String>, &'static str> {
    let mut hosts = BTreeSet::new();
    for selector in &tool.egress {
        let selected = match crate::mcp::resources::selected(args, &selector.pointer)
            .map_err(|_| "native_egress_type")?
        {
            None | Some(Value::Null) if selector.optional => continue,
            Some(value) => value,
            None => return Err("native_egress_missing"),
        };
        let values: Vec<&Value> = match selected {
            Value::Array(items) if items.len() <= 256 => items.iter().collect(),
            Value::String(_) => vec![selected],
            _ => return Err("native_egress_type"),
        };
        if values.is_empty() && !selector.optional {
            return Err("native_egress_missing");
        }
        for value in values {
            let text = value
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control))
                .ok_or("native_egress_type")?;
            let host = match selector.kind {
                EgressKind::UrlHost => {
                    crate::mcp::resources::canonical_url(text)
                        .map_err(|_| "native_egress_url")?
                        .1
                }
                EgressKind::EmailDomain => {
                    crate::mcp::resources::canonical_recipient(text)
                        .map_err(|_| "native_egress_email")?
                        .1
                }
            };
            hosts.insert(host);
        }
    }
    if hosts.is_empty() && (tool.action_class == ActionClass::Network || !tool.egress.is_empty()) {
        return Err("native_egress_missing");
    }
    Ok(hosts.into_iter().collect())
}

// Scope strings retain the wire format, but containment is typed: a host may
// narrow to an exact URL/mailbox; URLs and mailboxes never widen to a host.
fn scope_host(value: &str) -> Option<String> {
    if let Ok(ip) = value.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    if value.contains(['/', ':', '@', '?', '#']) {
        return None;
    }
    crate::mcp::resources::canonical_url(&format!("http://{value}"))
        .ok()
        .map(|(_, host, _)| host)
}

fn scope_contains(parent: &str, child: &str) -> bool {
    let cp = std::path::Path::new(child);
    let pp = std::path::Path::new(parent);
    if cp.is_absolute() || pp.is_absolute() {
        let clean = |p: &std::path::Path| {
            !p.components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        };
        return cp.is_absolute()
            && pp.is_absolute()
            && clean(cp)
            && clean(pp)
            && cp.starts_with(pp);
    }
    if let Ok((canonical, host, _)) = crate::mcp::resources::canonical_url(child) {
        return crate::mcp::resources::canonical_url(parent)
            .map(|(p, _, _)| p == canonical)
            .unwrap_or_else(|_| scope_host(parent).is_some_and(|p| p == host));
    }
    if let Ok((address, domain)) = crate::mcp::resources::canonical_recipient(child) {
        return crate::mcp::resources::canonical_recipient(parent)
            .map(|(p, _)| p == address)
            .unwrap_or_else(|_| scope_host(parent).is_some_and(|p| p == domain));
    }
    scope_host(parent)
        .zip(scope_host(child))
        .is_some_and(|(p, c)| p == c)
}

enum EgressDestination {
    Url { canonical: String },
    Email { address: String },
}

impl EgressDestination {
    fn matches_grant(&self, g: &str) -> bool {
        match self {
            EgressDestination::Url { canonical, .. } => scope_contains(g, canonical),
            EgressDestination::Email { address, .. } => scope_contains(g, address),
        }
    }
}

fn declared_destinations(
    tool: &Tool,
    args: &Value,
) -> Result<Vec<EgressDestination>, &'static str> {
    let mut destinations = Vec::new();
    for selector in &tool.egress {
        let selected = match crate::mcp::resources::selected(args, &selector.pointer)
            .map_err(|_| "native_egress_type")?
        {
            None | Some(Value::Null) if selector.optional => continue,
            Some(value) => value,
            None => return Err("native_egress_missing"),
        };
        let values: Vec<&Value> = match selected {
            Value::Array(items) if items.len() <= 256 => items.iter().collect(),
            Value::String(_) => vec![selected],
            _ => return Err("native_egress_type"),
        };
        if values.is_empty() && !selector.optional {
            return Err("native_egress_missing");
        }
        for value in values {
            let text = value
                .as_str()
                .filter(|s| !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control))
                .ok_or("native_egress_type")?;
            match selector.kind {
                EgressKind::UrlHost => {
                    let (canonical, _, _) = crate::mcp::resources::canonical_url(text)
                        .map_err(|_| "native_egress_url")?;
                    destinations.push(EgressDestination::Url { canonical });
                }
                EgressKind::EmailDomain => {
                    let (address, _) = crate::mcp::resources::canonical_recipient(text)
                        .map_err(|_| "native_egress_email")?;
                    destinations.push(EgressDestination::Email { address });
                }
            }
        }
    }
    if destinations.is_empty()
        && (tool.action_class == ActionClass::Network || !tool.egress.is_empty())
    {
        return Err("native_egress_missing");
    }
    Ok(destinations)
}

fn child_resources_authorized(
    granted: &[String],
    policy: Option<&resource::Policy>,
    tool: &Tool,
    args: &Value,
    admission: Option<&resource::Admission>,
) -> bool {
    if policy.is_some() {
        let Some(admission) = admission else {
            return false;
        };
        for ev in &admission.resources {
            let target = match &ev.resource {
                crate::mcp::resources::Resource::Path { canonical }
                | crate::mcp::resources::Resource::Url { canonical, .. } => canonical,
                crate::mcp::resources::Resource::Domain { host } => host,
                crate::mcp::resources::Resource::Recipient { address, .. } => address,
            };
            let matched = granted.iter().any(|g| scope_contains(g, target));
            if !matched {
                return false;
            }
        }
    }
    if !tool.egress.is_empty() || tool.action_class == ActionClass::Network {
        match declared_destinations(tool, args) {
            Ok(destinations) => {
                for dest in destinations {
                    if !granted.iter().any(|g| dest.matches_grant(g)) {
                        return false;
                    }
                }
            }
            Err(_) => return false,
        }
    }
    true
}

#[derive(Clone, Copy, PartialEq)]
enum Stage {
    Result,
    Context,
}

#[derive(Clone)]
struct Call {
    publication_outcome: Option<soup_wall_agent::Outcome>,
    publication_authorized: bool,
    #[cfg(target_os = "linux")]
    execution_args: Option<Value>,
    managed_policy: Option<soup_wall_agent::engine::ManagedActivePolicy>,
    host_call_id: Option<Value>,
    contract_version: &'static str,
    tool: String,
    args_sha256: String,
    binding_sha256: String,
    stage: Stage,
    expires: Instant,
    result_kind: Option<String>,
}

#[derive(Clone)]
pub(crate) struct Session {
    policy_transition: bool,
    pub host_session: Option<String>,
    pub server_id: Option<String>,
    pub agent_id: Option<String>,
    pub parent_id: Option<String>,
    pub granted_tools: Vec<String>,
    pub granted_resources: Option<Vec<String>>,
    pub authority_expires_at_ms: Option<u64>,
    pub(crate) parent_epoch: Option<String>,
    authority_digest: Option<String>,
    pub(crate) epoch: String,
    pub(crate) owner_token: String,
    seq: u64,
    pub(crate) touched: Instant,
    calls: BTreeMap<String, Call>,
    pub(crate) liveness_lease: Option<liveness::Lease>,
    pub(crate) terminal: bool,
}

impl Session {
    pub(crate) fn is_dead(&self, now: Instant, now_ms: u64, sessions: &Sessions) -> bool {
        if self.terminal {
            return true;
        }
        if let Some(lease) = &self.liveness_lease {
            if lease.is_expired(now) || validate_lineage(sessions, self, now_ms, now).is_err() {
                return true;
            }
        } else if now.duration_since(self.touched) >= TTL {
            return true;
        }
        self.authority_expires_at_ms
            .is_some_and(|exp| now_ms >= exp)
    }

    fn event_at(&self, seq: u64, kind: EventKind) -> AgentEvent {
        event_scoped(
            &self.epoch,
            self.agent_id.as_deref().unwrap_or("native-runtime"),
            self.parent_id.as_deref(),
            seq,
            kind,
        )
    }

    fn event(&self, kind: EventKind) -> AgentEvent {
        self.event_at(self.seq, kind)
    }

    fn host_event(&self, host_session: &str, seq: u64, kind: EventKind) -> AgentEvent {
        event_scoped(
            host_session,
            self.agent_id.as_deref().unwrap_or("native-runtime"),
            self.parent_id.as_deref(),
            seq,
            kind,
        )
    }
}

#[derive(Default)]
pub(crate) struct Sessions {
    purpose_spent: BTreeMap<String, u64>,
    pub(crate) consumer_terminal: BTreeMap<String, u64>,
    pub(crate) consumers: BTreeMap<String, crate::pilot_approval::consumer::Registration>,
    #[cfg(test)]
    analysis_hosts: BTreeSet<String>,
    pub(crate) entries: BTreeMap<String, Session>,
    // Bounded tombstones prevent a completed scoped host from silently reverting
    // to unsigned hooks. Reaching the cap refuses new host IDs until restart.
    pub(crate) scoped_hosts: BTreeSet<String>,
    // Spent child authority ledger: maps authority_digest to expires_at_ms.
    // Prevents reuse of signed child authority grants across sessions or after reclamation.
    pub(crate) spent_authorities: BTreeMap<String, u64>,
    pub(crate) pilot_cleanup: BTreeMap<String, pilot_cleanup::Record>,
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn wall_time_ms() -> Result<u64, &'static str> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .map_err(|_| "native_clock_unavailable")
}

pub(crate) fn validate_lineage(
    state: &Sessions,
    session: &Session,
    now_ms: u64,
    now: Instant,
) -> Result<(), &'static str> {
    let mut current = session;
    for _ in 0..=MAX_SESSIONS {
        if current.authority_digest.as_ref().is_some_and(|digest| {
            state
                .spent_authorities
                .get(digest)
                .is_some_and(|expiry| *expiry > now_ms)
        }) {
            return Err("native_child_authority_revoked");
        }
        if current.terminal {
            return Err("native_child_parent_unavailable");
        }
        if let Some(lease) = &current.liveness_lease {
            if lease.is_expired(now) {
                return Err("native_child_parent_unavailable");
            }
        } else if now.duration_since(current.touched) >= TTL {
            return Err("native_child_authority_expired");
        }
        if current
            .authority_expires_at_ms
            .is_some_and(|expires| now_ms >= expires)
        {
            return Err("native_child_authority_expired");
        }
        let Some(parent) = &current.parent_id else {
            return Ok(());
        };
        current = state
            .entries
            .values()
            .find(|p| {
                p.host_session == current.host_session
                    && p.agent_id.as_ref() == Some(parent)
                    && current.parent_epoch.as_ref() == Some(&p.epoch)
            })
            .ok_or("native_child_parent_unavailable")?;
    }
    Err("native_child_parent_unavailable")
}

fn publication_lifetime(
    state: &Sessions,
    session: &Session,
    now: Instant,
    now_ms: u64,
) -> Result<u64, &'static str> {
    let mut current = session;
    let mut remaining = TTL.as_millis() as u64;
    for _ in 0..=MAX_SESSIONS {
        let lease = current
            .liveness_lease
            .as_ref()
            .map(|l| l.expires_in_ms(now))
            .unwrap_or_else(|| {
                TTL.saturating_sub(now.saturating_duration_since(current.touched))
                    .as_millis() as u64
            });
        remaining = remaining.min(lease);
        if let Some(expiry) = current.authority_expires_at_ms {
            remaining = remaining.min(expiry.saturating_sub(now_ms));
        }
        let Some(parent) = &current.parent_id else {
            return Ok(remaining);
        };
        current = state
            .entries
            .values()
            .find(|p| {
                p.host_session == current.host_session
                    && p.agent_id.as_ref() == Some(parent)
                    && current.parent_epoch.as_ref() == Some(&p.epoch)
            })
            .ok_or("native_child_parent_unavailable")?;
    }
    Err("native_child_parent_unavailable")
}

pub struct NativeState {
    git_execution: Option<verified_git::Runtime>,
    pub registry: Registry,
    pub registry_sha256: String,
    pub token: String,
    instance_id: String,
    pub(crate) execution: Option<Arc<execution::Service>>,
    pub(crate) edit: Option<Arc<crate::edit_session::transport::Service>>,
    pub(crate) continuity: Option<continuity::Continuity>,
    pub(crate) sessions: Mutex<Sessions>,
    quarantine: Mutex<quarantine::Quarantine>,
    pub(crate) approval: Option<approval::ApprovalState>,
    test_time_offset_ms: std::sync::atomic::AtomicU64,
    pub(crate) policy_barrier: Option<crate::policy_transition::Barrier>,
}

/// Session negotiation cannot change between the compatibility check and swap.
pub(crate) struct PolicyTransitionGuard<'a> {
    _sessions: MutexGuard<'a, Sessions>,
}

/// Keeps authority and parent epochs stable through a synchronous hook decision.
/// Always acquire before the firewall mutex, and never hold across an await.
pub(crate) struct HookAuthorityGuard<'a> {
    native: &'a NativeState,
    sessions: MutexGuard<'a, Sessions>,
}

impl HookAuthorityGuard<'_> {
    pub fn resolve(
        &self,
        session: &str,
        agent: Option<&str>,
        parent: Option<&str>,
        proof: Option<&str>,
        call: Option<(&str, &Value)>,
    ) -> Result<(String, Option<String>, Option<String>), &'static str> {
        self.native.resolve_hook_identity_locked(
            &self.sessions,
            session,
            agent,
            parent,
            proof,
            call,
        )
    }

    pub fn inspect_call(
        &self,
        firewall: &mut soup_wall_agent::AgentFirewall,
        event: &AgentEvent,
    ) -> Outcome {
        if let EventKind::ToolCall { tool: name, args } = &event.kind {
            let tool = self
                .sessions
                .entries
                .values()
                .find(|s| {
                    s.host_session.as_deref() == Some(&event.session)
                        && s.agent_id.as_deref() == Some(&event.agent)
                })
                .and_then(|s| s.server_id.as_deref())
                .and_then(|server| self.native.hook_tool(server, name));
            if let Some(tool) = tool {
                if let Ok(hosts) = declared_hosts(tool, args) {
                    let mut canonical = event.clone();
                    if let EventKind::ToolCall { tool: name, .. } = &mut canonical.kind {
                        *name = tool.name.clone();
                    }
                    if let Ok(outcome) = invocation::inspect(firewall, &canonical, tool, &hosts) {
                        return outcome;
                    }
                }
            }
            let mut refused = Outcome::allow();
            refused.verdict = Verdict::Deny;
            refused.rule = Some("native_hook_tool_unsupported".into());
            return refused;
        }
        firewall.inspect(event)
    }

    pub fn has_host(&self, host: &str) -> bool {
        self.sessions
            .entries
            .values()
            .any(|s| s.host_session.as_deref() == Some(host))
    }
}

impl NativeState {
    pub fn from_bytes(bytes: &[u8], expected: &str, token: String) -> anyhow::Result<Self> {
        anyhow::ensure!(
            bytes.len() <= MAX_BODY && is_digest(expected) && sha256_hex(bytes) == expected,
            "native registry bytes do not match the explicit startup digest"
        );
        let registry: Registry = serde_json::from_slice(bytes)?;
        anyhow::ensure!(
            registry.contract_version == CONTRACT
                && identifier(&registry.registry_id)
                && !registry.tools.is_empty()
                && registry.tools.len() <= 256,
            "invalid native registry"
        );
        let mut names = BTreeSet::new();
        workspace::validate_registry(&registry)?;
        for tool in &registry.tools {
            anyhow::ensure!(
                identifier(&tool.name)
                    && names.insert(&tool.name)
                    && is_digest(&tool.schema_sha256)
                    && tool.egress.len() <= 32,
                "invalid native tool"
            );
            if let Some(policy) = &tool.resource_policy {
                policy.validate(tool)?;
            }
            if tool.workspace_profile.is_some() {
                workspace::validate(tool)?;
            }
            if let Some(profile) = &tool.mcp_result_profile {
                // One explicitly installed ORIGINAL filesystem create is the
                // only side-effecting selected MCP schema. Keep every other
                // selected name/profile read-only, including the legacy
                // filesystem and Git profiles. A generic writable registry
                // must not opt into this exceptional authority.
                let create_profile =
                    profile == crate::mcp::server_profile::filesystem_create::FORMAT;
                let original_write = create_profile && tool.name == "write_file";
                let expected_action = if original_write {
                    ActionClass::SideEffecting
                } else {
                    ActionClass::ReadOnly
                };
                anyhow::ensure!(
                    crate::mcp::server_profile::selected(Some(profile))
                        && (!create_profile || registry.registry_id == "filesystem-create-only-v1")
                        && tool.action_class == expected_action
                        && matches!(tool.result_provenance, ResultProvenance::Untrusted)
                        && tool.egress.is_empty()
                        && tool.resource_policy.is_none(),
                    "invalid selected MCP result profile authority"
                );
                let manifest = crate::mcp::server_profile::original_manifest_for(profile)?;
                let profiles =
                    crate::mcp::server_profile::classify_manifest_for(profile, &manifest)?;
                anyhow::ensure!(
                    profiles
                        .get(&tool.name)
                        .is_some_and(|p| p.unsupported_reason.is_none()),
                    "unsupported selected MCP result tool"
                );
                let definition = manifest["tools"]
                    .as_array()
                    .expect("shipped manifest")
                    .iter()
                    .find(|t| t["name"] == tool.name)
                    .expect("supported selected tool");
                anyhow::ensure!(
                    canonical_digest(&definition["inputSchema"]) == tool.schema_sha256,
                    "selected MCP input schema differs from upstream pin"
                );
            }
            for selector in &tool.egress {
                anyhow::ensure!(
                    json_pointer(&selector.pointer),
                    "invalid native egress pointer"
                );
            }
        }
        anyhow::ensure!(!token.is_empty(), "native collector token is absent");
        Ok(Self {
            git_execution: None,
            registry,
            registry_sha256: expected.into(),
            token,
            instance_id: crate::token::generate(),
            execution: None,
            edit: None,
            continuity: None,
            sessions: Mutex::default(),
            quarantine: Mutex::default(),
            approval: None,
            test_time_offset_ms: std::sync::atomic::AtomicU64::new(0),
            policy_barrier: None,
        })
    }

    pub fn with_continuity(
        mut self,
        home: &std::path::Path,
        firewall: &mut soup_wall_agent::AgentFirewall,
    ) -> anyhow::Result<Self> {
        self.continuity = Some(continuity::Continuity::attach(home, &mut self, firewall)?);
        Ok(self)
    }

    pub(crate) fn git_execution_selected(
        &self,
        server: &str,
        profile: &crate::mcp::server_profile::ProfileConfig,
    ) -> anyhow::Result<bool> {
        self.git_execution
            .as_ref()
            .map_or(Ok(false), |runtime| runtime.selected(server, profile))
    }

    pub fn with_policy_barrier(mut self, home: &std::path::Path) -> anyhow::Result<Self> {
        self.policy_barrier = Some(crate::policy_transition::Barrier::new(home)?);
        Ok(self)
    }

    pub(crate) fn policy_transition_guard(&self) -> anyhow::Result<PolicyTransitionGuard<'_>> {
        let sessions = self
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("native state unavailable"))?;
        anyhow::ensure!(
            sessions
                .entries
                .values()
                .all(|session| session.policy_transition),
            "managed activation requires transition-capable native collectors"
        );
        Ok(PolicyTransitionGuard {
            _sessions: sessions,
        })
    }

    /// Public runtime identifier, authenticated by the native transport endpoint.
    /// Scoped grant nonces bind to it without changing the HMAC wire encoding.
    /// Only the daemon startup attaches execution custody. Collector registry
    /// loads never initialize this authority or read the server's catalogue.
    pub fn with_execution(mut self, config: &NativeCfg) -> anyhow::Result<Self> {
        self.execution = config
            .execution
            .as_ref()
            .map(execution::Service::load)
            .transpose()?;
        Ok(self)
    }

    pub(crate) fn collector_view(&self) -> Self {
        Self {
            git_execution: None,
            registry: self.registry.clone(),
            registry_sha256: self.registry_sha256.clone(),
            token: self.token.clone(),
            instance_id: crate::token::generate(),
            execution: None,
            edit: None,
            continuity: None,
            sessions: Mutex::default(),
            quarantine: Mutex::default(),
            approval: None,
            test_time_offset_ms: std::sync::atomic::AtomicU64::new(0),
            policy_barrier: self.policy_barrier.clone(),
        }
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn test_time_offset(&self) -> u64 {
        self.test_time_offset_ms
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn monotonic_now(&self) -> Instant {
        Instant::now() + Duration::from_millis(self.test_time_offset())
    }

    pub fn set_test_time_offset_ms(&self, offset_ms: u64) {
        self.test_time_offset_ms
            .store(offset_ms, std::sync::atomic::Ordering::Release);
    }

    pub fn advance_test_time_ms(&self, delta_ms: u64) {
        self.test_time_offset_ms
            .fetch_add(delta_ms, std::sync::atomic::Ordering::SeqCst);
    }

    /// Enable the opt-in pending-approval lifecycle (SOU-48). Absent = refusal.
    pub fn with_approval(
        mut self,
        home: &std::path::Path,
        grant_key: &[u8],
        ttl_seconds: u64,
    ) -> anyhow::Result<Self> {
        self.approval = Some(approval::ApprovalState::new(home, grant_key, ttl_seconds)?);
        Ok(self)
    }

    pub fn has_active_host_session(&self, host_session: &str) -> bool {
        let Ok(sessions) = self.sessions.lock() else {
            return false;
        };
        sessions
            .entries
            .values()
            .any(|s| s.host_session.as_deref() == Some(host_session))
    }

    pub fn active_host_sessions(&self) -> Vec<String> {
        let Ok(sessions) = self.sessions.lock() else {
            return Vec::new();
        };
        let mut hosts = Vec::new();
        for s in sessions.entries.values() {
            if let Some(ref h) = s.host_session {
                if !hosts.contains(h) {
                    hosts.push(h.clone());
                }
            }
        }
        hosts
    }

    pub fn resolve_hook_identity(
        &self,
        session_id: &str,
        agent_id: Option<&str>,
        parent_id: Option<&str>,
        proof: Option<&str>,
        call: Option<(&str, &Value)>,
    ) -> Result<(String, Option<String>, Option<String>), &'static str> {
        self.lock_hook_authority()?
            .resolve(session_id, agent_id, parent_id, proof, call)
    }

    pub(crate) fn lock_hook_authority(&self) -> Result<HookAuthorityGuard<'_>, &'static str> {
        Ok(HookAuthorityGuard {
            native: self,
            sessions: self
                .sessions
                .lock()
                .map_err(|_| "native_state_unavailable")?,
        })
    }

    fn hook_tool(&self, server: &str, name: &str) -> Option<&Tool> {
        let qualified = format!("mcp__{server}__");
        let name = if name.starts_with("mcp__") {
            name.strip_prefix(&qualified)?
        } else {
            name
        };
        self.registry.tools.iter().find(|tool| tool.name == name)
    }

    fn resolve_hook_identity_locked(
        &self,
        sessions: &Sessions,
        session_id: &str,
        agent_id: Option<&str>,
        parent_id: Option<&str>,
        proof: Option<&str>,
        call: Option<(&str, &Value)>,
    ) -> Result<(String, Option<String>, Option<String>), &'static str> {
        #[cfg(test)]
        if sessions.analysis_hosts.contains(session_id) {
            return Err("analysis_purpose_effects_withheld");
        }
        let Some(proof) = proof else {
            if sessions.scoped_hosts.contains(session_id)
                || agent_id.is_some()
                || parent_id.is_some()
            {
                return Err("native_hook_authority_required");
            }
            return Ok(("main".into(), None, None));
        };
        let now_ms = wall_time_ms()?;
        let decoded =
            child_authority::decode_token(proof).map_err(|_| "native_hook_authority_invalid")?;
        let grant = child_authority::verify_token(
            &child_authority::derive_key(&self.token),
            proof,
            session_id,
            &decoded.server_id,
            now_ms,
        )
        .map_err(|_| "native_hook_authority_invalid")?;
        let agent = grant
            .agent_id
            .as_deref()
            .ok_or("native_hook_identity_unsupported")?;
        if agent_id.is_some_and(|id| id != agent)
            || parent_id.is_some_and(|id| Some(id) != grant.parent_id.as_deref())
        {
            return Err("native_hook_identity_mismatch");
        }
        let digest = sha256_hex(proof.as_bytes());
        let session = sessions
            .entries
            .values()
            .find(|s| {
                s.host_session.as_deref() == Some(session_id)
                    && s.agent_id.as_deref() == Some(agent)
                    && s.authority_digest.as_ref() == Some(&digest)
            })
            .ok_or("native_hook_session_unknown")?;
        validate_lineage(sessions, session, now_ms, Instant::now())?;
        if let Some((name, args)) = call {
            let tool = self
                .hook_tool(&grant.server_id, name)
                .ok_or("native_hook_tool_unsupported")?;
            if !session.granted_tools.iter().any(|t| t == &tool.name)
                || tool.resource_policy.is_some()
                || !child_resources_authorized(
                    session.granted_resources.as_deref().unwrap_or(&[]),
                    None,
                    tool,
                    args,
                    None,
                )
            {
                return Err("native_child_authority_escalation");
            }
        }
        Ok((agent.into(), grant.parent_id, Some(grant.server_id)))
    }

    pub fn load(config: &NativeCfg, token: String) -> anyhow::Result<Self> {
        anyhow::ensure!(
            config.registry_path.is_absolute(),
            "native registry needs an absolute operator path"
        );
        for part in config.registry_path.ancestors() {
            let metadata = std::fs::symlink_metadata(part)?;
            anyhow::ensure!(
                !metadata.file_type().is_symlink(),
                "native registry path is linked"
            );
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                anyhow::ensure!(
                    metadata.file_attributes() & 0x400 == 0,
                    "native registry path is redirected"
                );
            }
        }
        let mut bytes = Vec::new();
        std::fs::File::open(&config.registry_path)?
            .take((MAX_BODY + 1) as u64)
            .read_to_end(&mut bytes)?;
        let mut native = Self::from_bytes(&bytes, &config.registry_sha256, token)?;
        native.git_execution = config
            .git_execution
            .as_ref()
            .map(verified_git::Runtime::load)
            .transpose()?;
        if native.git_execution.is_some() {
            anyhow::ensure!(
                config.liveness.is_some(),
                "daemon Git execution requires authenticated liveness"
            );
        }
        Ok(native)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    liveness: Option<String>,
    policy_transition: Option<String>,
    contract_version: String,
    registry_sha256: String,
    session_id: String,
    event: String,
    tool: Option<String>,
    args: Option<Value>,
    schema_sha256: Option<String>,
    call_id: Option<String>,
    content: Option<String>,
    result_kind: Option<String>,
    delivery: Option<String>,
    resource_admission: Option<resource::Admission>,
    approval_id: Option<String>,
    selected_invocation: Option<approval::SelectedInvocation>,
    pub host_session: Option<String>,
    pub child_authority: Option<String>,
    pub server_id: Option<String>,
    pub agent_id: Option<String>,
    pub parent_id: Option<String>,
    mcp_host_call_id: Option<Value>,
}

fn mcp_host_result(request: &Request) -> bool {
    request.event == "result" && request.delivery.as_deref() == Some("mcp_host")
}

fn parse(body: &str) -> Result<Request, &'static str> {
    if body.len() > MAX_MCP_RESULT_BODY {
        return Err("native_body_over_cap");
    }
    // Deserialize directly as well: an intermediate Value would otherwise
    // discard duplicate protocol fields before the strict field check.
    let request: Request = serde_json::from_str(body).map_err(|_| {
        if body.len() > MAX_BODY {
            "native_body_over_cap"
        } else {
            "native_invalid_fields"
        }
    })?;
    // Only a selected-server result frame may use the larger result body.
    if body.len() > MAX_BODY && !mcp_host_result(&request) {
        return Err("native_body_over_cap");
    }
    let value: Value = serde_json::from_str(body).map_err(|_| "native_invalid_json")?;
    let event = value
        .get("event")
        .and_then(Value::as_str)
        .ok_or("native_invalid_event")?;
    let mut keys = BTreeSet::from(["contract_version", "registry_sha256", "session_id", "event"]);
    let object = value.as_object().ok_or("native_invalid_json")?;
    match event {
        "session_start" => {
            for key in [
                "liveness",
                "policy_transition",
                "host_session",
                "child_authority",
                "server_id",
                "agent_id",
                "parent_id",
            ] {
                if object.contains_key(key) {
                    keys.insert(key);
                }
            }
        }
        "session_end" => {}
        "call" => {
            keys.extend(["tool", "args", "schema_sha256"]);
            if object.contains_key("mcp_host_call_id") {
                keys.insert("mcp_host_call_id");
                if request.mcp_host_call_id.is_none() {
                    return Err("native_invalid_fields");
                }
            }
            if object.contains_key("approval_id") {
                keys.insert("approval_id");
            }
            if object.contains_key("selected_invocation") {
                keys.insert("selected_invocation");
                if request.selected_invocation.is_none()
                    || (request.approval_id.is_none()
                        && !request.selected_invocation.as_ref().is_some_and(|context| {
                            context.profile == crate::mcp::server_profile::filesystem_create::FORMAT
                                && context.original_create.is_some()
                                && request.tool.as_deref() == Some("write_file")
                        }))
                {
                    return Err("native_invalid_fields");
                }
            }
            if matches!(
                request.contract_version.as_str(),
                resource::CONTRACT
                    | resource::CREATE_CONTRACT
                    | resource::POST_CONTRACT
                    | resource::NETWORK_CONTRACT
                    | resource::WINDOWS_READ_CONTRACT
                    | resource::WINDOWS_CREATE_CONTRACT
                    | resource::MACOS_READ_CONTRACT
                    | resource::MACOS_CREATE_CONTRACT
                    | resource::replacement::CONTRACT
            ) {
                keys.insert("resource_admission");
            }
        }
        "result" => keys.extend([
            "call_id",
            "tool",
            "args",
            "content",
            "result_kind",
            "delivery",
        ]),
        "publish" => keys.extend(["call_id", "tool", "args"]),
        "context" => keys.extend(["call_id", "tool", "args", "content"]),
        _ => return Err("native_invalid_event"),
    }
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != keys {
        return Err("native_invalid_fields");
    }
    if request
        .liveness
        .as_deref()
        .is_some_and(|version| version != liveness::LIVENESS_CONTRACT)
    {
        return Err("native_liveness_unsupported");
    }
    if request
        .policy_transition
        .as_deref()
        .is_some_and(|v| v != crate::policy_transition::CONTRACT)
    {
        return Err("native_policy_transition_unsupported");
    }
    if request
        .host_session
        .as_ref()
        .is_some_and(|id| !identifier(id))
        || request.server_id.as_ref().is_some_and(|id| !identifier(id))
        || request.agent_id.as_ref().is_some_and(|id| !identifier(id))
        || request.parent_id.as_ref().is_some_and(|id| !identifier(id))
    {
        return Err("native_invalid_identity");
    }
    if (request.parent_id.is_some() || request.child_authority.is_some())
        && (request.host_session.is_none() || request.child_authority.is_none())
    {
        return Err("native_invalid_identity");
    }
    if !identifier(&request.session_id)
        || !matches!(
            request.contract_version.as_str(),
            CONTRACT
                | resource::CONTRACT
                | resource::CREATE_CONTRACT
                | resource::POST_CONTRACT
                | resource::NETWORK_CONTRACT
                | resource::WINDOWS_READ_CONTRACT
                | resource::WINDOWS_CREATE_CONTRACT
                | resource::MACOS_READ_CONTRACT
                | resource::MACOS_CREATE_CONTRACT
                | resource::replacement::CONTRACT
        )
        || (matches!(event, "session_start" | "session_end")
            && request.contract_version != CONTRACT)
    {
        return Err("native_invalid_identity");
    }
    if request.contract_version == resource::replacement::CONTRACT && !cfg!(target_os = "linux") {
        return Err("replace_platform_unsupported");
    }
    if event == "publish" && request.contract_version != resource::replacement::CONTRACT {
        return Err("native_publication_contract_required");
    }
    if request.contract_version == resource::WINDOWS_READ_CONTRACT && !cfg!(windows) {
        return Err("native_windows_read_platform_unsupported");
    }
    if request.contract_version == resource::WINDOWS_CREATE_CONTRACT && !cfg!(windows) {
        return Err("native_windows_create_platform_unsupported");
    }
    if request.contract_version == resource::MACOS_READ_CONTRACT
        && !cfg!(all(target_os = "macos", target_arch = "aarch64"))
    {
        return Err("native_macos_read_platform_unsupported");
    }
    if request.contract_version == resource::MACOS_CREATE_CONTRACT
        && !cfg!(all(target_os = "macos", target_arch = "aarch64"))
    {
        return Err("native_macos_create_platform_unsupported");
    }
    if event == "call"
        && matches!(
            request.contract_version.as_str(),
            resource::CONTRACT
                | resource::CREATE_CONTRACT
                | resource::POST_CONTRACT
                | resource::NETWORK_CONTRACT
                | resource::WINDOWS_READ_CONTRACT
                | resource::WINDOWS_CREATE_CONTRACT
                | resource::MACOS_READ_CONTRACT
                | resource::MACOS_CREATE_CONTRACT
                | resource::replacement::CONTRACT
        )
    {
        let admission = request
            .resource_admission
            .as_ref()
            .ok_or("native_resource_context_missing")?;
        admission.validate_shape()?;
        if admission.contract() != request.contract_version {
            return Err("native_resource_contract_mismatch");
        }
    } else if request.resource_admission.is_some() {
        return Err("native_invalid_fields");
    }
    if let Some(id) = &request.approval_id {
        if !identifier(id) {
            return Err("native_invalid_fields");
        }
        let is_plain = request.contract_version == CONTRACT && request.resource_admission.is_none();
        let is_supported_resource = matches!(
            request.contract_version.as_str(),
            resource::CONTRACT
                | resource::CREATE_CONTRACT
                | resource::NETWORK_CONTRACT
                | resource::replacement::CONTRACT
        ) && request.resource_admission.is_some();
        if !is_plain && !is_supported_resource {
            return Err("native_invalid_fields");
        }
    }
    if let Some(args) = &request.args {
        if !args.is_object() || args.to_string().len() > MAX_CONTENT {
            return Err("native_args_over_cap");
        }
    }
    if let Some(content) = &request.content {
        let cap = if mcp_host_result(&request) {
            MAX_MCP_RESULT_CONTENT
        } else {
            MAX_CONTENT
        };
        if content.len() > cap {
            return Err("native_content_over_cap");
        }
    }
    Ok(request)
}

#[derive(Serialize)]
struct Response {
    // Control-side diagnostics are not fields of the strict MCP receipt.
    #[serde(skip)]
    quarantine_id: Option<String>,
    #[serde(skip)]
    quarantine_error: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    publication_ttl_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    execution: Option<execution::Metadata>,
    #[serde(skip)]
    policy_shadow: Vec<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    managed_policy: Option<soup_wall_agent::engine::ManagedActivePolicy>,
    contract_version: &'static str,
    registry_sha256: String,
    session_id: String,
    event: String,
    verdict: &'static str,
    enforced: bool,
    release: bool,
    call_id: Option<String>,
    binding_sha256: Option<String>,
    content_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resources_sha256: Option<String>,
    reason_codes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_token: Option<String>,
}

fn merge_provenance_outcomes(mut local: Outcome, host: Outcome) -> Outcome {
    fn verdict_rank(v: Verdict) -> u8 {
        match v {
            Verdict::Deny => 3,
            Verdict::Ask => 2,
            Verdict::Escalate => 1,
            Verdict::Allow => 0,
        }
    }
    if verdict_rank(resolved(&host)) > verdict_rank(resolved(&local)) {
        let mut merged = host;
        merged.provenance_incomplete |= local.provenance_incomplete;
        if local.taint.is_some() && merged.taint.is_none() {
            merged.taint = local.taint;
        }
        if merged.rule.is_none() && local.rule.is_some() {
            merged.rule = local.rule;
        }
        merged
    } else {
        local.provenance_incomplete |= host.provenance_incomplete;
        if host.taint.is_some() && local.taint.is_none() {
            local.taint = host.taint;
        }
        if local.rule.is_none() && host.rule.is_some() {
            local.rule = host.rule;
        }
        local
    }
}

fn resolved(outcome: &Outcome) -> Verdict {
    match outcome.verdict {
        Verdict::Escalate => outcome.fallback.unwrap_or(Verdict::Ask),
        verdict => verdict,
    }
}

fn verdict_label(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "allow",
        Verdict::Deny => "deny",
        _ => "ask",
    }
}

/// Inspect the exact provider-visible error, or each original text block separately.
fn context_text(content: &str, tool: &str) -> Result<Vec<String>, &'static str> {
    let value: Value = serde_json::from_str(content).map_err(|_| "native_context_json")?;
    let message = value.as_object().ok_or("native_context_shape")?;
    let tool_call = value["tool_call"]
        .as_object()
        .ok_or("native_context_shape")?;
    if message.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != BTreeSet::from(["role", "content", "error", "tool_call", "tool_call_id"])
        || tool_call
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            != BTreeSet::from(["id", "function", "args", "placeholder_args"])
        || !value["tool_call"]["args"].is_object()
        || !(value["tool_call"]["placeholder_args"].is_null()
            || value["tool_call"]["placeholder_args"].is_object())
        || value["role"] != "tool"
        || value["tool_call"]["function"] != tool
        || !value["tool_call_id"].as_str().is_some_and(identifier)
        || value["tool_call"]["id"] != value["tool_call_id"]
    {
        return Err("native_context_shape");
    }
    let blocks = value["content"].as_array().ok_or("native_context_shape")?;
    if blocks.len() > 256 {
        return Err("native_context_shape");
    }
    let mut text = Vec::new();
    for block in blocks {
        let object = block.as_object().ok_or("native_context_shape")?;
        if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
            != BTreeSet::from(["type", "content"])
            || block["type"] != "text"
        {
            return Err("native_context_shape");
        }
        text.push(
            block["content"]
                .as_str()
                .ok_or("native_context_shape")?
                .to_string(),
        );
    }
    if !value["error"].is_null() {
        let error = value["error"].as_str().ok_or("native_context_shape")?;
        if !error.is_empty() {
            return Ok(vec![error.into()]);
        }
    }
    Ok(text)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpEnvelope {
    jsonrpc: String,
    id: Value,
    result: Option<McpTextResult>,
    error: Option<McpError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpTextResult {
    content: Vec<McpTextBlock>,
    #[serde(rename = "isError")]
    is_error: Option<bool>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpTextBlock {
    #[serde(rename = "type")]
    kind: String,
    text: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct McpError {
    #[serde(rename = "code")]
    _code: i64,
    message: String,
}

/// Inspect decoded original text, while the response hash binds the entire original
/// JSON-RPC line. This release reaches the MCP host, not an attested model context.
/// Unsupported structured/media/meta content must not silently escape inspection.
fn mcp_host_text(content: &str, result_kind: &str) -> Result<Vec<String>, &'static str> {
    // Typed deserialization rejects duplicate fields before Value can discard them.
    let envelope: McpEnvelope =
        serde_json::from_str(content).map_err(|_| "native_mcp_result_shape")?;
    let value: Value = serde_json::from_str(content).map_err(|_| "native_mcp_result_shape")?;
    let keys: BTreeSet<&str> = value
        .as_object()
        .ok_or("native_mcp_result_shape")?
        .keys()
        .map(String::as_str)
        .collect();
    if envelope.jsonrpc != "2.0"
        || !(envelope.id.is_i64()
            || envelope.id.is_u64()
            || envelope.id.as_str().is_some_and(|s| {
                !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control)
            }))
    {
        return Err("native_mcp_result_shape");
    }
    match (envelope.result, envelope.error) {
        (Some(result), None) => {
            if keys != BTreeSet::from(["jsonrpc", "id", "result"])
                || result.content.len() > 256
                || value["result"]
                    .get("isError")
                    .is_some_and(|v| !v.is_boolean())
                || result.content.iter().any(|block| block.kind != "text")
            {
                return Err("native_mcp_result_shape");
            }
            if result.is_error.unwrap_or(false) != (result_kind == "error") {
                return Err("native_mcp_result_kind");
            }
            Ok(result.content.into_iter().map(|block| block.text).collect())
        }
        (None, Some(error)) => {
            if keys != BTreeSet::from(["jsonrpc", "id", "error"]) {
                return Err("native_mcp_result_shape");
            }
            if result_kind != "error" {
                return Err("native_mcp_result_kind");
            }
            Ok(vec![error.message])
        }
        _ => Err("native_mcp_result_shape"),
    }
}

/// Both channels are decoded and independently inspected. Correlation and the
/// receipt hash continue to bind the complete untouched JSON-RPC response.
fn selected_mcp_host_text(content: &str, result_kind: &str) -> Result<Vec<String>, &'static str> {
    selected_mcp_host_text_profile(content, result_kind, true)
}

fn selected_mcp_host_text_profile(
    content: &str,
    result_kind: &str,
    structured_required: bool,
) -> Result<Vec<String>, &'static str> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SelectedEnvelope {
        jsonrpc: String,
        id: Value,
        result: Option<SelectedResult>,
        error: Option<McpError>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SelectedResult {
        content: Vec<McpTextBlock>,
        #[serde(rename = "structuredContent")]
        structured_content: Option<StructuredText>,
        #[serde(rename = "isError")]
        is_error: Option<bool>,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StructuredText {
        content: String,
    }

    let envelope: SelectedEnvelope =
        serde_json::from_str(content).map_err(|_| "native_mcp_result_shape")?;
    let super::mcp::admission::Strict(value) =
        serde_json::from_str(content).map_err(|_| "native_mcp_result_shape")?;
    let keys: BTreeSet<&str> = value
        .as_object()
        .ok_or("native_mcp_result_shape")?
        .keys()
        .map(String::as_str)
        .collect();
    if envelope.jsonrpc != "2.0"
        || !(envelope.id.is_i64()
            || envelope.id.is_u64()
            || envelope.id.as_str().is_some_and(|s| {
                !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control)
            }))
    {
        return Err("native_mcp_result_shape");
    }
    match (envelope.result, envelope.error) {
        (Some(result), None) => {
            if keys != BTreeSet::from(["jsonrpc", "id", "result"])
                || result.content.len() > 256
                || result.content.iter().any(|b| b.kind != "text")
                || value["result"]
                    .get("isError")
                    .is_some_and(|v| !v.is_boolean())
                || value["result"]
                    .get("structuredContent")
                    .is_some_and(|v| !v.is_object())
                || (structured_required
                    && result.structured_content.is_none()
                    && !result.is_error.unwrap_or(false))
                || (!structured_required && result.structured_content.is_some())
            {
                return Err("native_mcp_result_shape");
            }
            if result.is_error.unwrap_or(false) != (result_kind == "error") {
                return Err("native_mcp_result_kind");
            }
            let mut text: Vec<String> = result.content.into_iter().map(|b| b.text).collect();
            if let Some(structured) = result.structured_content {
                text.push(structured.content);
            }
            Ok(text)
        }
        (None, Some(error)) => {
            if keys != BTreeSet::from(["jsonrpc", "id", "error"]) {
                return Err("native_mcp_result_shape");
            }
            if result_kind != "error" {
                return Err("native_mcp_result_kind");
            }
            Ok(vec![error.message])
        }
        _ => Err("native_mcp_result_shape"),
    }
}

fn failure(code: &'static str, status: StatusCode) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({"contract_version": CONTRACT, "release": false, "error_code": code})),
    )
}

/// Trusted issuer bootstrap; the identifier itself conveys no authority.
/// Kept read-only so status polling does not mutate daemon state or bypass audit/continuity.
pub async fn instance(State(st): State<Shared>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    let Some(native) = &st.native else {
        return failure("native_not_configured", StatusCode::NOT_FOUND);
    };
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::token::verify(&native.token, auth) {
        return failure("native_unauthorized", StatusCode::UNAUTHORIZED);
    }
    let Ok(sessions) = native.sessions.lock() else {
        return failure("native_state_unavailable", StatusCode::SERVICE_UNAVAILABLE);
    };
    let Ok(firewall) = st.firewall.lock() else {
        return failure(
            "native_inspection_unavailable",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    };
    let now = native.monotonic_now();
    let now_ms = match wall_time_ms() {
        Ok(ms) => ms + native.test_time_offset(),
        Err(code) => return failure(code, StatusCode::SERVICE_UNAVAILABLE),
    };
    let bindings: Vec<Value> = sessions
        .entries
        .values()
        .filter(|s| {
            s.host_session.is_some()
                && s.agent_id.is_some()
                && !s.is_dead(now, now_ms, &sessions)
                && validate_lineage(&sessions, s, now_ms, now).is_ok()
        })
        .map(|s| {
            json!({
                "host_session": s.host_session,
                "agent_id": s.agent_id,
                "binding_sha256": sha256_hex(s.epoch.as_bytes())
            })
        })
        .collect();
    let pilot_collectors: Vec<Value> = sessions
        .entries
        .iter()
        .filter(|(_, s)| {
            s.host_session.is_some()
                && s.authority_digest.is_some()
                && s.liveness_lease.is_some()
        })
        .map(|(id, s)| {
            json!({"session_id": id, "session_epoch": s.epoch,
                "active": !s.is_dead(now, now_ms, &sessions) && validate_lineage(&sessions, s, now_ms, now).is_ok(),
            "host_session": s.host_session, "server_id": s.server_id, "agent_id": s.agent_id,
            "authority_sha256": s.authority_digest})
        })
        .collect();
    let pilot_pending = match native
        .approval
        .as_ref()
        .map(|a| a.operator_bindings())
        .transpose()
    {
        Ok(value) => value.unwrap_or_default(),
        Err(code) => return failure(code, StatusCode::SERVICE_UNAVAILABLE),
    };
    let mut description = json!({
        "instance_id": native.instance_id(),
        "registry_sha256": native.registry_sha256,
        "bindings": bindings,
        "pilot_collectors": pilot_collectors,
        "pilot_cleanup": sessions.pilot_cleanup.iter().map(|(digest, row)| json!({
            "authority_sha256":digest,"host_session":row.host_session,
            "server_id":row.server_id,"verified":row.verified
        })).collect::<Vec<_>>(),
        "pilot_pending": pilot_pending,
        "approval_enabled": native.approval.is_some(),
        "liveness_enabled": st.config.native.as_ref().and_then(|n| n.liveness.as_ref()).is_some(),
        "provenance": {
            "accounting_revision": "sw-provenance-storage/1",
            "limits": firewall.provenance_limits(),
            "usage": firewall.provenance_usage(),
        }
    });
    if let Some(service) = &native.execution {
        description["execution_service"] = service.metadata();
    }
    if let Some(service) = &native.edit {
        let tools = service.profile.tools();
        let owns = |session_id: &str, epoch: &str, tool: &str| {
            sessions.entries.get(session_id).is_some_and(|s| {
                s.epoch == epoch
                    && s.host_session.as_deref() == Some(service.host.as_str())
                    && s.server_id.as_deref() == Some(crate::edit_session::SERVER)
                    && tools.as_array().is_some_and(|definitions| {
                        definitions
                            .iter()
                            .any(|definition| definition["name"] == tool)
                    })
            })
        };
        let (pending, decisions) = match native
            .approval
            .as_ref()
            .map(|approval| approval.edit_bindings(owns))
            .transpose()
        {
            Ok(value) => value.unwrap_or_default(),
            Err(code) => return failure(code, StatusCode::SERVICE_UNAVAILABLE),
        };
        let collectors = sessions
            .entries
            .values()
            .filter(|s| {
                s.host_session.as_deref() == Some(service.host.as_str())
                    && s.server_id.as_deref() == Some(crate::edit_session::SERVER)
            })
            .take(9)
            .map(|s| {
                json!({"session_epoch":s.epoch,"host_session":s.host_session,
                    "server_id":s.server_id,
                    "active":!s.is_dead(now, now_ms, &sessions)
                        && validate_lineage(&sessions, s, now_ms, now).is_ok()})
            })
            .collect::<Vec<_>>();
        if collectors.len() > 8 {
            return failure(
                "edit_diagnostic_collector_cap",
                StatusCode::SERVICE_UNAVAILABLE,
            );
        }
        description["edit_diagnostic"] = json!({
            "format":"sw-installed-edit-live/1","profile_sha256":service.digest,
            "host_session":service.host,"collectors":collectors,
            "pending":pending,"decisions":decisions,
            "observation":"authenticated_current_memory_not_result_delivery_proof"
        });
    }
    (StatusCode::OK, Json(description))
}

pub async fn handler(
    State(st): State<Shared>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, Json<Value>) {
    handle_with_evidence(st, headers, body, None).await
}

async fn handle_with_evidence(
    st: Shared,
    headers: HeaderMap,
    body: String,
    evidence: Option<execution::OriginalResult>,
) -> (StatusCode, Json<Value>) {
    let Some(native) = &st.native else {
        return failure("native_disabled", StatusCode::SERVICE_UNAVAILABLE);
    };
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::token::verify(&native.token, auth) {
        return failure("native_unauthorized", StatusCode::UNAUTHORIZED);
    }
    if !st.config.enforce || st.config.judge.enabled {
        return failure(
            "native_enforcement_required",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }
    if body.len() > st.config.max_body_bytes {
        return failure("native_body_over_cap", StatusCode::PAYLOAD_TOO_LARGE);
    }
    let request = match parse(&body) {
        Ok(request) => request,
        Err(code) => return failure(code, StatusCode::BAD_REQUEST),
    };
    if evidence.is_some() && !mcp_host_result(&request) {
        return failure(
            "verified_execution_result_required",
            StatusCode::BAD_REQUEST,
        );
    }
    if request.registry_sha256 != native.registry_sha256 {
        return failure("native_registry_mismatch", StatusCode::CONFLICT);
    }
    // A selected original-server result is checked per decoded text, which
    // is what reaches the recorder; see `inspect_bound`. Others are unchanged.
    let selected_result = mcp_host_result(&request)
        && request.tool.as_deref().is_some_and(|name| {
            native.registry.tools.iter().any(|tool| {
                tool.name == name
                    && crate::mcp::server_profile::selected(tool.mcp_result_profile.as_deref())
            })
        });
    if request.content.as_ref().is_some_and(|content| {
        content.len()
            > if selected_result {
                MAX_MCP_RESULT_CONTENT
            } else {
                st.config.max_record_bytes.min(MAX_CONTENT)
            }
    }) || request
        .args
        .as_ref()
        .is_some_and(|args| args.to_string().len() > st.config.max_record_bytes)
        || request.resource_admission.as_ref().is_some_and(|context| {
            serde_json::to_vec(context)
                .map_or(true, |bytes| bytes.len() > st.config.max_record_bytes)
        })
    {
        return failure("native_record_over_cap", StatusCode::PAYLOAD_TOO_LARGE);
    }
    let identity = match liveness::collector_identity(&headers) {
        Ok(identity) => identity,
        Err(code) => return failure(code, StatusCode::BAD_REQUEST),
    };
    if request.event == "session_start" && identity.is_some() {
        return failure(
            "native_liveness_unexpected_identity",
            StatusCode::BAD_REQUEST,
        );
    }
    match inspect_bound(&st, native, request, identity.as_ref(), evidence) {
        Ok(response) => (
            StatusCode::OK,
            Json(serde_json::to_value(response).expect("native response serializes")),
        ),
        Err(code) => failure(code, StatusCode::CONFLICT),
    }
}

/// Reserve both required contexts before publishing an authenticated session.
/// Only fresh, unpublished shells may be removed on a failed start.
fn register_provenance_contexts(
    firewall: &mut soup_wall_agent::AgentFirewall,
    epoch: &str,
    host: Option<&str>,
) -> Result<Vec<String>, &'static str> {
    let mut created = Vec::with_capacity(2);
    for context in std::iter::once(epoch).chain(host) {
        match firewall.try_register_provenance_context(context) {
            Ok(true) => created.push(context.to_string()),
            Ok(false) => {}
            Err(_) => {
                rollback_provenance_contexts(firewall, &created);
                return Err("native_provenance_context_capacity");
            }
        }
    }
    Ok(created)
}

fn rollback_provenance_contexts(firewall: &mut soup_wall_agent::AgentFirewall, created: &[String]) {
    for context in created {
        firewall.end_provenance_context(context);
    }
}

/// Unified terminal retirement path for definitive session closure, expiration,
/// and orphan reclamation. Respects audit-before-release, durability/checkpoints,
/// and profile transition gates. Does not revive authority if audit or checkpoint fails.
pub(crate) fn retire_sessions_terminal(
    st: &Shared,
    native: &NativeState,
    targets: &[(String, Option<String>)],
    reason: &'static str,
) -> usize {
    let mut sessions = match native.sessions.lock() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let now = native.monotonic_now();
    let now_ms = wall_time_ms().unwrap_or(0) + native.test_time_offset();

    // Resolve every exact target against one locked snapshot before removing
    // any ancestor. Collector shutdown can beat maintenance after a rejected
    // renewal; it must not relabel an already expired lineage as healthy retire.
    let terminal_causes: BTreeMap<String, &'static str> = targets
        .iter()
        .filter_map(|(id, expected_epoch)| {
            let session = sessions.entries.get(id)?;
            if expected_epoch
                .as_ref()
                .is_some_and(|epoch| epoch != &session.epoch)
            {
                return None;
            }
            let dead = session.is_dead(now, now_ms, &sessions);
            if reason == "expired" && !dead {
                return None;
            }
            let cause = if reason == "retired" && dead {
                "expired"
            } else {
                reason
            };
            Some((id.clone(), cause))
        })
        .collect();
    let mut to_retire = Vec::new();
    for (id, cause) in terminal_causes {
        let mut session = sessions.entries.remove(&id).unwrap();
        session.terminal = true;
        if let Some(lease) = &mut session.liveness_lease {
            lease.state = liveness::LeaseState::Terminal(cause);
        }
        if session.parent_id.is_none() || cause != "ended" || session.liveness_lease.is_some() {
            if let (Some(digest), Some(exp)) =
                (&session.authority_digest, session.authority_expires_at_ms)
            {
                if exp > now_ms {
                    sessions.spent_authorities.insert(digest.clone(), exp);
                }
            }
        }
        to_retire.push((id, session, cause));
    }

    if to_retire.is_empty() {
        return 0;
    }

    // A leased session's explicit end is terminal for its complete lineage,
    // just like retirement or expiry. Keep legacy unleased end semantics.
    if reason != "ended" || to_retire.iter().any(|(_, s, _)| s.liveness_lease.is_some()) {
        let mut all_retired_epochs: BTreeMap<String, &'static str> = to_retire
            .iter()
            .map(|(_, s, cause)| (s.epoch.clone(), *cause))
            .collect();
        loop {
            let child_ids: Vec<(String, &'static str)> = sessions
                .entries
                .iter()
                .filter_map(|(id, s)| {
                    let cause = all_retired_epochs.get(s.parent_epoch.as_ref()?)?;
                    Some((id.clone(), *cause))
                })
                .collect();
            if child_ids.is_empty() {
                break;
            }
            for (cid, cause) in child_ids {
                if let Some(mut session) = sessions.entries.remove(&cid) {
                    session.terminal = true;
                    if let Some(lease) = &mut session.liveness_lease {
                        lease.state = liveness::LeaseState::Terminal(cause);
                    }
                    if let (Some(digest), Some(exp)) =
                        (&session.authority_digest, session.authority_expires_at_ms)
                    {
                        if exp > now_ms {
                            sessions.spent_authorities.insert(digest.clone(), exp);
                        }
                    }
                    all_retired_epochs.insert(session.epoch.clone(), cause);
                    to_retire.push((cid, session, cause));
                }
            }
        }
    }

    sessions.spent_authorities.retain(|_, exp| *exp > now_ms);

    if let Ok(mut quarantine) = native.quarantine.lock() {
        for (_, session, _) in &to_retire {
            quarantine.retire(&session.epoch);
        }
    }

    let count = to_retire.len();

    if let Some(approval) = &native.approval {
        for (id, _, cause) in &to_retire {
            approval.close_session(id, cause);
        }
    }

    let Ok(mut firewall) = st.firewall.lock() else {
        return 0;
    };

    for (id, session, cause) in &to_retire {
        if let (Some(host), Some(agent)) = (&session.host_session, &session.agent_id) {
            firewall.end_agent(host, agent);
        }
        firewall.inspect(&session.event_at(session.seq + 1, EventKind::SessionEnd));
        st.spans.end_session(&session.epoch);

        let record = json!({
            "at_ms": now_ms,
            "session": session.epoch,
            "session_id": id,
            "seq": session.seq + 1,
            "event": format!("native_session_{cause}"),
            "verdict": "allow",
            "shadow": false,
            "released": false,
            "registry_sha256": native.registry_sha256,
            "host_session": session.host_session,
            "agent_id": session.agent_id,
            "parent_id": session.parent_id,
        });
        if st.audit.write_native(&record).is_err() {
            firewall.mark_all_provenance_incomplete();
        }
    }

    drop(firewall);
    drop(sessions);

    count
}

#[cfg(test)]
fn inspect(st: &Shared, native: &NativeState, request: Request) -> Result<Response, &'static str> {
    inspect_bound(st, native, request, None, None)
}

fn inspect_bound(
    st: &Shared,
    native: &NativeState,
    request: Request,
    identity: Option<&liveness::CollectorIdentity>,
    evidence: Option<execution::OriginalResult>,
) -> Result<Response, &'static str> {
    inspect_bound_complete(st, native, request, identity, None, evidence)
}

#[cfg(target_os = "linux")]
fn inspect_bound_with_execution(
    st: &Shared,
    native: &NativeState,
    request: Request,
    identity: Option<&liveness::CollectorIdentity>,
    execution: Option<verified_git::OwnedResult>,
) -> Result<Response, &'static str> {
    inspect_bound_complete(st, native, request, identity, execution, None)
}

fn inspect_bound_complete(
    st: &Shared,
    native: &NativeState,
    request: Request,
    identity: Option<&liveness::CollectorIdentity>,
    execution: Option<verified_git::OwnedResult>,
    evidence: Option<execution::OriginalResult>,
) -> Result<Response, &'static str> {
    let mut timing = timing::Timing::new(&request);
    let result = inspect_bound_measured(
        st,
        native,
        request,
        identity,
        execution,
        evidence,
        &mut timing,
    );
    timing.finish(&result);
    result
}

fn inspect_bound_measured(
    st: &Shared,
    native: &NativeState,
    request: Request,
    identity: Option<&liveness::CollectorIdentity>,
    execution: Option<verified_git::OwnedResult>,
    evidence: Option<execution::OriginalResult>,
    timing: &mut timing::Timing,
) -> Result<Response, &'static str> {
    if execution.is_some() && evidence.is_some() {
        return Err("verified_execution_source_mismatch");
    }
    if request.event == "session_start"
        && request.host_session.is_none()
        && native
            .continuity
            .as_ref()
            .is_some_and(|c| c.requires_scoped_authority())
    {
        return Err("native_profile_authority_required");
    }

    let started = Instant::now();
    // One lock covers sequencing, inspection, admission and audit. No await,
    // external judge, or network request occurs while this guard is held.
    let mut state = native
        .sessions
        .lock()
        .map_err(|_| "native_state_unavailable")?;
    timing.session_wait_us = started.elapsed().as_micros();
    #[cfg(test)]
    purpose_prototype::guard(&state, &request)?;
    let wait = Instant::now();
    let mut firewall = st
        .firewall
        .lock()
        .map_err(|_| "native_inspection_unavailable")?;
    timing.firewall_wait_us = wait.elapsed().as_micros();
    if let Some(identity) = identity {
        let session = state
            .entries
            .get(&request.session_id)
            .ok_or("native_session_unknown")?;
        identity.verify(native, session)?;
    }
    let mut now = native.monotonic_now();
    let mut now_ms = wall_time_ms()? + native.test_time_offset();
    for session in state.entries.values_mut() {
        session.calls.retain(|_, call| call.expires > now);
    }
    let mut response = Response {
        quarantine_id: None,
        quarantine_error: None,
        policy_shadow: Vec::new(),
        publication_ttl_ms: None,
        execution: None,
        managed_policy: firewall.active_managed_policy(),
        contract_version: match request.contract_version.as_str() {
            resource::CONTRACT => resource::CONTRACT,
            resource::CREATE_CONTRACT => resource::CREATE_CONTRACT,
            resource::POST_CONTRACT => resource::POST_CONTRACT,
            resource::NETWORK_CONTRACT => resource::NETWORK_CONTRACT,
            resource::WINDOWS_READ_CONTRACT => resource::WINDOWS_READ_CONTRACT,
            resource::WINDOWS_CREATE_CONTRACT => resource::WINDOWS_CREATE_CONTRACT,
            resource::MACOS_READ_CONTRACT => resource::MACOS_READ_CONTRACT,
            resource::MACOS_CREATE_CONTRACT => resource::MACOS_CREATE_CONTRACT,
            resource::replacement::CONTRACT => resource::replacement::CONTRACT,
            _ => CONTRACT,
        },
        registry_sha256: native.registry_sha256.clone(),
        session_id: request.session_id.clone(),
        event: request.event.clone(),
        verdict: "allow",
        enforced: true,
        release: true,
        call_id: None,
        binding_sha256: None,
        content_sha256: request.content.as_ref().map(|c| sha256_hex(c.as_bytes())),
        resources_sha256: None,
        reason_codes: vec![],
        instance_id: None,
        owner_token: None,
    };
    if request.event == "session_start" {
        if firewall.active_managed_policy().is_some() && request.policy_transition.is_none() {
            return Err("native_policy_transition_required");
        }
        if let Some(existing) = state.entries.get(&request.session_id) {
            if existing.is_dead(now, now_ms, &state) {
                let existing_epoch = existing.epoch.clone();
                drop(state);
                drop(firewall);
                retire_sessions_terminal(
                    st,
                    native,
                    &[(request.session_id.clone(), Some(existing_epoch))],
                    "expired",
                );
                state = native
                    .sessions
                    .lock()
                    .map_err(|_| "native_state_unavailable")?;
                firewall = st
                    .firewall
                    .lock()
                    .map_err(|_| "native_inspection_unavailable")?;
                now = native.monotonic_now();
                now_ms = wall_time_ms()? + native.test_time_offset();
                response.managed_policy = firewall.active_managed_policy();
                if response.managed_policy.is_some() && request.policy_transition.is_none() {
                    return Err("native_policy_transition_required");
                }
            } else {
                return Err("native_session_exists");
            }
        }
        let dead_targets: Vec<(String, Option<String>)> = state
            .entries
            .iter()
            .filter(|(_, s)| s.is_dead(now, now_ms, &state))
            .map(|(id, s)| (id.clone(), Some(s.epoch.clone())))
            .collect();
        if !dead_targets.is_empty() {
            drop(state);
            drop(firewall);
            retire_sessions_terminal(st, native, &dead_targets, "expired");
            state = native
                .sessions
                .lock()
                .map_err(|_| "native_state_unavailable")?;
            firewall = st
                .firewall
                .lock()
                .map_err(|_| "native_inspection_unavailable")?;
            now = native.monotonic_now();
            now_ms = wall_time_ms()? + native.test_time_offset();
            response.managed_policy = firewall.active_managed_policy();
            if response.managed_policy.is_some() && request.policy_transition.is_none() {
                return Err("native_policy_transition_required");
            }
        }
        if state.entries.len() >= MAX_SESSIONS {
            return Err("native_session_cap");
        }
        let (granted_tools, granted_resources, agent_id, parent_id, authority_expires_at_ms) =
            if let Some(host_session) = &request.host_session {
                let token = request
                    .child_authority
                    .as_deref()
                    .ok_or("native_child_authority_missing")?;
                let key = child_authority::derive_key(&native.token);
                let grant = child_authority::verify_token(
                    &key,
                    token,
                    host_session,
                    request.server_id.as_deref().unwrap_or(""),
                    now_ms,
                )
                .map_err(|error| {
                    use child_authority::ChildAuthorityError;
                    match error {
                        ChildAuthorityError::BadSignature => "native_child_authority_bad_signature",
                        ChildAuthorityError::Expired => "native_child_authority_expired",
                        ChildAuthorityError::NotYetValid => "native_child_authority_not_yet_valid",
                        ChildAuthorityError::HostSessionMismatch => {
                            "native_child_authority_host_mismatch"
                        }
                        ChildAuthorityError::ServerIdMismatch => {
                            "native_child_authority_server_mismatch"
                        }
                        ChildAuthorityError::InvalidContract => {
                            "native_child_authority_invalid_contract"
                        }
                        ChildAuthorityError::MalformedToken => "native_child_authority_malformed",
                    }
                })?;
                let auth_digest = sha256_hex(token.as_bytes());
                state.spent_authorities.retain(|_, exp| *exp > now_ms);
                if state.spent_authorities.contains_key(&auth_digest)
                    || state
                        .entries
                        .values()
                        .any(|s| s.authority_digest.as_deref() == Some(&auth_digest))
                {
                    return Err("native_child_authority_already_spent");
                }
                let active_signed = state
                    .entries
                    .values()
                    .filter(|s| s.authority_digest.is_some())
                    .count();
                if state.spent_authorities.len() + active_signed >= MAX_SPENT_AUTHORITIES {
                    return Err("native_authority_ledger_saturated");
                }
                if let Some(req_agent) = &request.agent_id {
                    if grant.agent_id.as_ref() != Some(req_agent) {
                        return Err("native_invalid_identity");
                    }
                }
                if let Some(req_parent) = &request.parent_id {
                    if grant.parent_id.as_ref() != Some(req_parent) {
                        return Err("native_invalid_identity");
                    }
                }
                // Every host-bound collector shares authoritative provenance.
                // A legacy grant lacks authenticated agent/lifecycle authority
                // and must never be used as an alternate shared-host bootstrap.
                if grant.agent_id.is_none() {
                    return Err("native_child_authority_identity_required");
                }
                if grant.nonce.split_once('.').map(|(instance, _)| instance)
                    != Some(native.instance_id())
                {
                    return Err("native_child_authority_instance_mismatch");
                }
                let agent_id = grant.agent_id.or_else(|| request.agent_id.clone());
                let parent_id = grant.parent_id.or_else(|| request.parent_id.clone());
                if agent_id.as_deref().is_some_and(|id| !identifier(id))
                    || parent_id.as_deref().is_some_and(|id| !identifier(id))
                    || ((parent_id.is_some() || grant.granted_resources.is_some())
                        && agent_id.is_none())
                {
                    return Err("native_invalid_identity");
                }
                if let Some(agent) = &agent_id {
                    let dead_sessions: Vec<(String, Option<String>)> = state
                        .entries
                        .iter()
                        .filter(|(_, s)| {
                            s.host_session.as_ref() == Some(host_session)
                                && s.agent_id.as_ref() == Some(agent)
                                && s.is_dead(now, now_ms, &state)
                        })
                        .map(|(id, s)| (id.clone(), Some(s.epoch.clone())))
                        .collect();
                    if !dead_sessions.is_empty() {
                        drop(state);
                        drop(firewall);
                        retire_sessions_terminal(st, native, &dead_sessions, "expired");
                        state = native
                            .sessions
                            .lock()
                            .map_err(|_| "native_state_unavailable")?;
                        firewall = st
                            .firewall
                            .lock()
                            .map_err(|_| "native_inspection_unavailable")?;
                        now = native.monotonic_now();
                        now_ms = wall_time_ms()? + native.test_time_offset();
                        response.managed_policy = firewall.active_managed_policy();
                        if response.managed_policy.is_some() && request.policy_transition.is_none()
                        {
                            return Err("native_policy_transition_required");
                        }
                    }
                    if now_ms >= grant.expires_at_ms {
                        return Err("native_child_authority_expired");
                    }
                    if state
                        .spent_authorities
                        .contains_key(&sha256_hex(token.as_bytes()))
                    {
                        return Err("native_child_authority_already_spent");
                    }
                    if state.entries.values().any(|s| {
                        s.host_session.as_ref() == Some(host_session)
                            && s.agent_id.as_ref() == Some(agent)
                    }) {
                        return Err("native_agent_already_bound");
                    }
                    if !state.scoped_hosts.contains(host_session)
                        && state.scoped_hosts.len() >= MAX_SESSIONS
                    {
                        return Err("native_host_binding_cap");
                    }
                }
                if grant
                    .granted_resources
                    .as_ref()
                    .is_some_and(|rs| rs.iter().any(|r| !scope_contains(r, r)))
                {
                    return Err("native_child_authority_escalation");
                }
                if let Some(ref parent) = parent_id {
                    let ps = state
                        .entries
                        .values()
                        .find(|s| {
                            s.host_session.as_ref() == Some(host_session)
                                && s.agent_id.as_ref() == Some(parent)
                        })
                        .ok_or("native_child_parent_unavailable")?;
                    if grant.nonce.split('.').nth(1)
                        != Some(sha256_hex(ps.epoch.as_bytes()).as_str())
                    {
                        return Err("native_child_parent_binding_mismatch");
                    }
                    validate_lineage(&state, ps, now_ms, now)?;
                    if grant
                        .granted_tools
                        .iter()
                        .any(|t| !ps.granted_tools.contains(t))
                    {
                        return Err("native_child_authority_escalation");
                    }
                    for cr in grant.granted_resources.as_deref().unwrap_or(&[]) {
                        if !ps
                            .granted_resources
                            .as_deref()
                            .unwrap_or(&[])
                            .iter()
                            .any(|pr| scope_contains(pr, cr))
                        {
                            return Err("native_child_authority_escalation");
                        }
                    }
                }
                (
                    grant.granted_tools,
                    grant.granted_resources,
                    agent_id,
                    parent_id,
                    Some(grant.expires_at_ms),
                )
            } else {
                (
                    Vec::new(),
                    None,
                    request.agent_id.clone(),
                    request.parent_id.clone(),
                    None,
                )
            };
        let parent_epoch = parent_id.as_ref().and_then(|parent| {
            state
                .entries
                .values()
                .find(|s| {
                    s.host_session == request.host_session && s.agent_id.as_ref() == Some(parent)
                })
                .map(|s| s.epoch.clone())
        });
        let owner_token = format!("owner:{}", crate::token::generate());
        let session = Session {
            policy_transition: request.policy_transition.is_some(),
            parent_epoch,
            authority_digest: request
                .child_authority
                .as_ref()
                .map(|proof| sha256_hex(proof.as_bytes())),
            epoch: format!("native:{}", crate::token::generate()),
            owner_token: owner_token.clone(),
            seq: 1,
            touched: now,
            calls: BTreeMap::new(),
            host_session: request.host_session.clone(),
            server_id: request.server_id.clone(),
            agent_id,
            parent_id,
            granted_tools,
            granted_resources,
            authority_expires_at_ms,
            liveness_lease: None,
            terminal: false,
        };
        let created = register_provenance_contexts(
            &mut firewall,
            &session.epoch,
            session.host_session.as_deref(),
        )?;
        if let Err(reason) = audit(st, &request, &session, &response, None, timing) {
            rollback_provenance_contexts(&mut firewall, &created);
            return Err(reason);
        }
        let agent_name = session.agent_id.as_deref().unwrap_or("native-runtime");
        if let (Some(host), Some(agent)) = (&session.host_session, &session.agent_id) {
            if let Some(parent) = &session.parent_id {
                if firewall
                    .spawn(host, parent, agent, &session.granted_tools)
                    .is_some()
                {
                    rollback_provenance_contexts(&mut firewall, &created);
                    return Err("native_child_authority_escalation");
                }
            } else {
                firewall.set_root(host, agent, &session.granted_tools);
            }
            state.scoped_hosts.insert(host.clone());
        }
        let tools = if session.host_session.is_some() {
            session.granted_tools.clone()
        } else {
            native
                .registry
                .tools
                .iter()
                .map(|t| t.name.clone())
                .collect()
        };
        firewall.set_root(&session.epoch, agent_name, &tools);
        if request.liveness.is_some() {
            response.instance_id = Some(native.instance_id().to_string());
            response.owner_token = Some(owner_token);
        }
        state.entries.insert(request.session_id, session);
        return Ok(response);
    }
    if request.event == "session_end" {
        let session = state
            .entries
            .get_mut(&request.session_id)
            .ok_or("native_session_unknown")?;
        // The accepted end request and terminal cleanup have distinct audit rows.
        // Consume this sequence before retirement allocates its next one.
        session.seq += 1;
        audit(st, &request, session, &response, None, timing)?;
        let session_epoch = session.epoch.clone();
        drop(state);
        drop(firewall);
        retire_sessions_terminal(
            st,
            native,
            &[(request.session_id.clone(), Some(session_epoch))],
            "ended",
        );
        return Ok(response);
    }
    let total_calls: usize = state.entries.values().map(|s| s.calls.len()).sum();
    let session = state
        .entries
        .get(&request.session_id)
        .ok_or("native_session_unknown")?;
    validate_lineage(&state, session, now_ms, now)?;
    let publication_lifetime = if request.event == "publish" {
        publication_lifetime(&state, session, now, now_ms)?
    } else {
        0
    };
    let session = state
        .entries
        .get_mut(&request.session_id)
        .ok_or("native_session_unknown")?;
    session.touched = now;
    session.seq += 1;
    let name = request.tool.as_deref().ok_or("native_tool_missing")?;
    let tool = native
        .registry
        .tools
        .iter()
        .find(|t| t.name == name)
        .ok_or("native_tool_unknown")?;
    let args = request.args.as_ref().ok_or("native_args_missing")?;
    if request.event == "call" {
        if firewall.provenance_session_usage(&session.epoch).is_none()
            || session
                .host_session
                .as_deref()
                .is_some_and(|host| firewall.provenance_session_usage(host).is_none())
        {
            response.verdict = "deny";
            response.release = false;
            response
                .reason_codes
                .push("native_provenance_context_unavailable".into());
            let mut unavailable = Outcome::allow();
            unavailable.verdict = Verdict::Deny;
            unavailable.rule = Some("native_provenance_context_unavailable".into());
            unavailable.provenance_incomplete = true;
            audit(st, &request, session, &response, Some(&unavailable), timing)?;
            return Ok(response);
        }
        if args.to_string().len() > firewall.provenance_limits().max_input_bytes {
            firewall.mark_provenance_incomplete(&session.epoch);
            if let Some(host) = &session.host_session {
                firewall.mark_provenance_incomplete(host);
            }
            response.verdict = "deny";
            response.release = false;
            response.reason_codes.push("native_provenance_input".into());
            let mut unavailable = Outcome::allow();
            unavailable.verdict = Verdict::Deny;
            unavailable.rule = Some("native_provenance_input".into());
            unavailable.provenance_incomplete = true;
            audit(st, &request, session, &response, Some(&unavailable), timing)?;
            return Ok(response);
        }
        if session.host_session.is_some() {
            if !session.granted_tools.iter().any(|tool| tool == name) {
                return Err("native_child_authority_escalation");
            }
            if let Some(ref granted_res) = session.granted_resources {
                if !child_resources_authorized(
                    granted_res,
                    tool.resource_policy.as_ref(),
                    tool,
                    args,
                    request.resource_admission.as_ref(),
                ) {
                    return Err("native_child_authority_escalation");
                }
            } else if tool.resource_policy.is_some()
                || ((session.agent_id.is_some() || session.parent_id.is_some())
                    && (!tool.egress.is_empty() || tool.action_class == ActionClass::Network))
            {
                return Err("native_child_authority_escalation");
            }
        }
        let selected_result =
            crate::mcp::server_profile::selected(tool.mcp_result_profile.as_deref());
        if selected_result {
            if request.contract_version != CONTRACT
                || !request
                    .mcp_host_call_id
                    .as_ref()
                    .is_some_and(selected_host_id)
            {
                return Err("native_host_call_missing_or_invalid");
            }
        } else if request.mcp_host_call_id.is_some() {
            return Err("native_host_call_profile_required");
        }
        if request.schema_sha256.as_deref() != Some(tool.schema_sha256.as_str()) {
            return Err("native_schema_mismatch");
        }
        if tool.workspace_profile.is_some() {
            if session.host_session.is_some() {
                return Err("native_workspace_delegation_unsupported");
            }
            workspace::extract(tool, args)?;
        }
        if let Some(policy) = &tool.resource_policy {
            if request.contract_version != policy.contract() {
                if let Some(ref approval_id) = request.approval_id {
                    if let Some(ref approval) = native.approval {
                        approval.invalidate(
                            approval_id,
                            &request.session_id,
                            "native_resource_contract_required",
                        );
                    }
                }
                return Err("native_resource_contract_required");
            }
            let Some(admission) = &request.resource_admission else {
                if let Some(ref approval_id) = request.approval_id {
                    if let Some(ref approval) = native.approval {
                        approval.invalidate(
                            approval_id,
                            &request.session_id,
                            "native_resource_contract_required",
                        );
                    }
                }
                return Err("native_resource_contract_required");
            };
            if let Err(reason) =
                resource::authorize(policy, tool, &native.registry_sha256, args, admission)
            {
                if let Some(ref approval_id) = request.approval_id {
                    if let Some(ref approval) = native.approval {
                        approval.invalidate(approval_id, &request.session_id, reason);
                    }
                }
                response.verdict = "deny";
                response.release = false;
                response.reason_codes.push(reason.into());
                audit(st, &request, session, &response, None, timing)?;
                return Ok(response);
            }
        } else if request.resource_admission.is_some() {
            if let Some(ref approval_id) = request.approval_id {
                if let Some(ref approval) = native.approval {
                    approval.invalidate(
                        approval_id,
                        &request.session_id,
                        "native_resource_policy_missing",
                    );
                }
            }
            return Err("native_resource_policy_missing");
        }
        if total_calls >= MAX_CALLS || session.calls.len() >= MAX_SESSION_CALLS {
            return Err("native_call_cap");
        }
        let hosts = declared_hosts(tool, args)?;
        let ev = session.event(EventKind::ToolCall {
            tool: name.into(),
            args: args.clone(),
        });
        let mut outcome = invocation::inspect(&mut firewall, &ev, tool, &hosts)?;
        if let Some(host) = &session.host_session {
            let ev_host = session.host_event(
                host,
                session.seq,
                EventKind::ToolCall {
                    tool: name.into(),
                    args: args.clone(),
                },
            );
            let outcome_host = invocation::inspect(&mut firewall, &ev_host, tool, &hosts)?;
            outcome = merge_provenance_outcomes(outcome, outcome_host);
        }
        let mut verdict = resolved(&outcome);
        response.reason_codes = outcome.rule.iter().cloned().collect();
        if tool
            .resource_policy
            .as_ref()
            .is_some_and(|policy| policy.is_https_get() || policy.is_https_post())
            && !firewall.egress_hosts_allowlisted(&hosts)
        {
            verdict = Verdict::Deny;
            response
                .reason_codes
                .push("native_https_egress_not_allowlisted".into());
        }
        response.verdict = verdict_label(verdict);
        response.release = verdict == Verdict::Allow;
        let legacy_bound = binding(
            &native.registry_sha256,
            &session.epoch,
            name,
            &tool.schema_sha256,
            args,
            request.resource_admission.as_ref(),
        );
        let bound = if let Some(host_id) = &request.mcp_host_call_id {
            selected_host_binding(&legacy_bound, host_id)
        } else {
            legacy_bound
        };
        // Selected original creates retain typed target/content/root evidence
        // for ordinary Allow as well as Ask. The context binds observations;
        // the installed profile and policy still supply all authority.
        let bound = if let Some(context) = &request.selected_invocation {
            let valid = context.validate(tool, args).and_then(|()| {
                if !selected_result
                    || request.mcp_host_call_id.as_ref() != Some(&context.host_call_id)
                    || session
                        .server_id
                        .as_deref()
                        .is_some_and(|server| server != context.server_id)
                    || (request.approval_id.is_some() && session.server_id.is_none())
                {
                    Err("native_approval_selected_binding_mismatch")
                } else {
                    Ok(())
                }
            });
            if let Err(code) = valid {
                if let (Some(approval), Some(id)) = (&native.approval, &request.approval_id) {
                    approval.invalidate(id, &request.session_id, code);
                }
                return Err(code);
            }
            context.binding(&bound)
        } else {
            bound
        };
        if let Some(approval_id) = &request.approval_id {
            // Exact single-use operator approval, rechecked against the policy
            // verdict computed just now. A hard Deny can never be rescued.
            let approval = native.approval.as_ref().ok_or("native_approval_disabled")?;
            let approval_bound = if selected_result {
                if identity.is_none() {
                    approval.invalidate(
                        approval_id,
                        &request.session_id,
                        "native_approval_bound_owner_required",
                    );
                    return Err("native_approval_bound_owner_required");
                }
                let Some(context) = request.selected_invocation.as_ref() else {
                    approval.invalidate(
                        approval_id,
                        &request.session_id,
                        "native_approval_selected_context_required",
                    );
                    return Err("native_approval_selected_context_required");
                };
                let valid = context.validate(tool, args).and_then(|()| {
                    if request.mcp_host_call_id.as_ref() != Some(&context.host_call_id)
                        || session.server_id.as_deref() != Some(&context.server_id)
                    {
                        Err("native_approval_selected_binding_mismatch")
                    } else {
                        Ok(())
                    }
                });
                if let Err(code) = valid {
                    approval.invalidate(approval_id, &request.session_id, code);
                    return Err(code);
                }
                bound.clone()
            } else {
                if request.selected_invocation.is_some() {
                    approval.invalidate(
                        approval_id,
                        &request.session_id,
                        "native_approval_selected_unsupported",
                    );
                    return Err("native_approval_selected_unsupported");
                }
                bound.clone()
            };
            if verdict == Verdict::Deny {
                // An explicit hard Deny (including egress denial or lineage floor failure)
                // can never be approved or redeemed. Terminally invalidate the presented approval.
                approval.invalidate(
                    approval_id,
                    &request.session_id,
                    "native_approval_hard_deny",
                );
                response.verdict = "deny";
                response.release = false;
                response
                    .reason_codes
                    .push("native_approval_hard_deny".into());
            } else {
                let revalidate = if tool.resource_policy.is_some() {
                    resource_approval::revalidate_resource_execution(
                        tool,
                        args,
                        request.resource_admission.as_ref(),
                    )
                } else {
                    Ok(())
                };
                match revalidate {
                    Ok(()) => {
                        match approval.redeem(
                            approval_id,
                            &request.session_id,
                            &session.epoch,
                            name,
                            &tool.schema_sha256,
                            &approval_bound,
                            verdict,
                        ) {
                            Ok(()) => {
                                response.verdict = "allow";
                                response.release = true;
                                response
                                    .reason_codes
                                    .push(format!("native_approval_redeemed:{approval_id}"));
                            }
                            Err(code) => {
                                response.release = false;
                                if verdict != Verdict::Deny {
                                    response.verdict = "ask";
                                }
                                response.reason_codes.push(code.into());
                            }
                        }
                    }
                    Err(code) => {
                        // Terminal invalidation on failed presented approval:
                        // a refused mutation must not leave an approval retryable under
                        // the documented terminal-refusal contract.
                        approval.invalidate(approval_id, &request.session_id, code);
                        response.release = false;
                        if verdict != Verdict::Deny {
                            response.verdict = "ask";
                        }
                        response.reason_codes.push(code.into());
                    }
                }
            }
        }
        if response.release {
            response.binding_sha256 = Some(bound.clone());
            response.call_id = Some(crate::token::generate());
            if let Some(admission) = &request.resource_admission {
                response.resources_sha256 = Some(admission.resources_sha256());
            }
        }
        audit(st, &request, session, &response, Some(&outcome), timing)?;
        if let Some(id) = &response.call_id {
            session.calls.insert(
                id.clone(),
                Call {
                    publication_outcome: tool
                        .resource_policy
                        .as_ref()
                        .is_some_and(|p| p.is_replace_file())
                        .then(|| outcome.clone()),
                    publication_authorized: false,
                    #[cfg(target_os = "linux")]
                    execution_args: native
                        .git_execution
                        .as_ref()
                        .filter(|_| {
                            tool.mcp_result_profile
                                .as_deref()
                                .is_some_and(crate::mcp::server_profile::git_selected)
                        })
                        .map(|_| args.clone()),
                    managed_policy: firewall.active_managed_policy(),
                    host_call_id: request.mcp_host_call_id.clone().or_else(|| {
                        request
                            .resource_admission
                            .as_ref()
                            .map(|context| context.host_call_id.clone())
                    }),
                    contract_version: response.contract_version,
                    tool: name.into(),
                    args_sha256: args_hash(args),
                    binding_sha256: bound,
                    stage: Stage::Result,
                    expires: now + TTL,
                    result_kind: None,
                },
            );
        }
        return Ok(response);
    }
    let id = request.call_id.as_deref().ok_or("native_call_missing")?;
    // Remove before validation. A mismatched/failed completion cannot be retried
    // into a different admission after observing its error.
    let mut call = match execution.as_ref() {
        Some(owned) => {
            owned.validate(&request, session, now)?;
            owned.call.clone()
        }
        None => session
            .calls
            .remove(id)
            .ok_or("native_call_unknown_or_spent")?,
    };
    if request.event == "result"
        && crate::mcp::server_profile::selected(tool.mcp_result_profile.as_deref())
        && request.delivery.as_deref() != Some("mcp_host")
    {
        // A selected MCP grant cannot downgrade to the legacy opaque parent or
        // model route to evade typed host correlation and decoded inspection.
        return Err("native_selected_mcp_delivery");
    }
    if request.event == "result" && request.delivery.as_deref() == Some("mcp_host") {
        if let Some(host_id) = &call.host_call_id {
            let envelope: Value =
                serde_json::from_str(request.content.as_deref().ok_or("native_content_missing")?)
                    .map_err(|_| "native_mcp_result_shape")?;
            if envelope.get("id") != Some(host_id) {
                return Err("native_host_call_mismatch");
            }
        }
    }
    response.call_id = Some(id.into());
    response.binding_sha256 = Some(call.binding_sha256.clone());
    if call.contract_version != request.contract_version
        || call.tool != name
        || call.args_sha256 != args_hash(args)
    {
        return Err("native_call_binding_mismatch");
    }
    if request.event == "publish" {
        if call.contract_version != resource::replacement::CONTRACT
            || call.publication_authorized
            || call.stage != Stage::Result
            || call.managed_policy != firewall.active_managed_policy()
        {
            return Err("native_publication_stale_or_spent");
        }
        let hosts = declared_hosts(tool, args)?;
        let kind = EventKind::ToolCall {
            tool: name.into(),
            args: args.clone(),
        };
        let mut current =
            invocation::inspect(&mut firewall, &session.event(kind.clone()), tool, &hosts)?;
        if let Some(host) = &session.host_session {
            let host_outcome = invocation::inspect(
                &mut firewall,
                &session.host_event(host, session.seq, kind),
                tool,
                &hosts,
            )?;
            current = merge_provenance_outcomes(current, host_outcome);
        }
        // An Ask was already redeemed once. It remains usable only if the
        // exact policy outcome and provenance remain unchanged; this is not a
        // new grant and cannot rescue Deny or a newly introduced condition.
        if resolved(&current) == Verdict::Deny
            || call.publication_outcome.as_ref() != Some(&current)
        {
            return Err("native_publication_policy_changed");
        }
        call.publication_authorized = true;
        let gate_now = native.monotonic_now();
        let remaining = call.expires.saturating_duration_since(gate_now).as_millis() as u64;
        let remaining = remaining.min(
            publication_lifetime
                .saturating_sub(gate_now.saturating_duration_since(now).as_millis() as u64),
        );
        if remaining == 0 {
            return Err("native_publication_expired");
        }
        response.publication_ttl_ms = Some(remaining);
        audit(st, &request, session, &response, Some(&current), timing)?;
        session.calls.insert(id.into(), call);
        return Ok(response);
    }
    if request.event == "result"
        && call.publication_outcome.is_some()
        && !call.publication_authorized
        && request.result_kind.as_deref() != Some("error")
    {
        return Err("native_publication_required");
    }
    let consumed = evidence
        .map(|evidence| evidence.consume(native, session, &request, &call, now))
        .transpose()?;
    response.execution = consumed.as_ref().map(execution::Consumed::metadata);
    // A previously dispatched effect cannot be undone. Its result is a new
    // release boundary: a changed policy must authorize the original action
    // again, without reusing an old Ask approval, before inspecting its content.
    if call.managed_policy != firewall.active_managed_policy() {
        let hosts = declared_hosts(tool, args)?;
        let kind = EventKind::ToolCall {
            tool: name.into(),
            args: args.clone(),
        };
        let mut outcome =
            invocation::inspect(&mut firewall, &session.event(kind.clone()), tool, &hosts)?;
        if let Some(host) = &session.host_session {
            let host_outcome = invocation::inspect(
                &mut firewall,
                &session.host_event(host, session.seq, kind),
                tool,
                &hosts,
            )?;
            outcome = merge_provenance_outcomes(outcome, host_outcome);
        }
        let verdict = resolved(&outcome);
        if verdict != Verdict::Allow {
            response.verdict = verdict_label(verdict);
            response.release = false;
            response.reason_codes = vec!["native_policy_transition_result_refused".into()];
            response.reason_codes.extend(outcome.rule.iter().cloned());
            audit(st, &request, session, &response, Some(&outcome), timing)?;
            return Ok(response);
        }
    }
    let content = request.content.as_deref().ok_or("native_content_missing")?;
    let texts = if request.event == "result" {
        if call.stage != Stage::Result {
            return Err("native_stage_mismatch");
        }
        if !matches!(request.result_kind.as_deref(), Some("value" | "error")) {
            return Err("native_result_kind");
        }
        if !matches!(
            request.delivery.as_deref(),
            Some("parent" | "model" | "mcp_host")
        ) {
            return Err("native_delivery");
        }
        if request.delivery.as_deref() == Some("mcp_host") {
            if tool
                .mcp_result_profile
                .as_deref()
                .is_some_and(crate::mcp::server_profile::git_selected)
            {
                selected_mcp_host_text_profile(
                    content,
                    request.result_kind.as_deref().unwrap_or(""),
                    false,
                )?
            } else if matches!(
                tool.mcp_result_profile.as_deref(),
                Some(
                    crate::mcp::server_profile::FORMAT
                        | crate::mcp::server_profile::filesystem_roots::FORMAT
                        | crate::mcp::server_profile::filesystem_links::FORMAT
                )
            ) {
                selected_mcp_host_text(content, request.result_kind.as_deref().unwrap_or(""))?
            } else if tool.mcp_result_profile.as_deref()
                == Some(crate::mcp::server_profile::filesystem_create::FORMAT)
            {
                // The pinned ORIGINAL filesystem server emits both plain
                // content and independently inspected structuredContent even
                // for write_file. Require both original channels, exactly as
                // for its readonly tools; never loosen its result envelope.
                selected_mcp_host_text(content, request.result_kind.as_deref().unwrap_or(""))?
            } else {
                mcp_host_text(content, request.result_kind.as_deref().unwrap_or(""))?
            }
        } else {
            vec![content.to_string()]
        }
    } else {
        if call.stage != Stage::Context {
            return Err("native_stage_mismatch");
        }
        let envelope: Value = serde_json::from_str(content).map_err(|_| "native_context_json")?;
        let error = envelope
            .get("error")
            .and_then(Value::as_str)
            .is_some_and(|s| !s.is_empty());
        if error != (call.result_kind.as_deref() == Some("error")) {
            return Err("native_result_kind_mismatch");
        }
        context_text(content, name)?
    };
    if request.delivery.as_deref() == Some("mcp_host")
        && crate::mcp::server_profile::selected(tool.mcp_result_profile.as_deref())
        && texts
            .iter()
            .any(|text| text.len() > st.config.max_record_bytes)
    {
        // The grant is spent with an explicit refusal receipt. An enlarged
        // result is never released because the recorder could not admit it.
        response.verdict = verdict_label(Verdict::Deny);
        response.release = false;
        response.reason_codes = vec!["native_record_over_cap".into()];
        audit(st, &request, session, &response, None, timing)?;
        return Ok(response);
    }
    let provenance = match (
        request.delivery.as_deref(),
        &tool.result_provenance,
        &session.server_id,
    ) {
        (Some("mcp_host"), ResultProvenance::Untrusted, Some(server)) => Provenance::McpServer {
            name: server.clone(),
        },
        _ => source(&native.registry, tool),
    };
    let mut events = Vec::new();
    let mut strongest = Verdict::Allow;
    let mut representative = None;
    let mut observed_findings = BTreeMap::new();
    let mut max_block_risk = 0;
    let inspect_mcp_result = request.event == "result"
        && request.delivery.as_deref() == Some("mcp_host")
        && matches!(tool.result_provenance, ResultProvenance::Untrusted);
    let evidence_started = Instant::now();
    let mcp_evidence = if inspect_mcp_result {
        match soup_wall_core::InjectionDetector::mcp_result_evidence(
            &texts.iter().map(String::as_str).collect::<Vec<_>>(),
        ) {
            Ok(evidence) => Some(evidence),
            Err(limit) => {
                timing.evidence_us = evidence_started.elapsed().as_micros();
                // The Call was removed before result validation. No partial
                // findings, skipped suffix, taint or raw spans can be released.
                session.seq += 1;
                response.verdict = "deny";
                response.release = false;
                response.reason_codes = vec![
                    "native_mcp_result_evidence_incomplete".into(),
                    format!("native_mcp_result_evidence_limit_{}", limit.code()),
                ];
                let mut refusal = Outcome::allow();
                refusal.verdict = Verdict::Deny;
                refusal.rule = Some("native_mcp_result_evidence_incomplete".into());
                audit(st, &request, session, &response, Some(&refusal), timing)?;
                return Ok(response);
            }
        }
    } else {
        None
    };
    timing.evidence_us = evidence_started.elapsed().as_micros();
    let detectors_started = Instant::now();
    let block_count = texts.len();
    for (block_index, text) in texts.into_iter().enumerate() {
        session.seq += 1;
        let ev = session.event(EventKind::ToolResult {
            tool: name.into(),
            content: text,
            source: provenance.clone(),
        });
        let outcome = if let Some(evidence) = &mcp_evidence {
            if let Some(span) = execution
                .as_ref()
                .and_then(|owned| owned.formatter_span(&ev))
            {
                firewall.preview_verified_git_result(&ev, evidence, block_index, &span)
            } else if block_count > 2 {
                // Diagnostics are bounded to the two selected formatter channels.
                firewall.preview_native_mcp_result(&ev, evidence, block_index)
            } else {
                let EventKind::ToolResult { content, .. } = &ev.kind else {
                    unreachable!()
                };
                let spans = consumed
                    .as_ref()
                    .and_then(|owned| owned.formatter_spans(content, block_index, block_count));
                let (outcome, comparison) = match consumed.as_ref() {
                    Some(owned) => owned.inspect_formatter(
                        &mut firewall,
                        &ev,
                        evidence,
                        block_index,
                        block_count,
                    ),
                    None => firewall.preview_mcp_result_shadow(&ev, evidence, block_index, None),
                };
                let correction_applied = comparison
                    .as_ref()
                    .is_some_and(|pair| pair.original.verdict != outcome.verdict);

                let mut diagnostic = json!({
                    "block": block_index, "facet": "tool_result",
                    "eligibility": if spans.is_some() { "consumed_original_formatter" } else { "baseline_no_bound_formatter" },
                    "channel": if spans.is_some() { Some(if block_index == 0 { "result.content[0].text" } else { "result.structuredContent.content" }) } else { None },
                    "text_sha256": sha256_hex(content.as_bytes()), "comparison": comparison,
                    "correction_applied": correction_applied,
                    "production_authority": false, "task_complete": false,
                });
                // A diagnostic must not make a previously admissible response
                // exceed transport limits. Never change the production outcome.
                if diagnostic.to_string().len() > 65_536 {
                    diagnostic["comparison"] = Value::Null;
                    diagnostic["eligibility"] = json!("diagnostic_over_budget");
                }
                response.policy_shadow.push(diagnostic);
                outcome
            }
        } else {
            firewall.preview_native_result(&ev)
        };
        max_block_risk = max_block_risk.max(outcome.risk_score);
        for (facet, finding) in &outcome.findings {
            let key = (finding.detector.clone(), finding.severity);
            let entry = observed_findings
                .entry(key)
                .or_insert_with(|| (*facet, finding.clone()));
            if finding.confidence > entry.1.confidence {
                *entry = (*facet, finding.clone());
            }
        }
        let verdict = resolved(&outcome);
        if representative.is_none()
            || verdict == Verdict::Deny
            || (verdict == Verdict::Ask && strongest == Verdict::Allow)
        {
            strongest = verdict;
            representative = Some(outcome);
        }
        events.push(ev);
    }
    if let Some(outcome) = &mut representative {
        // Every original block was inspected independently. Audit all observed
        // detector kinds and the largest evaluated score. Cross-block lexical
        // evidence is additive; hash/delimiter heuristic scores are never
        // accumulated across unrelated original blocks.
        outcome.findings = observed_findings.into_values().collect();
        if let Some(evidence) = mcp_evidence {
            outcome.findings.extend(
                evidence
                    .into_audit()
                    .into_iter()
                    .map(|f| (soup_wall_agent::Facet::ToolResult, f)),
            );
        }
        outcome.risk_score = max_block_risk;
    }
    response.verdict = verdict_label(strongest);
    response.release = strongest == Verdict::Allow;
    response.reason_codes = representative
        .as_ref()
        .and_then(|o| o.rule.clone())
        .into_iter()
        .collect();
    timing.detectors_us = detectors_started.elapsed().as_micros();
    let tracking_started = Instant::now();
    let needs_tracking = request.event == "context"
        || matches!(request.delivery.as_deref(), Some("parent" | "mcp_host"));
    let shared_host = session
        .host_session
        .as_deref()
        .filter(|_| request.event == "result" && request.delivery.as_deref() == Some("mcp_host"));
    let mut host_sequences = vec![None; events.len()];
    if response.release && needs_tracking {
        // Commit bounded evidence before the Allow audit, without cloning the
        // tracker. Partial evidence may conservatively survive a later refusal
        // or audit failure; no part of the original result is released then.
        let mut tracking_failure = None;
        for (index, ev) in events.iter().enumerate() {
            if firewall.provenance_session_usage(&session.epoch).is_none() {
                tracking_failure = Some("context_unavailable");
            } else if let Err(reason) = firewall.try_admit_native_result(ev) {
                tracking_failure = Some(reason.code());
            }
            if let Some(host) = shared_host {
                let host_seq = st.sessions.next(host);
                host_sequences[index] = Some(host_seq);
                if firewall.provenance_session_usage(host).is_none() {
                    tracking_failure = Some("context_unavailable");
                    continue;
                }
                let mut ev_host = ev.clone();
                ev_host.session = host.to_string();
                ev_host.seq = host_seq;
                if let Err(reason) = firewall.try_admit_native_result(&ev_host) {
                    tracking_failure = Some(reason.code());
                }
            }
        }
        // Later blocks or the shared-host copy can evict evidence from an
        // earlier block. Recheck the complete original delivery before Allow.
        for (index, ev) in events.iter().enumerate() {
            if !matches!(firewall.native_result_is_retained(ev), Ok(true)) {
                tracking_failure.get_or_insert("batch_evicted");
            }
            if let (Some(host), Some(host_seq)) = (shared_host, host_sequences[index]) {
                let mut ev_host = ev.clone();
                ev_host.session = host.to_string();
                ev_host.seq = host_seq;
                if !matches!(firewall.native_result_is_retained(&ev_host), Ok(true)) {
                    tracking_failure.get_or_insert("batch_evicted");
                }
            }
        }
        if let Some(outcome) = &mut representative {
            outcome.provenance_incomplete |= firewall.provenance_incomplete(&session.epoch)
                || shared_host.is_some_and(|host| firewall.provenance_incomplete(host));
        }
        if let Some(reason) = tracking_failure {
            firewall.mark_provenance_incomplete(&session.epoch);
            if let Some(host) = shared_host {
                firewall.mark_provenance_incomplete(host);
            }
            response.verdict = "deny";
            response.release = false;
            response.reason_codes = vec![
                "native_provenance_unrecordable".into(),
                format!("native_provenance_{reason}"),
            ];
            let outcome = representative.get_or_insert_with(Outcome::allow);
            outcome.verdict = Verdict::Deny;
            outcome.rule = Some("native_provenance_unrecordable".into());
            outcome.provenance_incomplete = true;
        }
    }
    timing.tracking_us = tracking_started.elapsed().as_micros();
    audit(
        st,
        &request,
        session,
        &response,
        representative.as_ref(),
        timing,
    )?;
    if !response.release {
        if let (Some(consumed), Some(outcome)) = (consumed, representative.as_ref()) {
            match native
                .quarantine
                .lock()
                .map_err(|_| "analysis_quarantine_state")?
                .hold(
                    consumed,
                    quarantine::Capture {
                        session,
                        call: &call,
                        request: &request,
                        firewall: &firewall,
                        events: &events,
                        outcome,
                        now: native.monotonic_now(),
                    },
                ) {
                Ok(id) => response.quarantine_id = Some(id),
                Err(reason) => response.quarantine_error = Some(reason),
            }
        }
    }
    if response.release {
        // An outer model result is still held inside the collector until the
        // later context event. Raw judge spans remain post-audit only.
        if needs_tracking {
            for (index, ev) in events.iter().enumerate() {
                if let EventKind::ToolResult {
                    content, source, ..
                } = &ev.kind
                {
                    if source.trust() == Trust::Untrusted {
                        st.spans.put(&session.epoch, ev.seq, content);
                        if let (Some(host), Some(host_seq)) = (shared_host, host_sequences[index]) {
                            st.spans.put(host, host_seq, content);
                        }
                    }
                }
            }
        }
        if request.event == "result" && request.delivery.as_deref() == Some("model") {
            call.stage = Stage::Context;
            call.result_kind = request.result_kind;
            session.calls.insert(id.into(), call);
        }
    }
    Ok(response)
}

fn event_scoped(
    session: &str,
    agent: &str,
    parent: Option<&str>,
    seq: u64,
    kind: EventKind,
) -> AgentEvent {
    AgentEvent {
        session: session.into(),
        agent: agent.into(),
        parent: parent.map(Into::into),
        seq,
        at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0),
        kind,
    }
}

fn event(session: &str, seq: u64, kind: EventKind) -> AgentEvent {
    event_scoped(session, "native-runtime", None, seq, kind)
}

fn audit(
    st: &Shared,
    request: &Request,
    session: &Session,
    response: &Response,
    outcome: Option<&Outcome>,
    timing: &mut timing::Timing,
) -> Result<(), &'static str> {
    let started = Instant::now();
    let epoch = &session.epoch;
    let seq = session.seq;
    let mut record = json!({"at_ms": event(epoch, seq, EventKind::Unknown).at_ms, "session": epoch,
        "seq": seq, "event": format!("native_{}", request.event), "tool": request.tool,
        "verdict": response.verdict, "shadow": false, "released": response.release,
        "rule": outcome.and_then(|o| o.rule.as_ref()),
        "provenance_incomplete": outcome.is_some_and(|o| o.provenance_incomplete),
        "risk_score": outcome.map_or(0, |o| o.risk_score),
        "findings": outcome.map(|o| o.findings.iter().map(|(_, f)| json!({"detector": f.detector, "severity": format!("{:?}", f.severity).to_lowercase()})).collect::<Vec<_>>()).unwrap_or_default(),
        "egress_hosts": outcome.map(|o| o.egress_hosts.clone()).unwrap_or_default(),
        "taint": outcome.and_then(|o| o.taint.as_ref()).map(|t| json!({"source": t.source.label(),
            "origin": t.source.kind(), "source_name": t.source.source_name(),
            "trust": format!("{:?}", t.source.trust()).to_lowercase(), "seq": t.seq})),
        "latency_us": timing.elapsed_us(), "truncated": false, "registry_sha256": response.registry_sha256,
        "delivery": request.delivery,
        "call_id": response.call_id, "binding_sha256": response.binding_sha256,
        "content_sha256": response.content_sha256, "reason_codes": response.reason_codes});
    if let Some(outcome) = outcome {
        let reasons: Vec<_> = outcome
            .findings
            .iter()
            .filter(|(_, f)| f.label.contains("; cross-block lexical evidence;"))
            .map(|(_, f)| &f.label)
            .collect();
        if !reasons.is_empty() {
            // Static rule names and original byte coordinates, never raw text.
            record["cross_block_signature_evidence"] = json!(reasons);
        }
        let directives: Vec<_> = outcome
            .findings
            .iter()
            .filter(|(_, f)| f.label.starts_with("MCP result ") && f.span.is_some())
            .map(|(_, f)| json!({"reason": f.label, "original_byte_span": f.span}))
            .collect();
        if !directives.is_empty() {
            record["mcp_result_directive_evidence"] = json!(directives);
        }
    }
    if response
        .reason_codes
        .iter()
        .any(|code| code == "native_mcp_result_evidence_incomplete")
    {
        record["mcp_result_evidence"] = json!({"complete":false,"reason":"finite evidence budget exhausted","limits":{"findings":256,"audit_reason_bytes":65536,"charged_scan_bytes":33554432,"decoded_input_bytes":1048576}});
    }
    if !response.policy_shadow.is_empty() {
        record["policy_shadow"] = json!(response.policy_shadow);
    }
    if let Some(execution) = &response.execution {
        record["execution"] = json!(execution);
    }
    if let Some(policy) = &response.managed_policy {
        record["managed_policy"] = json!(policy);
    }
    if request.event == "call" {
        if let Some(context) = &request.selected_invocation {
            if let Some(resource) = &context.original_create {
                record["resource_details"] = json!(resource);
                record["selected_invocation_sha256"] = json!(canonical_digest(&json!(context)));
            }
        }
        if let Some(tool) = st.native.as_ref().and_then(|native| {
            native.registry.tools.iter().find(|tool| {
                request.tool.as_deref() == Some(tool.name.as_str())
                    && tool.workspace_profile.is_some()
            })
        }) {
            if let Some(extracted) = request
                .args
                .as_ref()
                .and_then(|args| workspace::extract(tool, args).ok())
            {
                record["workspace_profile"] = json!(workspace::PROFILE);
                record["workspace_resources_sha256"] = json!(canonical_digest(&extracted));
            }
        }
    }
    if let Some(host_session) = &session.host_session {
        record["host_session"] = json!(host_session);
    }
    if let Some(agent_id) = &session.agent_id {
        record["agent_id"] = json!(agent_id);
    }
    if let Some(parent_id) = &session.parent_id {
        record["parent_id"] = json!(parent_id);
    }
    let result = st
        .audit
        .write_native(&record)
        .map_err(|_| "native_audit_unavailable");
    timing.audit_us += started.elapsed().as_micros();
    result
}

#[cfg(test)]
mod tests;
