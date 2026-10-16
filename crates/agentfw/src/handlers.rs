// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! HTTP surface: `POST /hook` for every hook event, `GET /health` for liveness.
//! No detection logic lives here — verdicts come from `soup-wall-agent`.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use soup_wall_agent::{AgentFirewall, EventKind, Outcome, Trust, Verdict};

use crate::audit::{AuditFinding, AuditLine, AuditSink, AuditTaint};
use crate::config::Config;
use crate::decision;
use crate::hook::{HookEvent, HookPayload};
use futures_util::StreamExt;

use crate::judge::{Judge, Judgement};
use crate::map;
use crate::spans::SpanCache;

/// Bounded structural scanner for root-level JSON fields (depth 1 only).
/// Does not mistake nested fields, escaped quotes, or substrings for root fields.
#[derive(Debug, Default)]
pub struct RootJsonScan {
    pub string_fields: HashMap<String, String>,
    pub all_string_fields: HashMap<String, Vec<String>>,
    pub duplicate_keys: HashSet<String>,
    pub incomplete_keys: HashSet<String>,
    pub root_keys: HashSet<String>,
    pub opened_object: bool,
    pub closed_object: bool,
}

impl RootJsonScan {
    pub fn scan(raw: &str) -> Self {
        let mut scan = Self::default();
        let bytes = raw.as_bytes();
        let n = bytes.len();
        let mut i = 0;

        while i < n && bytes[i].is_ascii_whitespace() {
            i += 1;
        }

        if i >= n || bytes[i] != b'{' {
            return scan;
        }

        scan.opened_object = true;
        i += 1; // skip opening '{'

        enum State {
            Key,
            Colon(String),
            Value(String),
            CommaOrEnd,
        }

        let mut state = State::Key;

        while i < n {
            match state {
                State::Key => {
                    while i < n && bytes[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    if i >= n {
                        break;
                    }
                    if bytes[i] == b'}' {
                        scan.closed_object = true;
                        break;
                    }
                    if bytes[i] == b',' {
                        i += 1;
                        continue;
                    }
                    if bytes[i] == b'"' {
                        let (key_opt, next_i) = parse_json_string(bytes, i);
                        i = next_i;
                        if let Some(key) = key_opt {
                            if scan.root_keys.contains(&key) {
                                scan.duplicate_keys.insert(key.clone());
                            } else {
                                scan.root_keys.insert(key.clone());
                            }
                            state = State::Colon(key);
                        } else {
                            scan.incomplete_keys.insert("<incomplete_key>".to_string());
                            break;
                        }
                    } else {
                        break;
                    }
                }
                State::Colon(key) => {
                    while i < n && bytes[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    if i >= n {
                        scan.incomplete_keys.insert(key);
                        break;
                    }
                    if bytes[i] == b':' {
                        i += 1;
                        state = State::Value(key);
                    } else {
                        scan.incomplete_keys.insert(key);
                        break;
                    }
                }
                State::Value(key) => {
                    while i < n && bytes[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    if i >= n {
                        scan.incomplete_keys.insert(key);
                        break;
                    }
                    let b = bytes[i];
                    if b == b'"' {
                        let (val_opt, next_i) = parse_json_string(bytes, i);
                        i = next_i;
                        if let Some(val) = val_opt {
                            scan.all_string_fields
                                .entry(key.clone())
                                .or_default()
                                .push(val.clone());
                            scan.string_fields.insert(key, val);
                            state = State::CommaOrEnd;
                        } else {
                            scan.incomplete_keys.insert(key);
                            break;
                        }
                    } else if b == b'{' || b == b'[' {
                        let (complete, next_i) = skip_composite(bytes, i);
                        i = next_i;
                        if complete {
                            state = State::CommaOrEnd;
                        } else {
                            scan.incomplete_keys.insert(key);
                            break;
                        }
                    } else if b == b',' || b == b'}' {
                        scan.incomplete_keys.insert(key);
                        if b == b'}' {
                            scan.closed_object = true;
                        }
                        break;
                    } else {
                        let next_i = skip_primitive(bytes, i);
                        i = next_i;
                        state = State::CommaOrEnd;
                    }
                }
                State::CommaOrEnd => {
                    while i < n && bytes[i].is_ascii_whitespace() {
                        i += 1;
                    }
                    if i >= n {
                        break;
                    }
                    if bytes[i] == b',' {
                        i += 1;
                        state = State::Key;
                    } else if bytes[i] == b'}' {
                        scan.closed_object = true;
                        break;
                    } else {
                        break;
                    }
                }
            }
        }

        scan
    }

    pub fn get_root_string(&self, key: &str) -> Option<&str> {
        if self.duplicate_keys.contains(key) || self.incomplete_keys.contains(key) {
            return None;
        }
        self.string_fields.get(key).map(|s| s.as_str())
    }

    pub fn is_proven_non_pre(&self) -> bool {
        if !self.opened_object {
            return false;
        }
        if self.duplicate_keys.contains("hook_event_name")
            || self.duplicate_keys.contains("event")
            || self.incomplete_keys.contains("hook_event_name")
            || self.incomplete_keys.contains("event")
        {
            return false;
        }
        let event = self
            .string_fields
            .get("hook_event_name")
            .or_else(|| self.string_fields.get("event"));
        matches!(
            event.map(|s| s.as_str()),
            Some("PostToolUse" | "SessionStart" | "SessionEnd")
        )
    }

    pub fn is_protected_pretooluse(&self, raw: &str) -> bool {
        if !self.opened_object {
            return false;
        }
        let event = self
            .get_root_string("hook_event_name")
            .or_else(|| self.get_root_string("event"));
        if event != Some("PreToolUse") {
            return false;
        }
        let tool = self
            .get_root_string("tool_name")
            .or_else(|| self.get_root_string("tool"));
        let Some(tool) = tool else {
            return false;
        };
        const READ_ONLY: &[&str] = &[
            "Read",
            "Grep",
            "Glob",
            "NotebookRead",
            "TodoRead",
            "WebFetch",
            "WebSearch",
        ];
        if READ_ONLY.contains(&tool) {
            return false;
        }
        if tool == "Bash" {
            return raw.contains("\"command\"");
        }
        true
    }

    pub fn has_protected_tool(&self, raw: &str) -> bool {
        let mut tools = Vec::new();
        if let Some(t) = self
            .string_fields
            .get("tool_name")
            .or_else(|| self.string_fields.get("tool"))
        {
            tools.push(t.as_str());
        }
        if let Some(all_t) = self.all_string_fields.get("tool_name") {
            for t in all_t {
                tools.push(t.as_str());
            }
        }
        if let Some(all_t) = self.all_string_fields.get("tool") {
            for t in all_t {
                tools.push(t.as_str());
            }
        }
        if tools.is_empty() {
            return false;
        }
        const READ_ONLY: &[&str] = &[
            "Read",
            "Grep",
            "Glob",
            "NotebookRead",
            "TodoRead",
            "WebFetch",
            "WebSearch",
        ];
        for tool in tools {
            if !READ_ONLY.contains(&tool) {
                if tool == "Bash" {
                    if raw.contains("\"command\"") {
                        return true;
                    }
                } else {
                    return true;
                }
            }
        }
        false
    }
}

fn parse_json_string(bytes: &[u8], start: usize) -> (Option<String>, usize) {
    let n = bytes.len();
    if start >= n || bytes[start] != b'"' {
        return (None, start);
    }
    let mut i = start + 1;
    let mut has_escapes = false;
    let content_start = i;
    while i < n {
        let b = bytes[i];
        if b == b'"' {
            let res = if has_escapes {
                let slice = &bytes[start..=i];
                if let Ok(s) = std::str::from_utf8(slice) {
                    serde_json::from_str::<String>(s).ok()
                } else {
                    None
                }
            } else {
                let slice = &bytes[content_start..i];
                String::from_utf8(slice.to_vec()).ok()
            };
            return (res, i + 1);
        } else if b == b'\\' {
            has_escapes = true;
            i += 1;
            if i >= n {
                return (None, n);
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    (None, n)
}

fn skip_composite(bytes: &[u8], start: usize) -> (bool, usize) {
    let n = bytes.len();
    let mut depth: usize = 0;
    let mut i = start;
    let mut in_string = false;
    let mut escape = false;

    while i < n {
        let b = bytes[i];
        if in_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
        } else if b == b'"' {
            in_string = true;
        } else if b == b'{' || b == b'[' {
            depth += 1;
        } else if b == b'}' || b == b']' {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return (true, i + 1);
            }
        }
        i += 1;
    }
    (false, n)
}

fn skip_primitive(bytes: &[u8], start: usize) -> usize {
    let n = bytes.len();
    let mut i = start;
    while i < n {
        let b = bytes[i];
        if b == b',' || b == b'}' || b == b']' || b.is_ascii_whitespace() {
            break;
        }
        i += 1;
    }
    i
}

fn mark_lossy_provenance(st: &AppState, scan: &RootJsonScan) {
    let mut sessions_to_mark = Vec::new();
    if let Some(session_id) = scan.get_root_string("session_id").filter(|s| !s.is_empty()) {
        sessions_to_mark.push(session_id.to_string());
    } else {
        if let Some(vals) = scan.all_string_fields.get("session_id") {
            for sid in vals {
                if !sid.is_empty() && !sessions_to_mark.contains(sid) {
                    sessions_to_mark.push(sid.clone());
                }
            }
        }
        // Snapshot active hosts before acquiring firewall lock to prevent deadlock
        if let Some(ref native) = st.native {
            for host in native.active_host_sessions() {
                if !sessions_to_mark.contains(&host) {
                    sessions_to_mark.push(host);
                }
            }
        }
    }

    if sessions_to_mark.is_empty() {
        return;
    }

    let mut fw = st.firewall.lock().expect("firewall mutex");
    for host in sessions_to_mark {
        fw.mark_provenance_incomplete(&host);
    }
}

#[derive(Debug)]
pub enum BodyReadError {
    Oversized { prefix: Vec<u8>, total_len: usize },
    Io { prefix: Vec<u8>, error: String },
    InvalidUtf8 { prefix: Vec<u8> },
}

async fn read_bounded_string(
    body: axum::body::Body,
    max_bytes: usize,
) -> Result<String, BodyReadError> {
    let mut stream = body.into_data_stream();
    let mut buf = Vec::new();
    let mut total_len = 0;
    while let Some(chunk_res) = stream.next().await {
        let chunk = match chunk_res {
            Ok(c) => c,
            Err(e) => {
                return Err(BodyReadError::Io {
                    prefix: buf,
                    error: e.to_string(),
                });
            }
        };
        total_len += chunk.len();
        if buf.len() < max_bytes + 4096 {
            let to_take = chunk.len().min((max_bytes + 4096) - buf.len());
            buf.extend_from_slice(&chunk[..to_take]);
        }
        if total_len > max_bytes {
            drop(stream);
            return Err(BodyReadError::Oversized {
                prefix: buf,
                total_len,
            });
        }
    }
    match String::from_utf8(buf) {
        Ok(s) => Ok(s),
        Err(e) => Err(BodyReadError::InvalidUtf8 {
            prefix: e.into_bytes(),
        }),
    }
}

/// Turn a judgement plus the rule's declared fallback into a final verdict.
///
/// Delegate to the shared production resolver. Injection can tighten Allow to Ask;
/// Deny is preserved. Missing or recursive fallbacks require Ask.
pub fn resolve_escalation(j: Judgement, fallback: Option<Verdict>) -> Verdict {
    soup_wall_agent::resolution::resolve(
        Verdict::Escalate,
        fallback,
        matches!(j, Judgement::Injection),
    )
}

/// Stable audit-log string for a verdict. Deliberately explicit rather than
/// `Debug`-derived, for the same reason as `HookEvent::as_str`: the audit log is a
/// forensic record and must not change shape when a variant is renamed.
/// `replay::summarize` matches on these exact strings.
fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Allow => "allow",
        Verdict::Ask => "ask",
        Verdict::Deny => "deny",
        // Not expected to reach the audit log: the handler resolves `Escalate`
        // into a real verdict before `decision::decide` (and this) ever see it.
        // Named explicitly here rather than a catch-all so a future variant added
        // to `Verdict` fails to compile here too, instead of silently logging
        // under someone else's label.
        Verdict::Escalate => "escalate",
    }
}

/// Per-session monotonic sequence numbers.
#[derive(Default)]
pub struct Sessions {
    counters: Mutex<HashMap<String, u64>>,
}

impl Sessions {
    pub fn next(&self, session: &str) -> u64 {
        let mut m = self.counters.lock().expect("sessions mutex");
        let c = m.entry(session.to_string()).or_insert(0);
        *c += 1;
        *c
    }

    pub fn end(&self, session: &str) {
        self.counters
            .lock()
            .expect("sessions mutex")
            .remove(session);
    }
}

/// All state shared across hook requests.
pub struct AppState {
    pub native: Option<crate::native::NativeState>,
    pub firewall: Mutex<AgentFirewall>,
    pub sessions: Sessions,
    pub audit: AuditSink,
    pub config: Config,
    pub token: String,
    /// Bounded per-session cache of untrusted content, keyed by the sequence
    /// number the taint tracker recorded it under. The judge tier reads from this
    /// rather than from `TaintMark`, which deliberately carries only an 8-byte
    /// fingerprint. See `spans.rs`.
    pub spans: SpanCache,
    /// The optional local-model escalation tier. Off unless configured; when off,
    /// every `judge()` call returns `Unavailable` and the rule's fallback applies.
    pub judge: Judge,
    /// Persistent per-server MCP manifest pins (the rug-pull defense).
    pub manifests: crate::mcp::store::ManifestStore,
    /// Cross-server tool-name registry (the shadowing defense).
    pub tools: crate::mcp::store::ToolRegistry,
    /// Approvals an operator has issued but no call has matched yet.
    pub grants: crate::grant::GrantStore,
    /// Which approvals have been spent. Single use is enforced here, not by the
    /// pending file, so a failed delete cannot become a second authorization.
    pub grant_ledger: crate::grant::GrantLedger,
    /// Approval-signing key derived from the hook token with domain separation.
    /// A hook-token holder can derive this key; collector isolation is necessary.
    pub grant_key: Vec<u8>,
}

pub type Shared = Arc<AppState>;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Liveness probe. Also reports whether enforcement is on, so `curl`ing it tells
/// an operator at a glance whether a blocked call is expected behavior.
pub async fn health(State(st): State<Shared>) -> Json<serde_json::Value> {
    // This reads the actual in-process AgentFirewall, NOT a downloaded file.
    let (active, transport) = st
        .firewall
        .lock()
        .ok()
        .map(|fw| (fw.active_managed_policy(), fw.managed_transport_status()))
        .unwrap_or_default();
    Json(serde_json::json!({
        "status": "ok",
        "enforce": st.config.enforce,
        "managed_policy": active,
        "managed_transport": transport,
    }))
}

/// Every hook event lands here. On ANY internal failure this returns 200 with an
/// empty body, which Claude Code treats as "no opinion" — a security tool that
/// wedges the agent loop gets uninstalled the same day.
pub async fn hook(
    State(st): State<Shared>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> (StatusCode, Json<serde_json::Value>) {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::token::verify(&st.token, auth) {
        tracing::warn!("rejected an unauthenticated hook request");
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({})));
    }

    let body = match read_bounded_string(body, st.config.max_body_bytes).await {
        Ok(s) => s,
        Err(err) => {
            let (prefix, reason_msg) = match err {
                BodyReadError::Oversized { prefix, total_len } => {
                    tracing::warn!(
                        len = total_len,
                        "hook body over cap; proceeding without inspection"
                    );
                    (prefix, "hook body exceeds configured max_body_bytes")
                }
                BodyReadError::Io { prefix, error } => {
                    tracing::warn!(error = %error, "hook body stream error");
                    (prefix, "hook body stream read error; refused by policy")
                }
                BodyReadError::InvalidUtf8 { prefix } => {
                    tracing::warn!("hook body contains invalid UTF-8");
                    (prefix, "invalid UTF-8 in hook body; refused by policy")
                }
            };
            let lossy_prefix = String::from_utf8_lossy(&prefix);
            let scan = RootJsonScan::scan(&lossy_prefix);
            mark_lossy_provenance(&st, &scan);
            let is_proven_non_pre = scan.is_proven_non_pre() && scan.closed_object;
            if st.config.enforce && !is_proven_non_pre {
                let out = decision::Decision {
                    permission_decision: "deny",
                    reason: Some(reason_msg.into()),
                    shadow: false,
                    would_have_been: Verdict::Deny,
                }
                .to_hook_output();
                return (
                    StatusCode::OK,
                    Json(serde_json::to_value(out).unwrap_or_default()),
                );
            }
            return (StatusCode::OK, Json(serde_json::json!({})));
        }
    };

    let started = Instant::now();

    let payload: HookPayload = match serde_json::from_str(&body) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(error = %e, "unparsable hook payload; proceeding");
            let scan = RootJsonScan::scan(&body);
            mark_lossy_provenance(&st, &scan);
            let is_proven_non_pre = scan.is_proven_non_pre() && scan.closed_object;
            let has_protected_tool = scan.has_protected_tool(&body);
            if st.config.enforce && (!is_proven_non_pre && has_protected_tool) {
                let out = decision::Decision {
                    permission_decision: "deny",
                    reason: Some("unparsable hook payload; refused by policy".into()),
                    shadow: false,
                    would_have_been: Verdict::Deny,
                }
                .to_hook_output();
                return (
                    StatusCode::OK,
                    Json(serde_json::to_value(out).unwrap_or_default()),
                );
            }
            return (StatusCode::OK, Json(serde_json::json!({})));
        }
    };

    let is_pre = payload.event == HookEvent::PreToolUse;
    let is_protected = is_pre
        && payload.tool_name.as_ref().is_some_and(|tool| {
            const READ_ONLY: &[&str] = &[
                "Read",
                "Grep",
                "Glob",
                "NotebookRead",
                "TodoRead",
                "WebFetch",
                "WebSearch",
            ];
            if READ_ONLY.contains(&tool.as_str()) {
                false
            } else if tool == "Bash" {
                payload.tool_input.get("command").is_some()
            } else {
                true
            }
        });

    if payload.session_id.is_empty() {
        tracing::warn!("hook payload missing or empty session_id");
        if st.config.enforce && is_protected {
            let out = decision::Decision {
                permission_decision: "deny",
                reason: Some("protected PreToolUse missing valid session_id".into()),
                shadow: false,
                would_have_been: Verdict::Deny,
            }
            .to_hook_output();
            let _ = st.audit.write(&AuditLine {
                at_ms: now_ms(),
                session: String::new(),
                seq: 0,
                event: payload.event.as_str().to_string(),
                tool: payload.tool_name.clone(),
                verdict: "deny".into(),
                shadow: false,
                rule: Some("invalid-session".into()),
                risk_score: 0,
                findings: vec![],
                taint: None,
                judge: None,
                approval: None,
                egress_hosts: vec![],
                latency_us: started.elapsed().as_micros(),
                truncated: false,
                raw: st.config.capture_unknown_raw.then_some(body),
            });
            return (
                StatusCode::OK,
                Json(serde_json::to_value(out).unwrap_or_default()),
            );
        }
        return (StatusCode::OK, Json(serde_json::json!({})));
    }

    // An event kind this build does not know about, or a session id too degenerate
    // to key taint by (see `map::to_event`): proceed without blocking. Raw bodies
    // are omitted unless the operator explicitly opted into sensitive forensic capture.
    let seq = st.sessions.next(&payload.session_id);
    let Some(mapped) = map::to_event(&payload, seq, now_ms(), st.config.max_record_bytes) else {
        tracing::warn!(session = %payload.session_id, "unrecognized hook event");
        {
            let mut fw = st.firewall.lock().expect("firewall mutex");
            fw.mark_provenance_incomplete(&payload.session_id);
        }
        if st.config.enforce && is_protected {
            let out = decision::Decision {
                permission_decision: "deny",
                reason: Some("unrecognized protected hook event; refused by policy".into()),
                shadow: false,
                would_have_been: Verdict::Deny,
            }
            .to_hook_output();
            let _ = st.audit.write(&AuditLine {
                at_ms: now_ms(),
                session: payload.session_id.clone(),
                seq,
                event: "unknown".into(),
                tool: payload.tool_name.clone(),
                verdict: "deny".into(),
                shadow: false,
                rule: Some("unrecognized-protected-event".into()),
                risk_score: 0,
                findings: vec![],
                taint: None,
                judge: None,
                approval: None,
                egress_hosts: vec![],
                latency_us: started.elapsed().as_micros(),
                truncated: false,
                raw: st.config.capture_unknown_raw.then_some(body),
            });
            return (
                StatusCode::OK,
                Json(serde_json::to_value(out).unwrap_or_default()),
            );
        }
        let _ = st.audit.write(&AuditLine {
            at_ms: now_ms(),
            session: payload.session_id.clone(),
            seq,
            event: "unknown".into(),
            tool: payload.tool_name.clone(),
            verdict: "allow".into(),
            shadow: !st.config.enforce,
            rule: None,
            risk_score: 0,
            findings: vec![],
            taint: None,
            judge: None,
            approval: None,
            egress_hosts: vec![],
            latency_us: started.elapsed().as_micros(),
            truncated: false,
            raw: st.config.capture_unknown_raw.then_some(body),
        });
        return (StatusCode::OK, Json(serde_json::json!({})));
    };
    let event = mapped.event;
    if mapped.truncated {
        let mut fw = st.firewall.lock().expect("firewall mutex");
        fw.mark_provenance_incomplete(&payload.session_id);
    }

    let is_pre = payload.event == HookEvent::PreToolUse;
    let has_active_bound_children = st
        .native
        .as_ref()
        .is_some_and(|n| n.has_active_host_session(&payload.session_id));
    if payload.event == HookEvent::SessionEnd && !has_active_bound_children {
        st.sessions.end(&payload.session_id);
        st.spans.end_session(&payload.session_id);
    }

    // Retain untrusted content by the same sequence number the taint tracker
    // will fingerprint it under, so a later `Escalate` has something to hand the
    // judge. Mirrors exactly the condition `AgentFirewall::inspect` uses to
    // decide what becomes taint (`crates/agent/src/engine.rs`): a `ToolResult`
    // only when its source is untrusted, a `SubagentReport` unconditionally
    // (subagent output has no `source` field and is always treated as tainted).
    match &event.kind {
        EventKind::ToolResult {
            content, source, ..
        } => {
            if source.trust() == Trust::Untrusted {
                st.spans.put(&payload.session_id, seq, content);
            }
        }
        EventKind::SubagentReport { content, .. } => {
            st.spans.put(&payload.session_id, seq, content);
        }
        _ => {}
    }

    // `AgentFirewall::inspect` takes `&mut self`, so the guard must be held across
    // the call. Scoped in its own block so the `std::sync::Mutex` guard is dropped
    // before the function's first `.await` — nothing here awaits while it is held.
    let (outcome, inspected_deployment) = {
        let mut fw = st.firewall.lock().expect("firewall mutex");
        let outcome = if payload.event == HookEvent::SessionEnd && has_active_bound_children {
            Outcome::allow()
        } else {
            fw.inspect(&event)
        };
        let deployment = fw.active_managed_policy().map(|p| p.deployment_sequence);
        (outcome, deployment)
    };

    // Resolve `Escalate` into a concrete verdict via the judge before deciding. The
    // `std::sync::Mutex` guard above is already dropped (scoped block), so the judge's
    // `.await` never holds a lock. `judged` records what the model said for the audit
    // log, so a verdict landing on `Ask` (or not) is explainable after the fact.
    let mut verdict = outcome.verdict;
    let mut judged: Option<String> = None;
    if verdict == Verdict::Escalate {
        // The judge sees the tainted CONTENT and its source — never the tool call.
        // Following documentation is ordinary work; judge the content's intent.
        let (span, source) = match &outcome.taint {
            Some(t) => (
                st.spans.get(&payload.session_id, t.seq).unwrap_or_default(),
                t.source.label(),
            ),
            None => (String::new(), "unknown".to_string()),
        };
        if span.trim().is_empty() {
            // No retained content means nothing to judge — take the fallback rather
            // than asking the model about an empty string.
            verdict = resolve_escalation(
                Judgement::Unavailable("no retained span".into()),
                outcome.fallback,
            );
            judged = Some("Unavailable(\"no retained span\")".into());
        } else {
            let j = st.judge.judge(&span, &source).await;
            judged = Some(format!("{j:?}"));
            verdict = resolve_escalation(j, outcome.fallback);
        }
    }

    // The judge may have awaited while managed policy activation acquired the
    // firewall mutex. Recheck the authoritative live deployment and serialize
    // approval redemption + final decision against activation; never emit an
    // old-policy Allow after a concurrent switch. No await is held under lock.
    let _final_policy_guard = st.firewall.lock().expect("firewall mutex");
    let changed_while_in_flight = is_pre
        && _final_policy_guard
            .active_managed_policy()
            .map(|p| p.deployment_sequence)
            != inspected_deployment;
    let mut decision_rule = outcome.rule.clone();
    let mut decision_message = outcome.message.clone();
    if changed_while_in_flight {
        verdict = Verdict::Deny;
        decision_rule = Some("managed-policy-transition".into());
        decision_message = Some(
            "Managed policy changed while this call was being evaluated; retry under the new policy."
                .into(),
        );
        tracing::warn!("refused in-flight old-policy pre-tool decision after managed activation");
    }

    // A human approval, if the operator issued one for exactly this call. Only
    // `Ask` is redeemable: `Deny` is a policy refusal, and letting an approval
    // override it would turn every deny into a prompt an attacker can wait out.
    let mut approval = None;
    if is_pre && verdict == Verdict::Ask {
        if let Some(tool) = &payload.tool_name {
            let action = crate::grant::ActionRef {
                session: payload.session_id.clone(),
                tool: tool.clone(),
                args_fingerprint: crate::grant::action_fingerprint(tool, &payload.tool_input),
            };
            let redeemed = crate::grant::redeem_pending(
                &st.grant_key,
                &st.grants,
                &st.grant_ledger,
                &action,
                now_ms(),
                |grant, error| {
                    tracing::warn!(
                        nonce = %grant.nonce,
                        reason = error.reason(),
                        "a pending approval matched this action but was refused"
                    );
                },
            );
            if let Some(grant) = redeemed {
                tracing::info!(
                    nonce = %grant.nonce,
                    tool = %tool,
                    "a human approval authorized this call"
                );
                approval = Some(grant.nonce.clone());
                verdict = Verdict::Allow;
            }
        }
    }

    let d = decision::decide(
        verdict,
        decision_rule.as_deref(),
        decision_message.as_deref(),
        st.config.enforce,
    );

    let _ = st.audit.write(&AuditLine {
        at_ms: event.at_ms,
        session: payload.session_id.clone(),
        seq,
        event: payload.event.as_str().to_string(),
        tool: payload.tool_name.clone(),
        verdict: verdict_str(d.would_have_been).to_string(),
        shadow: d.shadow,
        rule: decision_rule.clone(),
        risk_score: outcome.risk_score,
        findings: outcome
            .findings
            .iter()
            .map(|(_, f)| AuditFinding {
                detector: f.detector.clone(),
                severity: format!("{:?}", f.severity).to_lowercase(),
                owasp: f.owasp.clone(),
                atlas: f.atlas.clone(),
            })
            .collect(),
        taint: outcome.taint.as_ref().map(|t| AuditTaint {
            source: t.source.label(),
            origin: t.source.kind().to_string(),
            source_name: t.source.source_name().map(str::to_string),
            trust: format!("{:?}", t.source.trust()).to_lowercase(),
            seq: t.seq,
        }),
        judge: judged,
        approval: approval.clone(),
        egress_hosts: outcome.egress_hosts.clone(),
        latency_us: started.elapsed().as_micros(),
        truncated: mapped.truncated,
        raw: None,
    });

    // Only PreToolUse carries a decision. Everything else mutates state only —
    // this is what "detect and gate, never rewrite" means concretely.
    if is_pre && d.permission_decision != "defer" {
        let out =
            serde_json::to_value(d.to_hook_output()).unwrap_or_else(|_| serde_json::json!({}));
        return (StatusCode::OK, Json(out));
    }
    (StatusCode::OK, Json(serde_json::json!({})))
}

#[derive(serde::Deserialize)]
pub struct McpHandshakeReq {
    pub server: String,
    #[serde(default)]
    pub tools: Vec<soup_wall_agent::ToolDecl>,
}

/// The MCP handshake endpoint. Computes drift + shadowing from persistent state, runs
/// detection + policy via `inspect_mcp_handshake`, pins the new manifest, audits, and
/// returns the verdict. On any internal failure it returns `allow` (fail open) — a
/// collector that blocks handshakes on its own bug gets uninstalled.
pub async fn mcp(
    State(st): State<Shared>,
    headers: HeaderMap,
    body: axum::body::Body,
) -> (StatusCode, Json<serde_json::Value>) {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::token::verify(&st.token, auth) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({})));
    }
    let body = match read_bounded_string(body, st.config.max_body_bytes).await {
        Ok(s) => s,
        Err(BodyReadError::Oversized { .. }) => {
            tracing::warn!("mcp body over cap; rejecting");
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(serde_json::json!({ "verdict": "deny", "error": "mcp_body_over_cap" })),
            );
        }
        Err(BodyReadError::Io { error, .. }) => {
            tracing::warn!(error = %error, "mcp stream error; rejecting");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "verdict": "deny", "error": "mcp_read_error" })),
            );
        }
        Err(BodyReadError::InvalidUtf8 { .. }) => {
            tracing::warn!("mcp invalid utf8; rejecting");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "verdict": "deny", "error": "invalid_utf8" })),
            );
        }
    };
    let req: McpHandshakeReq = match serde_json::from_str(&body) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "unparsable /mcp payload; allowing");
            return (
                StatusCode::OK,
                Json(serde_json::json!({ "verdict": "allow" })),
            );
        }
    };

    let hash = crate::mcp::manifest::manifest_hash(&req.tools);
    let pinned = st.manifests.get_pinned(&req.server);
    let manifest_changed = matches!(&pinned, Some(previous) if previous.hash != hash);
    let names: Vec<String> = req.tools.iter().map(|t| t.name.clone()).collect();
    let shadowed = st.tools.shadows(&req.server, &names);
    let shadow = shadowed.is_some();

    let outcome = {
        let mut fw = st.firewall.lock().expect("firewall mutex");
        fw.inspect_mcp_handshake(&req.server, &req.tools, manifest_changed, shadow)
    };

    // Compute the diff BEFORE re-pinning: once the new manifest is stored the
    // previous one is only reachable through history.
    let drift_detail = manifest_changed
        .then_some(pinned.as_ref())
        .flatten()
        .filter(|previous| !previous.tools.is_empty())
        .map(|previous| crate::mcp::manifest::detailed_diff(&previous.tools, &req.tools).render());

    // Pin the new manifest and record its names regardless of verdict: the operator is
    // being told about the change now, so the next handshake compares against it.
    let _ = st
        .manifests
        .put_manifest(&req.server, &hash, &req.tools, now_ms());
    st.tools.record(&req.server, &names);

    let reason = if manifest_changed {
        // A pin written before manifests were retained has no tools to compare
        // against, so it can only report that something changed. Say which case
        // this is rather than implying the diff was computed and came back empty.
        Some(match drift_detail {
            Some(detail) => format!("manifest drift on {}: {detail}", req.server),
            None => format!(
                "manifest drift on {}: the pinned tool manifest changed. The previous                  manifest predates manifest retention, so it cannot be diffed; the next                  change will be shown in full.",
                req.server
            ),
        })
    } else if let Some(name) = shadowed {
        Some(format!("tool name '{name}' collides with an existing tool"))
    } else {
        outcome.message.clone()
    };

    let d = decision::decide(
        outcome.verdict,
        outcome.rule.as_deref(),
        reason.as_deref(),
        st.config.enforce,
    );

    let _ = st.audit.write(&AuditLine {
        at_ms: now_ms(),
        session: req.server.clone(),
        seq: 0,
        event: "mcp_handshake".into(),
        tool: None,
        verdict: verdict_str(d.would_have_been).to_string(),
        shadow: d.shadow,
        rule: outcome.rule.clone(),
        risk_score: outcome.risk_score,
        findings: outcome
            .findings
            .iter()
            .map(|(_, f)| AuditFinding {
                detector: f.detector.clone(),
                severity: format!("{:?}", f.severity).to_lowercase(),
                owasp: f.owasp.clone(),
                atlas: f.atlas.clone(),
            })
            .collect(),
        taint: None,
        judge: None,
        approval: None,
        egress_hosts: vec![],
        latency_us: 0,
        truncated: false,
        raw: None,
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "verdict": verdict_str(d.would_have_been),
            "enforce": st.config.enforce,
            "reason": reason,
        })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::judge::Judgement;

    #[test]
    fn a_judgement_of_injection_becomes_ask() {
        assert_eq!(
            resolve_escalation(Judgement::Injection, Some(Verdict::Allow)),
            Verdict::Ask
        );
    }

    #[test]
    fn a_judgement_of_documentation_takes_the_fallback() {
        assert_eq!(
            resolve_escalation(Judgement::Documentation, Some(Verdict::Allow)),
            Verdict::Allow
        );
        assert_eq!(
            resolve_escalation(Judgement::Documentation, Some(Verdict::Ask)),
            Verdict::Ask
        );
    }

    #[test]
    fn an_unavailable_judge_takes_the_fallback() {
        assert_eq!(
            resolve_escalation(Judgement::Unavailable("off".into()), Some(Verdict::Allow)),
            Verdict::Allow
        );
    }

    #[test]
    fn a_missing_fallback_requires_review() {
        // Retains the historical missing-fallback input; the old Allow was unsafe.
        assert_eq!(
            resolve_escalation(Judgement::Unavailable("x".into()), None),
            Verdict::Ask
        );
    }

    #[test]
    fn the_judge_can_only_tighten_never_soften() {
        // Injection must never produce something weaker than the fallback.
        for fb in [Verdict::Allow, Verdict::Ask] {
            let out = resolve_escalation(Judgement::Injection, Some(fb));
            assert!(
                out == Verdict::Ask,
                "Injection must land on Ask regardless of fallback {fb:?}, got {out:?}"
            );
        }
    }

    #[test]
    fn session_sequence_numbers_are_monotonic_and_per_session() {
        let s = Sessions::default();
        assert_eq!(s.next("a"), 1);
        assert_eq!(s.next("a"), 2);
        assert_eq!(
            s.next("b"),
            1,
            "sequences must not be shared across sessions"
        );
        assert_eq!(s.next("a"), 3);
    }

    #[test]
    fn ending_a_session_resets_its_sequence() {
        let s = Sessions::default();
        s.next("a");
        s.next("a");
        s.end("a");
        assert_eq!(s.next("a"), 1);
    }

    #[test]
    fn root_json_scan_basic_and_proven_non_pre() {
        let raw = r#"{"session_id": "s1", "hook_event_name": "PostToolUse"}"#;
        let scan = RootJsonScan::scan(raw);
        assert_eq!(scan.get_root_string("session_id"), Some("s1"));
        assert_eq!(scan.get_root_string("hook_event_name"), Some("PostToolUse"));
        assert!(scan.is_proven_non_pre());
    }

    #[test]
    fn root_json_scan_ignores_nested_fields() {
        let raw = r#"{"metadata": {"hook_event_name": "PostToolUse", "session_id": "nested"}, "session_id": "root"}"#;
        let scan = RootJsonScan::scan(raw);
        assert_eq!(scan.get_root_string("session_id"), Some("root"));
        assert_eq!(scan.get_root_string("hook_event_name"), None);
        assert!(!scan.is_proven_non_pre());
    }

    #[test]
    fn root_json_scan_handles_escaped_quotes_in_strings() {
        let raw = r#"{"note": "nested \"hook_event_name\":\"PostToolUse\"", "hook_event_name": "PreToolUse"}"#;
        let scan = RootJsonScan::scan(raw);
        assert_eq!(scan.get_root_string("hook_event_name"), Some("PreToolUse"));
        assert_eq!(
            scan.get_root_string("note"),
            Some("nested \"hook_event_name\":\"PostToolUse\"")
        );
        assert!(!scan.is_proven_non_pre());
    }

    #[test]
    fn root_json_scan_duplicate_keys_are_ambiguous() {
        let raw = r#"{"hook_event_name": "PostToolUse", "session_id": "s1", "hook_event_name": "PreToolUse"}"#;
        let scan = RootJsonScan::scan(raw);
        assert!(scan.duplicate_keys.contains("hook_event_name"));
        assert_eq!(scan.get_root_string("hook_event_name"), None);
        assert_eq!(scan.get_root_string("session_id"), Some("s1"));
        assert!(!scan.is_proven_non_pre());
    }

    #[test]
    fn root_json_scan_incomplete_keys_and_values() {
        let raw_val = r#"{"hook_event_name": "Post"#;
        let scan_val = RootJsonScan::scan(raw_val);
        assert!(scan_val.incomplete_keys.contains("hook_event_name"));
        assert_eq!(scan_val.get_root_string("hook_event_name"), None);
        assert!(!scan_val.is_proven_non_pre());

        let raw_key = r#"{"hook_eve"#;
        let scan_key = RootJsonScan::scan(raw_key);
        assert!(!scan_key.incomplete_keys.is_empty());
        assert!(!scan_key.is_proven_non_pre());
    }

    #[test]
    fn root_json_scan_skips_arrays_and_objects() {
        let raw = r#"{"items": [{"hook_event_name": "PostToolUse"}], "session_id": "s1"}"#;
        let scan = RootJsonScan::scan(raw);
        assert_eq!(scan.get_root_string("session_id"), Some("s1"));
        assert_eq!(scan.get_root_string("hook_event_name"), None);
        assert!(!scan.is_proven_non_pre());
    }
}
