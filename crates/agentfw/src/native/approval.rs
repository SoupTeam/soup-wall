// SPDX-License-Identifier: Apache-2.0
//! SOU-48: opt-in, bounded, single-use operator approval for ONE outstanding
//! native MCP `Ask` call. State lives in the daemon; the operator decides through
//! files under the protected home (`native-pending/`, `native-grants/`).
//!
//! States of a pending record: `pending -> approved | rejected | expired |
//! cancelled | closed(reason) ; approved -> redeemed (once)`. See
//! `docs/operations/NATIVE_ASK_APPROVAL.md`.
//!
//! Approval is explicit authorization by whoever can write the operator files
//! (same OS user). It is not proof of human presence and not a defence against
//! a compromised same-user/OS environment.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::State as AxState;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use soup_wall_agent::{EventKind, Verdict};

use super::{binding, declared_hosts, identifier, is_digest, resolved, verdict_label};
use super::{CONTRACT, MAX_CONTENT};
use crate::grant::{self, ActionRef, GrantLedger, GrantStore};
use crate::handlers::Shared;

pub const APPROVAL_CONTRACT: &str = "sw-native-approval/1";
/// Versioned scope prefix: a hook approval can never match this tool name.
pub const SCOPE: &str = "native-mcp/approval/v1:";
const MAX_PENDING: usize = 16;
const KEEP_TERMINAL: usize = 64;

/// Key distinct from the hook approval key (domain separation).
pub fn native_key(grant_key: &[u8]) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"agentfw/native-approval-key/v1\0");
    h.update(grant_key);
    h.finalize().to_vec()
}

pub fn scope_tool(tool: &str) -> String {
    format!("{SCOPE}{tool}")
}

pub fn pending_dir(home: &Path) -> PathBuf {
    home.join("native-pending")
}

pub fn grants_dir(home: &Path) -> PathBuf {
    home.join("native-grants")
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Source {
    Daemon,
    Classifier,
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum State {
    Pending,
    Redeemed,
    Closed(&'static str),
}

struct Record {
    session_id: String,
    epoch: String,
    tool: String,
    schema_sha256: String,
    binding_sha256: String,
    source: Source,
    policy_epoch: u64,
    expires: Instant,
    state: State,
}

pub struct ApprovalState {
    home: PathBuf,
    key: Vec<u8>,
    ttl: Duration,
    store: GrantStore,
    ledger: GrantLedger,
    records: Mutex<BTreeMap<String, Record>>,
}

impl ApprovalState {
    /// Restart semantics: leftovers from an earlier daemon are removed. A pending
    /// approval, or an issued-but-unredeemed one, never survives a restart.
    pub fn new(home: &Path, grant_key: &[u8], ttl_seconds: u64) -> anyhow::Result<Self> {
        for dir in [pending_dir(home), grants_dir(home)] {
            std::fs::create_dir_all(&dir)?;
            for entry in std::fs::read_dir(&dir)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    std::fs::remove_file(entry.path())?;
                }
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
            }
        }
        Ok(Self {
            home: home.to_path_buf(),
            key: native_key(grant_key),
            ttl: Duration::from_secs(ttl_seconds.clamp(1, 300)),
            store: GrantStore::new(&grants_dir(home)),
            ledger: GrantLedger::open(&home.join("native-grants-spent.json")),
            records: Mutex::default(),
        })
    }

    fn pending_file(&self, id: &str) -> PathBuf {
        pending_dir(&self.home).join(format!("{id}.json"))
    }

    fn remove_files(&self, id: &str) {
        for ext in ["json", "deciding", "approved", "rejected"] {
            let _ = std::fs::remove_file(pending_dir(&self.home).join(format!("{id}.{ext}")));
        }
        let _ = std::fs::remove_file(grants_dir(&self.home).join(format!("{id}.json")));
    }

    fn prune(records: &mut BTreeMap<String, Record>, now: Instant) {
        for record in records.values_mut() {
            if record.state == State::Pending && record.expires <= now {
                record.state = State::Closed("expired");
            }
        }
        let terminal: Vec<String> = records
            .iter()
            .filter(|(_, r)| r.state != State::Pending)
            .map(|(id, _)| id.clone())
            .collect();
        if terminal.len() > KEEP_TERMINAL {
            for id in terminal.iter().take(terminal.len() - KEEP_TERMINAL) {
                records.remove(id);
            }
        }
    }

    /// Operator rejection is terminal even before a collector next polls it.
    /// Reconcile only the bounded in-memory pending set; never reopen a record.
    fn reconcile_rejections(&self, records: &mut BTreeMap<String, Record>) {
        for (id, record) in records.iter_mut() {
            if record.state == State::Pending
                && pending_dir(&self.home)
                    .join(format!("{id}.rejected"))
                    .exists()
            {
                record.state = State::Closed("rejected");
                self.remove_files(id);
            }
        }
    }

    /// Close every outstanding record of a session (end, expiry, cancel).
    pub fn close_session(&self, session_id: &str, reason: &'static str) {
        let mut ids = Vec::new();
        if let Ok(mut records) = self.records.lock() {
            for (id, record) in records.iter_mut() {
                if record.session_id == session_id && record.state == State::Pending {
                    record.state = State::Closed(reason);
                    ids.push(id.clone());
                }
            }
        }
        for id in ids {
            self.remove_files(&id);
        }
    }

    /// Atomic once-only redemption at the execution gate. `verdict` is the
    /// verdict computed *now* by the current policy for the presented call.
    #[allow(clippy::too_many_arguments)]
    pub fn redeem(
        &self,
        id: &str,
        session_id: &str,
        epoch: &str,
        tool: &str,
        schema_sha256: &str,
        bound: &str,
        verdict: Verdict,
    ) -> Result<(), &'static str> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| "native_approval_unavailable")?;
        let now = Instant::now();
        Self::prune(&mut records, now);
        let record = records.get_mut(id).ok_or("native_approval_unknown")?;
        match &record.state {
            State::Pending => {}
            State::Redeemed => return Err("native_approval_spent"),
            State::Closed("rejected") => return Err("native_approval_rejected"),
            State::Closed(_) => return Err("native_approval_closed"),
        }
        // From here any refusal terminally closes the record: it cannot be retried
        // after observing the error, so no rescue under another identity.
        let outcome = (|| {
            if verdict == Verdict::Deny {
                return Err("native_approval_hard_deny");
            }
            if record.session_id != session_id || record.epoch != epoch {
                return Err("native_approval_session_mismatch");
            }
            if record.expires <= now {
                return Err("native_approval_expired");
            }
            if record.tool != tool
                || record.schema_sha256 != schema_sha256
                || record.binding_sha256 != bound
            {
                return Err("native_approval_binding_mismatch");
            }
            let policy_ok = match record.source {
                Source::Daemon => verdict == Verdict::Ask,
                Source::Classifier => matches!(verdict, Verdict::Ask | Verdict::Allow),
            };
            if !policy_ok {
                return Err("native_approval_policy_changed");
            }
            if self.store.policy_epoch().ok() != Some(record.policy_epoch) {
                return Err("native_approval_stale_policy");
            }
            let rejected = pending_dir(&self.home).join(format!("{id}.rejected"));
            if rejected.exists() {
                return Err("native_approval_rejected");
            }
            let found = self.store.pending().into_iter().find(|g| g.nonce == id);
            let Some(found) = found else {
                return Err("native_approval_not_approved");
            };
            let action = ActionRef {
                session: epoch.to_string(),
                tool: scope_tool(tool),
                args_fingerprint: bound.to_string(),
            };
            grant::redeem(&self.key, &found, &action, now_ms(), &self.ledger).map_err(
                |e| match e {
                    grant::GrantError::StalePolicy => "native_approval_stale_policy",
                    grant::GrantError::AlreadyUsed => "native_approval_spent",
                    grant::GrantError::Expired => "native_approval_expired",
                    _ => "native_approval_invalid_grant",
                },
            )?;
            self.store.discard(&found);
            Ok(())
        })();
        match outcome {
            Ok(()) => {
                record.state = State::Redeemed;
                drop(records);
                self.remove_files(id);
                Ok(())
            }
            Err(code) => {
                record.state = State::Closed(code);
                drop(records);
                self.remove_files(id);
                Err(code)
            }
        }
    }

    /// Terminally invalidates a presented approval record upon validation or execution refusal.
    /// Once closed, an approval cannot be retried or rescued under another identity or argument.
    pub fn invalidate(&self, id: &str, session_id: &str, reason: &'static str) {
        if let Ok(mut records) = self.records.lock() {
            Self::prune(&mut records, Instant::now());
            if let Some(record) = records.get_mut(id) {
                if record.session_id == session_id && record.state == State::Pending {
                    record.state = State::Closed(reason);
                    drop(records);
                    self.remove_files(id);
                }
            }
        }
    }

    fn status(&self, id: &str, session_id: &str) -> Result<(&'static str, u64), &'static str> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| "native_approval_unavailable")?;
        let now = Instant::now();
        self.reconcile_rejections(&mut records);
        Self::prune(&mut records, now);
        let record = records.get(id).ok_or("native_approval_unknown")?;
        if record.session_id != session_id {
            return Err("native_approval_unknown");
        }
        let left = record.expires.saturating_duration_since(now).as_millis() as u64;
        let state = match &record.state {
            State::Redeemed => "redeemed",
            State::Closed("expired") => "expired",
            State::Closed("cancelled") => "cancelled",
            State::Closed("rejected") => "rejected",
            State::Closed(_) => "closed",
            State::Pending => {
                if pending_dir(&self.home)
                    .join(format!("{id}.rejected"))
                    .exists()
                {
                    "rejected"
                } else if self.store.pending().iter().any(|g| g.nonce == id) {
                    "approved"
                } else {
                    "pending"
                }
            }
        };
        Ok((state, left))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalRequest {
    contract_version: String,
    registry_sha256: String,
    session_id: String,
    action: String,
    source: Option<String>,
    tool: Option<String>,
    args: Option<Value>,
    schema_sha256: Option<String>,
    pending_id: Option<String>,
    #[serde(default)]
    resource_admission: Option<super::resource::Admission>,
}

fn failure(code: &'static str, status: StatusCode) -> (StatusCode, Json<Value>) {
    (
        status,
        Json(json!({"contract_version": APPROVAL_CONTRACT, "error_code": code})),
    )
}

fn audit(st: &Shared, record: Value) -> Result<(), &'static str> {
    st.audit
        .write_native(&record)
        .map_err(|_| "native_audit_unavailable")
}

pub async fn handler(
    AxState(st): AxState<Shared>,
    headers: HeaderMap,
    body: String,
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
    let Some(approval) = &native.approval else {
        return failure("native_approval_disabled", StatusCode::SERVICE_UNAVAILABLE);
    };
    if !st.config.enforce || st.config.judge.enabled {
        return failure(
            "native_enforcement_required",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }
    if body.len() > MAX_CONTENT * 2 || body.len() > st.config.max_body_bytes {
        return failure("native_body_over_cap", StatusCode::PAYLOAD_TOO_LARGE);
    }
    let Ok(request) = serde_json::from_str::<ApprovalRequest>(&body) else {
        return failure("native_invalid_fields", StatusCode::BAD_REQUEST);
    };
    if request.contract_version != CONTRACT
        || request.registry_sha256 != native.registry_sha256
        || !identifier(&request.session_id)
    {
        return failure("native_invalid_identity", StatusCode::BAD_REQUEST);
    }
    let identity = match super::liveness::collector_identity(&headers) {
        Ok(identity) => identity,
        Err(code) => return failure(code, StatusCode::BAD_REQUEST),
    };
    // Hold the native owner stable through status/cancel (native -> records).
    // Opening takes the same native lock itself before creating any record.
    let owner_guard = if request.action != "request" && identity.is_some() {
        let state = match native.sessions.lock() {
            Ok(state) => state,
            Err(_) => return failure("native_state_unavailable", StatusCode::SERVICE_UNAVAILABLE),
        };
        let verified = state
            .entries
            .get(&request.session_id)
            .ok_or("native_session_unknown")
            .and_then(|session| identity.as_ref().unwrap().verify(native, session));
        if let Err(code) = verified {
            return failure(code, StatusCode::CONFLICT);
        }
        Some(state)
    } else {
        None
    };
    let result = match request.action.as_str() {
        "request" => open_bound(&st, native, approval, &request, identity.as_ref()),
        "status" => {
            let Some(id) = request.pending_id.as_deref().filter(|id| identifier(id)) else {
                return failure("native_invalid_fields", StatusCode::BAD_REQUEST);
            };
            approval
                .status(id, &request.session_id)
                .map(|(state, left)| {
                    json!({"contract_version": APPROVAL_CONTRACT, "action": "status",
                    "pending_id": id, "state": state, "expires_in_ms": left})
                })
        }
        "cancel" => {
            let Some(id) = request.pending_id.as_deref().filter(|id| identifier(id)) else {
                return failure("native_invalid_fields", StatusCode::BAD_REQUEST);
            };
            cancel(&st, approval, id, &request.session_id)
        }
        _ => Err("native_invalid_event"),
    };
    drop(owner_guard);
    match result {
        Ok(value) => (StatusCode::OK, Json(value)),
        Err(code) => failure(code, StatusCode::CONFLICT),
    }
}

fn cancel(
    st: &Shared,
    approval: &ApprovalState,
    id: &str,
    session_id: &str,
) -> Result<Value, &'static str> {
    {
        let mut records = approval
            .records
            .lock()
            .map_err(|_| "native_approval_unavailable")?;
        let record = records.get_mut(id).ok_or("native_approval_unknown")?;
        if record.session_id != session_id {
            return Err("native_approval_unknown");
        }
        if record.state == State::Pending {
            record.state = State::Closed("cancelled");
        }
    }
    approval.remove_files(id);
    audit(
        st,
        json!({"at_ms": now_ms(), "event": "native_approval_cancelled", "approval_id": id,
            "released": false}),
    )?;
    Ok(
        json!({"contract_version": APPROVAL_CONTRACT, "action": "cancel",
        "pending_id": id, "state": "cancelled", "expires_in_ms": 0}),
    )
}

#[cfg(test)]
fn open(
    st: &Shared,
    native: &super::NativeState,
    approval: &ApprovalState,
    request: &ApprovalRequest,
) -> Result<Value, &'static str> {
    open_bound(st, native, approval, request, None)
}

fn open_bound(
    st: &Shared,
    native: &super::NativeState,
    approval: &ApprovalState,
    request: &ApprovalRequest,
    identity: Option<&super::liveness::CollectorIdentity>,
) -> Result<Value, &'static str> {
    let source = match request.source.as_deref() {
        Some("daemon") => Source::Daemon,
        Some("classifier") => Source::Classifier,
        _ => return Err("native_invalid_fields"),
    };
    let name = request.tool.as_deref().ok_or("native_tool_missing")?;
    let args = request.args.as_ref().ok_or("native_args_missing")?;
    if !args.is_object() || args.to_string().len() > MAX_CONTENT {
        return Err("native_args_over_cap");
    }
    let mut state = native
        .sessions
        .lock()
        .map_err(|_| "native_state_unavailable")?;
    let mut firewall = st
        .firewall
        .lock()
        .map_err(|_| "native_inspection_unavailable")?;
    let session = state
        .entries
        .get(&request.session_id)
        .ok_or("native_session_unknown")?;
    if let Some(identity) = identity {
        identity.verify(native, session)?;
    }
    if super::validate_lineage(&state, session, now_ms(), Instant::now()).is_err() {
        return Err("native_approval_hard_deny");
    }
    let session = state
        .entries
        .get_mut(&request.session_id)
        .ok_or("native_session_unknown")?;
    if args.to_string().len() > firewall.provenance_limits().max_input_bytes {
        firewall.mark_provenance_incomplete(&session.epoch);
        if let Some(host) = &session.host_session {
            firewall.mark_provenance_incomplete(host);
        }
        return Err("native_provenance_input");
    }
    let tool = native
        .registry
        .tools
        .iter()
        .find(|t| t.name == name)
        .ok_or("native_tool_unknown")?;
    if request.schema_sha256.as_deref() != Some(tool.schema_sha256.as_str())
        || !request.schema_sha256.as_deref().is_some_and(is_digest)
    {
        return Err("native_schema_mismatch");
    }
    let is_resource = tool.resource_policy.is_some();
    if is_resource && !super::resource_approval::is_supported_linux_resource_tool(tool) {
        return Err("native_approval_resource_tool_unsupported");
    }
    let hosts = declared_hosts(tool, args)?;
    session.seq += 1;
    let ev = session.event(EventKind::ToolCall {
        tool: name.into(),
        args: args.clone(),
    });
    let mut outcome = firewall.inspect_native_call(&ev, tool.action_class, &hosts);
    if let Some(host) = &session.host_session {
        let ev_host = session.host_event(
            host,
            session.seq,
            EventKind::ToolCall {
                tool: name.into(),
                args: args.clone(),
            },
        );
        let host_outcome = firewall.inspect_native_call(&ev_host, tool.action_class, &hosts);
        outcome = super::merge_provenance_outcomes(outcome, host_outcome);
    }
    let mut verdict = resolved(&outcome);
    let is_https_get = tool
        .resource_policy
        .as_ref()
        .is_some_and(|policy| policy.is_https_get());
    if is_https_get && !firewall.egress_hosts_allowlisted(&hosts) {
        verdict = Verdict::Deny;
    }
    match (source, verdict) {
        (_, Verdict::Deny) => return Err("native_approval_hard_deny"),
        (Source::Daemon, Verdict::Allow) => return Err("native_approval_not_required"),
        (Source::Daemon, Verdict::Ask | Verdict::Escalate) | (Source::Classifier, _) => {}
    }
    let resource_details = if is_resource {
        Some(super::resource_approval::build_resource_details(
            tool,
            args,
            request.resource_admission.as_ref(),
        )?)
    } else {
        None
    };
    let bound = binding(
        &native.registry_sha256,
        &session.epoch,
        name,
        &tool.schema_sha256,
        args,
        request.resource_admission.as_ref(),
    );
    let policy_epoch = approval
        .store
        .policy_epoch()
        .map_err(|_| "native_approval_unavailable")?;
    let id = crate::token::generate();
    let created_ms = now_ms();
    let mut records = approval
        .records
        .lock()
        .map_err(|_| "native_approval_unavailable")?;
    approval.reconcile_rejections(&mut records);
    ApprovalState::prune(&mut records, Instant::now());
    if records
        .values()
        .any(|r| r.session_id == request.session_id && r.state == State::Pending)
    {
        return Err("native_approval_already_pending");
    }
    if records
        .values()
        .filter(|r| r.state == State::Pending)
        .count()
        >= MAX_PENDING
    {
        return Err("native_approval_capacity");
    }
    let ttl_ms = approval.ttl.as_millis() as u64;
    let mut file = json!({
        "pending_id": id, "state": "pending", "scope": "native-mcp/approval/v1",
        "session_id": request.session_id, "session_epoch": session.epoch,
        "registry_sha256": native.registry_sha256, "registry_id": native.registry.registry_id,
        "tool": name, "schema_sha256": tool.schema_sha256,
        "args": args, "args_sha256": super::args_hash(args), "binding_sha256": bound,
        "source": if source == Source::Daemon { "daemon" } else { "classifier" },
        "verdict": verdict_label(verdict), "reason_codes": outcome.rule.iter().collect::<Vec<_>>(),
        "policy_epoch": policy_epoch, "created_at_ms": created_ms,
        "expires_at_ms": created_ms + ttl_ms,
    });
    if let Some(details) = resource_details {
        file["resource_details"] = details;
    }
    // Audit first and fail closed; the audit line never carries raw arguments.
    audit(
        st,
        json!({"at_ms": created_ms, "event": "native_approval_requested", "approval_id": id,
            "session": session.epoch, "tool": name, "binding_sha256": bound,
            "args_sha256": super::args_hash(args), "source": file["source"],
            "policy_epoch": policy_epoch, "expires_at_ms": created_ms + ttl_ms,
            "registry_sha256": native.registry_sha256, "released": false}),
    )?;
    let path = approval.pending_file(&id);
    let tmp = pending_dir(&approval.home).join(format!("{id}.tmp"));
    std::fs::write(
        &tmp,
        serde_json::to_vec_pretty(&file).map_err(|_| "native_approval_unavailable")?,
    )
    .and_then(|_| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
        std::fs::rename(&tmp, &path)
    })
    .map_err(|_| "native_approval_unavailable")?;
    records.insert(
        id.clone(),
        Record {
            session_id: request.session_id.clone(),
            epoch: session.epoch.clone(),
            tool: name.into(),
            schema_sha256: tool.schema_sha256.clone(),
            binding_sha256: bound.clone(),
            source,
            policy_epoch,
            expires: Instant::now() + approval.ttl,
            state: State::Pending,
        },
    );
    Ok(
        json!({"contract_version": APPROVAL_CONTRACT, "action": "request",
        "pending_id": id, "state": "pending", "binding_sha256": bound,
        "expires_in_ms": ttl_ms}),
    )
}

// ---- operator side (separate process; same protected home as the daemon) ----

fn safe_id(id: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !id.is_empty()
            && id.len() <= 128
            && id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "invalid pending id"
    );
    Ok(())
}

fn read_pending(home: &Path, id: &str) -> anyhow::Result<Value> {
    safe_id(id)?;
    let text = std::fs::read_to_string(pending_dir(home).join(format!("{id}.json")))
        .map_err(|_| anyhow::anyhow!("no such pending approval (decided, expired or restarted)"))?;
    let value: Value = serde_json::from_str(&text)?;
    anyhow::ensure!(
        value["pending_id"] == id && value["scope"] == "native-mcp/approval/v1",
        "pending file identity mismatch"
    );
    Ok(value)
}

/// Sanitized summary of every outstanding request. Raw arguments are not shown.
pub fn operator_list(home: &Path) -> Vec<Value> {
    let now = now_ms();
    let Ok(entries) = std::fs::read_dir(pending_dir(home)) else {
        return Vec::new();
    };
    let mut rows: Vec<Value> = entries
        .flatten()
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
        .filter_map(|e| std::fs::read_to_string(e.path()).ok())
        .filter_map(|t| serde_json::from_str::<Value>(&t).ok())
        .filter(|v| v["expires_at_ms"].as_u64().is_some_and(|x| x > now))
        .map(|v| {
            json!({"pending_id": v["pending_id"], "tool": v["tool"],
                "binding_sha256": v["binding_sha256"], "args_sha256": v["args_sha256"],
                "source": v["source"], "expires_in_ms": v["expires_at_ms"].as_u64().unwrap_or(0).saturating_sub(now)})
        })
        .collect();
    rows.sort_by_key(|r| r["pending_id"].to_string());
    rows
}

/// Full record, including the raw arguments, for the owning operator only.
pub fn operator_inspect(home: &Path, id: &str) -> anyhow::Result<Value> {
    read_pending(home, id)
}

fn claim(home: &Path, id: &str) -> anyhow::Result<()> {
    let dir = pending_dir(home);
    std::fs::rename(
        dir.join(format!("{id}.json")),
        dir.join(format!("{id}.deciding")),
    )
    .map_err(|_| anyhow::anyhow!("pending approval was already decided or is gone"))
}

/// Approve exactly one pending call. `binding` must equal the digest shown by
/// `list`/`inspect`; a tool name, category or description is never enough.
pub fn operator_approve(
    home: &Path,
    hook_token: &str,
    id: &str,
    binding: &str,
) -> anyhow::Result<()> {
    let record = read_pending(home, id)?;
    let now = now_ms();
    let expires = record["expires_at_ms"].as_u64().unwrap_or(0);
    anyhow::ensure!(expires > now, "pending approval has expired");
    anyhow::ensure!(
        is_digest(binding) && record["binding_sha256"] == binding,
        "binding digest does not match the pending call"
    );
    claim(home, id)?;
    let action = ActionRef {
        session: record["session_epoch"].as_str().unwrap_or("").to_string(),
        tool: scope_tool(record["tool"].as_str().unwrap_or("")),
        args_fingerprint: binding.to_string(),
    };
    let key = native_key(&grant::derive_key(hook_token));
    let store = GrantStore::new(&grants_dir(home));
    if let Err(error) = store.issue(&key, &action, now, expires - now, id.to_string()) {
        let _ = std::fs::remove_file(pending_dir(home).join(format!("{id}.deciding")));
        return Err(error.into());
    }
    let dir = pending_dir(home);
    let _ = std::fs::rename(
        dir.join(format!("{id}.deciding")),
        dir.join(format!("{id}.approved")),
    );
    Ok(())
}

pub fn operator_reject(home: &Path, id: &str) -> anyhow::Result<()> {
    read_pending(home, id)?;
    claim(home, id)?;
    let dir = pending_dir(home);
    std::fs::rename(
        dir.join(format!("{id}.deciding")),
        dir.join(format!("{id}.rejected")),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{inspect, parse, NativeState, Response};
    use super::*;
    use crate::{
        audit::AuditSink,
        handlers::{AppState, Sessions as HookSessions},
        Config,
    };
    use soup_wall_agent::{AgentFirewall, AgentPolicySet, DEFAULT_TAINT_CAP};
    use std::sync::Arc;

    const HOOK: &str = "hook-unit-key";
    const POLICY: &str = "agent_policies:\n  - name: unit-destructive-ask\n    when: { action_class: destructive }\n    action: ask\n  - name: unit-side-effecting-ask\n    when: { action_class: side_effecting }\n    action: ask\n  - name: unit-privilege-deny\n    when: { action_class: privilege_changing }\n    action: deny\ndefault: allow\n";

    struct Env {
        dir: tempfile::TempDir,
        st: Shared,
    }

    fn env(approval: Option<u64>) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let schema = "a".repeat(64);
        #[allow(unused_mut)]
        let mut tools = vec![
            json!({"name": "delete_note", "schema_sha256": schema, "action_class": "destructive",
             "result_provenance": "untrusted", "egress": []}),
            json!({"name": "read_note", "schema_sha256": schema, "action_class": "read_only",
             "result_provenance": "untrusted", "egress": []}),
            json!({"name": "grant_admin", "schema_sha256": schema, "action_class": "privilege_changing",
             "result_provenance": "untrusted", "egress": []}),
        ];
        #[cfg(unix)]
        {
            let create_schema =
                super::super::canonical_digest(&crate::native::resource::create_file_schema());
            let ws = dir.path().canonicalize().unwrap();
            let ws_str = ws.to_str().unwrap();
            let target_file = ws.join("test.txt").to_str().unwrap().to_string();
            tools.push(json!({"name": "create_file", "schema_sha256": create_schema, "action_class": "side_effecting",
                 "result_provenance": "untrusted", "egress": [], "resource_policy": {
                     "profile": {"server_id": "test-fs", "tool_name": "create_file", "schema_sha256": create_schema, "selectors": [{"pointer": "/path", "kind": "path", "allow_missing_leaf": true}]},
                     "workspace": ws_str, "cwd": ws_str,
                     "executor_sha256": crate::native::resource::create_file_executor_sha256(),
                     "classifier_sha256": "c".repeat(64),
                     "allowed_resources": [{"kind": "path", "canonical": target_file}],
                     "execution": {
                         "operation": "create_file", "action": "write", "max_content_bytes": 4096,
                         "executor_profile": "sw-native/create-file/linux-root-child/1",
                         "path_selector": "/path", "content_selector": "/content"
                     }
                 }}));
        }
        let bytes =
            json!({"contract_version": CONTRACT, "registry_id": "unit-approval", "tools": tools})
                .to_string()
                .into_bytes();
        let digest = super::super::hash(&bytes);
        let mut native =
            NativeState::from_bytes(&bytes, &digest, "native-unit-key".into()).unwrap();
        if let Some(ttl) = approval {
            native = native
                .with_approval(dir.path(), &grant::derive_key(HOOK), ttl)
                .unwrap();
        }
        let dirp = dir.path();
        let st = Arc::new(AppState {
            native: Some(native),
            firewall: std::sync::Mutex::new(AgentFirewall::new(
                AgentPolicySet::from_yaml(POLICY).unwrap(),
                DEFAULT_TAINT_CAP,
            )),
            sessions: HookSessions::default(),
            audit: AuditSink::open(&dirp.join("audit.jsonl")).unwrap(),
            spans: crate::spans::SpanCache::new(64, 4096),
            judge: crate::judge::Judge::new(Default::default()),
            manifests: crate::mcp::store::ManifestStore::new(&dirp.join("manifests")),
            tools: crate::mcp::store::ToolRegistry::with_builtins(),
            grants: GrantStore::new(&dirp.join("grants")),
            grant_ledger: GrantLedger::open(&dirp.join("grants-spent.json")),
            grant_key: grant::derive_key(HOOK),
            config: Config {
                enforce: true,
                ..Config::default()
            },
            token: HOOK.into(),
        });
        Env { dir, st }
    }

    impl Env {
        fn native(&self) -> &NativeState {
            self.st.native.as_ref().unwrap()
        }
        fn home(&self) -> &Path {
            self.dir.path()
        }
        fn start(&self, session: &str) {
            let fields = json!({"event": "session_start"});
            self.send(session, fields).unwrap();
        }
        fn send(&self, session: &str, fields: Value) -> Result<Response, &'static str> {
            let mut value = json!({"contract_version": CONTRACT,
                "registry_sha256": self.native().registry_sha256, "session_id": session});
            for (k, v) in fields.as_object().unwrap() {
                value[k] = v.clone();
            }
            inspect(&self.st, self.native(), parse(&value.to_string()).unwrap())
        }
        fn call(
            &self,
            session: &str,
            tool: &str,
            args: Value,
            approval: Option<&str>,
        ) -> Result<Response, &'static str> {
            let mut fields = json!({"event": "call", "tool": tool, "args": args,
                "schema_sha256": "a".repeat(64)});
            if let Some(id) = approval {
                fields["approval_id"] = json!(id);
            }
            self.send(session, fields)
        }
        fn open(
            &self,
            session: &str,
            tool: &str,
            args: Value,
            source: &str,
        ) -> Result<Value, &'static str> {
            let schema = self
                .native()
                .registry
                .tools
                .iter()
                .find(|t| t.name == tool)
                .map(|t| t.schema_sha256.clone())
                .unwrap_or_else(|| "a".repeat(64));
            let request = ApprovalRequest {
                contract_version: CONTRACT.into(),
                registry_sha256: self.native().registry_sha256.clone(),
                session_id: session.into(),
                action: "request".into(),
                source: Some(source.into()),
                tool: Some(tool.into()),
                args: Some(args),
                schema_sha256: Some(schema),
                pending_id: None,
                resource_admission: None,
            };
            super::open(
                &self.st,
                self.native(),
                self.native()
                    .approval
                    .as_ref()
                    .ok_or("native_approval_disabled")?,
                &request,
            )
        }
        fn state(&self, session: &str, id: &str) -> String {
            self.native()
                .approval
                .as_ref()
                .unwrap()
                .status(id, session)
                .map(|s| s.0.to_string())
                .unwrap_or_else(|e| e.to_string())
        }
        fn approve(&self, reply: &Value) {
            operator_approve(
                self.home(),
                HOOK,
                reply["pending_id"].as_str().unwrap(),
                reply["binding_sha256"].as_str().unwrap(),
            )
            .unwrap();
        }
    }

    fn id(reply: &Value) -> String {
        reply["pending_id"].as_str().unwrap().to_string()
    }

    fn codes(response: &Response) -> String {
        response.reason_codes.join(",")
    }

    #[test]
    fn default_config_keeps_the_refusal_and_has_no_approval_route() {
        let env = env(None);
        env.start("s1");
        let refused = env
            .call("s1", "delete_note", json!({"name": "a"}), None)
            .unwrap();
        assert!(!refused.release && refused.verdict == "ask");
        assert_eq!(
            env.call("s1", "delete_note", json!({"name": "a"}), Some("anything"))
                .err(),
            Some("native_approval_disabled")
        );
        assert!(env
            .open("s1", "delete_note", json!({"name": "a"}), "daemon")
            .is_err());
    }

    #[test]
    fn exact_approval_releases_the_original_call_exactly_once() {
        let env = env(Some(60));
        env.start("s1");
        let args = json!({"name": "inventory"});
        assert!(
            !env.call("s1", "delete_note", args.clone(), None)
                .unwrap()
                .release
        );
        let reply = env
            .open("s1", "delete_note", args.clone(), "daemon")
            .unwrap();
        let pending = id(&reply);
        assert_eq!(env.state("s1", &pending), "pending");
        // Not approved yet: presenting the id is refused and burns it.
        let early = env
            .call("s1", "delete_note", args.clone(), Some(&pending))
            .unwrap();
        assert!(!early.release, "{}", codes(&early));
        let reply = env
            .open("s1", "delete_note", args.clone(), "daemon")
            .unwrap();
        let pending = id(&reply);
        assert_eq!(operator_list(env.home()).len(), 1);
        env.approve(&reply);
        assert_eq!(env.state("s1", &pending), "approved");
        let released = env
            .call("s1", "delete_note", args.clone(), Some(&pending))
            .unwrap();
        assert!(
            released.release && released.call_id.is_some(),
            "{}",
            codes(&released)
        );
        assert_eq!(released.verdict, "allow");
        assert_eq!(env.state("s1", &pending), "redeemed");
        // Replay of the same approval never releases again.
        let replay = env.call("s1", "delete_note", args, Some(&pending)).unwrap();
        assert!(!replay.release && replay.call_id.is_none());
        assert!(operator_list(env.home()).is_empty());
    }

    #[test]
    fn reject_and_expiry_cannot_be_rescued() {
        let env = env(Some(1));
        env.start("s1");
        let args = json!({"name": "a"});
        let reply = env
            .open("s1", "delete_note", args.clone(), "daemon")
            .unwrap();
        let pending = id(&reply);
        operator_reject(env.home(), &pending).unwrap();
        assert_eq!(env.state("s1", &pending), "rejected");
        assert!(operator_approve(
            env.home(),
            HOOK,
            &pending,
            reply["binding_sha256"].as_str().unwrap()
        )
        .is_err());
        assert!(
            !env.call("s1", "delete_note", args.clone(), Some(&pending))
                .unwrap()
                .release
        );
        let reply = env
            .open("s1", "delete_note", args.clone(), "daemon")
            .unwrap();
        env.approve(&reply);
        std::thread::sleep(Duration::from_millis(1200));
        let pending = id(&reply);
        assert_eq!(env.state("s1", &pending), "expired");
        assert!(
            !env.call("s1", "delete_note", args, Some(&pending))
                .unwrap()
                .release
        );
    }

    #[test]
    fn changed_arguments_and_other_sessions_get_no_release() {
        let env = env(Some(60));
        env.start("s1");
        env.start("s2");
        let args = json!({"name": "inventory"});
        let reply = env
            .open("s1", "delete_note", args.clone(), "daemon")
            .unwrap();
        env.approve(&reply);
        let pending = id(&reply);
        let changed = env
            .call(
                "s1",
                "delete_note",
                json!({"name": "other"}),
                Some(&pending),
            )
            .unwrap();
        assert!(!changed.release, "{}", codes(&changed));
        // The refusal closed the approval: the original arguments are no longer rescued.
        assert!(
            !env.call("s1", "delete_note", args.clone(), Some(&pending))
                .unwrap()
                .release
        );

        let reply = env
            .open("s1", "delete_note", args.clone(), "daemon")
            .unwrap();
        env.approve(&reply);
        let pending = id(&reply);
        let other = env
            .call("s2", "delete_note", args.clone(), Some(&pending))
            .unwrap();
        assert!(!other.release, "{}", codes(&other));
        assert!(
            !env.call("s1", "delete_note", args, Some(&pending))
                .unwrap()
                .release
        );
    }

    #[test]
    fn policy_switch_hard_deny_and_unsupported_cannot_be_rescued() {
        let env = env(Some(60));
        env.start("s1");
        let args = json!({"name": "inventory"});
        let reply = env
            .open("s1", "delete_note", args.clone(), "daemon")
            .unwrap();
        env.approve(&reply);
        env.st.grants.invalidate_all_for_policy_switch().unwrap();
        let stale = env
            .call("s1", "delete_note", args.clone(), Some(&id(&reply)))
            .unwrap();
        assert!(
            !stale.release && codes(&stale).contains("stale_policy"),
            "{}",
            codes(&stale)
        );

        assert_eq!(
            env.open("s1", "grant_admin", json!({"name": "x"}), "daemon")
                .err(),
            Some("native_approval_hard_deny")
        );
        assert_eq!(
            env.open("s1", "grant_admin", json!({"name": "x"}), "classifier")
                .err(),
            Some("native_approval_hard_deny")
        );
        assert_eq!(
            env.open("s1", "read_note", json!({"name": "x"}), "daemon")
                .err(),
            Some("native_approval_not_required")
        );
        // An approval id attached to a hard-Deny call never releases it.
        let denied = env
            .call("s1", "grant_admin", json!({"name": "x"}), Some(&id(&reply)))
            .unwrap();
        assert!(!denied.release && denied.verdict == "deny");
    }

    #[test]
    fn concurrent_redemption_releases_exactly_one() {
        let env = Arc::new(env(Some(60)));
        env.start("s1");
        let args = json!({"name": "inventory"});
        let reply = env
            .open("s1", "delete_note", args.clone(), "daemon")
            .unwrap();
        env.approve(&reply);
        let pending = id(&reply);
        let mut threads = Vec::new();
        for _ in 0..8 {
            let (env, args, pending) = (env.clone(), args.clone(), pending.clone());
            threads.push(std::thread::spawn(move || {
                env.call("s1", "delete_note", args, Some(&pending))
                    .map(|r| r.release)
                    .unwrap_or(false)
            }));
        }
        let released = threads
            .into_iter()
            .map(|t| t.join().unwrap())
            .filter(|r| *r)
            .count();
        assert_eq!(released, 1);
    }

    #[test]
    fn restart_session_end_and_second_pending_close_or_refuse() {
        let env = env(Some(60));
        env.start("s1");
        let args = json!({"name": "inventory"});
        let reply = env
            .open("s1", "delete_note", args.clone(), "daemon")
            .unwrap();
        assert_eq!(
            env.open("s1", "delete_note", args.clone(), "daemon").err(),
            Some("native_approval_already_pending")
        );
        env.approve(&reply);
        let pending = id(&reply);
        env.send("s1", json!({"event": "session_end"})).unwrap();
        assert_eq!(env.state("s1", &pending), "closed");
        assert!(operator_list(env.home()).is_empty());
        assert!(!env
            .home()
            .join("native-grants")
            .join(format!("{pending}.json"))
            .exists());

        env.start("s2");
        let reply = env.open("s2", "delete_note", args, "daemon").unwrap();
        assert_eq!(operator_list(env.home()).len(), 1);
        let restarted = ApprovalState::new(env.home(), &grant::derive_key(HOOK), 60).unwrap();
        assert!(
            operator_list(env.home()).is_empty(),
            "a restart removes pending files"
        );
        assert!(restarted.records.lock().unwrap().is_empty());
        assert!(operator_inspect(env.home(), &id(&reply)).is_err());
    }

    #[test]
    fn hook_key_and_hook_grants_cannot_authorize_native_calls() {
        let env = env(Some(60));
        env.start("s1");
        let args = json!({"name": "inventory"});
        let reply = env
            .open("s1", "delete_note", args.clone(), "daemon")
            .unwrap();
        let pending = id(&reply);
        let epoch = env.native().sessions.lock().unwrap().entries["s1"]
            .epoch
            .clone();
        // A grant signed with the HOOK key, even with the matching scope, is not accepted.
        GrantStore::new(&grants_dir(env.home()))
            .issue(
                &grant::derive_key(HOOK),
                &ActionRef {
                    session: epoch.clone(),
                    tool: scope_tool("delete_note"),
                    args_fingerprint: reply["binding_sha256"].as_str().unwrap().into(),
                },
                now_ms(),
                60_000,
                pending.clone(),
            )
            .unwrap();
        let forged = env
            .call("s1", "delete_note", args.clone(), Some(&pending))
            .unwrap();
        assert!(!forged.release, "{}", codes(&forged));
        // An old-style hook approval for the same tool and arguments does not release it either.
        let hook_style = ActionRef {
            session: epoch,
            tool: "delete_note".into(),
            args_fingerprint: grant::action_fingerprint("delete_note", &args),
        };
        env.st
            .grants
            .issue(
                &env.st.grant_key,
                &hook_style,
                now_ms(),
                60_000,
                crate::token::generate(),
            )
            .unwrap();
        assert!(!env.call("s1", "delete_note", args, None).unwrap().release);
    }

    #[test]
    fn classifier_source_requires_the_same_exact_approval() {
        let env = env(Some(60));
        env.start("s1");
        let args = json!({"name": "inventory"});
        let reply = env
            .open("s1", "read_note", args.clone(), "classifier")
            .unwrap();
        // Unapproved: the daemon's own Allow does not accept an unapproved id.
        let pending = id(&reply);
        env.approve(&reply);
        let released = env
            .call("s1", "read_note", args.clone(), Some(&pending))
            .unwrap();
        assert!(released.release, "{}", codes(&released));
        let again = env.call("s1", "read_note", args, Some(&pending)).unwrap();
        assert!(!again.release);
    }

    #[test]
    #[cfg(unix)]
    fn resource_tool_can_be_approved_and_inspected() {
        let env = env(Some(60));
        env.start("s1");
        let ws_path = env.home().join("test.txt").to_str().unwrap().to_string();
        let args = json!({"path": ws_path, "content": "approved content bytes"});
        if !cfg!(target_os = "linux") {
            assert_eq!(
                env.open("s1", "create_file", args, "daemon").unwrap_err(),
                "native_approval_resource_tool_unsupported"
            );
            assert!(operator_list(env.home()).is_empty());
            return;
        }
        let reply = env
            .open("s1", "create_file", args.clone(), "daemon")
            .unwrap();
        let pending = id(&reply);
        let inspected = operator_inspect(env.home(), &pending).unwrap();
        assert_eq!(inspected["tool"], "create_file");
        assert_eq!(inspected["resource_details"]["operation"], "create_file");
        assert_eq!(inspected["resource_details"]["content_length"], 22);
        assert_eq!(inspected["binding_sha256"], reply["binding_sha256"]);

        assert_eq!(env.state("s1", &pending), "pending");
        env.approve(&reply);
        assert_eq!(env.state("s1", &pending), "approved");
    }

    #[test]
    #[cfg(unix)]
    fn unsupported_resource_tool_with_ask_is_refused() {
        let env = env(Some(60));
        env.start("s1");
        let mut tool = env
            .native()
            .registry
            .tools
            .iter()
            .find(|t| t.name == "create_file")
            .unwrap()
            .clone();
        if let Some(ref mut policy) = tool.resource_policy {
            policy.executor_sha256 = "0".repeat(64);
        }
        assert!(!crate::native::resource_approval::is_supported_linux_resource_tool(&tool));
    }
    #[tokio::test]
    async fn sou89_collector_guard_binds_approval_open_status_and_cancel_to_the_owner() {
        let env = env(Some(60));
        let start = env
            .send(
                "s1",
                json!({"event":"session_start", "liveness":"sw-native-liveness/1"}),
            )
            .unwrap();
        let epoch = env.native().sessions.lock().unwrap().entries["s1"]
            .epoch
            .clone();
        let identity = json!({"contract_version":"sw-native-liveness/1", "instance_id":env.native().instance_id(),
            "epoch":epoch, "owner_token":start.owner_token.unwrap()});
        let headers = |identity: &Value| {
            let mut h = HeaderMap::new();
            h.insert(
                "authorization",
                format!("Bearer {}", env.native().token).parse().unwrap(),
            );
            h.insert(
                super::super::liveness::COLLECTOR_IDENTITY_HEADER,
                identity.to_string().parse().unwrap(),
            );
            h
        };
        let request = json!({"contract_version":CONTRACT,"registry_sha256":env.native().registry_sha256,
            "session_id":"s1","action":"request","source":"daemon","tool":"delete_note",
            "schema_sha256":"a".repeat(64),"args":{"name":"inventory"}});
        let mut forged = identity.clone();
        forged["owner_token"] = json!("peer-owner");
        let (status, _) = handler(
            AxState(env.st.clone()),
            headers(&forged),
            request.to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(operator_list(env.home()).is_empty());
        let (status, Json(opened)) = handler(
            AxState(env.st.clone()),
            headers(&identity),
            request.to_string(),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let pending = opened["pending_id"].as_str().unwrap();
        for action in ["status", "cancel"] {
            let body = json!({"contract_version":CONTRACT,"registry_sha256":env.native().registry_sha256,
                "session_id":"s1","action":action,"pending_id":pending});
            let (status, _) =
                handler(AxState(env.st.clone()), headers(&forged), body.to_string()).await;
            assert_eq!(status, StatusCode::CONFLICT);
            assert_eq!(env.state("s1", pending), "pending");
            let (status, Json(reply)) = handler(
                AxState(env.st.clone()),
                headers(&identity),
                body.to_string(),
            )
            .await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(
                reply["state"],
                if action == "status" {
                    "pending"
                } else {
                    "cancelled"
                }
            );
        }
    }
}
