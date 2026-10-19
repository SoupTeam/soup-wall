// SPDX-License-Identifier: Apache-2.0
//! SOU-89: Separately versioned opt-in native session liveness and bounded orphan reclamation.
//! A healthy idle collector remains usable within its declared monotonic lease,
//! while a lost/dead collector is proactively reclaimed by the daemon maintenance path
//! without waiting for unrelated traffic or losing shared-host taint history.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::{failure, identifier, wall_time_ms, MAX_CONTENT};
use crate::handlers::Shared;
use crate::native::NativeState;

pub const LIVENESS_CONTRACT: &str = "sw-native-liveness/1";
/// Optional identity guard on native/approval requests from an enrolled collector.
/// The legacy operator request/receipt schemas are unchanged.
pub const COLLECTOR_IDENTITY_HEADER: &str = "x-agentfw-collector-liveness";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CollectorIdentity {
    contract_version: String,
    instance_id: String,
    epoch: String,
    owner_token: String,
}

pub(crate) fn collector_identity(
    headers: &HeaderMap,
) -> Result<Option<CollectorIdentity>, &'static str> {
    let mut values = headers.get_all(COLLECTOR_IDENTITY_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() || value.as_bytes().len() > 1024 {
        return Err("native_liveness_invalid_identity");
    }
    let identity: CollectorIdentity =
        serde_json::from_slice(value.as_bytes()).map_err(|_| "native_liveness_invalid_identity")?;
    if identity.contract_version != LIVENESS_CONTRACT
        || !identifier(&identity.instance_id)
        || !identifier(&identity.epoch)
        || identity.owner_token.is_empty()
        || identity.owner_token.len() > 256
    {
        return Err("native_liveness_invalid_identity");
    }
    Ok(Some(identity))
}

impl CollectorIdentity {
    pub(crate) fn verify(
        &self,
        native: &NativeState,
        session: &super::Session,
    ) -> Result<(), &'static str> {
        use subtle::ConstantTimeEq;
        if self.instance_id != native.instance_id() {
            return Err("native_instance_mismatch");
        }
        if self.epoch != session.epoch {
            return Err("native_liveness_epoch_mismatch");
        }
        if !bool::from(
            self.owner_token
                .as_bytes()
                .ct_eq(session.owner_token.as_bytes()),
        ) {
            return Err("native_liveness_owner_mismatch");
        }
        Ok(())
    }
}

pub const MIN_LEASE_SECONDS: u64 = 1;
pub const DEFAULT_LEASE_SECONDS: u64 = 10;
pub const MAX_LEASE_SECONDS: u64 = 60;
pub const DEFAULT_MAINTENANCE_INTERVAL_MS: u64 = 500;
pub const COLLECTOR_RETRY_BUDGET: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Active,
    Terminal(&'static str),
}

#[derive(Debug, Clone)]
pub struct Lease {
    pub session_id: String,
    pub epoch: String,
    pub instance_id: String,
    pub duration: Duration,
    pub expires_at: Instant,
    pub seq: u64,
    pub state: LeaseState,
}

impl Lease {
    pub fn new(
        session_id: String,
        epoch: String,
        instance_id: String,
        duration: Duration,
        now: Instant,
    ) -> Self {
        Self {
            session_id,
            epoch,
            instance_id,
            duration,
            expires_at: now + duration,
            seq: 1,
            state: LeaseState::Active,
        }
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self.state, LeaseState::Terminal(_))
    }

    pub fn is_expired(&self, now: Instant) -> bool {
        self.is_terminal() || now >= self.expires_at
    }

    pub fn expires_in_ms(&self, now: Instant) -> u64 {
        if self.is_terminal() || now >= self.expires_at {
            0
        } else {
            self.expires_at.duration_since(now).as_millis() as u64
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LivenessRequest {
    pub contract_version: String,
    pub registry_sha256: String,
    pub session_id: String,
    pub instance_id: String,
    pub action: String,
    pub owner_token: Option<String>,
    pub epoch: Option<String>,
    pub lease_seq: Option<u64>,
    pub lease_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct LivenessResponse {
    pub contract_version: &'static str,
    pub action: String,
    pub instance_id: String,
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_seq: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<&'static str>,
}

pub async fn handler(
    State(st): State<Shared>,
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
    if !st.config.enforce || st.config.judge.enabled {
        return failure(
            "native_enforcement_required",
            StatusCode::SERVICE_UNAVAILABLE,
        );
    }
    if body.len() > MAX_CONTENT * 2 || body.len() > st.config.max_body_bytes {
        return failure("native_body_over_cap", StatusCode::PAYLOAD_TOO_LARGE);
    }
    let Ok(request) = serde_json::from_str::<LivenessRequest>(&body) else {
        return failure("native_invalid_fields", StatusCode::BAD_REQUEST);
    };
    if request.contract_version != LIVENESS_CONTRACT
        || request.registry_sha256 != native.registry_sha256
        || !identifier(&request.session_id)
        || !identifier(&request.instance_id)
    {
        return failure("native_invalid_identity", StatusCode::BAD_REQUEST);
    }
    if request.instance_id != native.instance_id() {
        return failure("native_instance_mismatch", StatusCode::CONFLICT);
    }
    match request.action.as_str() {
        "enroll" => enroll(&st, native, &request),
        "renew" => renew(&st, native, &request),
        "retire" => retire(&st, native, &request),
        "status" => status(native, &request),
        _ => failure("native_invalid_event", StatusCode::BAD_REQUEST),
    }
}

// Epochs are audit identities. Only the per-session capability proves ownership.
fn verify_owner(session: &super::Session, request: &LivenessRequest) -> Result<(), &'static str> {
    use subtle::ConstantTimeEq;
    let owner = request
        .owner_token
        .as_deref()
        .ok_or("native_liveness_owner_token_required")?;
    if !bool::from(owner.as_bytes().ct_eq(session.owner_token.as_bytes())) {
        return Err("native_liveness_owner_mismatch");
    }
    Ok(())
}

fn enroll(
    st: &Shared,
    native: &NativeState,
    request: &LivenessRequest,
) -> (StatusCode, Json<Value>) {
    let configured_max = st
        .config
        .native
        .as_ref()
        .and_then(|n| n.liveness.as_ref())
        .map(|l| {
            l.max_lease_seconds
                .clamp(MIN_LEASE_SECONDS, MAX_LEASE_SECONDS)
        })
        .unwrap_or(MAX_LEASE_SECONDS);
    let configured_default = st
        .config
        .native
        .as_ref()
        .and_then(|n| n.liveness.as_ref())
        .map(|l| {
            l.default_lease_seconds
                .clamp(MIN_LEASE_SECONDS, configured_max)
        })
        .unwrap_or(DEFAULT_LEASE_SECONDS.min(configured_max));
    let requested = request.lease_seconds.unwrap_or(configured_default);
    let lease_secs = requested.clamp(MIN_LEASE_SECONDS, configured_max);
    let duration = Duration::from_secs(lease_secs);

    let mut sessions = match native.sessions.lock() {
        Ok(s) => s,
        Err(_) => return failure("native_state_unavailable", StatusCode::SERVICE_UNAVAILABLE),
    };

    // Lock contention must not extend an expired lease or authority.
    let now = native.monotonic_now();
    let now_ms = match super::wall_time_ms() {
        Ok(ms) => ms + native.test_time_offset(),
        Err(code) => return failure(code, StatusCode::SERVICE_UNAVAILABLE),
    };

    let epoch = {
        let session = match sessions.entries.get(&request.session_id) {
            Some(s) => s,
            None => return failure("native_session_unknown", StatusCode::NOT_FOUND),
        };
        if let Err(code) = verify_owner(session, request) {
            return failure(code, StatusCode::FORBIDDEN);
        }
        if session.terminal {
            return failure("native_session_terminal", StatusCode::CONFLICT);
        }
        if session.liveness_lease.is_some() {
            return failure("native_liveness_already_enrolled", StatusCode::CONFLICT);
        }
        if now.duration_since(session.touched) >= super::TTL {
            return failure("native_child_authority_expired", StatusCode::CONFLICT);
        }
        if session
            .authority_expires_at_ms
            .is_some_and(|exp| now_ms >= exp)
        {
            return failure("native_child_authority_expired", StatusCode::CONFLICT);
        }
        if let Err(code) = super::validate_lineage(&sessions, session, now_ms, now) {
            return failure(code, StatusCode::CONFLICT);
        }
        session.epoch.clone()
    };

    // Audit enrollment before committing lease state
    let record = json!({
        "at_ms": super::now_ms(),
        "event": "native_liveness_enrolled",
        "session": epoch,
        "session_id": request.session_id,
        "lease_seconds": lease_secs,
        "instance_id": native.instance_id(),
        "released": true,
    });
    if st.audit.write_native(&record).is_err() {
        if let Ok(mut fw) = st.firewall.lock() {
            fw.mark_all_provenance_incomplete();
        }
        return failure("native_audit_unavailable", StatusCode::SERVICE_UNAVAILABLE);
    }

    let lease = Lease::new(
        request.session_id.clone(),
        epoch.clone(),
        native.instance_id().to_string(),
        duration,
        now,
    );
    let session = sessions.entries.get_mut(&request.session_id).unwrap();
    session.liveness_lease = Some(lease.clone());
    session.touched = now;

    let response = LivenessResponse {
        contract_version: LIVENESS_CONTRACT,
        action: "enroll".into(),
        instance_id: native.instance_id().to_string(),
        session_id: request.session_id.clone(),
        epoch: Some(epoch),
        lease_seconds: Some(lease_secs),
        lease_seq: Some(lease.seq),
        expires_in_ms: Some(lease.expires_in_ms(now)),
        status: Some("active"),
    };

    (
        StatusCode::OK,
        Json(serde_json::to_value(response).unwrap()),
    )
}

fn renew(
    st: &Shared,
    native: &NativeState,
    request: &LivenessRequest,
) -> (StatusCode, Json<Value>) {
    let mut sessions = match native.sessions.lock() {
        Ok(s) => s,
        Err(_) => return failure("native_state_unavailable", StatusCode::SERVICE_UNAVAILABLE),
    };

    // Lock contention must not extend an expired lease or authority.
    let now = native.monotonic_now();
    let now_ms = match wall_time_ms() {
        Ok(ms) => ms + native.test_time_offset(),
        Err(code) => return failure(code, StatusCode::SERVICE_UNAVAILABLE),
    };

    // First validate while sessions is borrowed immutably
    let (current_epoch, is_expired) = {
        let session = match sessions.entries.get(&request.session_id) {
            Some(s) => s,
            None => return failure("native_session_unknown", StatusCode::NOT_FOUND),
        };

        if session.terminal {
            return failure("native_session_terminal", StatusCode::CONFLICT);
        }

        if let Err(code) = verify_owner(session, request) {
            return failure(code, StatusCode::FORBIDDEN);
        }
        // Bind the owner capability to this exact session incarnation.
        let Some(epoch) = &request.epoch else {
            return failure("native_liveness_epoch_required", StatusCode::BAD_REQUEST);
        };
        if epoch != &session.epoch {
            return failure("native_liveness_epoch_mismatch", StatusCode::FORBIDDEN);
        }

        let Some(lease) = &session.liveness_lease else {
            return failure("native_liveness_not_enrolled", StatusCode::CONFLICT);
        };

        if lease.is_terminal() {
            return failure("native_liveness_terminal", StatusCode::CONFLICT);
        }

        // Monotonic clock check for lease expiry
        if now >= lease.expires_at {
            (session.epoch.clone(), true)
        } else {
            // Sequence replay protection
            let Some(seq) = request.lease_seq else {
                return failure("native_liveness_seq_required", StatusCode::BAD_REQUEST);
            };
            if seq <= lease.seq {
                return failure("native_liveness_seq_stale", StatusCode::CONFLICT);
            }

            // Signed child authority check: a lease renewal cannot extend child authority
            if let Some(exp) = session.authority_expires_at_ms {
                if now_ms >= exp {
                    return failure("native_liveness_authority_expired", StatusCode::CONFLICT);
                }
            }

            // Lineage check: a lease renewal cannot extend parent validity
            if let Err(code) = super::validate_lineage(&sessions, session, now_ms, now) {
                return failure(code, StatusCode::CONFLICT);
            }

            (session.epoch.clone(), false)
        }
    };

    if is_expired {
        if let Some(session) = sessions.entries.get_mut(&request.session_id) {
            if let Some(lease) = &mut session.liveness_lease {
                lease.state = LeaseState::Terminal("expired");
            }
        }
        return failure("native_liveness_expired", StatusCode::CONFLICT);
    }

    let seq = request.lease_seq.unwrap();

    let record = json!({
        "at_ms": super::now_ms(),
        "event": "native_liveness_renewed",
        "session": current_epoch,
        "session_id": request.session_id,
        "lease_seq": seq,
        "released": true,
    });
    if st.audit.write_native(&record).is_err() {
        if let Ok(mut fw) = st.firewall.lock() {
            fw.mark_all_provenance_incomplete();
        }
        return failure("native_audit_unavailable", StatusCode::SERVICE_UNAVAILABLE);
    }

    let session = sessions.entries.get_mut(&request.session_id).unwrap();
    let lease = session.liveness_lease.as_mut().unwrap();
    lease.seq = seq;
    lease.expires_at = now + lease.duration;
    session.touched = now;

    let response = LivenessResponse {
        contract_version: LIVENESS_CONTRACT,
        action: "renew".into(),
        instance_id: native.instance_id().to_string(),
        session_id: request.session_id.clone(),
        epoch: None,
        lease_seconds: Some(lease.duration.as_secs()),
        lease_seq: Some(lease.seq),
        expires_in_ms: Some(lease.expires_in_ms(now)),
        status: Some("active"),
    };

    (
        StatusCode::OK,
        Json(serde_json::to_value(response).unwrap()),
    )
}

fn retire(
    st: &Shared,
    native: &NativeState,
    request: &LivenessRequest,
) -> (StatusCode, Json<Value>) {
    let sessions = match native.sessions.lock() {
        Ok(s) => s,
        Err(_) => return failure("native_state_unavailable", StatusCode::SERVICE_UNAVAILABLE),
    };

    let session = match sessions.entries.get(&request.session_id) {
        Some(s) => s,
        None => return failure("native_session_unknown", StatusCode::NOT_FOUND),
    };

    if let Err(code) = verify_owner(session, request) {
        return failure(code, StatusCode::FORBIDDEN);
    }

    let Some(epoch) = &request.epoch else {
        return failure("native_liveness_epoch_required", StatusCode::BAD_REQUEST);
    };
    if epoch != &session.epoch {
        return failure("native_liveness_epoch_mismatch", StatusCode::FORBIDDEN);
    }
    let session_epoch = session.epoch.clone();

    // Release the sessions lock so unified retirement can execute cleanly
    drop(sessions);

    super::retire_sessions_terminal(
        st,
        native,
        &[(request.session_id.clone(), Some(session_epoch))],
        "retired",
    );

    let response = LivenessResponse {
        contract_version: LIVENESS_CONTRACT,
        action: "retire".into(),
        instance_id: native.instance_id().to_string(),
        session_id: request.session_id.clone(),
        epoch: None,
        lease_seconds: None,
        lease_seq: None,
        expires_in_ms: Some(0),
        status: Some("retired"),
    };

    (
        StatusCode::OK,
        Json(serde_json::to_value(response).unwrap()),
    )
}

fn status(native: &NativeState, request: &LivenessRequest) -> (StatusCode, Json<Value>) {
    let sessions = match native.sessions.lock() {
        Ok(s) => s,
        Err(_) => return failure("native_state_unavailable", StatusCode::SERVICE_UNAVAILABLE),
    };

    let now = native.monotonic_now();
    let Some(session) = sessions.entries.get(&request.session_id) else {
        return failure("native_session_unknown", StatusCode::NOT_FOUND);
    };

    // A collector whose enrollment reply was lost may recover only its own
    // bootstrap epoch for terminal cleanup. Operator telemetry stays unchanged.
    let owned_epoch = if request.owner_token.is_some() {
        if let Err(code) = verify_owner(session, request) {
            return failure(code, StatusCode::FORBIDDEN);
        }
        Some(session.epoch.clone())
    } else {
        None
    };

    let (state_str, left_ms, seq) = match &session.liveness_lease {
        Some(lease) => (
            if lease.is_expired(now) {
                "expired"
            } else {
                "active"
            },
            lease.expires_in_ms(now),
            Some(lease.seq),
        ),
        None => (
            if session.terminal {
                "terminal"
            } else {
                "unleased"
            },
            0,
            None,
        ),
    };

    let response = LivenessResponse {
        contract_version: LIVENESS_CONTRACT,
        action: "status".into(),
        instance_id: native.instance_id().to_string(),
        session_id: request.session_id.clone(),
        epoch: owned_epoch,
        lease_seconds: session
            .liveness_lease
            .as_ref()
            .map(|l| l.duration.as_secs()),
        lease_seq: seq,
        expires_in_ms: Some(left_ms),
        status: Some(state_str),
    };

    (
        StatusCode::OK,
        Json(serde_json::to_value(response).unwrap()),
    )
}

/// Daemon maintenance worker loop: runs continuously in background as long as the daemon serves.
pub async fn run_maintenance_loop(st: Shared, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let interval_ms = st
        .config
        .native
        .as_ref()
        .and_then(|n| n.liveness.as_ref())
        .map(|l| l.maintenance_interval_ms)
        .unwrap_or(DEFAULT_MAINTENANCE_INTERVAL_MS);
    let interval = Duration::from_millis(interval_ms.clamp(50, 10_000));

    loop {
        tokio::select! {
            res = shutdown.changed() => {
                if res.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            _ = tokio::time::sleep(interval) => {
                perform_maintenance(&st).await;
            }
        }
    }
}

/// One sweep of the bounded maintenance path. Returns count of reclaimed sessions.
pub async fn perform_maintenance(st: &Shared) -> usize {
    let Some(native) = &st.native else {
        return 0;
    };

    let _gate = match &native.continuity {
        Some(c) => Some(c.gate().lock().await),
        _ => None,
    };

    // Coordinate with profile transition gates safely: do not mutate during profile transition
    if let Some(continuity) = &native.continuity {
        if continuity.is_transition_pending() {
            return 0;
        }
    }

    let dead_targets: Vec<(String, Option<String>)> = {
        let Ok(mut sessions) = native.sessions.lock() else {
            return 0;
        };
        let now = native.monotonic_now();
        let now_ms = match wall_time_ms() {
            Ok(ms) => ms + native.test_time_offset(),
            Err(_) => return 0,
        };
        sessions.spent_authorities.retain(|_, exp| *exp > now_ms);
        sessions
            .entries
            .iter()
            .filter(|(_, s)| s.is_dead(now, now_ms, &sessions))
            .map(|(id, s)| (id.clone(), Some(s.epoch.clone())))
            .collect()
    };

    if dead_targets.is_empty() {
        return 0;
    }

    if let Some(continuity) = &native.continuity {
        if continuity.is_enabled() && continuity.begin().is_err() {
            if let Ok(mut fw) = st.firewall.lock() {
                fw.mark_all_provenance_incomplete();
            }
            return 0;
        }
    }

    let reclaimed = super::retire_sessions_terminal(st, native, &dead_targets, "expired");

    if reclaimed > 0 {
        if let Some(continuity) = &native.continuity {
            if continuity.is_enabled() && continuity.commit(st, native).is_err() {
                if let Ok(mut fw) = st.firewall.lock() {
                    fw.mark_all_provenance_incomplete();
                }
            }
        }
    }

    reclaimed
}

/// Collector-side client helper to maintain an authenticated lease.
#[derive(Clone)]
pub struct CollectorLivenessClient {
    client: reqwest::Client,
    url: String,
    token: String,
    registry_sha256: String,
    session_id: String,
    instance_id: String,
    owner_token: Option<String>,
    epoch: Arc<tokio::sync::RwLock<Option<String>>>,
    lease_seq: Arc<std::sync::atomic::AtomicU64>,
    lease_seconds: Arc<std::sync::atomic::AtomicU64>,
    local_deadline: Arc<std::sync::RwLock<Option<Instant>>>,
    lease_failed: Arc<AtomicBool>,
}

impl CollectorLivenessClient {
    pub fn new(
        client: reqwest::Client,
        url: String,
        token: String,
        registry_sha256: String,
        session_id: String,
        instance_id: String,
        owner_token: Option<String>,
    ) -> Self {
        Self {
            client,
            url,
            token,
            registry_sha256,
            session_id,
            instance_id,
            owner_token,
            epoch: Arc::new(tokio::sync::RwLock::new(None)),
            lease_seq: Arc::new(std::sync::atomic::AtomicU64::new(1)),
            lease_seconds: Arc::new(std::sync::atomic::AtomicU64::new(DEFAULT_LEASE_SECONDS)),
            local_deadline: Arc::new(std::sync::RwLock::new(None)),
            lease_failed: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_uncertain(&self) -> bool {
        if self.lease_failed.load(Ordering::Acquire) {
            return true;
        }
        if let Ok(guard) = self.local_deadline.read() {
            if let Some(deadline) = *guard {
                if Instant::now() >= deadline {
                    self.lease_failed.store(true, Ordering::Release);
                    return true;
                }
            }
        }
        false
    }

    pub fn mark_failed(&self) {
        self.lease_failed.store(true, Ordering::Release);
    }

    pub async fn enroll(&self, requested_lease_seconds: Option<u64>) -> anyhow::Result<u64> {
        let body = json!({
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": self.registry_sha256,
            "session_id": self.session_id,
            "instance_id": self.instance_id,
            "action": "enroll",
            "owner_token": self.owner_token,
            "lease_seconds": requested_lease_seconds,
        });

        let request_start = Instant::now();
        let response = self
            .client
            .post(&self.url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            self.mark_failed();
            anyhow::bail!("liveness enrollment refused: {error}");
        }

        let resp: Value = response.json().await?;
        let epoch = resp["epoch"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("liveness enroll reply missing epoch"))?
            .to_string();
        let granted_secs = resp["lease_seconds"]
            .as_u64()
            .unwrap_or(DEFAULT_LEASE_SECONDS);
        let seq = resp["lease_seq"].as_u64().unwrap_or(1);

        *self.epoch.write().await = Some(epoch);
        self.lease_seconds.store(granted_secs, Ordering::Release);
        self.lease_seq.store(seq, Ordering::Release);
        if let Ok(mut dl) = self.local_deadline.write() {
            *dl = Some(request_start + Duration::from_secs(granted_secs));
        }
        Ok(granted_secs)
    }

    pub async fn renew(&self) -> anyhow::Result<()> {
        if self.is_uncertain() {
            anyhow::bail!("liveness lease already uncertain");
        }

        let epoch = self.epoch.read().await.clone();
        let Some(epoch) = epoch else {
            anyhow::bail!("not enrolled in liveness");
        };

        let next_seq = self.lease_seq.fetch_add(1, Ordering::SeqCst) + 1;
        let body = json!({
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": self.registry_sha256,
            "session_id": self.session_id,
            "instance_id": self.instance_id,
            "action": "renew",
            "owner_token": self.owner_token,
            "epoch": epoch,
            "lease_seq": next_seq,
        });

        let request_start = Instant::now();
        let response = self
            .client
            .post(&self.url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?;

        if !response.status().is_success() {
            let error = response.text().await.unwrap_or_default();
            self.mark_failed();
            anyhow::bail!("liveness renewal refused: {error}");
        }

        let resp: Value = response.json().await?;
        if let Some(returned_seq) = resp["lease_seq"].as_u64() {
            self.lease_seq.store(returned_seq, Ordering::Release);
        }
        let secs = self.lease_seconds.load(Ordering::Acquire);
        if let Ok(mut dl) = self.local_deadline.write() {
            *dl = Some(request_start + Duration::from_secs(secs));
        }
        Ok(())
    }

    pub async fn admission_identity(&self) -> anyhow::Result<String> {
        anyhow::ensure!(!self.is_uncertain(), "native_liveness_uncertain");
        let epoch = self
            .epoch
            .read()
            .await
            .clone()
            .ok_or_else(|| anyhow::anyhow!("native_liveness_not_enrolled"))?;
        let owner_token = self
            .owner_token
            .clone()
            .ok_or_else(|| anyhow::anyhow!("native_liveness_owner_token_required"))?;
        anyhow::ensure!(!self.is_uncertain(), "native_liveness_uncertain");
        Ok(serde_json::to_string(&CollectorIdentity {
            contract_version: LIVENESS_CONTRACT.into(),
            instance_id: self.instance_id.clone(),
            epoch,
            owner_token,
        })?)
    }

    pub async fn retire(&self) -> anyhow::Result<()> {
        // Latch uncertainty before any await, including bootstrap cleanup.
        self.mark_failed();
        let cached_epoch = self.epoch.read().await.clone();
        let epoch = match cached_epoch {
            Some(epoch) => epoch,
            None => {
                let response = self
                    .client
                    .post(&self.url)
                    .bearer_auth(&self.token)
                    .json(&json!({
                        "contract_version": LIVENESS_CONTRACT,
                        "registry_sha256": self.registry_sha256,
                        "session_id": self.session_id,
                        "instance_id": self.instance_id,
                        "action": "status",
                        "owner_token": self.owner_token,
                    }))
                    .send()
                    .await?
                    .error_for_status()?;
                let reply: Value = response.json().await?;
                anyhow::ensure!(
                    reply["contract_version"] == LIVENESS_CONTRACT
                        && reply["action"] == "status"
                        && reply["instance_id"] == self.instance_id
                        && reply["session_id"] == self.session_id,
                    "liveness bootstrap identity mismatch"
                );
                reply["epoch"]
                    .as_str()
                    .filter(|epoch| identifier(epoch))
                    .ok_or_else(|| anyhow::anyhow!("liveness bootstrap epoch unavailable"))?
                    .to_string()
            }
        };

        let body = json!({
            "contract_version": LIVENESS_CONTRACT,
            "registry_sha256": self.registry_sha256,
            "session_id": self.session_id,
            "instance_id": self.instance_id,
            "action": "retire",
            "owner_token": self.owner_token,
            "epoch": epoch,
        });

        self.client
            .post(&self.url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub fn spawn_renewal_task(
        self: Arc<Self>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let lease_secs = self.lease_seconds.load(Ordering::Acquire);
            let renew_interval = Duration::from_millis((lease_secs * 1000) / 3);

            while !*shutdown.borrow() && !self.is_uncertain() {
                tokio::select! {
                    _ = shutdown.changed() => {
                        break;
                    }
                    _ = tokio::time::sleep(renew_interval) => {
                        if self.is_uncertain() {
                            break;
                        }
                        let mut attempts = 0;
                        let mut success = false;
                        while attempts < COLLECTOR_RETRY_BUDGET {
                            if self.is_uncertain() {
                                break;
                            }
                            match self.renew().await {
                                Ok(()) => {
                                    success = true;
                                    break;
                                }
                                Err(_) => {
                                    attempts += 1;
                                    let backoff = Duration::from_millis(50.min((lease_secs * 1000) / 10));
                                    tokio::time::sleep(backoff).await;
                                }
                            }
                        }
                        if !success {
                            self.mark_failed();
                            break;
                        }
                    }
                }
            }
        })
    }
}
