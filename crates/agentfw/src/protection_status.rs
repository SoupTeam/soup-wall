// SPDX-License-Identifier: Apache-2.0
//! Read-only runtime diagnostics. Transport observations are never execution proof.
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::handlers::Shared;
use crate::{lifecycle::ManagedHealth, Config};

pub const CONTRACT: &str = "sw-protection-status/1";
pub const ENDPOINT: &str = "/diagnostics/v1/protection";
pub const NONCE_HEADER: &str = "x-agentfw-status-nonce";
const LIMIT: usize = 32 * 1024;

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn digest(value: &impl Serialize) -> String {
    // All fields are structs/vectors; field order is part of this versioned format.
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(value).expect("diagnostic value serializes"))
    )
}

pub fn config_digest(config: &Config) -> String {
    digest(config)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identity {
    pub pid: u32,
    pub instance: String,
    pub started_at_ms: u64,
    pub binary_sha256: Option<String>,
    pub loaded_config_sha256: String,
    pub lifecycle: Option<ManagedHealth>,
}

/// Fixed-size transport observations, with no session IDs, arguments or content.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Activity {
    pub authenticated_requests: u64,
    pub last_seen_ms: Option<u64>,
}

pub struct Runtime {
    identity: Identity,
    activity: Mutex<[Activity; 3]>,
}

impl Runtime {
    pub fn new(config: &Config) -> Self {
        Self {
            identity: Identity {
                pid: std::process::id(),
                instance: crate::token::generate(),
                started_at_ms: now_ms(),
                binary_sha256: None,
                loaded_config_sha256: config_digest(config),
                lifecycle: None,
            },
            activity: Mutex::new(Default::default()),
        }
    }

    pub fn with_binary(mut self, digest: Option<String>) -> Self {
        self.identity.binary_sha256 = digest.filter(|s| is_digest(s));
        self
    }

    /// Reuse the existing managed identity; do not alter lifecycle transactions.
    pub fn with_lifecycle(mut self, identity: ManagedHealth) -> Self {
        self.identity.instance = identity.instance.clone();
        self.identity.binary_sha256 = Some(identity.binary_digest.clone());
        self.identity.lifecycle = Some(identity);
        self
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    Supported,
    Unsupported,
    Unknown,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Enforcing,
    Shadow,
    Unavailable,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyIdentity {
    pub digest_format: String,
    pub sha256: String,
    pub rule_count: usize,
    pub managed_revision: Option<String>,
    pub managed_sequence: Option<u64>,
    pub managed_source_sha256: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryIdentity {
    pub state: Evidence,
    pub id: Option<String>,
    pub sha256: Option<String>,
    pub tool_count: Option<usize>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathCoverage {
    pub path: String,
    pub capability: Evidence,
    pub configured: Option<bool>,
    pub execution_coverage: Evidence,
    pub reason: String,
    pub activity: Option<Activity>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub contract_version: String,
    pub nonce: String,
    pub captured_at_ms: u64,
    pub mode: Mode,
    pub runtime: Identity,
    pub policy: PolicyIdentity,
    pub registry: RegistryIdentity,
    pub paths: Vec<PathCoverage>,
}

fn safe_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
}
fn is_nonce(s: &str) -> bool {
    (16..=128).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
}
fn is_digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn path(
    id: &str,
    capability: Evidence,
    configured: Option<bool>,
    reason: &str,
    activity: Option<Activity>,
) -> PathCoverage {
    PathCoverage {
        path: id.into(),
        capability,
        configured,
        reason: reason.into(),
        activity,
        execution_coverage: Evidence::Unknown,
    }
}

fn snapshot(st: &Shared, rt: &Runtime, nonce: String) -> Result<Snapshot, &'static str> {
    // Activity is written only after handlers return and never holds the engine
    // lock. Native registry/config are immutable. The engine guard binds the live
    // operator policy and managed metadata to the same instant, including rollout.
    let activity = rt.activity.lock().map_err(|_| "activity_unavailable")?;
    let fw = st.firewall.lock().map_err(|_| "runtime_unavailable")?;
    let policy = fw.policy_for_diagnostics();
    let managed = fw.active_managed_policy();
    let registry = match &st.native {
        Some(n) if safe_id(&n.registry.registry_id) && is_digest(&n.registry_sha256) => {
            RegistryIdentity {
                state: Evidence::Supported,
                id: Some(n.registry.registry_id.clone()),
                sha256: Some(n.registry_sha256.clone()),
                tool_count: Some(n.registry.tools.len()),
            }
        }
        _ => RegistryIdentity {
            state: Evidence::Unknown,
            id: None,
            sha256: None,
            tool_count: None,
        },
    };
    let native_ready =
        registry.state == Evidence::Supported && st.config.enforce && !st.config.judge.enabled;
    let paths = vec![
        path(
            "legacy_http_hook",
            Evidence::Supported,
            None,
            "legacy_http_hook_fail_open",
            Some(activity[0].clone()),
        ),
        path(
            "mcp_manifest",
            Evidence::Supported,
            None,
            "manifest_check_only_not_execution",
            Some(activity[1].clone()),
        ),
        path(
            "native_admission",
            if native_ready {
                Evidence::Supported
            } else {
                Evidence::Unsupported
            },
            Some(st.native.is_some()),
            if native_ready {
                "trusted_collector_required"
            } else {
                "registry_enforce_and_no_judge_required"
            },
            Some(activity[2].clone()),
        ),
        path(
            "unbound_mcp_resource_executor",
            Evidence::Unsupported,
            None,
            "resource_executor_unsupported",
            None,
        ),
        path(
            "arbitrary_server_containment",
            Evidence::Unsupported,
            None,
            "no_arbitrary_server_containment",
            None,
        ),
        path(
            "model_consumption",
            Evidence::Unknown,
            None,
            "model_consumption_unverified",
            None,
        ),
        path(
            "bound_resource_executor",
            Evidence::Unknown,
            st.native
                .as_ref()
                .map(|n| n.registry.tools.iter().any(|t| t.resource_policy.is_some())),
            "executor_runtime_unverified",
            None,
        ),
    ];
    Ok(Snapshot {
        contract_version: CONTRACT.into(),
        nonce,
        captured_at_ms: now_ms(),
        mode: if st.config.enforce {
            Mode::Enforcing
        } else {
            Mode::Shadow
        },
        runtime: rt.identity.clone(),
        policy: PolicyIdentity {
            digest_format: "agent-policy-json/1".into(),
            sha256: digest(policy),
            rule_count: policy.agent_policies.len(),
            managed_revision: managed
                .as_ref()
                .and_then(|m| safe_id(&m.revision).then(|| m.revision.clone())),
            managed_sequence: managed.as_ref().map(|m| m.deployment_sequence),
            managed_source_sha256: managed
                .as_ref()
                .and_then(|m| is_digest(&m.policy_sha256).then(|| m.policy_sha256.clone())),
        },
        registry,
        paths,
    })
}

pub async fn handler(
    State(st): State<Shared>,
    Extension(rt): Extension<Arc<Runtime>>,
    headers: HeaderMap,
) -> Response {
    let auth = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let result = if !crate::token::verify(&st.token, auth) {
        Err((StatusCode::UNAUTHORIZED, "status_unauthorized"))
    } else {
        match headers.get(NONCE_HEADER).and_then(|h| h.to_str().ok()) {
            Some(nonce) if is_nonce(nonce) => snapshot(&st, &rt, nonce.into())
                .map_err(|code| (StatusCode::SERVICE_UNAVAILABLE, code)),
            _ => Err((StatusCode::BAD_REQUEST, "status_nonce_required")),
        }
    };
    let mut response = match result {
        Ok(value) => Json(value).into_response(),
        Err((status, code)) => (status, Json(serde_json::json!({"contract_version":CONTRACT,"mode":"unavailable","error_code":code}))).into_response(),
    };
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
}

/// Observe authenticated HTTP contact only. Never inspect/store bodies or infer
/// execution from 200, which may mean fail-open/no-op on legacy hooks.
pub async fn observe(
    State((st, rt)): State<(Shared, Arc<Runtime>)>,
    req: Request,
    next: Next,
) -> Response {
    let (index, token) = match req.uri().path() {
        "/hook" => (Some(0), Some(st.token.as_str())),
        "/mcp" => (Some(1), Some(st.token.as_str())),
        "/native/v1" => (Some(2), st.native.as_ref().map(|n| n.token.as_str())),
        _ => (None, None),
    };
    let auth = req
        .headers()
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let authenticated = token.is_some_and(|t| crate::token::verify(t, auth));
    let response = next.run(req).await;
    if let Some(index) = index.filter(|_| authenticated) {
        if let Ok(mut observations) = rt.activity.lock() {
            let sample = &mut observations[index];
            sample.authenticated_requests = sample.authenticated_requests.saturating_add(1);
            sample.last_seen_ms = Some(now_ms());
        }
    }
    response
}

#[derive(Default)]
pub struct Expectations {
    pub instance: Option<String>,
    pub policy_sha256: Option<String>,
    pub registry_sha256: Option<String>,
    pub config_sha256: Option<String>,
    pub binary_sha256: Option<String>,
}

/// Reject stale/mismatched replies before printing any remote strings.
pub fn validate(
    s: &Snapshot,
    nonce: &str,
    now: u64,
    expected: &Expectations,
) -> Result<(), &'static str> {
    if s.mode == Mode::Unavailable
        || s.contract_version != CONTRACT
        || s.nonce != nonce
        || !is_nonce(&s.runtime.instance)
        || s.runtime.pid == 0
        || s.runtime.started_at_ms > s.captured_at_ms
        || s.captured_at_ms > now.saturating_add(1000)
        || now.saturating_sub(s.captured_at_ms) > 10_000
        || s.policy.digest_format != "agent-policy-json/1"
        || !is_digest(&s.policy.sha256)
        || !is_digest(&s.runtime.loaded_config_sha256)
        || s.runtime
            .binary_sha256
            .as_deref()
            .is_some_and(|d| !is_digest(d))
        || s.policy
            .managed_revision
            .as_deref()
            .is_some_and(|id| !safe_id(id))
        || s.policy
            .managed_source_sha256
            .as_deref()
            .is_some_and(|d| !is_digest(d))
    {
        return Err("status_invalid_or_stale");
    }
    for (wanted, actual) in [
        (
            expected.instance.as_deref(),
            Some(s.runtime.instance.as_str()),
        ),
        (
            expected.policy_sha256.as_deref(),
            Some(s.policy.sha256.as_str()),
        ),
        (
            expected.registry_sha256.as_deref(),
            s.registry.sha256.as_deref(),
        ),
        (
            expected.config_sha256.as_deref(),
            Some(s.runtime.loaded_config_sha256.as_str()),
        ),
        (
            expected.binary_sha256.as_deref(),
            s.runtime.binary_sha256.as_deref(),
        ),
    ] {
        if wanted.is_some() && wanted != actual {
            return Err("status_identity_mismatch");
        }
    }
    if let Some(life) = &s.runtime.lifecycle {
        if life.pid != s.runtime.pid
            || life.instance != s.runtime.instance
            || Some(life.binary_digest.as_str()) != s.runtime.binary_sha256.as_deref()
            || !is_digest(&life.config_digest)
        {
            return Err("status_identity_mismatch");
        }
    }
    match s.registry.state {
        Evidence::Supported
            if s.registry.id.as_deref().is_some_and(safe_id)
                && s.registry.sha256.as_deref().is_some_and(is_digest)
                && s.registry
                    .tool_count
                    .is_some_and(|n| (1..=256).contains(&n)) => {}
        Evidence::Unknown
            if s.registry.id.is_none()
                && s.registry.sha256.is_none()
                && s.registry.tool_count.is_none() => {}
        _ => return Err("status_invalid_registry"),
    }
    let ids = [
        "legacy_http_hook",
        "mcp_manifest",
        "native_admission",
        "unbound_mcp_resource_executor",
        "arbitrary_server_containment",
        "model_consumption",
        "bound_resource_executor",
    ];
    let reasons = [
        "legacy_http_hook_fail_open",
        "manifest_check_only_not_execution",
        "trusted_collector_required",
        "registry_enforce_and_no_judge_required",
        "resource_executor_unsupported",
        "no_arbitrary_server_containment",
        "model_consumption_unverified",
        "executor_runtime_unverified",
    ];
    if s.paths.len() != ids.len()
        || s.paths.iter().zip(ids).any(|(p, id)| {
            p.path != id
                || !reasons.contains(&p.reason.as_str())
                || p.execution_coverage != Evidence::Unknown
                || p.activity
                    .as_ref()
                    .is_some_and(|a| a.last_seen_ms.is_some_and(|t| t > s.captured_at_ms))
        })
    {
        return Err("status_invalid_coverage");
    }
    let p = &s.paths;
    if p[0].capability != Evidence::Supported
        || p[0].reason != "legacy_http_hook_fail_open"
        || p[1].capability != Evidence::Supported
        || p[1].reason != "manifest_check_only_not_execution"
        || p[3].capability != Evidence::Unsupported
        || p[3].reason != "resource_executor_unsupported"
        || p[4].capability != Evidence::Unsupported
        || p[4].reason != "no_arbitrary_server_containment"
        || p[5].capability != Evidence::Unknown
        || p[5].reason != "model_consumption_unverified"
        || p[6].capability != Evidence::Unknown
        || p[6].reason != "executor_runtime_unverified"
        || p.iter().enumerate().any(|(i, p)| {
            (i != 2 && i != 6 && p.configured.is_some())
                || (i < 3) != p.activity.is_some()
                || p.activity
                    .as_ref()
                    .is_some_and(|a| (a.authenticated_requests == 0) != a.last_seen_ms.is_none())
        })
    {
        return Err("status_invalid_coverage");
    }
    match p[2].capability {
        Evidence::Supported
            if s.mode == Mode::Enforcing
                && s.registry.state == Evidence::Supported
                && p[2].configured == Some(true)
                && p[2].reason == "trusted_collector_required" => {}
        Evidence::Unsupported
            if p[2].configured.is_some()
                && p[2].reason == "registry_enforce_and_no_judge_required" => {}
        _ => return Err("status_invalid_coverage"),
    }
    Ok(())
}

/// Bounded authenticated loopback query, no redirects/proxies or raw error bodies.
pub async fn query(
    config: &Config,
    token: &str,
    expected: &Expectations,
    timeout: Duration,
) -> Result<Snapshot, &'static str> {
    config.validate().map_err(|_| "status_invalid_config")?;
    let nonce = crate::token::generate();
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
        .map_err(|_| "status_client_unavailable")?;
    let response = client
        .get(config.endpoint_url(ENDPOINT))
        .bearer_auth(token)
        .header(NONCE_HEADER, &nonce)
        .send()
        .await
        .map_err(|_| "status_unavailable")?;
    if response.status() != StatusCode::OK {
        return Err("status_query_rejected");
    }
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| "status_unavailable")?;
        if bytes.len().saturating_add(chunk.len()) > LIMIT {
            return Err("status_response_over_cap");
        }
        bytes.extend_from_slice(&chunk);
    }
    let value: Snapshot = serde_json::from_slice(&bytes).map_err(|_| "status_invalid_response")?;
    validate(&value, &nonce, now_ms(), expected)?;
    Ok(value)
}

#[derive(clap::Args)]
pub struct QueryArgs {
    #[arg(long)]
    pub home: Option<std::path::PathBuf>,
    /// Exit 0 for a validated query only; does not assert protection coverage.
    #[arg(long)]
    pub query_only: bool,
    #[arg(long)]
    pub require_enforce: bool,
    #[arg(long)]
    pub expect_instance: Option<String>,
    #[arg(long)]
    pub expect_policy_sha256: Option<String>,
    #[arg(long)]
    pub expect_registry_sha256: Option<String>,
    #[arg(long)]
    pub expect_binary_sha256: Option<String>,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..=5))]
    pub timeout_seconds: u64,
}

fn read_limited(path: &std::path::Path, limit: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(std::io::Error::other(
            "status input must be a bounded regular file",
        ));
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // A regular path can be replaced by a FIFO after the metadata check.
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(std::io::Error::other(
            "status input must be a bounded regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other("status input over cap"));
    }
    Ok(bytes)
}

fn cli_query(args: &QueryArgs) -> Result<Snapshot, &'static str> {
    let home = args
        .home
        .clone()
        .map(Ok)
        .unwrap_or_else(Config::home_path)
        .map_err(|_| "status_home_unavailable")?;
    let config = match read_limited(&home.join("config.yaml"), 1024 * 1024) {
        Ok(bytes) => {
            Config::from_yaml(std::str::from_utf8(&bytes).map_err(|_| "status_invalid_config")?)
                .map_err(|_| "status_invalid_config")?
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Config::default(),
        Err(_) => return Err("status_config_unavailable"),
    };
    // Strictly read-only: do not call load_or_create, chmod, create dirs, or touch lifecycle locks.
    let token = read_limited(&home.join("token"), 4096).map_err(|_| "status_token_unavailable")?;
    let token = std::str::from_utf8(&token)
        .map_err(|_| "status_token_unavailable")?
        .trim();
    if token.is_empty() {
        return Err("status_token_unavailable");
    }
    let expected = Expectations {
        instance: args.expect_instance.clone(),
        policy_sha256: args.expect_policy_sha256.clone(),
        registry_sha256: args.expect_registry_sha256.clone(),
        binary_sha256: args.expect_binary_sha256.clone(),
        config_sha256: Some(config_digest(&config)),
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| "status_client_unavailable")?;
    runtime.block_on(query(
        &config,
        token,
        &expected,
        Duration::from_secs(args.timeout_seconds),
    ))
}

pub fn run_cli(args: QueryArgs) -> i32 {
    match cli_query(&args) {
        Ok(value) => {
            let wrong_mode = args.require_enforce && value.mode != Mode::Enforcing;
            println!(
                "{}",
                serde_json::json!({"query":"answered", "query_only":args.query_only,
                "protection":"unknown", "snapshot":value})
            );
            // Ordinary queries never convert unknown end-to-end coverage to success.
            if args.query_only && !wrong_mode {
                0
            } else {
                2
            }
        }
        Err(code) => {
            println!(
                "{}",
                serde_json::json!({"contract_version":CONTRACT,"mode":"unavailable", "protection":"unknown", "error_code":code})
            );
            1
        }
    }
}
