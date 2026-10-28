// SPDX-License-Identifier: Apache-2.0
//! Daemon-owned original-runtime custody. Wire metadata is descriptive only.
//! The affine result below has no Deserialize/Clone or public constructor.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::handlers::Shared;
use crate::mcp::admission::{AdmissionCfg, InvocationClassifier};
use crate::mcp::server_profile::ProfileConfig;
use crate::mcp::verified_closure::Runtime;

mod formatter;
pub mod transport;

pub const FORMAT: &str = "sw-mcp/verified-original-execution/1";
pub const ENDPOINT: &str = "/native/execution/v1";
const CATALOGUE_FORMAT: &str = "sw-mcp/original-execution-catalogue/1";

/// Only static identifiers can cross the diagnostic boundary. In particular,
/// an HTTP error chain can contain credentials or upstream-controlled text.
fn failure_code(error: &anyhow::Error) -> &'static str {
    const CODES: &[&str] = &[
        "mcp_owner_launch_invalid",
        "mcp_owner_sealed_closure_invalid",
        "mcp_owner_budget_adoption_unverified",
        "mcp_owner_budget_transfer_failed",
        "mcp_owner_cleanup_unverified",
        "mcp_owner_control_closed",
        "mcp_owner_control_failed",
        "mcp_owner_control_invalid",
        "mcp_owner_descriptor_invalid",
        "mcp_owner_namespace_identity_invalid",
        "mcp_owner_original_spawn_failed",
        "mcp_owner_parent_lost",
        "mcp_owner_liveness_unverified",
        "mcp_owner_lost",
        "mcp_owner_launch_unavailable",
        "mcp_owner_parent_identity_invalid",
        "mcp_owner_process_identity_invalid",
        "mcp_owner_sandbox_spawn_failed",
        "mcp_owner_spawn_failed",
        "mcp_owner_startup_failed",
        "mcp_owner_startup_identity_invalid",
        "mcp_budget_mount_observation_failed",
        "mcp_budget_hugetlb_mount_unsupported",
        "mcp_budget_delegation_unavailable",
        "pilot_budget_selection_changed",
        "pilot_budget_binding_invalid",
        "native_child_authority_invalid",
        "native_child_authority_expired",
        "native_child_authority_escalation",
        "native_mcp_terminated",
        "verified_execution_process_unverified",
        "verified_execution_profile_changed",
        "verified_execution_withdrawn",
    ];
    for cause in error.chain() {
        let message = cause.to_string();
        if let Some(code) = CODES.iter().find(|code| message == **code) {
            return code;
        }
    }
    "verified_execution_session_failed"
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub catalogue_path: PathBuf,
    pub catalogue_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Baseline {
    script: PathBuf,
    script_sha256: String,
    python: PathBuf,
    python_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Budget {
    binding: PathBuf,
    budget_sha256: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalogue {
    format: String,
    server_id: String,
    profile: ProfileConfig,
    classifier: Baseline,
    #[serde(default)]
    approval_wait_seconds: u64,
    #[serde(default)]
    budget: Option<Budget>,
}

pub(crate) struct Service {
    catalogue: Catalogue,
    digest: String,
    runtime: Arc<Runtime>,
    classifier: Arc<dyn InvocationClassifier>,
    slots: Arc<tokio::sync::Semaphore>,
    hosts: Mutex<BTreeSet<String>>,
}

fn operator_bytes(path: &Path, cap: u64) -> anyhow::Result<Vec<u8>> {
    ensure!(
        path.is_absolute(),
        "verified_execution_operator_path_required"
    );
    for part in path.ancestors() {
        let info = std::fs::symlink_metadata(part)?;
        ensure!(
            !info.file_type().is_symlink(),
            "verified_execution_operator_path_linked"
        );
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let info = file.metadata()?;
    ensure!(
        info.is_file() && info.len() <= cap,
        "verified_execution_operator_file_invalid"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            info.uid() == unsafe { libc::geteuid() } && info.mode() & 0o022 == 0,
            "verified_execution_operator_file_unowned"
        );
    }
    let mut bytes = Vec::new();
    file.take(cap + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= cap,
        "verified_execution_operator_file_over_cap"
    );
    Ok(bytes)
}

impl Service {
    pub(crate) fn load(config: &Config) -> anyhow::Result<Arc<Self>> {
        ensure!(
            super::is_digest(&config.catalogue_sha256),
            "verified_execution_catalogue_digest_invalid"
        );
        let bytes = operator_bytes(&config.catalogue_path, 131072)?;
        ensure!(
            super::hash(&bytes) == config.catalogue_sha256,
            "verified_execution_catalogue_changed"
        );
        let crate::mcp::admission::Strict(value) = serde_json::from_slice(&bytes)?;
        let catalogue: Catalogue = serde_json::from_value(value)?;
        ensure!(
            catalogue.format == CATALOGUE_FORMAT
                && catalogue.server_id == "filesystem"
                && catalogue.profile.format == crate::mcp::server_profile::FORMAT
                && catalogue.profile.workspace_identity.is_some()
                && catalogue.approval_wait_seconds <= 300,
            "verified_execution_catalogue_unsupported"
        );
        ProfileConfig::read(&serde_json::to_vec(&catalogue.profile)?)?;
        let classifier = crate::mcp::admission::explicit_rule_baseline(
            &catalogue.classifier.script,
            &catalogue.classifier.script_sha256,
            &catalogue.classifier.python,
            &catalogue.classifier.python_sha256,
        )?;
        let runtime = Arc::new(Runtime::capture(&catalogue.profile)?);
        Ok(Arc::new(Self {
            catalogue,
            digest: config.catalogue_sha256.clone(),
            runtime,
            classifier,
            slots: Arc::new(tokio::sync::Semaphore::new(4)),
            hosts: Mutex::new(BTreeSet::new()),
        }))
    }

    pub(crate) fn metadata(&self) -> Value {
        json!({"contract":FORMAT,"catalogue_sha256":self.digest,"runtime":self.runtime.metadata(),
            "connection_limit":4,"available_slots":self.slots.available_permits(),
            "retained_host_entries":self.hosts.lock().ok().map(|hosts|hosts.len())})
    }

    fn admission(
        &self,
        st: &Shared,
        host: String,
        authority: String,
    ) -> anyhow::Result<AdmissionCfg> {
        let native = st
            .native
            .as_ref()
            .context("verified_execution_native_disabled")?;
        let lease = st
            .config
            .native
            .as_ref()
            .and_then(|c| c.liveness.as_ref())
            .context("verified_execution_liveness_required")?;
        ensure!(
            self.catalogue.approval_wait_seconds == 0 || native.approval.is_some(),
            "verified_execution_approval_unavailable"
        );
        Ok(AdmissionCfg {
            host_session: Some(host),
            child_authority: Some(authority),
            daemon_url: st.config.endpoint_url("/native/v1"),
            manifest_url: st.config.endpoint_url("/mcp"),
            manifest_token: st.token.clone(),
            server_id: self.catalogue.server_id.clone(),
            native: native.collector_view(),
            command: self
                .catalogue
                .profile
                .runtime_path
                .to_str()
                .context("verified_execution_path_invalid")?
                .into(),
            args: vec![
                self.catalogue
                    .profile
                    .package_root
                    .join(crate::mcp::server_profile::SERVER_ENTRYPOINT)
                    .to_str()
                    .context("verified_execution_path_invalid")?
                    .into(),
                "/workspace".into(),
            ],
            classifier: Some(self.classifier.clone()),
            resource_profiles: Default::default(),
            approval: (self.catalogue.approval_wait_seconds > 0).then(|| {
                crate::mcp::admission::ApprovalWait {
                    url: st.config.endpoint_url("/native/approval/v1"),
                    wait: std::time::Duration::from_secs(self.catalogue.approval_wait_seconds),
                }
            }),
            liveness_url: Some(st.config.endpoint_url("/native/liveness/v1")),
            liveness_lease_seconds: Some(lease.default_lease_seconds),
        })
    }
}

struct Process {
    identity: Value,
    failed: Arc<AtomicBool>,
    #[cfg(target_os = "linux")]
    live: Option<crate::mcp::linux_owner::ExecutionLiveness>,
}

pub(crate) struct SessionContext {
    daemon: Shared,
    runtime: Arc<Runtime>,
    catalogue: String,
    host: String,
    channel: String,
    pub(crate) withdrawn: Arc<AtomicBool>,
    process: OnceLock<Process>,
    stage: AtomicU8,
}

impl SessionContext {
    pub(crate) fn runtime(&self) -> &Arc<Runtime> {
        &self.runtime
    }
    pub(crate) fn bind(&self, owner: &crate::mcp::linux_owner::OwnerGuard) -> anyhow::Result<()> {
        owner.check()?;
        let identity = owner.metadata();
        ensure!(
            identity.get("original").is_some_and(Value::is_object),
            "verified_execution_process_unverified"
        );
        self.process
            .set(Process {
                identity,
                failed: owner.failed(),
                #[cfg(target_os = "linux")]
                live: Some(owner.execution_liveness()?),
            })
            .map_err(|_| anyhow::anyhow!("verified_execution_process_replaced"))?;
        self.stage.store(2, Ordering::Release);
        Ok(())
    }

    pub(crate) fn preparing(&self) {
        self.stage.store(1, Ordering::Release);
    }
    pub(crate) fn cleaned(&self) {
        self.stage.store(3, Ordering::Release);
    }
    fn reusable(&self) -> bool {
        matches!(self.stage.load(Ordering::Acquire), 0 | 3)
    }

    pub(crate) fn dispatched(
        self: &Arc<Self>,
        session: &str,
        call_id: &str,
        binding: &str,
        raw: &[u8],
    ) -> anyhow::Result<Dispatch> {
        self.check()?;
        let native = self
            .daemon
            .native
            .as_ref()
            .context("verified_execution_native_disabled")?;
        let sessions = native
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("verified_execution_state_unavailable"))?;
        let session_state = sessions
            .entries
            .get(session)
            .context("verified_execution_session_unavailable")?;
        let now = native.monotonic_now();
        let now_ms = super::wall_time_ms().map_err(anyhow::Error::msg)? + native.test_time_offset();
        ensure!(
            !session_state.is_dead(now, now_ms, &sessions)
                && super::validate_lineage(&sessions, session_state, now_ms, now).is_ok()
                && session_state.host_session.as_deref() == Some(&self.host)
                && session_state.server_id.as_deref() == Some("filesystem"),
            "verified_execution_session_unavailable"
        );
        let call = session_state
            .calls
            .get(call_id)
            .context("verified_execution_call_unavailable")?;
        let crate::mcp::admission::Strict(request) = serde_json::from_slice(raw)?;
        ensure!(
            call.stage == super::Stage::Result
                && call.expires > now
                && call.binding_sha256 == binding
                && call.host_call_id.as_ref() == request.get("id")
                && request["method"] == "tools/call"
                && request["params"]["name"] == call.tool
                && super::args_hash(
                    &request["params"]
                        .get("arguments")
                        .cloned()
                        .unwrap_or_else(|| json!({}))
                ) == call.args_sha256,
            "verified_execution_dispatch_mismatch"
        );
        Ok(Dispatch {
            context: self.clone(),
            instance: native.instance_id.clone(),
            session: session.into(),
            epoch: session_state.epoch.clone(),
            call_id: call_id.into(),
            binding: binding.into(),
            request_sha256: super::hash(raw),
            host_id: call.host_call_id.clone().expect("checked host ID"),
            deadline: call.expires,
        })
    }

    pub(crate) fn check(&self) -> anyhow::Result<()> {
        let process = self
            .process
            .get()
            .context("verified_execution_process_unverified")?;
        #[cfg(target_os = "linux")]
        match &process.live {
            Some(live) => live.check()?,
            None => ensure!(cfg!(test), "verified_execution_process_unverified"),
        }
        ensure!(
            self.stage.load(Ordering::Acquire) == 2
                && !self.withdrawn.load(Ordering::Acquire)
                && !process.failed.load(Ordering::Acquire),
            "verified_execution_withdrawn"
        );
        Ok(())
    }
}

pub(crate) struct Dispatch {
    context: Arc<SessionContext>,
    instance: String,
    session: String,
    epoch: String,
    call_id: String,
    binding: String,
    request_sha256: String,
    host_id: Value,
    deadline: std::time::Instant,
}

/// Affine private channel result. A serialized copy cannot reconstruct this type.
pub(crate) struct OriginalResult {
    dispatch: Dispatch,
    result_sha256: String,
    result_bytes: usize,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GitObjectKind {
    Blob,
    Tree,
    Commit,
    Tag,
}

/// Descriptive extension shape for SOU-156. Only its separately reviewed
/// producer may attach this to private custody; no wire redemption exists.
#[derive(Clone, Debug, Serialize)]
pub struct GitObjectWitness {
    pub contract: &'static str,
    pub object_kind: GitObjectKind,
    pub object_id: String,
    pub snapshot_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct Metadata {
    pub contract: &'static str,
    pub daemon_instance_id: String,
    pub catalogue_sha256: String,
    pub closure_sha256: String,
    pub process_generation_sha256: String,
    pub channel_generation_sha256: String,
    pub session_epoch_sha256: String,
    pub native_call_id: String,
    pub invocation_sha256: String,
    pub original_result_sha256: String,
    pub original_result_bytes: usize,
    /// Reserved narrow producer extension: SOU-156 has no producer in this PR.
    pub domain_witness: Option<GitObjectWitness>,
    /// Diagnostic only; never an input to inspection or a release predicate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub formatter_shadow: Option<formatter::Attribution>,
}

impl Dispatch {
    pub(crate) fn response(self, bytes: &[u8]) -> anyhow::Result<OriginalResult> {
        self.context.check()?;
        let crate::mcp::admission::Strict(value) = serde_json::from_slice(bytes)?;
        ensure!(
            value.get("id") == Some(&self.host_id),
            "verified_execution_response_mismatch"
        );
        Ok(OriginalResult {
            dispatch: self,
            result_sha256: super::hash(bytes),
            result_bytes: bytes.len(),
        })
    }
}

impl OriginalResult {
    pub(crate) fn metadata(&self) -> Metadata {
        let d = &self.dispatch;
        let process = d.context.process.get().expect("private bound process");
        Metadata {
            contract: FORMAT,
            daemon_instance_id: d.instance.clone(),
            catalogue_sha256: d.context.catalogue.clone(),
            closure_sha256: d.context.runtime.digest().into(),
            process_generation_sha256: super::canonical_digest(&process.identity),
            channel_generation_sha256: super::hash(d.context.channel.as_bytes()),
            session_epoch_sha256: super::hash(d.epoch.as_bytes()),
            native_call_id: d.call_id.clone(),
            invocation_sha256: d.request_sha256.clone(),
            original_result_sha256: self.result_sha256.clone(),
            original_result_bytes: self.result_bytes,
            domain_witness: None,
            formatter_shadow: None,
        }
    }

    pub(super) fn consume(
        self,
        native: &super::NativeState,
        session: &super::Session,
        request: &super::Request,
        call: &super::Call,
        now: std::time::Instant,
    ) -> Result<Metadata, &'static str> {
        let d = &self.dispatch;
        d.context
            .check()
            .map_err(|_| "verified_execution_withdrawn")?;
        let content = request
            .content
            .as_deref()
            .ok_or("verified_execution_content_missing")?;
        let current_catalogue = native.execution.as_ref().is_some_and(|service| {
            service.digest == d.context.catalogue
                && Arc::ptr_eq(&service.runtime, &d.context.runtime)
        });
        let selected = native.registry.tools.iter().any(|tool| {
            request.tool.as_deref() == Some(tool.name.as_str())
                && tool.mcp_result_profile.as_deref() == Some(crate::mcp::server_profile::FORMAT)
        });
        if !current_catalogue
            || !selected
            || session.host_session.as_deref() != Some(d.context.host.as_str())
            || session.server_id.as_deref() != Some("filesystem")
            || request.event != "result"
            || request.delivery.as_deref() != Some("mcp_host")
            || d.instance != native.instance_id
            || d.session != request.session_id
            || d.epoch != session.epoch
            || request.call_id.as_deref() != Some(d.call_id.as_str())
            || d.binding != call.binding_sha256
            || call.stage != super::Stage::Result
            || d.deadline != call.expires
            || now >= d.deadline
            || call.host_call_id.as_ref() != Some(&d.host_id)
            || super::hash(content.as_bytes()) != self.result_sha256
            || content.len() != self.result_bytes
        {
            return Err("verified_execution_result_mismatch");
        }
        let mut metadata = self.metadata();
        if let Some(args) = request
            .args
            .as_ref()
            .filter(|args| super::args_hash(args) == call.args_sha256)
        {
            if call.tool == "read_multiple_files" {
                // Custody, selected profile, exact call and original result were
                // validated above. Serialized metadata never enters this path.
                metadata.formatter_shadow = formatter::derive(args, content);
            }
        }
        Ok(metadata)
    }

    pub(crate) async fn inspect(
        self,
        body: &Value,
        identity: reqwest::header::HeaderValue,
    ) -> anyhow::Result<(axum::http::StatusCode, Value)> {
        let daemon = self.dispatch.context.daemon.clone();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "authorization",
            format!(
                "Bearer {}",
                daemon
                    .native
                    .as_ref()
                    .context("verified_execution_native_disabled")?
                    .token
            )
            .parse()?,
        );
        headers.insert(super::liveness::COLLECTOR_IDENTITY_HEADER, identity);
        let (status, axum::Json(reply)) =
            super::handle_with_evidence(daemon, headers, body.to_string(), Some(self)).await;
        Ok((status, reply))
    }
}

#[cfg(test)]
mod tests;
