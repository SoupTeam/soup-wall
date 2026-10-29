// SPDX-License-Identifier: Apache-2.0
//! Read-only bounded diagnosis of one explicitly selected edit run. Descriptive
//! local records never become execution attestations or reusable authority.
use clap::Args as ClapArgs;
use serde::Serialize;
use std::path::PathBuf;

#[derive(ClapArgs, Debug, Clone)]
pub(crate) struct Args {
    #[arg(long)]
    pub run: PathBuf,
    /// Emit the bounded, content-free versioned report.
    #[arg(long)]
    pub json: bool,
    /// Observe only exact declared output children; never infer their author.
    #[arg(long)]
    pub check_output: bool,
    /// Explicit new private destination for the existing sanitized support export.
    #[arg(long)]
    pub support_bundle: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Identity {
    pub run_sha256: String,
    pub context_sha256: String,
    pub profile_sha256: String,
    pub registry_sha256: String,
    pub source_commit: String,
    pub source_tree: String,
    pub component_sha256: String,
    pub agent_sha256: String,
    pub claude_sha256: String,
    pub policy_sha256: String,
    pub config_sha256: String,
    pub host_session_sha256: String,
    pub instance_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Call {
    pub target_index: usize,
    pub operation: &'static str,
    pub session_sha256: String,
    pub call_sha256: Option<String>,
    pub binding_sha256: Option<String>,
    pub admission: &'static str,
    pub publication_gate: &'static str,
    pub commit: &'static str,
    pub result_release: &'static str,
    pub host_delivery: &'static str,
    pub model_consumption: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Audit {
    pub provenance: &'static str,
    pub completeness: &'static str,
    pub reason_code: &'static str,
    pub file_sha256: Option<String>,
    pub records: usize,
    pub ask_requests: usize,
    pub calls: Vec<Call>,
}
impl Default for Audit {
    fn default() -> Self {
        Self {
            provenance: "retained_local_records_not_runtime_attestation",
            completeness: "incomplete",
            reason_code: "audit_not_observed",
            file_sha256: None,
            records: 0,
            ask_requests: 0,
            calls: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Request {
    pub target_index: usize,
    pub operation: &'static str,
    pub state: &'static str,
    pub binding_sha256: String,
    pub args_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Output {
    pub target_index: usize,
    pub operation: &'static str,
    pub observation: &'static str,
    pub sha256: Option<String>,
    pub bytes: Option<u64>,
    pub matches_prepared_baseline: Option<bool>,
    pub attribution: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct Report {
    pub schema: &'static str,
    pub observed_at_ms: u64,
    pub status: &'static str,
    pub reason_code: &'static str,
    pub provenance: &'static str,
    pub identity: Option<Identity>,
    pub recorded_host_outcome: &'static str,
    pub owner_process: &'static str,
    pub host_process: &'static str,
    pub authenticated_daemon: &'static str,
    pub requests: Vec<Request>,
    pub audit: Audit,
    pub outputs: Vec<Output>,
    pub effects: &'static str,
    pub host_delivery: &'static str,
    pub model_consumption: &'static str,
    pub next_steps: Vec<&'static str>,
}
impl Report {
    fn unknown() -> Self {
        Self {
            schema: "sw-installed-edit-status/1",
            observed_at_ms: crate::protection_status::now_ms(),
            status: "unknown",
            reason_code: "selected_state_unavailable_or_unsafe",
            provenance: "local_records_are_not_authenticated_runtime_attestation",
            identity: None,
            recorded_host_outcome: "unknown",
            owner_process: "unknown",
            host_process: "unknown",
            authenticated_daemon: "not_queried",
            requests: vec![],
            audit: Audit::default(),
            outputs: vec![],
            effects: "indeterminate",
            host_delivery: "unknown",
            model_consumption: "unknown",
            next_steps: vec![
                "Inspect the intended target independently before deciding whether another edit is needed.",
                "Prepare a fresh exact plan and obtain new exact authority for any new mutation; do not replay old approvals or spent receipts.",
                "Cancellation and withheld or absent results do not roll back previously committed bytes.",
            ],
        }
    }
}

pub(crate) fn inspect(args: &Args) -> Report {
    #[cfg(target_os = "linux")]
    {
        let mut report = Report::unknown();
        if let Err(code) = linux::inspect(args, &mut report) {
            // A changed/unsafe binding invalidates all earlier observations,
            // including an authenticated reply selected through that binding.
            report = Report::unknown();
            report.reason_code = code;
        }
        report
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        let mut report = Report::unknown();
        report.status = "unsupported";
        report.reason_code = "installed_edit_diagnosis_requires_native_linux_x86_64";
        report
    }
}

pub(crate) fn text(report: &Report) -> String {
    let mut text = format!(
        "Edit-session diagnosis: {} ({})\nLocal host record: {}. Authenticated daemon: {}.\nEffects: {}; host delivery: {}; model consumption: {}.\nAudit: {} ({}). Local records are not runtime attestations.\n",
        report.status, report.reason_code, report.recorded_host_outcome,
        report.authenticated_daemon, report.effects, report.host_delivery,
        report.model_consumption, report.audit.completeness, report.audit.reason_code,
    );
    for call in &report.audit.calls {
        text.push_str(&format!(
            "Target {} {}: admission {}; publication gate {}; commit {}; result release {}; delivery unknown.\n",
            call.target_index, call.operation, call.admission, call.publication_gate, call.commit, call.result_release,
        ));
    }
    for request in &report.requests {
        text.push_str(&format!(
            "Target {} {} Ask: {}.\n",
            request.target_index, request.operation, request.state
        ));
    }
    for output in &report.outputs {
        text.push_str(&format!(
            "Target {} {} output: {}; authorship unknown.\n",
            output.target_index, output.operation, output.observation
        ));
    }
    for step in &report.next_steps {
        text.push_str(step);
        text.push('\n');
    }
    text
}

#[cfg(target_os = "linux")]
mod audit;
#[cfg(target_os = "linux")]
mod io;
#[cfg(target_os = "linux")]
mod linux;
