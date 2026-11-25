// SPDX-License-Identifier: Apache-2.0
use super::{
    audit,
    io::{Budget, Directory, Result},
    Args, Identity, Output, Report, Request,
};
use crate::edit_session::{
    profile::{self, Profile},
    quota::{Limits, RetainedQuota},
    record::{self, Context, ProcessIdentity},
    FORMAT,
};
use serde::Deserialize;
use serde_json::Value;
use std::{collections::BTreeSet, os::unix::fs::MetadataExt, path::PathBuf, time::Duration};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Run {
    format: String,
    run: PathBuf,
    home: PathBuf,
    profile_sha256: String,
    host_session: String,
    instance_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Cleanup {
    cleaned: bool,
    reaped: bool,
    exit_success: bool,
    graceful_observed: bool,
    ownership: String,
    failure: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Terminal {
    format: String,
    state: String,
    reason: String,
    run: PathBuf,
    profile_sha256: String,
    cleanup: Cleanup,
    daemon_clean: bool,
    mutation_dispatches: u64,
    effect_status: String,
    #[serde(default, deserialize_with = "retained_quota")]
    mutation_quota: Option<RetainedQuota>,
}
fn retained_quota<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<RetainedQuota>, D::Error> {
    // Missing is legacy-v1 compatibility; explicit null is not quota metadata.
    RetainedQuota::deserialize(d).map(Some)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    serde_json::from_value(audit::strict(bytes)?).map_err(|_| "selected_state_schema_invalid")
}
fn required(dir: &Directory, name: &str, cap: u64, budget: &mut Budget) -> Result<Vec<u8>> {
    dir.read(name, cap, budget)?
        .ok_or("diagnostic_binding_missing")
}
fn process(identity: &ProcessIdentity) -> &'static str {
    if record::process_identity(identity.pid).is_ok_and(|current| &current == identity) {
        "identity_matches_liveness_not_established"
    } else {
        "unavailable_or_changed"
    }
}
fn live_policy_digest(policy: &soup_wall_agent::AgentPolicySet) -> Result<String> {
    // agent-policy-json/1 hashes the declared struct serialization order. The
    // retained edit profile uses its separate canonical-object digest format;
    // those two valid identities must never be compared as if interchangeable.
    serde_json::to_vec(policy)
        .map(|bytes| audit::sha(&bytes))
        .map_err(|_| "retained_policy_invalid")
}
fn protection_failure(code: &'static str) -> &'static str {
    match code {
        "status_unavailable" | "status_client_unavailable" | "status_query_rejected" => {
            "unavailable"
        }
        // Producer-owned identity, freshness, shape and cap failures retain
        // mismatch/uncertainty, without exposing a remote body or raw error.
        _ => "invalid_or_mismatched",
    }
}
pub(in crate::edit_session) fn terminal(
    raw: &[u8],
    context: &Context,
    limits: Option<&Limits>,
) -> Result<&'static str> {
    let terminal: Terminal = decode(raw)?;
    // Validate retained local structure and the selected plan's exact ceilings.
    // These counters are never used as authenticated commit/delivery proof.
    let quota_uncertain = match (limits, terminal.mutation_quota.as_ref()) {
        (None, None) => false,
        (Some(expected), Some(RetainedQuota::Known(usage))) if &usage.limits == expected => {
            usage.indeterminate_publications != 0 || usage.pending_prepublication_attempts != 0
        }
        (Some(_), Some(RetainedQuota::Unavailable(_))) => true,
        _ => return Err("terminal_quota_profile_mismatch"),
    };
    if terminal.format != FORMAT || terminal.run != context.run || terminal.profile_sha256 != context.profile_sha256
        || terminal.mutation_dispatches != 0
        || terminal.effect_status != "consult-native-audit; interrupted-or-withheld-result-is-indeterminate; no-automatic-retry"
        || terminal.cleanup.ownership.is_empty() || terminal.cleanup.ownership.len() > 128
        || terminal.cleanup.failure.as_ref().is_some_and(|s| s.len() > 128) {
        return Err("terminal_binding_invalid_or_dispatch_observed");
    }
    // These fields are consumed only as private structure. Never render caller
    // supplied ownership/failure strings, even when all other fields agree.
    let _ = terminal.cleanup.graceful_observed;
    if terminal.state == "host_completed" && quota_uncertain {
        return Err("terminal_quota_completion_contradictory");
    }
    match (terminal.state.as_str(), terminal.reason.as_str()) {
        ("host_completed", "host_completed")
            if terminal.cleanup.cleaned
                && terminal.cleanup.reaped
                && terminal.cleanup.exit_success
                && terminal.daemon_clean =>
        {
            Ok("recorded_host_completed")
        }
        ("failed", "host_completed") if quota_uncertain => {
            Ok("recorded_indeterminate_mutation_quota")
        }
        ("failed", "host_completed")
            if terminal.cleanup.reaped && !terminal.cleanup.exit_success =>
        {
            Ok("recorded_unsuccessful_host_exit")
        }
        ("failed", "host_completed") => Ok("recorded_cleanup_or_stream_failure"),
        ("failed", "cancelled") => Ok("recorded_cancellation"),
        // Retained outcome only: not authenticated Stop/cleanup or rollback proof.
        ("failed", "operator_stop") => Ok("recorded_operator_stop"),
        ("failed", "invalid_stop_request") => Ok("recorded_invalid_stop_request"),
        ("failed", "deadline") => Ok("recorded_deadline"),
        ("failed", "daemon_lost") => Ok("recorded_daemon_loss"),
        ("failed", "host_stream_failure") => Ok("recorded_host_stream_failure"),
        ("failed", "provider_child_environment_unavailable") => {
            Ok("recorded_provider_environment_failure")
        }
        _ => Err("terminal_contradictory_or_unknown_outcome"),
    }
}

pub(in crate::edit_session) struct Selection {
    pub directory: Directory,
    pub context: Context,
    pub profile: Profile,
    pub run_bytes: Vec<u8>,
    pub context_bytes: Vec<u8>,
    pub profile_bytes: Vec<u8>,
}
pub(in crate::edit_session) fn select(
    run_path: &std::path::Path,
    budget: &mut Budget,
) -> Result<Selection> {
    let run_dir = Directory::open(run_path)?;
    let context_bytes = required(&run_dir, "diagnostic-context.json", 16 * 1024, budget)?;
    let context: Context = decode(&context_bytes)?;
    context
        .validate()
        .map_err(|_| "diagnostic_context_invalid")?;
    if context.run.as_path() != run_path
        || context.owner.uid != unsafe { libc::geteuid() }
        || context.started_at_ms > crate::protection_status::now_ms().saturating_add(5000)
    {
        return Err("diagnostic_context_foreign_or_future");
    }
    let run_bytes = required(&run_dir, "run.json", 16 * 1024, budget)?;
    let run: Run = decode(&run_bytes)?;
    if run.format != FORMAT
        || run.run != context.run
        || run.home != context.home
        || run.profile_sha256 != context.profile_sha256
        || run.host_session != context.host_session
        || run.instance_id != context.instance_id
    {
        return Err("run_context_binding_mismatch");
    }
    let profile_bytes = required(&run_dir, "profile.json", 128 * 1024, budget)?;
    let profile: Profile = decode(&profile_bytes)?;
    profile.validate().map_err(|_| "retained_profile_invalid")?;
    if profile::canonical(&profile).map_err(|_| "retained_profile_invalid")? != profile_bytes
        || audit::sha(&profile_bytes) != context.profile_sha256
        || required(&run_dir, "profile.sha256", 64, budget)? != context.profile_sha256.as_bytes()
    {
        return Err("retained_profile_digest_mismatch");
    }
    Ok(Selection {
        directory: run_dir,
        context,
        profile,
        run_bytes,
        context_bytes,
        profile_bytes,
    })
}

pub(super) fn inspect(args: &Args, report: &mut Report) -> Result<()> {
    if !cfg!(target_arch = "x86_64") {
        report.status = "unsupported";
        report.reason_code = "installed_edit_diagnosis_requires_native_linux_x86_64";
        return Ok(());
    }
    let mut budget = Budget::new();
    let Selection {
        directory: run_dir,
        context,
        profile,
        run_bytes,
        context_bytes,
        profile_bytes,
    } = select(&args.run, &mut budget)?;
    let home_name = context
        .home
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("run_context_binding_mismatch")?;
    let home = run_dir.child_dir(home_name)?;
    let registry = profile::digest(&profile.registry().map_err(|_| "retained_profile_invalid")?)
        .map_err(|_| "retained_profile_invalid")?;
    if audit::sha(&required(&home, "registry.json", 128 * 1024, &mut budget)?) != registry {
        return Err("retained_registry_digest_mismatch");
    }
    let policy_bytes = required(&home, "policy.yaml", 128 * 1024, &mut budget)?;
    let policy = soup_wall_agent::AgentPolicySet::from_yaml(
        std::str::from_utf8(&policy_bytes).map_err(|_| "retained_policy_invalid")?,
    )
    .map_err(|_| "retained_policy_invalid")?;
    if profile::digest(&policy).map_err(|_| "retained_policy_invalid")? != profile.policy_sha256 {
        return Err("retained_policy_digest_mismatch");
    }
    let live_policy_sha256 = live_policy_digest(&policy)?;
    report.identity = Some(Identity {
        run_sha256: audit::sha(&run_bytes),
        context_sha256: audit::sha(&context_bytes),
        profile_sha256: context.profile_sha256.clone(),
        registry_sha256: registry.clone(),
        source_commit: profile.component.source_commit.clone(),
        source_tree: profile.component.source_tree.clone(),
        component_sha256: profile.component.id.clone(),
        agent_sha256: profile.agent.sha256.clone(),
        claude_sha256: profile.claude.sha256.clone(),
        policy_sha256: profile.policy_sha256.clone(),
        config_sha256: context.config_sha256.clone(),
        host_session_sha256: audit::sha(context.host_session.as_bytes()),
        instance_sha256: audit::sha(context.instance_id.as_bytes()),
    });
    report.owner_process = process(&context.owner);
    if let Some(bytes) = run_dir.read("host-process.json", 4096, &mut budget)? {
        let host: ProcessIdentity = decode(&bytes)?;
        host.validate()
            .map_err(|_| "recorded_host_identity_invalid")?;
        if host.uid != unsafe { libc::geteuid() } {
            return Err("recorded_host_foreign_owner");
        }
        report.host_process = process(&host);
    }
    let terminal_bytes = run_dir.read("terminal.json", 32 * 1024, &mut budget)?;
    report.recorded_host_outcome = match terminal_bytes.as_deref() {
        Some(raw) => terminal(raw, &context, profile.mutation_quota.as_ref())?,
        None => "terminal_not_recorded",
    };
    report.audit = match home.read("audit.jsonl", 1024 * 1024, &mut budget) {
        Ok(Some(bytes)) => audit::inspect(&bytes, &profile, &context, &registry),
        Ok(None) => super::Audit {
            reason_code: "audit_empty_or_missing",
            ..Default::default()
        },
        Err(reason) => super::Audit {
            reason_code: reason,
            ..Default::default()
        },
    };
    if args.check_output {
        report.outputs = outputs(&profile, &mut budget)?;
    }
    // Once the recorded owner identity is absent/reused, never send a retained
    // bearer credential to a port that an unrelated process may now occupy.
    if report.owner_process == "identity_matches_liveness_not_established"
        && terminal_bytes.is_none()
    {
        report.authenticated_daemon = query(
            &home,
            &profile,
            &context,
            &registry,
            &live_policy_sha256,
            &mut budget,
            &mut report.requests,
        );
    } else {
        report.authenticated_daemon = "unavailable";
    }
    // Re-read only the three selected immutable binding leaves. No discovery
    // walk, runtime validation, target read, token mutation or retry occurs.
    if required(&run_dir, "run.json", 16 * 1024, &mut budget)? != run_bytes
        || required(&run_dir, "diagnostic-context.json", 16 * 1024, &mut budget)? != context_bytes
        || required(&run_dir, "profile.json", 128 * 1024, &mut budget)? != profile_bytes
    {
        return Err("selected_binding_changed_during_diagnosis");
    }
    if report.audit.completeness == "incomplete" {
        report.status = "incomplete";
        report.reason_code = report.audit.reason_code;
    } else if report.authenticated_daemon == "stale_epoch" {
        report.status = "incomplete";
        report.reason_code = "selected_run_epoch_is_stale";
    } else if report.authenticated_daemon == "matching_current_epoch" {
        report.status = "live";
        report.reason_code = "authenticated_current_edit_run_not_execution_proof";
    } else if report.recorded_host_outcome == "recorded_host_completed" {
        report.status = "recorded_host_completed";
        report.reason_code = "host_completion_does_not_establish_edit_outcome";
    } else if terminal_bytes.is_some() {
        report.status = "recorded_host_interrupted";
        report.reason_code = "interrupted_effects_remain_indeterminate";
    } else {
        report.status = "incomplete";
        report.reason_code = "terminal_missing_interruption_or_unrecorded_outcome";
    }
    Ok(())
}

fn outputs(profile: &Profile, budget: &mut Budget) -> Result<Vec<Output>> {
    let directory = Directory::open(&profile.root)?;
    let meta = directory.metadata()?;
    if meta.dev() != profile.root_identity.device || meta.ino() != profile.root_identity.inode {
        return Err("current_output_root_identity_changed");
    }
    if meta.mode() & 0o7777 != 0o700 || meta.gid() != unsafe { libc::getegid() } {
        return Err("current_output_metadata_unsupported");
    }
    let mut result = vec![];
    for (index, target) in profile
        .targets
        .iter()
        .enumerate()
        .filter(|(_, t)| t.create || t.replacement.is_some())
    {
        let mut row = Output {
            target_index: index,
            operation: if target.create { "create" } else { "replace" },
            observation: "unavailable_or_unsafe",
            sha256: None,
            bytes: None,
            matches_prepared_baseline: None,
            attribution: "observed_postcondition_not_writer_or_commit_proof",
        };
        match directory.read_output(&target.name, 4096, budget) {
            Ok(Some((bytes, meta))) => {
                let digest = audit::sha(&bytes);
                row.observation = "present";
                row.bytes = Some(bytes.len() as u64);
                row.matches_prepared_baseline = target.replacement.as_ref().map(|baseline| {
                    baseline.sha256 == digest
                        && baseline.identity.device == meta.dev()
                        && baseline.identity.inode == meta.ino()
                        && baseline.identity.size == meta.len()
                        && baseline.identity.uid == meta.uid()
                        && baseline.identity.gid == meta.gid()
                        && baseline.identity.mode == meta.mode()
                        && baseline.identity.mtime_seconds == meta.mtime()
                        && baseline.identity.mtime_nanoseconds == meta.mtime_nsec()
                        && baseline.identity.ctime_seconds == meta.ctime()
                        && baseline.identity.ctime_nanoseconds == meta.ctime_nsec()
                });
                row.sha256 = Some(digest);
            }
            Ok(None) => row.observation = "absent",
            Err(_) => (),
        }
        result.push(row);
    }
    Ok(result)
}

fn query(
    home: &Directory,
    profile: &Profile,
    context: &Context,
    registry: &str,
    live_policy_sha256: &str,
    budget: &mut Budget,
    requests: &mut Vec<Request>,
) -> &'static str {
    fn selected(
        home: &Directory,
        context: &Context,
        budget: &mut Budget,
    ) -> Result<(crate::Config, String, String)> {
        let config = required(home, "config.yaml", 128 * 1024, budget)?;
        let config = crate::Config::from_yaml(
            std::str::from_utf8(&config).map_err(|_| "retained_config_invalid")?,
        )
        .map_err(|_| "retained_config_invalid")?;
        if !matches!(config.bind.as_str(), "127.0.0.1" | "::1")
            || config.policy.as_ref() != Some(&context.home.join("policy.yaml"))
            || config.audit.as_ref() != Some(&context.home.join("audit.jsonl"))
            || !config.enforce
            || config.judge.enabled
            || config
                .native
                .as_ref()
                .is_none_or(|n| n.registry_path != context.home.join("registry.json"))
        {
            return Err("retained_config_invalid");
        }
        // The selected endpoint must still match the startup binding, before
        // any private diagnostic credential is read or transmitted.
        if crate::protection_status::config_digest(&config) != context.config_sha256 {
            return Err("retained_config_digest_mismatch");
        }
        record::observe_listener(&context.owner, &context.listener, &config.bind, config.port)
            .map_err(|_| "recorded_listener_identity_unavailable_or_changed")?;
        let token = String::from_utf8(required(home, "token", 4096, budget)?)
            .map_err(|_| "diagnostic_credential_unsafe")?;
        let native = String::from_utf8(required(home, "native-token", 4096, budget)?)
            .map_err(|_| "diagnostic_credential_unsafe")?;
        if ![&token, &native].iter().all(|t| {
            t.len() == 43
                && t.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
        }) {
            return Err("diagnostic_credential_unsafe");
        }
        Ok((config, token, native))
    }
    let Ok((config, token, native)) = selected(home, context, budget) else {
        return "invalid_or_mismatched";
    };
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return "unavailable";
    };
    let result = runtime.block_on(async {
        let expected = crate::protection_status::Expectations {
            config_sha256: Some(context.config_sha256.clone()),
            policy_sha256: Some(live_policy_sha256.into()),
            registry_sha256: Some(registry.into()),
            ..Default::default()
        };
        record::observe_listener(&context.owner, &context.listener, &config.bind, config.port)
            .map_err(|_| "invalid_or_mismatched")?;
        let observed =
            crate::protection_status::query(&config, &token, &expected, Duration::from_secs(2))
                .await
                .map_err(protection_failure)?;
        if observed.runtime.pid != context.owner.pid
            || observed.mode != crate::protection_status::Mode::Enforcing
        {
            return Err("invalid_or_mismatched");
        }
        let client = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(2))
            .build()
            .map_err(|_| "unavailable")?;
        record::observe_listener(&context.owner, &context.listener, &config.bind, config.port)
            .map_err(|_| "invalid_or_mismatched")?;
        let mut response = client
            .get(config.endpoint_url("/native/v1/instance"))
            .bearer_auth(native)
            .send()
            .await
            .map_err(|_| "unavailable")?;
        if !response.status().is_success() {
            return Err("unavailable");
        }
        let mut bytes = vec![];
        while let Some(chunk) = response.chunk().await.map_err(|_| "unavailable")? {
            if bytes.len() + chunk.len() > 65536 {
                return Err("invalid_or_mismatched");
            }
            bytes.extend_from_slice(&chunk);
        }
        let value = audit::strict(&bytes).map_err(|_| "invalid_or_mismatched")?;
        validate_live(value, profile, context, registry)
    });
    if process(&context.owner) != "identity_matches_liveness_not_established"
        || record::observe_listener(&context.owner, &context.listener, &config.bind, config.port)
            .is_err()
    {
        return "unavailable";
    }
    match result {
        Ok(rows) => {
            *requests = rows;
            "matching_current_epoch"
        }
        Err(code) => code,
    }
}

fn validate_live(
    value: Value,
    profile: &Profile,
    context: &Context,
    registry: &str,
) -> Result<Vec<Request>> {
    if value["instance_id"] != context.instance_id {
        return Err("stale_epoch");
    }
    if value["registry_sha256"] != registry {
        return Err("invalid_or_mismatched");
    }
    let edit = &value["edit_diagnostic"];
    if edit["format"] != "sw-installed-edit-live/1"
        || edit["profile_sha256"] != context.profile_sha256
        || edit["host_session"] != context.host_session
    {
        return Err("invalid_or_mismatched");
    }
    let collectors = edit["collectors"]
        .as_array()
        .ok_or("invalid_or_mismatched")?;
    if collectors.len() > 8 {
        return Err("invalid_or_mismatched");
    }
    let mut sessions = BTreeSet::new();
    for collector in collectors {
        let epoch = collector["session_epoch"]
            .as_str()
            .filter(|s| crate::native::identifier(s))
            .ok_or("invalid_or_mismatched")?;
        if collector["host_session"] != context.host_session
            || collector["server_id"] != crate::edit_session::SERVER
            || !collector["active"].is_boolean()
            || !sessions.insert(epoch)
        {
            return Err("invalid_or_mismatched");
        }
    }
    let mut requests = vec![];
    let mut identities = BTreeSet::new();
    for field in ["pending", "decisions"] {
        let rows = edit[field].as_array().ok_or("invalid_or_mismatched")?;
        if rows.len() > if field == "pending" { 16 } else { 64 } {
            return Err("invalid_or_mismatched");
        }
        for row in rows {
            let state = match row["state"].as_str() {
                Some("pending") if field == "pending" => "pending",
                Some("rejected") => "rejected",
                Some("redeemed") => "redeemed",
                Some("expired") => "expired",
                Some("cancelled") => "cancelled",
                Some("closed") => "closed",
                _ => return Err("invalid_or_mismatched"),
            };
            if field == "pending" && state != "pending" {
                return Err("invalid_or_mismatched");
            }
            let epoch = row["session_epoch"]
                .as_str()
                .ok_or("invalid_or_mismatched")?;
            let id = row["pending_id"]
                .as_str()
                .filter(|s| crate::native::identifier(s))
                .ok_or("invalid_or_mismatched")?;
            let tool = row["tool"].as_str().ok_or("invalid_or_mismatched")?;
            let (index, operation) =
                audit::operation(profile, tool).map_err(|_| "invalid_or_mismatched")?;
            if !sessions.contains(epoch)
                || !identities.insert(id)
                || row["expires_at_ms"].as_u64().is_none()
                || !["binding_sha256", "args_sha256"]
                    .iter()
                    .all(|key| row[*key].as_str().is_some_and(crate::native::is_digest))
            {
                return Err("invalid_or_mismatched");
            }
            requests.push(Request {
                target_index: index,
                operation,
                state,
                binding_sha256: row["binding_sha256"].as_str().unwrap().into(),
                args_sha256: row["args_sha256"].as_str().unwrap().into(),
            });
        }
    }
    Ok(requests)
}

#[cfg(test)]
mod tests;
