// SPDX-License-Identifier: Apache-2.0
use super::{
    audit,
    io::{Budget, Directory, Result},
    Args, Identity, Output, Report, Request,
};
use crate::edit_session::{
    profile::{self, Profile},
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
fn terminal(raw: &[u8], context: &Context) -> Result<&'static str> {
    let terminal: Terminal = decode(raw)?;
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
    match (terminal.state.as_str(), terminal.reason.as_str()) {
        ("host_completed", "host_completed")
            if terminal.cleanup.cleaned
                && terminal.cleanup.reaped
                && terminal.cleanup.exit_success
                && terminal.daemon_clean =>
        {
            Ok("recorded_host_completed")
        }
        ("failed", "host_completed")
            if terminal.cleanup.reaped && !terminal.cleanup.exit_success =>
        {
            Ok("recorded_unsuccessful_host_exit")
        }
        ("failed", "host_completed") => Ok("recorded_cleanup_or_stream_failure"),
        ("failed", "cancelled") => Ok("recorded_cancellation"),
        ("failed", "deadline") => Ok("recorded_deadline"),
        ("failed", "daemon_lost") => Ok("recorded_daemon_loss"),
        ("failed", "host_stream_failure") => Ok("recorded_host_stream_failure"),
        ("failed", "provider_child_environment_unavailable") => {
            Ok("recorded_provider_environment_failure")
        }
        _ => Err("terminal_contradictory_or_unknown_outcome"),
    }
}

pub(super) fn inspect(args: &Args, report: &mut Report) -> Result<()> {
    if !cfg!(target_arch = "x86_64") {
        report.status = "unsupported";
        report.reason_code = "installed_edit_diagnosis_requires_native_linux_x86_64";
        return Ok(());
    }
    let mut budget = Budget::new();
    let run_dir = Directory::open(&args.run)?;
    let context_bytes = required(&run_dir, "diagnostic-context.json", 16 * 1024, &mut budget)?;
    let context: Context = decode(&context_bytes)?;
    context
        .validate()
        .map_err(|_| "diagnostic_context_invalid")?;
    if context.run != args.run
        || context.owner.uid != unsafe { libc::geteuid() }
        || context.started_at_ms > report.observed_at_ms.saturating_add(5000)
    {
        return Err("diagnostic_context_foreign_or_future");
    }
    let run_bytes = required(&run_dir, "run.json", 16 * 1024, &mut budget)?;
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
    let profile_bytes = required(&run_dir, "profile.json", 128 * 1024, &mut budget)?;
    let profile: Profile = decode(&profile_bytes)?;
    profile.validate().map_err(|_| "retained_profile_invalid")?;
    if profile::canonical(&profile).map_err(|_| "retained_profile_invalid")? != profile_bytes
        || audit::sha(&profile_bytes) != context.profile_sha256
        || required(&run_dir, "profile.sha256", 64, &mut budget)?
            != context.profile_sha256.as_bytes()
    {
        return Err("retained_profile_digest_mismatch");
    }
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
        Some(raw) => terminal(raw, &context)?,
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
mod tests {
    use super::*;
    use serde_json::json;
    use std::{fs, os::unix::fs::PermissionsExt};
    fn private(path: &std::path::Path, bytes: &[u8]) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn dir(path: &std::path::Path) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fn fixture() -> (tempfile::TempDir, Args, Profile, Context) {
        let temp = tempfile::tempdir().unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let run = temp.path().join("run");
        dir(&run);
        let home = run.join("h".repeat(43));
        dir(&home);
        let mut p = crate::edit_session::profile::fixture();
        p.policy_sha256 = profile::digest(&crate::edit_session::launch::policy().unwrap()).unwrap();
        let root = temp.path().join("outputs");
        dir(&root);
        p.root = root;
        let root_meta = fs::metadata(&p.root).unwrap();
        p.root_identity = crate::mcp::replace_file::RootIdentity {
            device: root_meta.dev(),
            inode: root_meta.ino(),
        };
        let c = Context {
            format: record::FORMAT.into(),
            run: run.clone(),
            home: home.clone(),
            profile_sha256: profile::digest(&p).unwrap(),
            host_session: "host-1".into(),
            instance_id: "instance-1".into(),
            started_at_ms: crate::protection_status::now_ms(),
            owner: record::process_identity(std::process::id()).unwrap(),
            config_sha256: "d".repeat(64),
            listener: record::ListenerIdentity {
                fd: 3,
                device: 1,
                inode: 1,
            },
        };
        private(
            &run.join("diagnostic-context.json"),
            &profile::canonical(&c).unwrap(),
        );
        private(&run.join("run.json"),&serde_json::to_vec(&json!({"format":FORMAT,"run":run,"home":home,"profile_sha256":c.profile_sha256,"host_session":c.host_session,"instance_id":c.instance_id})).unwrap());
        private(&run.join("profile.json"), &profile::canonical(&p).unwrap());
        private(&run.join("profile.sha256"), c.profile_sha256.as_bytes());
        private(
            &home.join("registry.json"),
            &profile::canonical(&p.registry().unwrap()).unwrap(),
        );
        private(
            &home.join("policy.yaml"),
            crate::edit_session::launch::POLICY.as_bytes(),
        );
        (
            temp,
            Args {
                run,
                json: true,
                check_output: false,
                support_bundle: None,
            },
            p,
            c,
        )
    }
    #[test]
    fn missing_audit_never_means_not_executed_and_default_creates_no_state_or_target_reads() {
        let (_temp, args, p, c) = fixture();
        let canary = b"private-content-secret-canary";
        private(&p.root.join("draft.txt"), canary);
        let before = fs::read_dir(&args.run).unwrap().count();
        let target = fs::metadata(p.root.join("draft.txt")).unwrap();
        let report = super::super::inspect(&args);
        assert_eq!(report.reason_code, "audit_empty_or_missing");
        assert!(report.outputs.is_empty());
        assert_eq!(report.effects, "indeterminate");
        assert!(report.audit.calls.is_empty());
        assert_eq!(fs::read_dir(&args.run).unwrap().count(), before);
        let after = fs::metadata(p.root.join("draft.txt")).unwrap();
        assert!(super::super::io::stable(&target, &after));
        assert_eq!(fs::read(p.root.join("draft.txt")).unwrap(), canary);
        let rendered = format!(
            "{}{}",
            serde_json::to_string(&report).unwrap(),
            super::super::text(&report)
        );
        for secret in [
            "private-content-secret-canary",
            c.home.to_str().unwrap(),
            p.root.to_str().unwrap(),
            "draft.txt",
            "create_output_0",
        ] {
            assert!(!rendered.contains(secret));
        }
        assert!(!rendered.contains("not executed"));
    }
    #[test]
    fn unsuccessful_reaped_host_is_distinct_from_missing_exit_or_cleanup_failure() {
        let (_temp, _args, _profile, context) = fixture();
        let mut row = json!({"format":FORMAT,"state":"failed","reason":"host_completed",
            "run":context.run,"profile_sha256":context.profile_sha256,
            "cleanup":{"cleaned":true,"reaped":true,"exit_success":false,
                "graceful_observed":true,"ownership":"owned-process-group","failure":null},
            "daemon_clean":true,"mutation_dispatches":0,
            "effect_status":"consult-native-audit; interrupted-or-withheld-result-is-indeterminate; no-automatic-retry"});
        assert_eq!(
            terminal(&serde_json::to_vec(&row).unwrap(), &context).unwrap(),
            "recorded_unsuccessful_host_exit"
        );
        // A failed or missing reap does not establish how the host exited.
        row["cleanup"]["reaped"] = json!(false);
        row["cleanup"]["cleaned"] = json!(false);
        assert_eq!(
            terminal(&serde_json::to_vec(&row).unwrap(), &context).unwrap(),
            "recorded_cleanup_or_stream_failure"
        );
        // A successful host can still leave incomplete owned cleanup.
        row["cleanup"]["reaped"] = json!(true);
        row["cleanup"]["exit_success"] = json!(true);
        assert_eq!(
            terminal(&serde_json::to_vec(&row).unwrap(), &context).unwrap(),
            "recorded_cleanup_or_stream_failure"
        );
    }
    #[tokio::test]
    async fn live_policy_identity_matches_authenticated_producer_without_reusing_profile_hash_format(
    ) {
        use std::sync::{Arc, Mutex};
        use tower::ServiceExt;
        let directory = tempfile::tempdir().unwrap();
        let policy = crate::edit_session::launch::policy().unwrap();
        let config = crate::Config {
            enforce: true,
            ..Default::default()
        };
        let token = crate::token::generate();
        let state = Arc::new(crate::AppState {
            native: None,
            firewall: Mutex::new(
                soup_wall_agent::AgentFirewall::with_taint_limits(
                    policy.clone(),
                    soup_wall_agent::DEFAULT_TAINT_CAP,
                    config.provenance.clone(),
                )
                .unwrap(),
            ),
            sessions: Default::default(),
            audit: crate::audit::AuditSink::open(&directory.path().join("audit")).unwrap(),
            config: config.clone(),
            token: token.clone(),
            spans: crate::spans::SpanCache::new(64, 262144),
            judge: crate::judge::Judge::new(Default::default()),
            manifests: crate::mcp::store::ManifestStore::new(&directory.path().join("manifests")),
            tools: crate::mcp::store::ToolRegistry::with_builtins(),
            grants: crate::grant::GrantStore::new(&directory.path().join("grants")),
            grant_ledger: crate::grant::GrantLedger::open(&directory.path().join("spent")),
            grant_key: crate::grant::derive_key(&token),
        });
        let nonce = crate::token::generate();
        let request = axum::http::Request::get(crate::protection_status::ENDPOINT)
            .header("authorization", format!("Bearer {token}"))
            .header(crate::protection_status::NONCE_HEADER, &nonce)
            .body(axum::body::Body::empty())
            .unwrap();
        let response = crate::app(state).oneshot(request).await.unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let raw = axum::body::to_bytes(response.into_body(), 32768)
            .await
            .unwrap();
        let observed: crate::protection_status::Snapshot = serde_json::from_slice(&raw).unwrap();
        let live = live_policy_digest(&policy).unwrap();
        let retained = profile::digest(&policy).unwrap();
        assert_ne!(retained, live);
        let mut expected = crate::protection_status::Expectations {
            policy_sha256: Some(live),
            config_sha256: Some(crate::protection_status::config_digest(&config)),
            ..Default::default()
        };
        crate::protection_status::validate(
            &observed,
            &nonce,
            crate::protection_status::now_ms(),
            &expected,
        )
        .unwrap();
        expected.policy_sha256 = Some(retained);
        let mismatch = crate::protection_status::validate(
            &observed,
            &nonce,
            crate::protection_status::now_ms(),
            &expected,
        )
        .unwrap_err();
        assert_eq!(mismatch, "status_identity_mismatch");
        assert_eq!(protection_failure(mismatch), "invalid_or_mismatched");
    }
    #[test]
    fn unavailable_transport_and_invalid_authenticated_evidence_remain_distinct_and_allowlisted() {
        for code in [
            "status_unavailable",
            "status_client_unavailable",
            "status_query_rejected",
        ] {
            assert_eq!(protection_failure(code), "unavailable");
        }
        for code in [
            "status_identity_mismatch",
            "status_invalid_or_stale",
            "status_invalid_response",
            "status_response_over_cap",
            "status_invalid_config",
            "status_invalid_registry",
            "status_invalid_coverage",
            "arbitrary-private-error-canary",
        ] {
            assert_eq!(protection_failure(code), "invalid_or_mismatched");
            assert!(!protection_failure(code).contains("canary"));
        }
    }
    #[test]
    fn output_digest_is_only_an_explicit_postcondition_observation() {
        let (_temp, mut args, p, _c) = fixture();
        private(&p.root.join("draft.txt"), b"changed independently");
        args.check_output = true;
        let report = super::super::inspect(&args);
        assert_eq!(report.outputs.len(), 1);
        assert_eq!(report.outputs[0].observation, "present");
        assert_eq!(
            report.outputs[0].attribution,
            "observed_postcondition_not_writer_or_commit_proof"
        );
        assert_eq!(report.effects, "indeterminate");
    }
    #[test]
    fn tampered_profile_foreign_run_and_duplicate_context_do_not_trigger_network_or_output_reads() {
        let (_temp, args, _p, c) = fixture();
        let original = fs::read(args.run.join("run.json")).unwrap();
        let mut changed: Value = serde_json::from_slice(&original).unwrap();
        changed["run"] = json!("/foreign");
        private(
            &args.run.join("run.json"),
            &serde_json::to_vec(&changed).unwrap(),
        );
        let report = super::super::inspect(&args);
        assert_eq!(report.reason_code, "run_context_binding_mismatch");
        assert_eq!(report.authenticated_daemon, "not_queried");
        private(&args.run.join("run.json"), &original);
        private(&args.run.join("profile.json"), b"{}");
        assert_eq!(
            super::super::inspect(&args).reason_code,
            "selected_state_schema_invalid"
        );
        private(
            &args.run.join("diagnostic-context.json"),
            format!(
                "{{\"format\":\"{}\",\"format\":\"private-secret-canary\"}}",
                c.format
            )
            .as_bytes(),
        );
        let report = super::super::inspect(&args);
        assert_eq!(report.reason_code, "selected_json_malformed_or_duplicate");
        assert!(!super::super::text(&report).contains("private-secret-canary"));
    }
    #[test]
    fn changed_config_and_coherent_local_hash_tampering_send_no_credentials_to_foreign_listener() {
        use std::{net::TcpListener, os::fd::AsRawFd};
        let (_temp, args, profile, mut context) = fixture();
        let original = TcpListener::bind("127.0.0.1:0").unwrap();
        let foreign = TcpListener::bind("127.0.0.1:0").unwrap();
        foreign.set_nonblocking(true).unwrap();
        let mut config = crate::Config {
            bind: "127.0.0.1".into(),
            port: original.local_addr().unwrap().port(),
            enforce: true,
            policy: Some(context.home.join("policy.yaml")),
            audit: Some(context.home.join("audit.jsonl")),
            native: Some(crate::config::NativeCfg {
                execution: None,
                git_execution: None,
                registry_path: context.home.join("registry.json"),
                registry_sha256: profile::digest(&profile.registry().unwrap()).unwrap(),
                approval: None,
                liveness: None,
            }),
            ..Default::default()
        };
        context.config_sha256 = crate::protection_status::config_digest(&config);
        context.listener = record::listener_identity(original.as_raw_fd()).unwrap();
        private(
            &context.home.join("token"),
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        );
        private(
            &context.home.join("native-token"),
            b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
        );
        config.port = foreign.local_addr().unwrap().port();
        private(
            &context.home.join("config.yaml"),
            serde_yaml::to_string(&config).unwrap().as_bytes(),
        );
        for coherently_changed_hash in [false, true] {
            if coherently_changed_hash {
                context.config_sha256 = crate::protection_status::config_digest(&config);
            }
            private(
                &args.run.join("diagnostic-context.json"),
                &profile::canonical(&context).unwrap(),
            );
            let report = super::super::inspect(&args);
            assert_eq!(report.authenticated_daemon, "invalid_or_mismatched");
            assert_eq!(
                foreign.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
            let encoded = serde_json::to_string(&report).unwrap();
            assert!(!encoded.contains("AAAAAAAAAAAA"));
            assert!(!encoded.contains("BBBBBBBBBBBB"));
        }
    }
    #[test]
    fn live_view_requires_exact_instance_profile_host_and_nonduplicate_correlated_requests() {
        let (_temp, _args, p, c) = fixture();
        let registry = profile::digest(&p.registry().unwrap()).unwrap();
        let row = json!({"pending_id":"pending-1","session_epoch":"native:epoch-1","tool":"create_output_0","binding_sha256":"a".repeat(64),"args_sha256":"b".repeat(64),"expires_at_ms":c.started_at_ms+120000,"state":"pending"});
        let good = json!({"instance_id":c.instance_id,"registry_sha256":registry,"edit_diagnostic":{"format":"sw-installed-edit-live/1","profile_sha256":c.profile_sha256,"host_session":c.host_session,
            "collectors":[{"session_epoch":"native:epoch-1","host_session":c.host_session,"server_id":"private-output","active":true}],"pending":[row],"decisions":[]}});
        let observed = validate_live(good.clone(), &p, &c, &registry).unwrap();
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].state, "pending");
        let mut stale = good.clone();
        stale["instance_id"] = json!("stale");
        assert_eq!(
            validate_live(stale, &p, &c, &registry).unwrap_err(),
            "stale_epoch"
        );
        let mut duplicate = good.clone();
        duplicate["edit_diagnostic"]["pending"]
            .as_array_mut()
            .unwrap()
            .push(row.clone());
        assert!(validate_live(duplicate, &p, &c, &registry).is_err());
        let mut foreign = good;
        foreign["edit_diagnostic"]["host_session"] = json!("foreign");
        assert!(validate_live(foreign, &p, &c, &registry).is_err());
    }
}
