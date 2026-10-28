// SPDX-License-Identifier: Apache-2.0
//! A finite selected-run lookup. Gaps, contradictions and ambiguous correlation
//! invalidate the whole observation; no partial prefix is promoted to success.
use super::{io::Result, Audit, Call};
use crate::edit_session::{profile::Profile, record::Context};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn sha(bytes: &[u8]) -> String {
    crate::mcp::replace_file::content_sha256(bytes)
}
pub(super) fn strict(bytes: &[u8]) -> Result<Value> {
    let crate::mcp::admission::Strict(value) =
        serde_json::from_slice(bytes).map_err(|_| "selected_json_malformed_or_duplicate")?;
    Ok(value)
}
pub(super) fn operation(profile: &Profile, name: &str) -> Result<(usize, &'static str)> {
    for (index, target) in profile.targets.iter().enumerate() {
        for (prefix, enabled, operation) in [
            ("read_output_", target.read, "read"),
            ("create_output_", target.create, "create"),
            ("replace_output_", target.replacement.is_some(), "replace"),
        ] {
            if enabled && name == format!("{prefix}{index}") {
                return Ok((index, operation));
            }
        }
    }
    Err("audit_foreign_or_undeclared_tool")
}
fn id(value: &Value) -> Result<&str> {
    value
        .as_str()
        .filter(|s| crate::native::identifier(s))
        .ok_or("audit_identity_invalid")
}
fn digest(value: &Value) -> Result<&str> {
    value
        .as_str()
        .filter(|s| crate::native::is_digest(s))
        .ok_or("audit_identity_invalid")
}
fn admitted(row: &Value) -> Result<&'static str> {
    let verdict = match row["verdict"].as_str() {
        Some("allow") => "recorded_allow",
        Some("ask") => "recorded_ask",
        Some("deny") => "recorded_deny",
        _ => return Err("audit_verdict_invalid"),
    };
    if row["released"].as_bool() != Some(verdict == "recorded_allow")
        || row["shadow"] != false
        || row["truncated"] != false
    {
        return Err("audit_contradictory_or_shadow_record");
    }
    if row["provenance_incomplete"] != false {
        return Err("audit_provenance_incomplete");
    }
    Ok(verdict)
}

pub(super) fn inspect(bytes: &[u8], profile: &Profile, context: &Context, registry: &str) -> Audit {
    let mut report = Audit {
        file_sha256: Some(sha(bytes)),
        ..Audit::default()
    };
    match parse(bytes, profile, context, registry, &mut report) {
        Ok(()) => {
            report.completeness = "selected_bounded_records_only";
            report.reason_code = "local_audit_observations_not_commit_or_delivery_proof";
        }
        Err(reason) => {
            // Inconsistent evidence must not leave an apparently useful prefix.
            report = Audit {
                file_sha256: Some(sha(bytes)),
                reason_code: reason,
                ..Audit::default()
            };
        }
    }
    report
}

fn parse(
    bytes: &[u8],
    profile: &Profile,
    context: &Context,
    registry: &str,
    report: &mut Audit,
) -> Result<()> {
    let started = std::time::Instant::now();
    if bytes.is_empty() {
        return Err("audit_empty_or_missing");
    }
    if bytes.len() > 1024 * 1024 || !bytes.ends_with(b"\n") {
        return Err("audit_oversized_or_truncated");
    }
    let mut sessions = BTreeMap::<String, u64>::new();
    let mut seen = BTreeSet::<(String, u64)>::new();
    let mut calls = BTreeMap::<String, usize>::new();
    let mut approvals = BTreeSet::new();
    let mut cancelled = BTreeSet::new();
    for (index, line) in bytes[..bytes.len() - 1].split(|b| *b == b'\n').enumerate() {
        if started.elapsed() > std::time::Duration::from_secs(2) {
            return Err("audit_parse_time_bound");
        }
        if index >= 512 || line.is_empty() || line.len() > 65536 {
            return Err("audit_record_bound");
        }
        let row = strict(line)?;
        if !row.is_object() {
            return Err("audit_record_invalid");
        }
        report.records += 1;
        let at = row["at_ms"].as_u64().ok_or("audit_timestamp_invalid")?;
        if at.saturating_add(5000) < context.started_at_ms
            || at > context.started_at_ms.saturating_add(240_000)
            || at > crate::protection_status::now_ms().saturating_add(5000)
        {
            return Err("audit_stale_or_future_evidence");
        }
        if row
            .get("host_session")
            .is_some_and(|s| s != &context.host_session)
            || row.get("registry_sha256").is_some_and(|s| s != registry)
            || row
                .get("instance_id")
                .is_some_and(|s| s != &context.instance_id)
        {
            return Err("audit_foreign_run_or_instance");
        }
        let event = row["event"].as_str().ok_or("audit_record_invalid")?;
        if event == "native_approval_cancelled" {
            let approval = id(&row["approval_id"])?;
            if !approvals.contains(approval)
                || !cancelled.insert(approval.to_string())
                || row["released"] != false
            {
                return Err("audit_ambiguous_approval");
            }
            continue;
        }
        let session = id(&row["session"])?;
        if event == "native_session_start" {
            if row["host_session"] != context.host_session
                || row["registry_sha256"] != registry
                || admitted(&row)? != "recorded_allow"
                || row["seq"] != 1
                || sessions.insert(session.into(), 1).is_some()
            {
                return Err("audit_session_binding_invalid");
            }
            seen.insert((session.into(), 1));
            continue;
        }
        if !sessions.contains_key(session) {
            return Err("audit_missing_or_foreign_session_start");
        }
        if let Some(seq) = row.get("seq") {
            let seq = seq
                .as_u64()
                .filter(|n| *n > 0)
                .ok_or("audit_sequence_invalid")?;
            let previous = sessions.get_mut(session).unwrap();
            if seq <= *previous || !seen.insert((session.into(), seq)) {
                return Err("audit_duplicate_or_out_of_order");
            }
            *previous = seq;
        }
        match event {
            "native_liveness_enrolled" => {
                if row["instance_id"] != context.instance_id {
                    return Err("audit_foreign_run_or_instance");
                }
            }
            "native_liveness_renewed" => {
                if row["lease_seq"].as_u64().is_none() || row["released"] != true {
                    return Err("audit_record_invalid");
                }
            }
            "native_session_end"
            | "native_session_ended"
            | "native_session_expired"
            | "native_session_retired"
            | "native_session_revoked" => (),
            "native_approval_requested" => {
                operation(profile, id(&row["tool"])?)?;
                digest(&row["binding_sha256"])?;
                digest(&row["args_sha256"])?;
                if row["registry_sha256"] != registry
                    || row["released"] != false
                    || !approvals.insert(id(&row["approval_id"])?.to_string())
                {
                    return Err("audit_ambiguous_approval");
                }
                report.ask_requests += 1;
            }
            "native_call" => {
                let (target_index, operation) = operation(profile, id(&row["tool"])?)?;
                if row["registry_sha256"] != registry
                    || row["host_session"] != context.host_session
                    || row.get("seq").is_none()
                {
                    return Err("audit_call_binding_invalid");
                }
                let admission = admitted(&row)?;
                let mut call = Call {
                    target_index,
                    operation,
                    session_sha256: sha(session.as_bytes()),
                    call_sha256: None,
                    binding_sha256: None,
                    admission,
                    publication_gate: "not_recorded",
                    commit: "unknown",
                    result_release: "not_recorded",
                    host_delivery: "unknown",
                    model_consumption: "unknown",
                };
                if admission == "recorded_allow" {
                    let call_id = id(&row["call_id"])?;
                    if calls
                        .insert(format!("{session}\0{call_id}"), report.calls.len())
                        .is_some()
                    {
                        return Err("audit_duplicate_or_out_of_order");
                    }
                    call.call_sha256 = Some(sha(call_id.as_bytes()));
                    call.binding_sha256 = Some(digest(&row["binding_sha256"])?.into());
                } else if !row["call_id"].is_null() || !row["binding_sha256"].is_null() {
                    return Err("audit_contradictory_or_shadow_record");
                }
                if report.calls.len() >= 128 {
                    return Err("audit_call_bound");
                }
                report.calls.push(call);
            }
            "native_publish" | "native_result" => {
                let (target, operation) = operation(profile, id(&row["tool"])?)?;
                let call_id = id(&row["call_id"])?;
                let key = format!("{session}\0{call_id}");
                let call = report
                    .calls
                    .get_mut(
                        *calls
                            .get(&key)
                            .ok_or("audit_result_without_matching_call")?,
                    )
                    .ok_or("audit_result_without_matching_call")?;
                if row["registry_sha256"] != registry
                    || row["host_session"] != context.host_session
                    || call.target_index != target
                    || call.operation != operation
                    || row.get("seq").is_none()
                    || Some(digest(&row["binding_sha256"])?) != call.binding_sha256.as_deref()
                {
                    return Err("audit_call_binding_invalid");
                }
                let observation = admitted(&row)?;
                if event == "native_publish" {
                    if call.publication_gate != "not_recorded"
                        || call.result_release != "not_recorded"
                        || operation != "replace"
                    {
                        return Err("audit_duplicate_or_contradictory_boundary");
                    }
                    call.publication_gate = observation;
                } else {
                    if call.result_release != "not_recorded" || row["delivery"] != "mcp_host" {
                        return Err("audit_duplicate_or_contradictory_boundary");
                    }
                    digest(&row["content_sha256"])?;
                    call.result_release = observation;
                }
            }
            _ => return Err("audit_unrecognized_or_unattributable_record"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn fixtures() -> (Profile, Context, String, Vec<Value>) {
        let profile = crate::edit_session::profile::fixture();
        let context = Context {
            format: "sw-installed-edit-diagnostic-context/1".into(),
            run: "/private/run".into(),
            home: "/private/run/home".into(),
            profile_sha256: crate::edit_session::profile::digest(&profile).unwrap(),
            host_session: "host-1".into(),
            instance_id: "instance-1".into(),
            started_at_ms: crate::protection_status::now_ms(),
            owner: crate::edit_session::record::process_identity(std::process::id()).unwrap(),
            config_sha256: "d".repeat(64),
            listener: crate::edit_session::record::ListenerIdentity {
                fd: 3,
                device: 1,
                inode: 1,
            },
        };
        let registry = crate::edit_session::profile::digest(&profile.registry().unwrap()).unwrap();
        let common = json!({"at_ms":context.started_at_ms,"session":"native:session-1","host_session":context.host_session,"registry_sha256":registry,
            "shadow":false,"truncated":false,"provenance_incomplete":false,"verdict":"allow","released":true});
        let mut start = common.clone();
        start["event"] = json!("native_session_start");
        start["seq"] = json!(1);
        let mut call = common.clone();
        call["event"] = json!("native_call");
        call["seq"] = json!(2);
        call["tool"] = json!("create_output_0");
        call["call_id"] = json!("call-1");
        call["binding_sha256"] = json!("a".repeat(64));
        let mut result = call.clone();
        result["event"] = json!("native_result");
        result["seq"] = json!(3);
        result["delivery"] = json!("mcp_host");
        result["content_sha256"] = json!("b".repeat(64));
        (profile, context, registry, vec![start, call, result])
    }
    fn bytes(rows: &[Value]) -> Vec<u8> {
        rows.iter()
            .map(|r| format!("{r}\n"))
            .collect::<String>()
            .into_bytes()
    }
    #[test]
    fn result_release_is_only_recorded_release_never_commit_or_delivery() {
        let (p, c, r, rows) = fixtures();
        let report = inspect(&bytes(&rows), &p, &c, &r);
        assert_eq!(report.completeness, "selected_bounded_records_only");
        assert_eq!(report.calls.len(), 1);
        let call = &report.calls[0];
        assert_eq!(call.operation, "create");
        assert_eq!(call.result_release, "recorded_allow");
        assert_eq!(call.commit, "unknown");
        assert_eq!(call.host_delivery, "unknown");
        assert_eq!(call.model_consumption, "unknown");
    }
    #[test]
    fn replacement_publication_gate_without_a_result_is_indeterminate() {
        let (mut p, mut c, _, mut rows) = fixtures();
        p.targets[0].create = false;
        p.targets[0].replacement = Some(crate::edit_session::profile::Baseline {
            sha256: "c".repeat(64),
            identity: crate::mcp::replace_file::Identity {
                device: p.root_identity.device,
                inode: 3,
                size: 7,
                mtime_seconds: 1,
                mtime_nanoseconds: 0,
                ctime_seconds: 1,
                ctime_nanoseconds: 0,
                uid: unsafe { libc::geteuid() },
                gid: unsafe { libc::getegid() },
                mode: 0o100600,
            },
        });
        c.profile_sha256 = crate::edit_session::profile::digest(&p).unwrap();
        let registry = crate::edit_session::profile::digest(&p.registry().unwrap()).unwrap();
        for row in &mut rows {
            row["registry_sha256"] = serde_json::json!(registry);
        }
        rows[1]["tool"] = serde_json::json!("replace_output_0");
        rows[2]["tool"] = serde_json::json!("replace_output_0");
        rows[2]["event"] = serde_json::json!("native_publish");
        let observed = inspect(&bytes(&rows), &p, &c, &registry);
        assert_eq!(observed.completeness, "selected_bounded_records_only");
        assert_eq!(observed.calls[0].operation, "replace");
        assert_eq!(observed.calls[0].publication_gate, "recorded_allow");
        assert_eq!(observed.calls[0].result_release, "not_recorded");
        assert_eq!(observed.calls[0].commit, "unknown");
    }
    #[test]
    fn duplicate_stale_foreign_and_contradictory_records_discard_partial_prefix() {
        let (p, c, r, rows) = fixtures();
        let mut variants = vec![];
        let mut duplicate = rows.clone();
        duplicate.push(rows[2].clone());
        variants.push(duplicate);
        let mut stale = rows.clone();
        stale[2]["at_ms"] = json!(0);
        variants.push(stale);
        let mut foreign = rows.clone();
        foreign[2]["host_session"] = json!("another-host");
        variants.push(foreign);
        let mut wrong = rows.clone();
        wrong[2]["binding_sha256"] = json!("c".repeat(64));
        variants.push(wrong);
        let mut contradiction = rows.clone();
        contradiction[2]["released"] = json!(false);
        variants.push(contradiction);
        let mut absent = rows.clone();
        absent.remove(1);
        variants.push(absent);
        for rows in variants {
            let observed = inspect(&bytes(&rows), &p, &c, &r);
            assert_eq!(observed.completeness, "incomplete");
            assert!(observed.calls.is_empty());
        }
    }
    #[test]
    fn malformed_truncated_duplicate_keys_and_record_caps_are_not_skipped() {
        let (p, c, r, rows) = fixtures();
        let mut truncated = bytes(&rows);
        truncated.pop();
        let mut duplicate = bytes(&rows);
        duplicate.extend_from_slice(b"{\"secret\":1,\"secret\":2}\n");
        let mut malformed = bytes(&rows);
        malformed.extend_from_slice(b"not-json\n");
        let mut too_many = vec![rows[0].clone(); 513];
        too_many[0] = rows[0].clone();
        for raw in [truncated, duplicate, malformed, bytes(&too_many)] {
            let observed = inspect(&raw, &p, &c, &r);
            assert_eq!(observed.completeness, "incomplete");
            assert!(observed.calls.is_empty());
        }
    }
    #[test]
    fn untrusted_strings_and_payload_canaries_are_never_rendered() {
        let (p, c, r, mut rows) = fixtures();
        rows[2]["unexpected_payload"] = json!("private-secret-canary /home/private/target");
        let observed = inspect(&bytes(&rows), &p, &c, &r);
        let rendered = serde_json::to_string(&observed).unwrap();
        assert!(!rendered.contains("private-secret-canary"));
        assert!(!rendered.contains("/home/private"));
        assert!(!rendered.contains("create_output_0"));
    }
}
