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
fn handshake_metadata(row: &Value) -> Result<()> {
    // handlers::mcp writes the server label and seq=0 using AuditLine. This
    // record has no native epoch, host binding, call ID or release receipt.
    // Validate it separately; it can never supply missing native evidence.
    let object = row.as_object().ok_or("audit_handshake_metadata_invalid")?;
    let allowed = [
        "at_ms",
        "session",
        "seq",
        "event",
        "verdict",
        "shadow",
        "rule",
        "risk_score",
        "findings",
        "egress_hosts",
        "latency_us",
        "truncated",
    ];
    if object.keys().any(|key| !allowed.contains(&key.as_str()))
        || row["session"] != crate::edit_session::SERVER
        || row["seq"] != 0
        || row["shadow"] != false
        || row["truncated"] != false
        || !matches!(
            row["verdict"].as_str(),
            Some("allow" | "ask" | "deny" | "escalate")
        )
        || row["risk_score"].as_u64().is_none_or(|n| n > 255)
        || row["latency_us"] != 0
        || row["egress_hosts"] != serde_json::json!([])
        || row
            .get("rule")
            .is_some_and(|value| value.as_str().is_none_or(|s| s.len() > 256))
        || !row["findings"].as_array().is_some_and(|findings| {
            findings.len() <= 256
                && findings.iter().all(|finding| {
                    finding.as_object().is_some_and(|value| {
                        value.keys().all(|key| {
                            ["detector", "severity", "owasp", "atlas"].contains(&key.as_str())
                        }) && ["detector", "severity"].iter().all(|key| {
                            finding[*key]
                                .as_str()
                                .is_some_and(|s| !s.is_empty() && s.len() <= 256)
                        }) && ["owasp", "atlas"].iter().all(|key| {
                            finding
                                .get(*key)
                                .is_none_or(|value| value.as_str().is_some_and(|s| s.len() <= 256))
                        })
                    })
                })
        })
    {
        return Err("audit_handshake_metadata_invalid");
    }
    Ok(())
}

// The Stop producer also emits this metadata during normal run cleanup.
// It carries no per-call execution, publication, result or rollback proof.
fn revocation_metadata(row: &Value, context: &Context, registry: &str) -> Result<()> {
    let object = row.as_object().ok_or("audit_revocation_metadata_invalid")?;
    let keys = [
        "event",
        "at_ms",
        "instance_id",
        "host_session",
        "registry_sha256",
        "retired_sessions",
        "released",
        "running_effects_rolled_back",
    ];
    if object.len() != keys.len()
        || object.keys().any(|key| !keys.contains(&key.as_str()))
        || row["instance_id"] != context.instance_id
        || row["host_session"] != context.host_session
        || row["registry_sha256"] != registry
        // Current native session capacity is 64. A future producer expansion
        // needs its own reviewed diagnostic contract, not silent acceptance.
        || row["retired_sessions"].as_u64().is_none_or(|n| n > 64)
        || row["released"] != false
        || row["running_effects_rolled_back"] != false
    {
        return Err("audit_revocation_metadata_invalid");
    }
    Ok(())
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
    let mut handshake_seen = false;
    let mut leases = BTreeMap::<String, (String, u64)>::new();
    let mut closed = BTreeSet::new();
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
        if event == "pilot_run_authority_revoked" {
            revocation_metadata(&row, context, registry)?;
            continue;
        }
        if event == "mcp_handshake" {
            if handshake_seen
                || sessions.is_empty()
                || !report.calls.is_empty()
                || report.ask_requests != 0
            {
                return Err("audit_handshake_duplicate_or_out_of_order");
            }
            handshake_metadata(&row)?;
            handshake_seen = true;
            continue;
        }
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
        if closed.contains(session) {
            return Err("audit_event_after_terminal_session");
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
                if row["instance_id"] != context.instance_id
                    || row["released"] != true
                    || !row["lease_seconds"]
                        .as_u64()
                        .is_some_and(|n| (1..=60).contains(&n))
                    || leases
                        .insert(session.into(), (id(&row["session_id"])?.into(), 0))
                        .is_some()
                {
                    return Err("audit_foreign_run_or_instance");
                }
            }
            "native_liveness_renewed" => {
                let sequence = row["lease_seq"].as_u64().ok_or("audit_record_invalid")?;
                let lease = leases
                    .get_mut(session)
                    .ok_or("audit_renewal_without_matching_enrollment")?;
                if id(&row["session_id"])? != lease.0
                    || sequence <= lease.1
                    || row["released"] != true
                {
                    return Err("audit_record_invalid");
                }
                lease.1 = sequence;
            }
            "native_session_end"
            | "native_session_ended"
            | "native_session_expired"
            | "native_session_retired"
            | "native_session_revoked" => {
                if row["host_session"] != context.host_session
                    || row["registry_sha256"] != registry
                    || row["verdict"] != "allow"
                    || row["shadow"] != false
                    || row.get("seq").is_none()
                    || row["released"].as_bool() != Some(event == "native_session_end")
                {
                    return Err("audit_terminal_binding_invalid");
                }
                if event != "native_session_end" {
                    closed.insert(session.to_string());
                }
            }
            "native_approval_requested" => {
                operation(profile, id(&row["tool"])?)?;
                digest(&row["binding_sha256"])?;
                digest(&row["args_sha256"])?;
                if row["registry_sha256"] != registry
                    || row["released"] != false
                    || !matches!(row["source"].as_str(), Some("classifier" | "daemon"))
                    || row["policy_epoch"].as_u64().is_none()
                    || !row["expires_at_ms"]
                        .as_u64()
                        .is_some_and(|expiry| expiry >= at && expiry <= at.saturating_add(300_000))
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
    fn stop_cleanup_metadata_preserves_unknown_execution_and_rejects_forgery() {
        let (profile, context, registry, rows) = fixtures();
        let before = inspect(&bytes(&rows), &profile, &context, &registry);
        let revocation = json!({
            "event":"pilot_run_authority_revoked", "at_ms":context.started_at_ms,
            "instance_id":context.instance_id, "host_session":context.host_session,
            "registry_sha256":registry, "retired_sessions":1,
            "released":false, "running_effects_rolled_back":false,
        });
        let mut completed = rows.clone();
        completed.push(revocation.clone());
        let observed = inspect(&bytes(&completed), &profile, &context, &registry);
        assert_eq!(observed.completeness, "selected_bounded_records_only");
        assert_eq!(observed.records, before.records + 1);
        assert_eq!(observed.calls.len(), before.calls.len());
        assert!(observed
            .calls
            .iter()
            .all(|call| { call.commit == "unknown" && call.host_delivery == "unknown" }));
        for (key, value) in [
            ("instance_id", json!("foreign-instance")),
            ("host_session", json!("foreign-host")),
            ("registry_sha256", json!("f".repeat(64))),
            ("retired_sessions", json!(65)),
            ("retired_sessions", json!(-1)),
            ("retired_sessions", json!("1")),
            ("released", json!(true)),
            ("running_effects_rolled_back", json!(true)),
            ("session", json!("forged-session")),
            ("call_id", json!("forged-call")),
        ] {
            let mut invalid = rows.clone();
            let mut extra = revocation.clone();
            extra[key] = value;
            invalid.push(extra);
            let rejected = inspect(&bytes(&invalid), &profile, &context, &registry);
            assert_eq!(rejected.completeness, "incomplete");
            assert!(rejected.calls.is_empty());
        }
        for key in revocation.as_object().unwrap().keys() {
            let mut invalid = rows.clone();
            let mut missing = revocation.clone();
            missing.as_object_mut().unwrap().remove(key);
            invalid.push(missing);
            let rejected = inspect(&bytes(&invalid), &profile, &context, &registry);
            assert_eq!(rejected.completeness, "incomplete");
            assert!(rejected.calls.is_empty());
        }
    }

    fn installed_create_sequence() -> (Profile, Context, String, Vec<Value>) {
        // Sanitized shape/order observed in an installed create/read run,
        // reconciled with native::audit, native::liveness and handlers::mcp.
        let (mut p, mut c, _, base) = fixtures();
        p.targets.push(crate::edit_session::profile::Target {
            name: "source.txt".into(),
            read: true,
            create: false,
            replacement: None,
        });
        c.profile_sha256 = crate::edit_session::profile::digest(&p).unwrap();
        let registry = crate::edit_session::profile::digest(&p.registry().unwrap()).unwrap();
        let mut start = base[0].clone();
        start["registry_sha256"] = json!(registry);
        let mut call = base[1].clone();
        call["registry_sha256"] = json!(registry);
        let session = start["session"].clone();
        let enrollment = json!({"at_ms":c.started_at_ms,"event":"native_liveness_enrolled","session":session,
            "session_id":"collector-1","lease_seconds":4,"instance_id":c.instance_id,"released":true});
        // Exercise the real typed handshake serializer: it omits native host,
        // registry, release and optional-null fields and uses a server label.
        let handshake = serde_json::to_value(crate::audit::AuditLine {
            at_ms: c.started_at_ms,
            session: crate::edit_session::SERVER.into(),
            agent_id: None,
            parent_id: None,
            seq: 0,
            event: "mcp_handshake".into(),
            tool: None,
            verdict: "allow".into(),
            shadow: false,
            rule: None,
            risk_score: 0,
            findings: vec![],
            taint: None,
            judge: None,
            approval: None,
            egress_hosts: vec![],
            latency_us: 0,
            truncated: false,
            raw: None,
        })
        .unwrap();
        let mut read_before = call.clone();
        read_before["tool"] = json!("read_output_1");
        read_before["call_id"] = json!("read-before");
        read_before["binding_sha256"] = json!("b".repeat(64));
        let result = |call: &Value, seq: u64| {
            let mut row = call.clone();
            row["seq"] = json!(seq);
            row["event"] = json!("native_result");
            row["delivery"] = json!("mcp_host");
            row["content_sha256"] = json!("c".repeat(64));
            row
        };
        let renewal = |sequence: u64| {
            json!({"at_ms":c.started_at_ms,"event":"native_liveness_renewed",
            "session":session,"session_id":"collector-1","lease_seq":sequence,"released":true})
        };
        let mut ask = call.clone();
        ask["seq"] = json!(5);
        ask["verdict"] = json!("ask");
        ask["released"] = json!(false);
        ask["call_id"] = Value::Null;
        ask["binding_sha256"] = Value::Null;
        let approval = json!({"at_ms":c.started_at_ms,"event":"native_approval_requested","approval_id":"approval-1",
            "session":session,"tool":"create_output_0","binding_sha256":"a".repeat(64),"args_sha256":"d".repeat(64),
            "source":"daemon","policy_epoch":0,"expires_at_ms":c.started_at_ms+120000,"registry_sha256":registry,"released":false});
        call["seq"] = json!(7);
        let mut read_after = read_before.clone();
        read_after["seq"] = json!(10);
        read_after["tool"] = json!("read_output_0");
        read_after["call_id"] = json!("read-after");
        let retired = json!({"at_ms":c.started_at_ms,"session":session,"session_id":"collector-1","seq":13,
            "event":"native_session_retired","verdict":"allow","shadow":false,"released":false,
            "registry_sha256":registry,"host_session":c.host_session,"agent_id":"agent-1","parent_id":null});
        let rows = vec![
            start,
            enrollment,
            handshake,
            read_before.clone(),
            result(&read_before, 4),
            renewal(1),
            ask,
            approval,
            renewal(2),
            call.clone(),
            renewal(3),
            result(&call, 9),
            read_after.clone(),
            result(&read_after, 12),
            retired,
        ];
        (p, c, registry, rows)
    }
    #[test]
    fn installed_handshake_liveness_ask_allow_result_and_retirement_remain_separate_evidence() {
        let (p, c, registry, rows) = installed_create_sequence();
        let observed = inspect(&bytes(&rows), &p, &c, &registry);
        assert_eq!(observed.completeness, "selected_bounded_records_only");
        assert_eq!(observed.records, 15);
        assert_eq!(observed.ask_requests, 1);
        assert_eq!(observed.calls.len(), 4);
        assert_eq!(observed.calls[0].operation, "read");
        assert_eq!(observed.calls[1].admission, "recorded_ask");
        assert!(observed.calls[1].call_sha256.is_none());
        assert_eq!(observed.calls[2].operation, "create");
        assert_eq!(observed.calls[2].result_release, "recorded_allow");
        assert_eq!(observed.calls[3].operation, "read");
        assert!(observed
            .calls
            .iter()
            .all(|call| call.commit == "unknown" && call.host_delivery == "unknown"));
    }
    #[test]
    fn foreign_duplicate_or_execution_shaped_metadata_never_supplies_a_native_session() {
        let (p, c, registry, rows) = installed_create_sequence();
        let mut variants = vec![];
        let mut foreign = rows.clone();
        foreign[2]["session"] = json!("foreign-server");
        variants.push(foreign);
        let mut duplicate = rows.clone();
        duplicate.insert(3, rows[2].clone());
        variants.push(duplicate);
        let mut execution = rows.clone();
        execution[2]["call_id"] = json!("forged-call");
        variants.push(execution);
        let mut shadow = rows.clone();
        shadow[2]["shadow"] = json!(true);
        variants.push(shadow);
        let mut native = rows.clone();
        native[2]["event"] = json!("native_call");
        variants.push(native);
        let mut renewal = rows.clone();
        renewal[8]["lease_seq"] = json!(1);
        variants.push(renewal);
        let mut missing = rows.clone();
        missing.remove(1);
        variants.push(missing);
        let mut after = rows.clone();
        after.push(rows[12].clone());
        variants.push(after);
        for variant in variants {
            let observed = inspect(&bytes(&variant), &p, &c, &registry);
            assert_eq!(observed.completeness, "incomplete");
            assert!(observed.calls.is_empty());
        }
    }
    #[test]
    fn producer_approval_cancellation_and_session_end_are_attributable_without_execution_claim() {
        let (p, c, registry, full) = installed_create_sequence();
        let mut end = full[14].clone();
        end["seq"] = json!(3);
        end["event"] = json!("native_session_end");
        end["released"] = json!(true);
        let mut ended = full[14].clone();
        ended["seq"] = json!(4);
        ended["event"] = json!("native_session_ended");
        let cancelled = json!({"at_ms":c.started_at_ms,"event":"native_approval_cancelled","approval_id":"approval-1","released":false});
        let mut rows = vec![
            full[0].clone(),
            full[1].clone(),
            full[2].clone(),
            full[7].clone(),
            cancelled.clone(),
            end,
            ended,
        ];
        let observed = inspect(&bytes(&rows), &p, &c, &registry);
        assert_eq!(observed.completeness, "selected_bounded_records_only");
        assert_eq!(observed.ask_requests, 1);
        assert!(observed.calls.is_empty());
        rows.insert(5, cancelled);
        let duplicate = inspect(&bytes(&rows), &p, &c, &registry);
        assert_eq!(duplicate.completeness, "incomplete");
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
