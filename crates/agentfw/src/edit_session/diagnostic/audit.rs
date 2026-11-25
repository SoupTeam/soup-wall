// SPDX-License-Identifier: Apache-2.0
//! A finite selected-run lookup. Gaps, contradictions and ambiguous correlation
//! invalidate the whole observation; no partial prefix is promoted to success.
use super::{io::Result, Audit, Call};
use crate::edit_session::{profile::Profile, record::Context};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub(in crate::edit_session) fn sha(bytes: &[u8]) -> String {
    crate::mcp::replace_file::content_sha256(bytes)
}
pub(in crate::edit_session) fn strict(bytes: &[u8]) -> Result<Value> {
    let crate::mcp::admission::Strict(value) =
        serde_json::from_slice(bytes).map_err(|_| "selected_json_malformed_or_duplicate")?;
    Ok(value)
}
pub(in crate::edit_session) fn operation(
    profile: &Profile,
    name: &str,
) -> Result<(usize, &'static str)> {
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

pub(in crate::edit_session) fn inspect(
    bytes: &[u8],
    profile: &Profile,
    context: &Context,
    registry: &str,
) -> Audit {
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
mod tests;
