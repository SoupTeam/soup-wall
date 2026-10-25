// SPDX-License-Identifier: Apache-2.0
//! Bounded lookup, not history search. Untrusted records contribute only fixed
//! reason codes and digests. They never become authenticated runtime evidence.
use super::{sha, strict, PilotArgs};
use serde::Serialize;
use serde_json::Value;

const FILE_CAP: u64 = 8 * 1024 * 1024;
const LINE_CAP: usize = 64 * 1024;
const ROW_CAP: usize = 8192;
const AGE_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Serialize)]
pub struct Incident {
    pub source: &'static str,
    pub completeness: &'static str,
    pub boundary: &'static str,
    pub reason_code: &'static str,
    pub explanation: &'static str,
    pub next_step: &'static str,
    pub current_instance_binding: &'static str,
    pub execution: &'static str,
    pub model_consumption: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_sha256: Option<String>,
    pub selected_record_sha256: Vec<String>,
}
impl Incident {
    fn unknown(source: &'static str, reason: &'static str) -> Self {
        Self {source, completeness:"incomplete",boundary:"unknown",reason_code:reason,
            explanation:"The selected evidence cannot establish an attributable incident cause. No current execution or model-consumption claim is made.",
            next_step:"Select one private original audit/report file and an exact call ID or session/event reference. Retain rotated evidence privately; never share raw logs.",
            current_instance_binding:"not_recorded_by_this_source", execution:"unknown", model_consumption:"unknown",file_sha256:None,selected_record_sha256:vec![]}
    }
    fn observed(
        &mut self,
        boundary: &'static str,
        reason: &'static str,
        explanation: &'static str,
        next: &'static str,
    ) {
        self.completeness = "selected_records_only_history_not_scanned";
        self.boundary = boundary;
        self.reason_code = reason;
        self.explanation = explanation;
        self.next_step = next;
    }
}

fn native_tool(tool: &str) -> bool {
    [
        super::server_profile::FORMAT,
        super::server_profile::git::FORMAT,
    ]
    .iter()
    .any(|format| {
        super::server_profile::original_manifest_for(format)
            .ok()
            .and_then(|v| v["tools"].as_array().cloned())
            .is_some_and(|tools| tools.iter().any(|v| v["name"] == tool))
    })
}
fn known_code(row: &Value, code: &str) -> bool {
    row["reason_codes"]
        .as_array()
        .is_some_and(|codes| codes.iter().any(|v| v == code))
}
fn digest(value: &Value) -> bool {
    value.as_str().is_some_and(crate::native::is_digest)
}
fn identifier(value: &Value) -> bool {
    value.as_str().is_some_and(crate::native::identifier)
}
fn scoped_fields(row: &Value, nullable: bool) -> bool {
    ["host_session", "agent_id", "parent_id"].iter().all(|key| {
        row.get(*key)
            .is_none_or(|v| identifier(v) || (nullable && v.is_null()))
    })
}
fn native_reason(row: &Value, report: &mut Incident) {
    let refused =
        matches!(row["verdict"].as_str(), Some("ask" | "deny")) && row["released"] == false;
    // Schema/owner/transport failures are returned before this audit producer
    // writes a call/result row. A similarly named operator rule is not evidence
    // of those failures. Only the producer's recorded provenance flag supports
    // this narrower observation about unavailable admission evidence.
    if refused
        && row["verdict"] == "deny"
        && row["provenance_incomplete"] == true
        && (known_code(row, "native_provenance_context_unavailable")
            || known_code(row, "native_provenance_unrecordable"))
    {
        report.observed("daemon_uncertainty","recorded_daemon_uncertainty","Local record reports unavailable admission evidence; cause beyond that boundary is unknown.",
            "Inspect private daemon health and bounded audit retention; retry only through the normal fail-closed launch workflow.");
    } else if refused && row["event"] == "native_result" {
        report.observed("result_release","recorded_result_withheld","Local audit records a withheld result. A tool effect may already have occurred; withholding does not undo it.",
            "Review the selected result policy and risk context privately. Do not force release or assume rollback; check effects separately.");
    } else if refused && row["event"] == "native_call" {
        report.observed("native_policy","recorded_native_policy_refusal","Local audit records an Ask/Deny at native action/resource admission. It does not prove a tool executed.",
            "Review the exact request and current action/resource policy privately. Use the supported operator approval flow only for an intended Ask; do not weaken policy.");
    } else if row["verdict"] == "allow" && row["released"] == true {
        report.observed("native_admission","recorded_native_admission_only","Local audit records admission/release, not server execution, host delivery or model consumption.",
            "For execution questions retain the independent process/effect witnesses from the owned run; doctor does not call tools.");
    }
}

fn native_shape(row: &Value) -> bool {
    row["tool"].as_str().is_some_and(native_tool)
        && row["truncated"] == false
        && scoped_fields(row, false)
        && row["provenance_incomplete"].is_boolean()
        && row["risk_score"]
            .as_u64()
            .is_some_and(|v| v <= u8::MAX.into())
        && row["latency_us"].as_u64().is_some()
        && row["findings"]
            .as_array()
            .is_some_and(|v| v.iter().all(Value::is_object))
        && row["egress_hosts"]
            .as_array()
            .is_some_and(|v| v.iter().all(Value::is_string))
        && row
            .get("taint")
            .is_some_and(|v| v.is_null() || v.is_object())
        && row
            .get("rule")
            .is_some_and(|v| v.is_null() || v.is_string())
        && row["reason_codes"].as_array().is_some_and(|v| {
            v.len() <= 256 && v.iter().all(|v| v.as_str().is_some_and(|v| v.len() <= 256))
        })
}

fn native_records(
    selected: &[Value],
    registry: &str,
    by_call: bool,
    report: &mut Incident,
) -> Result<(), &'static str> {
    let now = crate::protection_status::now_ms();
    let first = &selected[0];
    let mut last_seq = None;
    let mut kinds = std::collections::BTreeSet::new();
    for row in selected {
        let at = row["at_ms"].as_u64().ok_or("incident_missing_provenance")?;
        if at > now.saturating_add(5000) || now.saturating_sub(at) > AGE_MS {
            return Err("incident_stale_or_future_record");
        }
        let seq = row["seq"]
            .as_u64()
            .filter(|v| *v > 0)
            .ok_or("incident_missing_provenance")?;
        let event = row["event"].as_str().ok_or("incident_missing_provenance")?;
        if row["registry_sha256"] != registry
            || row["shadow"] != false
            || !identifier(&row["session"])
            || row["session"] != first["session"]
            || last_seq.is_some_and(|last| seq <= last)
            || !kinds.insert(event)
        {
            return Err("incident_mismatched_or_ambiguous");
        }
        if matches!(event, "native_session_expired" | "native_session_ended") {
            // The accepted terminal format records cleanup, not a failed call,
            // and intentionally has no tool, call ID or result-binding fields.
            if by_call
                || selected.len() != 1
                || row["verdict"] != "allow"
                || row["released"] != false
                || !identifier(&row["session_id"])
                || !scoped_fields(row, true)
                || [
                    "tool",
                    "call_id",
                    "binding_sha256",
                    "reason_codes",
                    "truncated",
                ]
                .iter()
                .any(|key| row.get(*key).is_some())
            {
                return Err("incident_mismatched_or_ambiguous");
            }
            report.observed("session_lifecycle", "recorded_session_terminal_cleanup",
                "Local audit records terminal cleanup of the selected session epoch. It does not establish a call failure cause or authenticate the current daemon instance.",
                "Use fresh authority through the normal operator lifecycle workflow if another run is intended; do not replay old grants or reset shared-host risk.");
        } else {
            if !matches!(event, "native_call" | "native_result")
                || !native_shape(row)
                || !matches!(row["verdict"].as_str(), Some("allow" | "ask" | "deny"))
                || row["released"].as_bool() != Some(row["verdict"] == "allow")
            {
                return Err("incident_inconsistent_native_record");
            }
            let bound = identifier(&row["call_id"]) && digest(&row["binding_sha256"]);
            if event == "native_call" {
                let admitted = row["released"] == true;
                if (admitted && !bound)
                    || (!admitted
                        && (row.get("call_id") != Some(&Value::Null)
                            || row.get("binding_sha256") != Some(&Value::Null)))
                    || row.get("content_sha256") != Some(&Value::Null)
                    || row.get("delivery") != Some(&Value::Null)
                {
                    return Err("incident_inconsistent_native_binding");
                }
            } else if !bound
                || !digest(&row["content_sha256"])
                || !matches!(
                    row["delivery"].as_str(),
                    Some("parent" | "model" | "mcp_host")
                )
            {
                return Err("incident_inconsistent_native_binding");
            }
            if selected.len() > 1
                && (selected.len() != 2
                    || first["event"] != "native_call"
                    || first["released"] != true
                    || row["tool"] != first["tool"]
                    || row["call_id"] != first["call_id"]
                    || row["binding_sha256"] != first["binding_sha256"]
                    || ["host_session", "agent_id", "parent_id"]
                        .iter()
                        .any(|key| row.get(*key) != first.get(*key))
                    || (last_seq.is_some() && event != "native_result"))
            {
                return Err("incident_mismatched_or_ambiguous");
            }
            native_reason(row, report);
        }
        report
            .selected_record_sha256
            .push(crate::native::canonical_digest(row));
        last_seq = Some(seq);
    }
    if selected.len() == 1 && first["event"] == "native_result" {
        report.completeness = "selected_result_only_invocation_not_in_file";
    } else if selected.len() == 1 && first["event"] == "native_call" && first["released"] == true {
        report.completeness = "selected_invocation_only_result_not_in_file";
    }
    Ok(())
}

pub(super) fn lookup(
    args: &PilotArgs,
    registry: Option<&str>,
    classifier: Option<&str>,
) -> Incident {
    let source = match args.incident_source.as_deref() {
        Some("native-audit") => "local_native_audit_assertion",
        Some("collector-report") => "local_collector_report_assertion",
        _ => "unsupported_selected_source",
    };
    let mut report = Incident::unknown(source, "incident_unavailable_or_unsafe");
    let Some(path) = args.incident_file.as_deref() else {
        return report;
    };
    let Ok(bytes) = crate::doctor::read_private(path, FILE_CAP) else {
        return report;
    };
    report.file_sha256 = Some(sha(&bytes));
    let result = lookup_bytes(args, &bytes, registry, classifier, &mut report);
    if let Err(code) = result {
        let digest = report.file_sha256.take();
        report = Incident::unknown(source, code);
        report.file_sha256 = digest;
    }
    report
}

fn lookup_bytes(
    args: &PilotArgs,
    bytes: &[u8],
    registry: Option<&str>,
    classifier: Option<&str>,
    report: &mut Incident,
) -> Result<(), &'static str> {
    if bytes.is_empty() || !bytes.ends_with(b"\n") {
        return Err("incident_incomplete_jsonl");
    }
    let source = args.incident_source.as_deref();
    let native = source == Some("native-audit");
    if !native && source != Some("collector-report") {
        return Err("incident_source_unsupported");
    }
    let call = args
        .incident_call_id
        .as_deref()
        .filter(|s| crate::native::identifier(s));
    let session = args
        .incident_session
        .as_deref()
        .filter(|s| crate::native::identifier(s));
    let host = args
        .incident_host_id_json
        .as_deref()
        .filter(|s| s.len() <= 512)
        .and_then(|s| strict(s.as_bytes()).ok())
        .filter(|v| {
            v.as_i64()
                .is_some_and(|v| v.unsigned_abs() <= 9_007_199_254_740_991)
                || v.as_str().is_some_and(|s| !s.is_empty() && s.len() <= 128)
        });
    if native {
        if !(call.is_some() && args.incident_seq.is_none() && host.is_none()
            || call.is_none() && args.incident_seq.is_some() && session.is_some() && host.is_none())
        {
            return Err("incident_selector_invalid");
        }
    } else if host.is_none()
        || !matches!(args.incident_server.as_deref(), Some("filesystem" | "git"))
        || call.is_some()
        || args.incident_seq.is_some()
    {
        return Err("incident_selector_invalid");
    }
    let mut selected = Vec::new();
    for (index, line) in bytes[..bytes.len() - 1].split(|b| *b == b'\n').enumerate() {
        if index >= ROW_CAP {
            return Err("incident_record_limit");
        }
        if line.is_empty() {
            return Err("incident_malformed_record");
        }
        if line.len() > LINE_CAP {
            return Err("incident_record_oversized");
        }
        let row = strict(line).map_err(|_| "incident_malformed_record")?;
        if !row.is_object() {
            return Err("incident_malformed_record");
        }
        let matches = if native {
            if let Some(call) = call {
                row["call_id"] == call
            } else {
                row["session"] == session.unwrap() && row["seq"].as_u64() == args.incident_seq
            }
        } else {
            row["host_call_id"] == *host.as_ref().unwrap()
                && row["server_id"].as_str() == args.incident_server.as_deref()
        };
        if matches {
            if selected.len() >= 16 {
                return Err("incident_ambiguous_reference");
            }
            selected.push(row);
        }
    }
    if selected.is_empty() {
        return Err("incident_missing_or_rotated");
    }
    let registry = registry.ok_or("incident_registry_unattributable")?;
    if !crate::native::is_digest(registry) {
        return Err("incident_registry_unattributable");
    }
    if native {
        native_records(&selected, registry, call.is_some(), report)?;
    } else {
        // Collector reports do not record an authenticated instance or timestamp.
        // Even an exact typed ID and digest match is only a local assertion.
        if selected.len() != 1 {
            return Err("incident_ambiguous_reference");
        }
        let row = &selected[0];
        let tool = row["tool"].as_str().ok_or("incident_missing_provenance")?;
        let format = if args.incident_server.as_deref() == Some("git") {
            super::server_profile::git::FORMAT
        } else {
            super::server_profile::FORMAT
        };
        let manifest = super::server_profile::original_manifest_for(format)
            .map_err(|_| "incident_missing_provenance")?;
        let definition = manifest["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == tool)
            .ok_or("incident_tool_mismatch")?;
        if row["event"] != "mcp_classification"
            || row["contract_version"] != "sw-classification/candidate-1"
            || !matches!(
                row["source"].as_str(),
                Some("rule-baseline/python" | "rule-baseline/packaged-worker")
            )
            || row["registry_sha256"] != registry
            || !classifier.is_some_and(crate::native::is_digest)
            || row["classifier_sha256"].as_str() != classifier
            || row["schema_sha256"] != crate::native::canonical_digest(&definition["inputSchema"])
            || row["definition_sha256"] != crate::native::canonical_digest(definition)
            || ["snapshot_sha256", "input_sha256", "args_sha256"]
                .iter()
                .any(|key| !digest(&row[*key]))
        {
            return Err("incident_missing_or_mismatched_provenance");
        }
        let unknown = row["classification"]["unknown"]
            .as_bool()
            .ok_or("incident_missing_provenance")?;
        let uncertainty = row["classification"]["uncertainty"]
            .as_f64()
            .filter(|v| (0.0..=1.0).contains(v))
            .ok_or("incident_missing_provenance")?;
        let actions = row["classification"]["actions"]
            .as_array()
            .ok_or("incident_missing_provenance")?;
        let unique: std::collections::BTreeSet<_> =
            actions.iter().filter_map(Value::as_str).collect();
        if actions.len() > 5
            || unique.len() != actions.len()
            || !unique.iter().all(|action| {
                matches!(
                    *action,
                    "read" | "write" | "delete" | "send_data" | "change_permissions"
                )
            })
            || !row["classification"]["confidence"]
                .as_f64()
                .is_some_and(|v| (0.0..=1.0).contains(&v))
            || !digest(&row["classification"]["reason_sha256"])
            || row["policy"] != "reached"
            || row.get("failure") != Some(&Value::Null)
            || !matches!(
                row["authoritative_verdict"].as_str(),
                Some("allow" | "ask" | "deny")
            )
            || !matches!(
                row["adapter_verdict"].as_str(),
                Some("allow" | "ask" | "deny")
            )
            || row.get("operator_execution_profile") != Some(&Value::Null)
            || row["latency_us"].as_u64().is_none()
        {
            return Err("incident_inconsistent_classification");
        }
        let registry = super::registry_for(format).map_err(|_| "incident_missing_provenance")?;
        let baseline = registry["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == tool)
            .ok_or("incident_tool_mismatch")?["action_class"]
            .clone();
        let mapped = if !unknown && actions.len() == 1 {
            Value::String(
                match actions[0].as_str().unwrap() {
                    "read" => "read_only",
                    "write" => "side_effecting",
                    "delete" => "destructive",
                    "send_data" => "network",
                    _ => "privilege_changing",
                }
                .into(),
            )
        } else {
            Value::Null
        };
        let mismatch = if mapped.is_null() {
            Value::Null
        } else {
            Value::Bool(mapped != baseline)
        };
        if row["trusted_baseline"] != baseline
            || row.get("mapped_action_class") != Some(&mapped)
            || row.get("baseline_mismatch") != Some(&mismatch)
            || ((unknown || uncertainty >= 0.8) && row["authoritative_verdict"] == "allow")
        {
            return Err("incident_inconsistent_classification");
        }
        if (unknown || uncertainty >= 0.8)
            && matches!(row["authoritative_verdict"].as_str(), Some("ask" | "deny"))
        {
            report.observed("classifier","recorded_classifier_uncertainty","Selected collector record reports classifier uncertainty together with an Ask/Deny, without establishing uncertainty as the sole cause. Its time and current instance are not recorded; freshness is unknown.",
                "Inspect the original tool/schema and reviewed classifier privately; use the supported operator flow for an intended Ask. Do not assume a model consumed a result.");
        }
        report
            .selected_record_sha256
            .push(crate::native::canonical_digest(row));
    }
    if report.boundary == "unknown" {
        return Err("incident_cause_not_established");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn args() -> PilotArgs {
        PilotArgs {
            incident_source: Some("native-audit".into()),
            incident_session: Some("epoch".into()),
            incident_seq: Some(2),
            ..Default::default()
        }
    }
    fn call_args() -> PilotArgs {
        PilotArgs {
            incident_source: Some("native-audit".into()),
            incident_call_id: Some("selected".into()),
            ..Default::default()
        }
    }
    fn row() -> Value {
        json!({"at_ms":crate::protection_status::now_ms(),"session":"epoch","seq":2,"event":"native_call",
        "tool":"read_text_file","verdict":"ask","released":false,"shadow":false,"truncated":false,"call_id":null,"binding_sha256":null,"content_sha256":null,"delivery":null,
        "provenance_incomplete":false,"risk_score":0,"findings":[],"egress_hosts":[],"taint":null,"latency_us":10,
        "registry_sha256":"a".repeat(64),"reason_codes":[],"rule":"PRIVATE-CANARY-RULE","raw":"PRIVATE-CANARY-ARGS"})
    }
    fn admitted() -> Value {
        let mut r = row();
        r["verdict"] = json!("allow");
        r["released"] = json!(true);
        r["call_id"] = json!("selected");
        r["binding_sha256"] = json!("b".repeat(64));
        r
    }
    fn withheld() -> Value {
        let mut r = admitted();
        r["event"] = json!("native_result");
        r["seq"] = json!(3);
        r["verdict"] = json!("deny");
        r["released"] = json!(false);
        r["content_sha256"] = json!("c".repeat(64));
        r["delivery"] = json!("mcp_host");
        r
    }
    fn grade(args: &PilotArgs, rows: &[Value]) -> Incident {
        let mut report = Incident::unknown("local_native_audit_assertion", "unknown");
        let mut bytes = Vec::new();
        for row in rows {
            bytes.extend(serde_json::to_vec(row).unwrap());
            bytes.push(b'\n');
        }
        match lookup_bytes(
            args,
            &bytes,
            Some(&"a".repeat(64)),
            Some(&"b".repeat(64)),
            &mut report,
        ) {
            Ok(()) => report,
            Err(code) => Incident::unknown("local_native_audit_assertion", code),
        }
    }
    #[test]
    fn selected_refusal_is_local_only_and_allowlisted() {
        let report = grade(&args(), &[row()]);
        assert_eq!(report.reason_code, "recorded_native_policy_refusal");
        assert_eq!(report.execution, "unknown");
        assert_eq!(
            report.current_instance_binding,
            "not_recorded_by_this_source"
        );
        assert!(!serde_json::to_string(&report).unwrap().contains("CANARY"));
    }
    #[test]
    fn paired_result_withholding_is_not_rollback() {
        let report = grade(&call_args(), &[admitted(), withheld()]);
        assert_eq!(report.reason_code, "recorded_result_withheld");
        assert_eq!(report.selected_record_sha256.len(), 2);
        assert!(report.explanation.contains("already have occurred"));
    }
    #[test]
    fn partial_result_and_invocation_remain_explicitly_partial() {
        let report = grade(&call_args(), &[withheld()]);
        assert_eq!(
            report.completeness,
            "selected_result_only_invocation_not_in_file"
        );
        let report = grade(&call_args(), &[admitted()]);
        assert_eq!(
            report.completeness,
            "selected_invocation_only_result_not_in_file"
        );
    }
    #[test]
    fn exact_session_sequence_and_native_call_selection_are_distinct() {
        let mut a = args();
        a.incident_session = Some("other".into());
        assert_eq!(
            grade(&a, &[row()]).reason_code,
            "incident_missing_or_rotated"
        );
        assert_eq!(
            grade(&call_args(), &[row()]).reason_code,
            "incident_missing_or_rotated"
        );
        let mut unrelated = row();
        unrelated["seq"] = json!(99);
        assert_eq!(
            grade(&args(), &[unrelated]).reason_code,
            "incident_missing_or_rotated"
        );
    }
    #[test]
    fn repeated_or_mismatched_bindings_never_supply_a_cause() {
        assert_eq!(
            grade(&args(), &[row(), row()]).reason_code,
            "incident_mismatched_or_ambiguous"
        );
        let mut result = withheld();
        result["binding_sha256"] = json!("d".repeat(64));
        assert_eq!(
            grade(&call_args(), &[admitted(), result]).boundary,
            "unknown"
        );
        assert_eq!(
            grade(&call_args(), &[withheld(), admitted()]).boundary,
            "unknown"
        );
        let mut refused = row();
        refused["call_id"] = json!("selected");
        refused["binding_sha256"] = json!("b".repeat(64));
        assert_eq!(
            grade(&call_args(), &[refused, withheld()]).boundary,
            "unknown"
        );
    }
    #[test]
    fn contradictory_verdicts_or_invented_refusal_reasons_are_not_interpreted() {
        let mut r = admitted();
        r["released"] = json!(false);
        r["reason_codes"] = json!(["native_schema_mismatch"]);
        assert_eq!(
            grade(&call_args(), &[r]).reason_code,
            "incident_inconsistent_native_record"
        );
        let mut r = admitted();
        r["reason_codes"] = json!(["native_schema_mismatch"]);
        assert_eq!(
            grade(&call_args(), &[r]).reason_code,
            "recorded_native_admission_only"
        );
    }
    #[test]
    fn malformed_truncated_future_stale_mismatch_and_shadow_are_unknown() {
        for (key, value) in [
            ("registry_sha256", json!("b".repeat(64))),
            ("shadow", json!(true)),
            ("truncated", json!(true)),
            ("released", json!(true)),
            ("session", json!("/private/CANARY x")),
            ("tool", json!("unsupported")),
        ] {
            let mut r = row();
            r[key] = value;
            assert_eq!(grade(&args(), &[r]).boundary, "unknown", "{key}");
        }
        for timestamp in [1, crate::protection_status::now_ms() + 60000] {
            let mut r = row();
            r["at_ms"] = json!(timestamp);
            assert_eq!(
                grade(&args(), &[r]).reason_code,
                "incident_stale_or_future_record"
            );
        }
    }
    #[test]
    fn malformed_duplicate_and_over_limit_records_are_not_skipped() {
        for bytes in [
            b"{\"call_id\":\"selected\",\"call_id\":\"other\"}\n".to_vec(),
            b"{}\nnot json\n".to_vec(),
            vec![b'x'; LINE_CAP + 2],
            b"{}".to_vec(),
        ] {
            let mut report = Incident::unknown("test", "unknown");
            assert!(
                lookup_bytes(&args(), &bytes, Some(&"a".repeat(64)), None, &mut report).is_err()
            );
        }
        let bytes = b"{}\n".repeat(ROW_CAP + 1);
        let mut report = Incident::unknown("test", "unknown");
        assert_eq!(
            lookup_bytes(&args(), &bytes, None, None, &mut report),
            Err("incident_record_limit")
        );
    }
    #[test]
    fn terminal_cleanup_is_not_a_failed_call_cause() {
        let r = json!({"at_ms":crate::protection_status::now_ms(),"session":"epoch","session_id":"physical","seq":2,"event":"native_session_expired",
            "verdict":"allow","shadow":false,"released":false,"registry_sha256":"a".repeat(64),"host_session":null,"agent_id":null,"parent_id":null});
        let report = grade(&args(), &[r]);
        assert_eq!(report.reason_code, "recorded_session_terminal_cleanup");
        assert_eq!(report.execution, "unknown");
    }
    fn collector() -> (PilotArgs, Value) {
        let manifest = super::super::server_profile::original_manifest();
        let tool = manifest["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "read_text_file")
            .unwrap();
        let args = PilotArgs {
            incident_source: Some("collector-report".into()),
            incident_host_id_json: Some("1".into()),
            incident_server: Some("filesystem".into()),
            ..Default::default()
        };
        let row = json!({"event":"mcp_classification","contract_version":"sw-classification/candidate-1","source":"rule-baseline/python","host_call_id":1,"server_id":"filesystem","tool":"read_text_file","registry_sha256":"a".repeat(64),
            "classifier_sha256":"b".repeat(64),"schema_sha256":crate::native::canonical_digest(&tool["inputSchema"]),"definition_sha256":crate::native::canonical_digest(tool),
            "snapshot_sha256":"c".repeat(64),"input_sha256":"d".repeat(64),"args_sha256":"e".repeat(64),"mapped_action_class":null,"trusted_baseline":"read_only","operator_execution_profile":null,"baseline_mismatch":null,
            "classification":{"actions":[],"unknown":true,"confidence":0.0,"uncertainty":0.9,"reason_sha256":"f".repeat(64)},"adapter_verdict":"ask","policy":"reached","failure":null,"latency_us":10,"authoritative_verdict":"ask","raw":"PRIVATE-CANARY"});
        (args, row)
    }
    #[test]
    fn typed_collector_identity_and_original_schema_are_required() {
        let (a, mut r) = collector();
        assert_eq!(
            grade(&a, &[r.clone()]).reason_code,
            "recorded_classifier_uncertainty"
        );
        r["host_call_id"] = json!("1");
        assert_eq!(
            grade(&a, &[r.clone()]).reason_code,
            "incident_missing_or_rotated"
        );
        r["host_call_id"] = json!(1);
        r["schema_sha256"] = json!("c".repeat(64));
        assert_eq!(
            grade(&a, &[r]).reason_code,
            "incident_missing_or_mismatched_provenance"
        );
    }
    #[test]
    fn collector_contract_failure_or_inconsistent_state_stays_unknown() {
        for (key, value) in [
            ("contract_version", json!("wrong")),
            ("policy", json!("not_reached")),
            ("failure", json!("classifier_error")),
            ("source", json!("test-double/read-v1")),
            ("authoritative_verdict", json!("allow")),
            ("args_sha256", json!(null)),
            ("mapped_action_class", json!("read_only")),
        ] {
            let (a, mut r) = collector();
            r[key] = value;
            assert_eq!(grade(&a, &[r]).boundary, "unknown", "{key}");
        }
    }
}
