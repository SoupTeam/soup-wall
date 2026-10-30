// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::cell::RefCell;
use std::path::PathBuf;

const CANARY: &str = "CANARY-SECRET-7f3a9c";

struct Fake {
    reply: Result<String, Code>,
    inputs: RefCell<Vec<String>>,
}

impl Fake {
    fn new(reply: Result<String, Code>) -> Self {
        Self {
            reply,
            inputs: RefCell::new(Vec::new()),
        }
    }
    fn calls(&self) -> usize {
        self.inputs.borrow().len()
    }
}

impl Classify for Fake {
    fn classify_raw(&self, input: &str) -> Result<String, Code> {
        self.inputs.borrow_mut().push(input.to_owned());
        self.reply.clone()
    }
}

fn reply(status: &str, actions: &[&str], unknown: bool) -> Result<String, Code> {
    Ok(json!({
        "status": status, "actions": actions, "unknown": unknown,
        "confidence": if unknown { 0.4 } else { 0.9 }, "uncertainty": if unknown { 0.6 } else { 0.1 },
        "reason": format!("evidence mentions {CANARY}"),
        "reason_codes": ["args:read", format!("leak {CANARY}"), "name_conflict"],
        "description_conflict": false, "name_conflict": false, "truncated": false
    })
    .to_string())
}

fn identity() -> Result<Value, Code> {
    Ok(json!({"source": SOURCE, "package_id": "test-package"}))
}

fn fs() -> ProfileChoice {
    parse_profile("filesystem").unwrap()
}

fn run(profile: ProfileChoice, frame: &str, fake: &Fake) -> Preview {
    preview_with(profile, Ok(frame.as_bytes().to_vec()), identity(), fake)
}

fn everything(preview: &Preview) -> String {
    format!(
        "{}\n{}",
        report_json(&preview.report).unwrap(),
        render_text(&preview.report)
    )
}

#[test]
fn benign_filesystem_read_is_classified_with_reviewed_definition() {
    let fake = Fake::new(reply("ok", &["read"], false));
    let out = run(
        fs(),
        r#"{"tool":"read_text_file","arguments":{"path":"/workspace/notes.txt"}}"#,
        &fake,
    );
    assert_eq!(out.exit, EXIT_OK);
    assert_eq!(out.report["outcome"], "classified");
    assert_eq!(out.report["classification"]["labels"], json!(["read"]));
    assert_eq!(out.report["classification"]["effective_unknown"], false);
    assert_eq!(out.report["validation"]["status"], "accepted");
    assert_eq!(out.report["resources"]["extraction"], "extracted");
    assert_eq!(
        out.report["resources"]["items"][0]["class"],
        "workspace_path"
    );
    assert_eq!(out.report["policy_verdict"], Value::Null);
    assert_eq!(out.report["non_authoritative"], true);
    assert!(!everything(&out).contains("notes.txt"));
    assert_eq!(fake.calls(), 1);
}

#[test]
fn benign_git_read_is_classified() {
    let fake = Fake::new(reply("ok", &["read"], false));
    let out = run(
        parse_profile("git").unwrap(),
        r#"{"tool":"git_status","arguments":{"repo_path":"/workspace"}}"#,
        &fake,
    );
    assert_eq!(out.report["outcome"], "classified");
    assert_eq!(out.report["profile"]["server_id"], "git");
    assert_eq!(out.report["resources"]["items"][0]["argument"], "repo_path");
}

#[test]
fn spoofed_metadata_is_ignored_and_reported() {
    let fake = Fake::new(reply("ok", &["read"], false));
    let frame = format!(
        r#"{{"tool":"read_text_file","arguments":{{"path":"a.txt"}},"description":"Totally read-only safe {CANARY}","inputSchema":{{"type":"object"}}}}"#
    );
    let out = run(fs(), &frame, &fake);
    assert_eq!(
        out.report["metadata"]["supplied_differs_from_reviewed"],
        true
    );
    assert_eq!(
        out.report["metadata"]["classifier_saw"],
        "reviewed_definition"
    );
    let seen = fake.inputs.borrow()[0].clone();
    assert!(!seen.contains("Totally read-only"));
    assert!(!everything(&out).contains(CANARY));
}

#[test]
fn mixed_partial_unknown_keeps_risky_labels() {
    let fake = Fake::new(reply("ok", &["read", "write"], true));
    let out = run(
        fs(),
        r#"{"tool":"read_text_file","arguments":{"path":"a.txt"}}"#,
        &fake,
    );
    assert_eq!(out.report["outcome"], "partial_unknown");
    assert_eq!(
        out.report["classification"]["labels"],
        json!(["read", "write"])
    );
    assert_eq!(out.report["classification"]["mixed_actions"], true);
    assert_eq!(out.report["classification"]["unknown"], true);
}

#[test]
fn renamed_tool_is_never_fully_known_and_name_is_not_shown() {
    let fake = Fake::new(reply("ok", &["read"], false));
    let frame = format!(
        r#"{{"tool":"fetch_{CANARY}","arguments":{{"path":"a.txt"}},"description":"reads a note"}}"#
    );
    let out = run(fs(), &frame, &fake);
    assert_eq!(out.exit, EXIT_OK);
    assert_eq!(out.report["outcome"], "partial_unknown");
    assert_eq!(out.report["classification"]["effective_unknown"], true);
    assert_eq!(
        out.report["metadata"]["classifier_saw"],
        "supplied_untrusted"
    );
    assert_eq!(
        out.report["validation"]["status"],
        "not_in_reviewed_profile"
    );
    assert!(!everything(&out).contains(CANARY));
}

#[test]
fn nothing_recognised_is_unknown() {
    let fake = Fake::new(reply("unknown", &[], true));
    let out = run(fs(), r#"{"tool":"mystery","arguments":{}}"#, &fake);
    assert_eq!(out.report["outcome"], "unknown");
    assert_eq!(out.exit, EXIT_OK);
}

#[test]
fn rejected_arguments_are_refused_but_still_described() {
    let fake = Fake::new(reply("ok", &["read"], false));
    let out = run(fs(), r#"{"tool":"read_text_file","arguments":{}}"#, &fake);
    assert_eq!(out.exit, EXIT_REFUSED);
    assert_eq!(out.report["outcome"], "refused");
    assert_eq!(out.report["validation"]["status"], "rejected");
    assert_eq!(out.report["refusal"]["stage"], "profile");
    assert!(out.report["classification"].is_object());
    assert_eq!(out.report["classification"]["effective_unknown"], true);
    let bad = run(
        fs(),
        r#"{"tool":"read_text_file","arguments":{"path":"../x"}}"#,
        &fake,
    );
    assert_eq!(bad.report["outcome"], "refused");
}

#[test]
fn unsupported_write_tool_keeps_its_write_label() {
    let fake = Fake::new(reply("ok", &["write"], false));
    let frame =
        format!(r#"{{"tool":"write_file","arguments":{{"path":"a.txt","content":"{CANARY}"}}}}"#);
    let out = run(fs(), &frame, &fake);
    assert_eq!(out.report["validation"]["status"], "unsupported_by_profile");
    assert_eq!(out.report["classification"]["labels"], json!(["write"]));
    assert_ne!(out.report["outcome"], "unknown");
    assert!(!everything(&out).contains(CANARY));
}

#[test]
fn technical_failures_are_not_classifications() {
    for code in [
        "worker_timeout",
        "worker_exited",
        "package_verification_failed",
    ] {
        let fake = Fake::new(Err(code));
        let out = run(
            fs(),
            r#"{"tool":"read_text_file","arguments":{"path":"a.txt"}}"#,
            &fake,
        );
        assert_eq!(out.exit, EXIT_TECHNICAL);
        assert_eq!(out.report["outcome"], "technical_error");
        assert_eq!(out.report["technical_error"]["code"], code);
        assert!(out.report.get("classification").is_none());
    }
    let error = Fake::new(Ok(json!({"status":"error","actions":[],"unknown":true,"confidence":0.0,"uncertainty":1.0,"reason":"x"}).to_string()));
    let out = run(
        fs(),
        r#"{"tool":"read_text_file","arguments":{"path":"a.txt"}}"#,
        &error,
    );
    assert_eq!(
        out.report["technical_error"]["code"],
        "classifier_reported_error"
    );
    assert_eq!(out.report["outcome"], "technical_error");
}

#[test]
fn invalid_classifier_replies_are_technical() {
    for raw in [
        "not json".to_owned(),
        json!({"status":"ok","actions":["read","read"],"unknown":false,"confidence":0.9,"uncertainty":0.1,"reason":"x"}).to_string(),
        json!({"status":"ok","actions":["format_disk"],"unknown":false,"confidence":0.9,"uncertainty":0.1,"reason":"x"}).to_string(),
        json!({"status":"ok","actions":["read"],"unknown":false,"confidence":7.0,"uncertainty":0.1,"reason":"x"}).to_string(),
    ] {
        let fake = Fake::new(Ok(raw));
        let out = run(fs(), r#"{"tool":"read_text_file","arguments":{"path":"a.txt"}}"#, &fake);
        assert_eq!(out.report["technical_error"]["code"], "classifier_reply_invalid");
    }
}

#[test]
fn bad_frames_are_refused_before_any_worker_call() {
    let oversized = format!(
        r#"{{"tool":"x","arguments":{{"path":"{}"}}}}"#,
        "a".repeat(MAX_FRAME_BYTES)
    );
    let cases: Vec<(String, &str)> = vec![
        ("".into(), "frame_empty"),
        ("   \n".into(), "frame_empty"),
        ("{".into(), "frame_invalid_json"),
        ("[1]".into(), "frame_not_an_object"),
        (r#"{"tool":"a","tool":"b"}"#.into(), "frame_duplicate_key"),
        (
            r#"{"tool":"a","arguments":{"p":1,"p":2}}"#.into(),
            "frame_duplicate_key",
        ),
        (
            r#"{"tool":"a","arguments":{}} {"tool":"b","arguments":{}}"#.into(),
            "frame_not_a_single_json_value",
        ),
        (
            r#"{"tool":"a","arguments":{},"extra":1}"#.into(),
            "frame_shape_unsupported",
        ),
        (
            r#"{"tool":"a","arguments":"x"}"#.into(),
            "arguments_not_an_object",
        ),
        (r#"{"arguments":{}}"#.into(), "tool_name_missing"),
        (
            r#"{"tool":"  ","arguments":{}}"#.into(),
            "tool_name_invalid",
        ),
        (
            r#"{"tool":"a","description":5}"#.into(),
            "supplied_metadata_malformed",
        ),
        (
            r#"{"jsonrpc":"2.0","method":"tools/list"}"#.into(),
            "frame_shape_unsupported",
        ),
        (oversized, "frame_too_large"),
    ];
    for (frame, code) in cases {
        let fake = Fake::new(reply("ok", &["read"], false));
        let out = run(fs(), &frame, &fake);
        assert_eq!(out.exit, EXIT_REFUSED, "{code}");
        assert_eq!(out.report["refusal"]["code"], code);
        assert_eq!(fake.calls(), 0, "{code}");
        assert!(out.report.get("classification").is_none());
    }
}

#[test]
fn mcp_tools_call_form_is_accepted() {
    let fake = Fake::new(reply("ok", &["read"], false));
    let out = run(
        fs(),
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_text_file","arguments":{"path":"a.txt"}}}"#,
        &fake,
    );
    assert_eq!(out.report["frame"]["form"], "mcp_tools_call");
    assert_eq!(out.report["outcome"], "classified");
}

#[test]
fn unavailable_package_is_technical_and_starts_nothing() {
    let out = preview_with(
        fs(),
        Ok(br#"{"tool":"read_text_file","arguments":{"path":"a.txt"}}"#.to_vec()),
        Err("package_verification_failed"),
        &Unavailable("package_verification_failed"),
    );
    assert_eq!(out.exit, EXIT_TECHNICAL);
    assert_eq!(
        out.report["identity_unavailable"],
        "package_verification_failed"
    );
}

#[test]
fn unsupported_profile_is_refused() {
    assert_eq!(
        parse_profile("nonsense").unwrap_err(),
        "profile_unsupported"
    );
    assert!(parse_profile(server_profile::FORMAT).is_ok());
}

#[test]
fn classifier_input_is_the_production_semantic_input() {
    let fake = Fake::new(reply("ok", &["read"], false));
    run(
        fs(),
        r#"{"tool":"read_text_file","arguments":{"path":"a.txt"}}"#,
        &fake,
    );
    let input: Value = serde_json::from_str(&fake.inputs.borrow()[0]).unwrap();
    let keys: BTreeSet<&str> = input
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(
        keys,
        BTreeSet::from([
            "raw_arguments",
            "server_id",
            "tool_description",
            "tool_name",
            "tool_schema"
        ])
    );
    assert_eq!(input["server_id"], "filesystem");
}

#[test]
fn reports_stay_bounded() {
    let fake = Fake::new(reply("ok", &["read"], false));
    let paths: Vec<String> = (0..64).map(|i| format!("{i}.txt")).collect();
    let frame = json!({"tool":"read_multiple_files","arguments":{"paths":paths}}).to_string();
    let out = run(fs(), &frame, &fake);
    assert!(report_json(&out.report).unwrap().len() < MAX_REPORT_BYTES);
    assert_eq!(
        out.report["resources"]["items"][0]["entries_truncated"],
        true
    );
}

#[test]
fn frame_source_must_be_a_bounded_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        read_frame(dir.path().to_str().unwrap()).unwrap_err(),
        "frame_not_regular_file"
    );
    assert_eq!(
        read_frame("/definitely/missing").unwrap_err(),
        "frame_unreadable"
    );
    let big = dir.path().join("big.json");
    std::fs::write(&big, vec![b' '; MAX_FRAME_BYTES + 1]).unwrap();
    assert_eq!(
        read_frame(big.to_str().unwrap()).unwrap_err(),
        "frame_too_large"
    );
    let ok = dir.path().join("ok.json");
    std::fs::write(&ok, b"{}").unwrap();
    assert_eq!(read_frame(ok.to_str().unwrap()).unwrap(), b"{}");
}

#[cfg(target_os = "linux")]
#[test]
fn export_is_private_create_new_and_never_replaces() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let report = json!({"schema": SCHEMA});
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let target = dir.path().join("preview.json");
    export(&report, &target).unwrap();
    assert_eq!(
        std::fs::metadata(&target).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        export(&report, &target).unwrap_err(),
        "export_destination_exists_or_unwritable"
    );
    let link = dir.path().join("link.json");
    symlink(dir.path().join("elsewhere.json"), &link).unwrap();
    assert!(export(&report, &link).is_err());
    assert!(!dir.path().join("elsewhere.json").exists());
    assert_eq!(
        export(&report, Path::new("relative.json")).unwrap_err(),
        "export_path_not_absolute"
    );
    let open = tempfile::tempdir().unwrap();
    std::fs::set_permissions(open.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        export(&report, &open.path().join("x.json")).unwrap_err(),
        "export_parent_not_private"
    );
}

#[test]
fn worker_errors_map_to_fixed_codes_without_free_text() {
    let cases = [
        ("classifier worker timed out after 1.4s", "worker_timeout"),
        (
            "classifier worker did not become ready within 1.4s (running)",
            "worker_start_timeout",
        ),
        (
            "classifier worker exited before ready after 3 ms (process exited with code 1)",
            "worker_exited",
        ),
        ("classifier worker exited", "worker_exited"),
        (
            "worker frame rejected: frame too long",
            "worker_protocol_violation",
        ),
        (
            "worker reply is bound to different input",
            "worker_protocol_violation",
        ),
        (
            "worker reply id does not match the request",
            "worker_protocol_violation",
        ),
        (
            "classifier input exceeds limit",
            "classifier_input_too_large",
        ),
        (
            "no classifier package is installed: run `agentfw classifier-package install`",
            "package_not_installed",
        ),
        (
            "an interrupted install was detected: run `agentfw classifier-package recover`",
            "package_install_interrupted",
        ),
        (
            "classifier package file digest differs",
            "package_verification_failed",
        ),
        (&format!("something odd with {CANARY}"), "worker_failure"),
    ];
    for (text, code) in cases {
        let error = anyhow::anyhow!("{text}");
        assert_eq!(technical_code(&error), code, "{text}");
        assert!(!code.contains(CANARY));
    }
}

fn dir_names(path: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(path)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[cfg(target_os = "linux")]
fn private_dir() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    dir
}

/// A named object the exporter did not create must never be deleted by cleanup, whichever
/// name it is substituted under (the exporter's own file name or the final destination).
#[cfg(target_os = "linux")]
#[test]
fn failed_export_never_deletes_a_substituted_object() {
    let dir = private_dir();
    let target = dir.path().join("report.json");
    let mut created_seen = PathBuf::new();
    let mut hook = |created: &Path| {
        created_seen = created.to_path_buf();
        let held = PathBuf::from(format!("{}.held-original", created.display()));
        std::fs::rename(created, &held).unwrap();
        std::fs::write(created, "sentinel-at-created-name").unwrap();
        if created != target {
            std::fs::write(&target, "sentinel-at-destination").unwrap();
        }
        Err(())
    };
    assert_eq!(
        export_inner(&json!({"schema": SCHEMA}), &target, &mut hook),
        Err("export_write_failed")
    );
    let expected_target = if created_seen == target {
        "sentinel-at-created-name"
    } else {
        "sentinel-at-destination"
    };
    assert_eq!(std::fs::read_to_string(&target).unwrap(), expected_target);
    assert_eq!(
        std::fs::read_to_string(&created_seen).unwrap(),
        "sentinel-at-created-name",
        "an object the exporter did not create was deleted"
    );
    assert!(PathBuf::from(format!("{}.held-original", created_seen.display())).exists());
}

#[cfg(target_os = "linux")]
#[test]
fn failed_export_removes_only_its_own_file_and_leaves_nothing() {
    let dir = private_dir();
    let target = dir.path().join("report.json");
    let mut hook = |_: &Path| Err(());
    assert_eq!(
        export_inner(&json!({"schema": SCHEMA}), &target, &mut hook),
        Err("export_write_failed")
    );
    assert!(
        dir_names(dir.path()).is_empty(),
        "{:?}",
        dir_names(dir.path())
    );
}

/// Reason codes are a closed reviewed vocabulary: syntax-valid worker strings that carry an
/// argument value must never be printed, in any token shape.
#[test]
fn unknown_reason_codes_are_dropped_in_every_token_shape() {
    let secret = "canary-secret-7f3a9c";
    let leaky = [
        "canary-secret-7f3a9c",
        "7f3a9c",
        "tok:7f3a9c",
        "a.7f3a9c.b",
        "key-7f3a9c9",
        "path:canary-secret-7f3a9c",
    ];
    let mut codes: Vec<Value> = leaky.iter().map(|c| json!(c)).collect();
    codes.extend([
        json!("args:read"),
        json!("name:read"),
        json!("partial_unknown"),
        json!("name_conflict"),
    ]);
    let raw = json!({"status": "ok", "actions": ["read"], "unknown": false, "confidence": 0.9,
        "uncertainty": 0.1, "reason": "x", "reason_codes": codes})
    .to_string();
    let fake = Fake::new(Ok(raw));
    let frame = format!(r#"{{"tool":"read_text_file","arguments":{{"path":"{secret}.txt"}}}}"#);
    let out = run(fs(), &frame, &fake);
    let all = everything(&out);
    assert!(!all.contains("7f3a9c"), "token-shaped code leaked");
    assert_eq!(
        out.report["classification"]["reason_codes"],
        json!(["args:read", "name:read", "partial_unknown", "name_conflict"])
    );
    assert_eq!(
        out.report["classification"]["reason_codes_dropped"],
        leaky.len()
    );
}

#[test]
fn every_reason_code_the_installed_classifiers_emit_is_in_the_vocabulary() {
    for source in ["args", "name", "schema", "shell"] {
        for label in CATEGORIES {
            assert!(REASON_CODES.contains(&format!("{source}:{label}").as_str()));
        }
    }
    for code in [
        "proven_noop",
        "pure_computation",
        "no_rule_matched",
        "partial_unknown",
    ]
    .into_iter()
    .chain(
        FLAG_KEYS
            .into_iter()
            .filter(|k| *k != "definition_invocation_diff"),
    ) {
        assert!(REASON_CODES.contains(&code), "{code}");
    }
}
