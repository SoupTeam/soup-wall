// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)
use super::*;

/// The audit record must be readable without this crate's source. The trust
/// class is the security-relevant field, so it is emitted rather than left
/// to be inferred from the origin, and the origin and name are emitted as
/// their own values rather than recovered by splitting the human label.
#[test]
fn a_taint_record_carries_structured_origin_and_trust() {
    let taint = AuditTaint {
        source: "mcp:docs".into(),
        origin: "mcp".into(),
        source_name: Some("docs".into()),
        trust: "untrusted".into(),
        seq: 7,
    };
    let rendered = serde_json::to_value(&taint).expect("taint serializes");
    assert_eq!(rendered["origin"], "mcp");
    assert_eq!(rendered["source_name"], "docs");
    assert_eq!(
        rendered["trust"], "untrusted",
        "a reader must not have to know this crate to classify the source"
    );
    assert_eq!(rendered["seq"], 7);
    assert_eq!(
        rendered["source"], "mcp:docs",
        "the human label stays for existing consumers"
    );
}

/// An origin with no name of its own must omit the field rather than emit an
/// empty string, which a consumer could mistake for a source identity.
#[test]
fn an_unnamed_origin_omits_the_name_rather_than_emitting_an_empty_one() {
    let taint = AuditTaint {
        source: "user".into(),
        origin: "user".into(),
        source_name: None,
        trust: "trusted".into(),
        seq: 1,
    };
    let rendered = serde_json::to_value(&taint).expect("taint serializes");
    assert!(
        rendered.get("source_name").is_none(),
        "absent, not empty: {rendered}"
    );
}

fn line() -> AuditLine {
    AuditLine {
        at_ms: 1,
        session: "s1".into(),
        agent_id: None,
        parent_id: None,
        seq: 2,
        event: "tool_call".into(),
        tool: Some("Bash".into()),
        verdict: "deny".into(),
        shadow: true,
        rule: Some("deny-x".into()),
        risk_score: 90,
        findings: vec![],
        taint: None,
        judge: None,
        approval: None,
        egress_hosts: vec![],
        latency_us: 120,
        truncated: false,
        raw: None,
    }
}

#[test]
fn writes_one_json_object_per_line() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("audit.jsonl");
    let sink = AuditSink::open(&p).unwrap();
    sink.write(&line()).unwrap();
    sink.write(&line()).unwrap();

    let body = std::fs::read_to_string(&p).unwrap();
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2);
    for l in lines {
        let v: serde_json::Value = serde_json::from_str(l).unwrap();
        assert_eq!(v["session"], "s1");
        assert_eq!(v["shadow"], true);
    }
}

#[test]
fn appends_rather_than_truncating_on_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("audit.jsonl");
    AuditSink::open(&p).unwrap().write(&line()).unwrap();
    AuditSink::open(&p).unwrap().write(&line()).unwrap();
    assert_eq!(std::fs::read_to_string(&p).unwrap().lines().count(), 2);
}

#[test]
fn legacy_partial_append_failure_requires_operator_repair_and_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let sink = AuditSink::open(&path).unwrap();
    sink.write_native(&serde_json::json!({"event":"before"}))
        .unwrap();
    let committed = std::fs::read(&path).unwrap();
    {
        let mut storage = sink.inner.lock().unwrap();
        #[cfg(any(target_os = "linux", windows))]
        let AuditStorage::Legacy(legacy) = &mut *storage
        else {
            panic!("expected legacy audit sink")
        };
        #[cfg(not(any(target_os = "linux", windows)))]
        let AuditStorage::Legacy(legacy) = &mut *storage;
        legacy.fail_after_bytes = Some(8);
    }
    assert!(sink
        .write_native(&serde_json::json!({"event":"interrupted"}))
        .is_err());
    let partial = std::fs::read(&path).unwrap();
    assert_eq!(partial.len(), committed.len() + 8);
    assert!(partial.starts_with(&committed));
    assert_ne!(partial.last(), Some(&b'\n'));
    assert_eq!(sink.health()["state"], "unavailable");
    assert!(sink
        .write_native(&serde_json::json!({"event":"later"}))
        .is_err());
    assert!(sink.write(&line()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), partial);
    drop(sink);

    // Linux refuses an interrupted final record without altering evidence.
    // Other legacy platforms retain their existing unverified reopen.
    #[cfg(target_os = "linux")]
    {
        let error = AuditSink::open(&path).err().unwrap();
        assert!(error.to_string().contains("incomplete tail"));
        assert!(error.to_string().contains("preserve the log as evidence"));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let reopened = AuditSink::open(&path).unwrap();
        assert_eq!(reopened.health()["state"], "unverified");
    }
    assert_eq!(std::fs::read(&path).unwrap(), partial);

    // Model an explicit operator repair: preserve the interrupted log,
    // then open a fresh legacy log. No automatic truncation loses evidence.
    let evidence = dir.path().join("interrupted.jsonl");
    std::fs::rename(&path, &evidence).unwrap();
    let repaired = AuditSink::open(&path).unwrap();
    repaired
        .write_native(&serde_json::json!({"event":"after_repair"}))
        .unwrap();
    assert_eq!(std::fs::read(&evidence).unwrap(), partial);
    let body = std::fs::read_to_string(&path).unwrap();
    assert_eq!(body.lines().count(), 1);
    let record: serde_json::Value = serde_json::from_str(body.trim()).unwrap();
    assert_eq!(record["event"], "after_repair");
    assert_eq!(repaired.health()["state"], "unverified");
}

#[test]
fn legacy_append_error_stays_unavailable_after_storage_is_writable_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let sink = AuditSink::open(&path).unwrap();
    sink.fail_writes_for_test(&path);
    assert!(sink
        .write_native(&serde_json::json!({"event":"append_failed"}))
        .is_err());
    let bytes = std::fs::read(&path).unwrap();
    assert!(bytes.is_empty());
    assert_eq!(sink.health()["state"], "unavailable");
    {
        let mut storage = sink.inner.lock().unwrap();
        #[cfg(any(target_os = "linux", windows))]
        let AuditStorage::Legacy(legacy) = &mut *storage
        else {
            panic!("expected legacy audit sink")
        };
        #[cfg(not(any(target_os = "linux", windows)))]
        let AuditStorage::Legacy(legacy) = &mut *storage;
        // Restoring a writable handle cannot clear the failure latch.
        legacy.file = open_private_append(&path).unwrap();
    }
    assert!(sink
        .write_native(&serde_json::json!({"event":"later"}))
        .is_err());
    assert!(sink.write(&line()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
}

#[cfg(target_os = "linux")]
#[test]
fn legacy_tail_check_does_not_claim_historical_json_validation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    std::fs::write(&path, b"historical non-json bytes\n").unwrap();
    let sink = AuditSink::open(&path).unwrap();
    assert_eq!(sink.health()["state"], "unverified");
    sink.write_native(&serde_json::json!({"event":"new_record"}))
        .unwrap();
    assert!(std::fs::read(&path)
        .unwrap()
        .starts_with(b"historical non-json bytes\n"));
}

#[cfg(target_os = "linux")]
#[test]
fn legacy_native_sync_failure_stays_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let sink = AuditSink::open(&path).unwrap();
    {
        let mut storage = sink.inner.lock().unwrap();
        #[cfg(any(target_os = "linux", windows))]
        let AuditStorage::Legacy(legacy) = &mut *storage
        else {
            panic!("expected legacy audit sink")
        };
        #[cfg(not(any(target_os = "linux", windows)))]
        let AuditStorage::Legacy(legacy) = &mut *storage;
        legacy.fail_sync = true;
    }
    // Hook evidence retains best-effort append semantics. Linux native
    // evidence requires sync before releasing a result.
    sink.write(&line()).unwrap();
    assert!(sink
        .write_native(&serde_json::json!({"event":"sync_failed"}))
        .is_err());
    let bytes = std::fs::read(&path).unwrap();
    assert_eq!(sink.health()["state"], "unavailable");
    assert!(sink
        .write_native(&serde_json::json!({"event":"later"}))
        .is_err());
    assert!(sink.write(&line()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    let body = std::str::from_utf8(&bytes).unwrap();
    assert_eq!(body.lines().count(), 2);
    for record in body.lines() {
        serde_json::from_str::<serde_json::Value>(record).unwrap();
    }
}

#[test]
fn preserves_raw_bytes_when_explicitly_supplied() {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("audit.jsonl");
    let sink = AuditSink::open(&p).unwrap();
    let mut l = line();
    l.event = "unknown".into();
    l.raw = Some(r#"{"hook_event_name":"FutureThing"}"#.into());
    sink.write(&l).unwrap();

    let v: serde_json::Value =
        serde_json::from_str(std::fs::read_to_string(&p).unwrap().trim()).unwrap();
    assert!(v["raw"].as_str().unwrap().contains("FutureThing"));
}

#[cfg(unix)]
#[test]
fn the_audit_file_is_not_world_readable() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("audit.jsonl");
    AuditSink::open(&p).unwrap();
    let mode = std::fs::metadata(&p).unwrap().permissions().mode();
    assert_eq!(
        mode & 0o077,
        0,
        "audit log holds prompts and paths; got {:o}",
        mode
    );
}

// Regression guard for hazard #2: this must fail if the file were created
// WITHOUT the 0o600 mode and the assertion above only happened to pass because
// the ambient umask was already tight. Requesting 0o600 explicitly means the
// umask can only CLEAR bits it already has cleared in the request — it can
// never ADD permission bits back — so 0o600 cannot be loosened by any umask.
// This does not mutate the process umask (that would race concurrently-run
// test binaries); it only documents/checks the reasoning against a request
// that deliberately asks for the loosest legal mode, 0o666.
#[cfg(unix)]
#[test]
fn requesting_0o600_is_not_an_umask_accident() {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let dir = tempfile::tempdir().unwrap();
    let loose = dir.path().join("loose");
    // A bare `create(true)` file (mode request 0o666, the OS default for a new
    // regular file) picks up whatever the umask allows.
    let _ = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o666)
        .open(&loose)
        .unwrap();
    let loose_mode = std::fs::metadata(&loose).unwrap().permissions().mode() & 0o777;

    // Our sink asks for 0o600 explicitly, which the umask cannot loosen.
    let p = dir.path().join("audit.jsonl");
    AuditSink::open(&p).unwrap();
    let strict_mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;

    assert_eq!(
        strict_mode, 0o600,
        "explicit 0o600 request must be honoured exactly"
    );
    // If the ambient umask were tight enough to produce 0o600 from a 0o666
    // request too, this comparison couldn't distinguish "we asked for 0o600"
    // from "umask happened to be tight" — so assert the loose file is NOT
    // already 0o600, proving the two requests diverge in this environment.
    assert_ne!(
        loose_mode, 0o600,
        "test environment's umask is already this tight; this test cannot \
             distinguish an explicit 0o600 request from an umask accident here"
    );
}
