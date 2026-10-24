// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Append-only JSONL audit sink for decision review, replay and policy tuning.
//! Complete decision records matter more than brevity.

use std::fs::File;
#[cfg(not(windows))]
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

use serde::Serialize;

#[cfg(target_os = "linux")]
#[path = "audit_retention.rs"]
mod retention;
#[cfg(windows)]
#[path = "audit_retention_windows.rs"]
mod retention;
#[cfg(any(target_os = "linux", windows))]
pub use retention::recover_retention;
#[cfg(any(target_os = "linux", windows))]
use retention::RetainedSink;

/// Explicit versioned limits for the retained segment store. The directory is a
/// dedicated private directory, never an existing audit JSONL path.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionConfig {
    pub version: u8,
    pub directory: std::path::PathBuf,
    pub segment_size_bytes: u64,
    pub segment_count: usize,
    pub total_disk_bytes: u64,
    pub max_record_bytes: usize,
}

impl RetentionConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.version == 1, "unsupported audit retention version");
        anyhow::ensure!(
            self.directory.is_absolute(),
            "audit retention directory must be absolute"
        );
        anyhow::ensure!(
            (64 * 1024..=16 * 1024 * 1024).contains(&self.segment_size_bytes),
            "audit segment size must be 64 KiB..=16 MiB"
        );
        anyhow::ensure!(
            (2..=64).contains(&self.segment_count),
            "audit segment count must be 2..=64"
        );
        anyhow::ensure!(
            (256..=64 * 1024).contains(&self.max_record_bytes),
            "audit record limit must be 256 bytes..=64 KiB"
        );
        anyhow::ensure!(
            self.max_record_bytes as u64 <= self.segment_size_bytes,
            "audit record exceeds segment size"
        );
        let required = self.segment_size_bytes * self.segment_count as u64 + 2 * 64 * 1024 + 4096;
        anyhow::ensure!(
            required <= self.total_disk_bytes && self.total_disk_bytes <= 1024 * 1024 * 1024,
            "audit total disk cap must cover all segments and metadata and be <= 1 GiB"
        );
        #[cfg(not(any(target_os = "linux", windows)))]
        anyhow::bail!("bounded audit retention is supported on Linux and Windows only");
        #[cfg(any(target_os = "linux", windows))]
        Ok(())
    }
}

/// One audited event.
#[derive(Debug, Clone, Serialize)]
pub struct AuditLine {
    pub at_ms: u64,
    pub session: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    pub seq: u64,
    pub event: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    pub verdict: String,
    /// True when the verdict was computed but not enforced.
    pub shadow: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub risk_score: u8,
    pub findings: Vec<AuditFinding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taint: Option<AuditTaint>,
    /// What the local judge concluded, when an `Escalate` verdict was resolved by it.
    /// Absent on every event that did not escalate — the common case. Recorded so the
    /// audit log explains why a verdict landed where it did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub judge: Option<String>,
    /// Nonce of the human approval that authorized this call, when one did.
    /// Present only on a call an operator explicitly approved, so the audit
    /// trail distinguishes "policy allowed this" from "a human allowed this".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<String>,
    pub egress_hosts: Vec<String>,
    pub latency_us: u128,
    pub truncated: bool,
    /// Raw received body for unrecognized events, only when sensitive forensic
    /// capture was explicitly enabled by the operator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditFinding {
    pub detector: String,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owasp: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub atlas: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditTaint {
    /// Human-readable source label, e.g. `network:evil.com`. Kept for operators
    /// and existing consumers; **not** a parsing target — use the structured
    /// fields below.
    pub source: String,
    /// Origin discriminant: `user`, `project`, `system`, `network`, `mcp`,
    /// `subagent`. Emitted separately so a consumer can group and filter without
    /// re-implementing a split this crate already knows how to do.
    pub origin: String,
    /// The specific host, server, or subagent name. Absent for origins that have
    /// no name of their own, rather than an empty string a reader might mistake
    /// for a source identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_name: Option<String>,
    /// Trust class this origin implies: `untrusted`, `semi`, or `trusted`.
    ///
    /// Recorded rather than left to be derived. It is the security-relevant
    /// classification in the whole record, and without it a log reader needs
    /// this crate's source to interpret their own audit trail.
    pub trust: String,
    /// Sequence number of the event that introduced the tainted content.
    pub seq: u64,
}

/// Append-only sink. Serialized behind a mutex so concurrent hooks cannot
/// interleave partial lines.
pub struct AuditSink {
    inner: Mutex<AuditStorage>,
}

enum AuditStorage {
    Legacy(LegacySink),
    #[cfg(any(target_os = "linux", windows))]
    Retained(Box<RetainedSink>),
}

struct LegacySink {
    file: File,
    failed: bool,
    #[cfg(test)]
    fail_after_bytes: Option<usize>,
    #[cfg(all(test, target_os = "linux"))]
    fail_sync: bool,
}

impl LegacySink {
    fn new(file: File) -> Self {
        Self {
            file,
            failed: false,
            #[cfg(test)]
            fail_after_bytes: None,
            #[cfg(all(test, target_os = "linux"))]
            fail_sync: false,
        }
    }

    fn write_serialized(&mut self, line: &impl Serialize, durable: bool) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.failed,
            "legacy audit sink requires operator repair and reopen"
        );
        let mut json = serde_json::to_vec(line)?;
        json.push(b'\n');
        let result = self.append(&json, durable);
        // write_all can fail after appending a prefix. Neither a later append nor
        // a later sync repairs that record, so never release native results from
        // this sink again after an I/O failure.
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn append(&mut self, bytes: &[u8], durable: bool) -> anyhow::Result<()> {
        #[cfg(test)]
        if let Some(count) = self.fail_after_bytes.take() {
            self.file.write_all(&bytes[..count.min(bytes.len())])?;
            anyhow::bail!("injected partial legacy audit write");
        }
        self.file.write_all(bytes)?;
        // Linux native results require durable evidence. Windows legacy handles
        // are append-only and cannot FlushFileBuffers; preserve their existing
        // compatibility behavior rather than broadening handle access here.
        if durable && cfg!(target_os = "linux") {
            #[cfg(all(test, target_os = "linux"))]
            if std::mem::take(&mut self.fail_sync) {
                anyhow::bail!("injected legacy audit sync failure");
            }
            self.file.sync_data()?;
        }
        Ok(())
    }
}

impl AuditSink {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = open_private_append(path)?;
        // Belt and suspenders on Unix, mirroring `token.rs::load_or_create`: `.mode()` on
        // `OpenOptions` is only honoured when the file is actually CREATED by this
        // call. A pre-existing file at loose permissions (e.g. left over from a
        // build before this fix landed, or created by some other tool) is opened
        // as-is, so tighten it explicitly every time. This file holds prompts, file
        // paths, and tool arguments, so it must never sit at the process umask even
        // for the brief window between create and chmod.
        // On Windows `open_private_append` has already secured this exact handle.
        // Reopening by path here would introduce a path-replacement race.
        #[cfg(not(windows))]
        crate::token::restrict(path)?;
        #[cfg(target_os = "linux")]
        check_legacy_tail(&file)?;
        Ok(Self {
            inner: Mutex::new(AuditStorage::Legacy(LegacySink::new(file))),
        })
    }

    pub fn open_retained(config: &RetentionConfig) -> anyhow::Result<Self> {
        config.validate()?;
        #[cfg(any(target_os = "linux", windows))]
        {
            Ok(Self {
                inner: Mutex::new(AuditStorage::Retained(Box::new(RetainedSink::open(
                    config, false,
                )?))),
            })
        }
        #[cfg(not(any(target_os = "linux", windows)))]
        {
            anyhow::bail!("bounded audit retention is supported on Linux and Windows only")
        }
    }

    /// Coarse, path-free operational status for the loopback health endpoint.
    pub fn health(&self) -> serde_json::Value {
        match self.inner.lock() {
            Ok(storage) => match &*storage {
                AuditStorage::Legacy(sink) if sink.failed => {
                    serde_json::json!({"mode":"legacy","state":"unavailable","reason":"audit_unavailable"})
                }
                AuditStorage::Legacy(_) => {
                    serde_json::json!({"mode":"legacy","state":"unverified"})
                }
                #[cfg(any(target_os = "linux", windows))]
                AuditStorage::Retained(sink) => sink.health(),
            },
            Err(_) => {
                serde_json::json!({"mode":"unknown","state":"unavailable","reason":"audit_mutex_poisoned"})
            }
        }
    }

    /// Write one line. Failures are returned, never panicked — a broken audit log
    /// must not take down the hook path.
    pub fn write(&self, line: &AuditLine) -> anyhow::Result<()> {
        self.write_serialized(line, false)
    }

    /// Native admission requires successful aggregate evidence before release.
    pub(crate) fn write_native(&self, line: &serde_json::Value) -> anyhow::Result<()> {
        self.write_serialized(line, true)
    }

    #[cfg(test)]
    pub(crate) fn fail_writes_for_test(&self, path: &Path) {
        *self.inner.lock().unwrap() =
            AuditStorage::Legacy(LegacySink::new(File::open(path).unwrap()));
    }

    #[cfg(all(test, any(target_os = "linux", windows)))]
    pub(crate) fn fail_retained_write_for_test(&self, errno: i32) {
        let mut storage = self.inner.lock().unwrap();
        let AuditStorage::Retained(sink) = &mut *storage else {
            panic!("expected retained audit sink")
        };
        sink.inject_write_error(errno);
    }

    fn write_serialized(&self, line: &impl Serialize, durable: bool) -> anyhow::Result<()> {
        let mut storage = self
            .inner
            .lock()
            .map_err(|_| anyhow::anyhow!("audit mutex poisoned"))?;
        match &mut *storage {
            AuditStorage::Legacy(f) => {
                f.write_serialized(line, durable)?;
            }
            #[cfg(any(target_os = "linux", windows))]
            AuditStorage::Retained(f) => f.write_serialized(line)?,
        }
        Ok(())
    }
}

/// Check only the final record boundary through the opened append handle. This
/// does not validate earlier JSONL history or repair interrupted records.
#[cfg(target_os = "linux")]
fn check_legacy_tail(file: &File) -> anyhow::Result<()> {
    use std::os::unix::fs::FileExt;

    let len = file.metadata()?.len();
    if len > 0 {
        let mut tail = [0u8; 1];
        anyhow::ensure!(
            file.read_at(&mut tail, len - 1)? == 1 && tail[0] == b'\n',
            "legacy audit log has an incomplete tail; stop the daemon, preserve the log as evidence, and repair or replace it before restarting"
        );
    }
    Ok(())
}

/// Open for append, creating the file with owner-only permissions from the outset
/// on unix. Creating loose and chmod'ing after (`OpenOptions::create(true)` then a
/// separate `set_permissions`) leaves a window — however brief — where the file
/// sits at the process umask, and this file holds prompts and file paths. Same
/// reasoning as `token.rs::write_private`.
#[cfg(unix)]
fn open_private_append(path: &Path) -> anyhow::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let f = OpenOptions::new()
        .create(true)
        .append(true)
        .read(cfg!(target_os = "linux"))
        .mode(0o600)
        .open(path)?;
    Ok(f)
}

#[cfg(windows)]
fn open_private_append(path: &Path) -> anyhow::Result<File> {
    Ok(crate::private_file_windows::open_audit(path)?)
}

#[cfg(not(any(unix, windows)))]
fn open_private_append(path: &Path) -> anyhow::Result<File> {
    let f = OpenOptions::new().create(true).append(true).open(path)?;
    Ok(f)
}

#[cfg(test)]
mod tests {
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
            let AuditStorage::Legacy(legacy) = &mut *storage else {
                panic!("expected legacy audit sink")
            };
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
}
