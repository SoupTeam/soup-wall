// SPDX-License-Identifier: Apache-2.0
//! Explicit Linux operator experiment. Never an unattended test or product Allow.
use super::super::ledger::Ledger;
use super::*;
use crate::native::analysis_purpose::fixture_v2::provider;
use crate::native::{consumer, execution};
use std::{
    io::{Read, Write},
    os::unix::process::CommandExt,
    path::PathBuf,
};
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    #[serde(default = "original_model")]
    model: String,
    project: String,
    ledger: PathBuf,
    native_token_file: PathBuf,
    evidence_file: PathBuf,
    non_billed_free_tier: bool,
    quota_available: bool,
    #[serde(default = "initial_row_ceiling")]
    row_ceiling: usize,
    #[serde(default)]
    metadata_recovery_started_sha256: Option<String>,
    #[serde(default)]
    parent_attempt: Option<ParentAttempt>,
    #[serde(default)]
    resume_http503: Option<ParentAttempt>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ParentAttempt {
    ledger: PathBuf,
    report_sha256: String,
}
fn original_model() -> String {
    "gemini-3.8-flash".into()
}
fn initial_row_ceiling() -> usize {
    20
}
impl Config {
    fn validate(&self) -> Result<()> {
        ensure!(
            self.model == MODEL
                && !self.project.is_empty()
                && self.project.len() <= 128
                && self
                    .project
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
                && self.non_billed_free_tier
                && self.quota_available
                && (1..=30).contains(&self.row_ceiling)
                && self.ledger.is_absolute()
                && self.native_token_file.is_absolute()
                && self.evidence_file.is_absolute(),
            "gemini_operator_config"
        );
        if let Some(digest) = &self.metadata_recovery_started_sha256 {
            ensure!(
                digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
                "gemini_metadata_recovery_digest"
            );
        }
        ensure!(
            self.resume_http503.is_none()
                || (self.parent_attempt.is_none()
                    && self.metadata_recovery_started_sha256.is_none()),
            "gemini_resume_exclusive"
        );
        for parent in self.parent_attempt.iter().chain(self.resume_http503.iter()) {
            ensure!(
                parent.ledger.is_absolute()
                    && parent.ledger != self.ledger
                    && parent.report_sha256.len() == 64
                    && parent.report_sha256.bytes().all(|b| b.is_ascii_hexdigit())
                    && self.metadata_recovery_started_sha256.is_none(),
                "gemini_parent_attempt_config"
            );
        }
        Ok(())
    }
}

#[test]
fn gemini_operator_config_rejects_credentials_and_unconfirmed_access() {
    let valid = json!({"model":MODEL,"project":"public-project", "ledger":"/private/journal",
        "native_token_file":"/private/native-token", "evidence_file":"/private/evidence.txt",
        "non_billed_free_tier":true, "quota_available":true});
    serde_json::from_value::<Config>(valid.clone())
        .unwrap()
        .validate()
        .unwrap();
    for (field, value) in [
        ("non_billed_free_tier", json!(false)),
        ("quota_available", json!(false)),
        ("ledger", json!("relative")),
        ("native_token_file", json!("relative")),
        ("project", json!("bad\nproject")),
        ("row_ceiling", json!(0)),
        ("row_ceiling", json!(31)),
        ("model", json!("different-model")),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        assert!(serde_json::from_value::<Config>(invalid)
            .unwrap()
            .validate()
            .is_err());
    }
    let mut invalid = valid;
    invalid["api_key"] = json!("synthetic-only");
    assert!(serde_json::from_value::<Config>(invalid).is_err());
}

#[test]
fn gemini_operator_ordinary_test_refuses_before_config_or_prompt() {
    assert_ne!(std::env::args().nth(1).as_deref(), Some("pilot-launch"));
    assert!(open().is_err());
}

struct Held(std::process::Child);
impl Drop for Held {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Capture {
    token: Zeroizing<String>,
    retained: Option<execution::tests::ReaderCapture>,
}

pub(in crate::native) async fn exercise_operator_capture() {
    let mut capture = Capture {
        token: Zeroizing::new(crate::token::generate()),
        retained: None,
    };
    // Existing private synthetic wire: complete batch, errors and replay controls.
    // Never selects a live provider for these diagnostic credentials.
    runner::exercise_serial(&mut capture).await;
    assert_eq!(
        capture
            .retained
            .unwrap()
            .st
            .native
            .as_ref()
            .unwrap()
            .quarantine
            .lock()
            .unwrap()
            .analysis_charge(),
        0
    );
}
impl runner::Capture for Capture {
    async fn authorize(
        &mut self,
        text: &str,
        preflight: Preflight,
        ledger: &Ledger,
    ) -> Result<(crate::handlers::Shared, provider::PendingProvider)> {
        if let Some(previous) = self.retained.take() {
            ensure!(
                previous
                    .st
                    .native
                    .as_ref()
                    .unwrap()
                    .quarantine
                    .lock()
                    .unwrap()
                    .analysis_charge()
                    == 0,
                "gemini_operator_lease"
            );
        }
        let mut held = Held(
            std::process::Command::new("/bin/sleep")
                .env_clear()
                .arg("60")
                .process_group(0)
                .spawn()?,
        );
        let captured = execution::tests::operator_analysis_capture(&held.0, text, &self.token);
        let mut headers = axum::http::HeaderMap::new();
        let bearer = Zeroizing::new(format!("Bearer {}", self.token.as_str()));
        let mut value: axum::http::HeaderValue = bearer.parse()?;
        value.set_sensitive(true);
        headers.insert("authorization", value);
        let registered = consumer::handler(
            axum::extract::State(captured.st.clone()),
            headers,
            serde_json::to_string(&captured.registration)?,
        )
        .await;
        ensure!(
            registered.0 == axum::http::StatusCode::NO_CONTENT,
            "gemini_operator_registration"
        );
        // The fixed component runtime remains explicitly synthetic. Only its
        // signer is the actual operator credential; no installed-daemon claim.
        let grant = provider::mint_fixture_provider(
            &captured.st,
            &captured.registration,
            &captured.id,
            ledger,
            &preflight,
        );
        let pending = provider::consume(&captured.st, &grant, ledger, preflight)?;
        held.0.kill()?;
        held.0.wait()?;
        let st = captured.st.clone();
        self.retained = Some(captured);
        Ok((st, pending))
    }
}

fn confirm(project: &str, row_ceiling: usize, recovery: Option<&str>) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/tty")?;
    let phrase = match recovery {
        Some(digest) => format!("RECOVER METADATA {digest} USD0"),
        None => format!("RUN {project} {MODEL} 6+24 USD0"),
    };
    if recovery.is_some() {
        writeln!(tty, "At most one metadata-only GET per signed personal confirmation. A retained absent-baseModelId response is revalidated offline without another GET. Each observation is journaled separately. Retain the complete history and inspect any failure before another personal confirmation.")?;
    }
    writeln!(tty, "Public Gemini experiment only. No replay, paid fallback or policy Allow.\nCumulative attempted-row ceiling: {row_ceiling}/30; wait 61 seconds before each new row.\nOnly raise the ceiling after verifying fresh quota; it is not a per-launch allowance.\nConfirm verified non-billed Free Tier and current quota for project {project}.\nType exactly: {phrase}")?;
    tty.flush()?;
    let mut answer = Vec::new();
    for _ in 0..160 {
        let mut byte = [0];
        tty.read_exact(&mut byte)?;
        if byte[0] == b'\n' {
            break;
        }
        answer.push(byte[0]);
    }
    let answer = std::str::from_utf8(&answer)
        .map_err(|_| anyhow::anyhow!("gemini_operator_confirmation"))?
        .trim();
    let answer = answer.strip_prefix("\x1b[200~").unwrap_or(answer);
    let answer = answer.strip_suffix("\x1b[201~").unwrap_or(answer).trim();
    ensure!(answer == phrase, "gemini_operator_confirmation");
    Ok(())
}

fn bind_parent_attempt(config: &Config, ledger: &Ledger, key_sha256: &str) -> Result<()> {
    if let Some(parent) = &config.parent_attempt {
        if config.row_ceiling > 1 {
            ensure!(
                ledger.read("parent-attempt.receipt")?.is_some(),
                "gemini_smoke_required"
            );
            let source = hash(row(0)?.frame.as_bytes());
            let terminal = ledger
                .read(&format!("{source}.controller-terminal"))?
                .ok_or_else(|| anyhow::anyhow!("gemini_smoke_required"))?;
            let Strict(terminal) = serde_json::from_slice(&terminal)?;
            ensure!(
                matches!(
                    terminal["state"].as_str(),
                    Some("valid_untrusted" | "invalid")
                ),
                "gemini_smoke_technical_stop"
            );
        }
        let previous = Ledger::open(&parent.ledger)?;
        let report = previous
            .read(&format!("report-{}.json", parent.report_sha256))?
            .ok_or_else(|| anyhow::anyhow!("gemini_parent_report_missing"))?;
        ensure!(
            hash(&report) == parent.report_sha256,
            "gemini_parent_report_changed"
        );
        let manifest = previous
            .read("batch.manifest")?
            .ok_or_else(|| anyhow::anyhow!("gemini_parent_manifest_missing"))?;
        let Strict(manifest) = serde_json::from_slice(&manifest)?;
        ensure!(
            manifest["project"] == config.project && manifest["key_sha256"] == key_sha256,
            "gemini_parent_project_or_key_changed"
        );
        let Strict(report_value) = serde_json::from_slice(&report)?;
        let rows = report_value["rows"]
            .as_array()
            .ok_or_else(|| anyhow::anyhow!("gemini_parent_report"))?;
        ensure!(
            rows.len() == 30
                && rows[0]["state"] == "technical_stop"
                && rows[1..].iter().all(|r| r["state"] == "unrun"),
            "gemini_parent_report"
        );
        let source = hash(row(0)?.frame.as_bytes());
        let raw = previous
            .read(&format!("{source}.response"))?
            .ok_or_else(|| anyhow::anyhow!("gemini_parent_response_missing"))?;
        let Strict(error) = serde_json::from_slice(&raw)?;
        ensure!(
            error["error"]["code"] == 503 && rows[0]["raw_sha256"] == hash(&raw),
            "gemini_parent_not_503"
        );
        let receipt = serde_json::to_vec(&json!({"contract":"sw-personal-new-attempt/1",
            "parent_ledger":previous.identity()?,"parent_report_sha256":parent.report_sha256,
            "parent_response_sha256":hash(&raw),"previous_attempts":1,"new_row_ceiling":1,
            "model":MODEL,"profile":profile_hash(),"parent_unchanged":true}))?;
        if let Some(old) = ledger.read("parent-attempt.receipt")? {
            ensure!(old == receipt, "gemini_parent_receipt_changed");
        } else {
            ledger.create("parent-attempt.receipt", &receipt)?;
        }
    }
    Ok(())
}

#[test]
fn gemini_new_attempt_binds_parent_error_key_and_history() {
    use std::os::unix::fs::PermissionsExt;
    for mode in [
        "valid",
        "wrong-key",
        "wrong-project",
        "not-503",
        "changed-hash",
        "other-row-started",
    ] {
        let parent = tempfile::tempdir().unwrap();
        let child = tempfile::tempdir().unwrap();
        for dir in [&parent, &child] {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let previous = Ledger::open(parent.path()).unwrap();
        let key_hash = hash(b"synthetic key");
        previous
            .create(
                "batch.manifest",
                &serde_json::to_vec(&json!({"project":"test-project","key_sha256":key_hash}))
                    .unwrap(),
            )
            .unwrap();
        let raw =
            serde_json::to_vec(&json!({"error":{"code":if mode=="not-503" {400} else {503}}}))
                .unwrap();
        let source = hash(row(0).unwrap().frame.as_bytes());
        previous
            .create(&format!("{source}.response"), &raw)
            .unwrap();
        let mut rows = vec![json!({"state":"unrun"}); 30];
        rows[0] = json!({"state":"technical_stop","raw_sha256":if mode=="changed-hash" {hash(b"other")} else {hash(&raw)}});
        if mode == "other-row-started" {
            rows[1]["state"] = json!("started_unknown");
        }
        let report = serde_json::to_vec(&json!({"rows":rows})).unwrap();
        let digest = hash(&report);
        previous
            .create(&format!("report-{digest}.json"), &report)
            .unwrap();
        drop(previous);
        let config:Config=serde_json::from_value(json!({"model":MODEL,"project":if mode=="wrong-project" {"other"} else {"test-project"},
            "ledger":child.path(),"native_token_file":"/private/token","evidence_file":"/private/evidence",
            "non_billed_free_tier":true,"quota_available":true,"row_ceiling":1,
            "parent_attempt":{"ledger":parent.path(),"report_sha256":digest}})).unwrap();
        config.validate().unwrap();
        let ledger = Ledger::open(child.path()).unwrap();
        let result = bind_parent_attempt(
            &config,
            &ledger,
            if mode == "wrong-key" {
                "wrong"
            } else {
                &key_hash
            },
        );
        assert_eq!(result.is_ok(), mode == "valid", "{mode}: {result:?}");
        if mode == "valid" {
            bind_parent_attempt(&config, &ledger, &key_hash).unwrap();
            let mut continuation = config;
            continuation.row_ceiling = 20;
            continuation.validate().unwrap();
            assert!(bind_parent_attempt(&continuation, &ledger, &key_hash).is_err());
            ledger
                .create(
                    &format!("{source}.controller-terminal"),
                    br#"{"state":"invalid"}"#,
                )
                .unwrap();
            bind_parent_attempt(&continuation, &ledger, &key_hash).unwrap();
        }
        assert_eq!(
            std::fs::read(parent.path().join(format!("report-{digest}.json"))).unwrap(),
            report
        );
        assert_eq!(
            std::fs::read(parent.path().join(format!("{source}.response"))).unwrap(),
            raw
        );
        assert_eq!(
            ledger.read("parent-attempt.receipt").unwrap().is_some(),
            mode == "valid"
        );
        assert!(ledger.read("model.started").unwrap().is_none());
    }
}

fn open() -> Result<(runner::Controller, Capture, usize)> {
    ensure!(
        std::env::args().nth(1).as_deref() == Some("pilot-launch"),
        "gemini_operator_explicit_launcher"
    );
    ensure!(std::env::var_os("CI").is_none(), "gemini_operator_no_ci");
    let path = std::env::var_os("SOUP_WALL_GEMINI_MANUAL_CONFIG")
        .ok_or_else(|| anyhow::anyhow!("gemini_operator_not_enabled"))?;
    let bytes = crate::pilot_approval::read_file(std::path::Path::new(&path), true)?;
    ensure!(bytes.len() <= 4096, "gemini_operator_config_limit");
    let Strict(value) = serde_json::from_slice(&bytes)?;
    let config: Config = serde_json::from_value(value)?;
    config.validate()?;
    let evidence = crate::pilot_approval::read_file(&config.evidence_file, true)?;
    ensure!(
        !evidence.is_empty() && evidence.len() <= 4096,
        "gemini_operator_evidence"
    );
    let raw = Zeroizing::new(crate::pilot_approval::read_file(
        &config.native_token_file,
        true,
    )?);
    let token = Zeroizing::new(std::str::from_utf8(&raw)?.trim().to_owned());
    ensure!(
        (32..=256).contains(&token.len())
            && token
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-'),
        "gemini_operator_native_token"
    );
    let ledger = Ledger::open(&config.ledger)?;
    if config.resume_http503.is_some() {
        eprintln!("Explicit separate continuation after retained HTTP 503. Completed rows are inherited without provider replay. The failed row gets one new attempt; all original evidence remains unchanged. No automatic retry.");
    }
    confirm(
        &config.project,
        config.row_ceiling,
        config.metadata_recovery_started_sha256.as_deref(),
    )?;
    let config_name = format!("operator-config-{}.json", hash(&bytes));
    if let Some(old) = ledger.read(&config_name)? {
        ensure!(old == bytes, "gemini_operator_config_changed");
    } else {
        ledger.create(&config_name, &bytes)?;
    }
    let mut key = super::super::manual_key::prompt()?;
    bind_parent_attempt(&config, &ledger, &hash(key.as_bytes()))?;
    if let Some(parent) = &config.resume_http503 {
        super::resume::bind(
            &parent.ledger,
            &parent.report_sha256,
            &ledger,
            &config.project,
            &hash(key.as_bytes()),
        )?;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    // Real local operator declaration, signed only after interactive assent.
    // Its evidence is an operator statement, not a Google billing API response.
    let mut claim = AccessClaim {
        profile: profile_hash(),
        ledger: ledger.identity()?,
        key_sha256: hash(key.as_bytes()),
        project: config.project,
        evidence_sha256: hash(&evidence),
        non_billed_free_tier: true,
        quota_available: true,
        metadata_recovery_started_sha256: config.metadata_recovery_started_sha256,
        issued: now,
        expires: now + 3600,
        signature: String::new(),
    };
    claim.signature =
        URL_SAFE_NO_PAD.encode(access_mac(token.as_bytes(), &claim).finalize().into_bytes());
    let evidence_name = format!("operator-evidence-{}.txt", hash(&evidence));
    if let Some(old) = ledger.read(&evidence_name)? {
        ensure!(old == evidence, "gemini_operator_evidence_changed");
    } else {
        ledger.create(&evidence_name, &evidence)?;
    }
    let controller = runner::Controller::open_held(
        ledger,
        &serde_json::to_vec(&claim)?,
        Some(std::mem::take(&mut key)),
        token.as_bytes(),
    )?;
    Ok((
        controller,
        Capture {
            token,
            retained: None,
        },
        config.row_ceiling,
    ))
}

#[test]
#[ignore = "manual operator only: explicit config, real controlling terminal and confirmation required"]
fn manual_public_gemini_operator() {
    // Suppress potentially sensitive library error details. No key prompt or
    // request occurs unless all of open()'s explicit operator gates pass.
    let result = (|| -> Result<()> {
        let (mut controller, mut capture, row_ceiling) = open()?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let outcome = runtime.block_on(controller.run_bounded(&mut capture, row_ceiling));
        // Save a report on ordinary error too; uncertain attempts remain fenced.
        controller.save_operator_report()?;
        outcome?;
        Ok(())
    })();
    if let Err(error) = result {
        panic!("{}", super::super::manual_key::input_diagnostic(&error));
    }
}
