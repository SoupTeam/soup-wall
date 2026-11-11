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
    project: String,
    ledger: PathBuf,
    native_token_file: PathBuf,
    evidence_file: PathBuf,
    non_billed_free_tier: bool,
    quota_available: bool,
    #[serde(default = "initial_row_ceiling")]
    row_ceiling: usize,
}
fn initial_row_ceiling() -> usize {
    20
}
impl Config {
    fn validate(&self) -> Result<()> {
        ensure!(
            !self.project.is_empty()
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
        Ok(())
    }
}

#[test]
fn gemini_operator_config_rejects_credentials_and_unconfirmed_access() {
    let valid = json!({"project":"public-project", "ledger":"/private/journal",
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

fn confirm(project: &str, row_ceiling: usize) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/dev/tty")?;
    let phrase = format!("RUN {project} 6+24 USD0");
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
    confirm(&config.project, config.row_ceiling)?;
    let config_name = format!("operator-config-{}.json", hash(&bytes));
    if let Some(old) = ledger.read(&config_name)? {
        ensure!(old == bytes, "gemini_operator_config_changed");
    } else {
        ledger.create(&config_name, &bytes)?;
    }
    let mut key = super::super::manual_key::prompt()?;
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
