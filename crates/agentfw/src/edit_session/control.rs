// SPDX-License-Identifier: Apache-2.0
//! Exact-run operator intent; only the existing owning supervisor can confirm
//! revocation and cleanup. A durable record never authorizes a numeric kill.
use super::{control_io::Dir, profile, runtime::RunRecord, FORMAT};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::File,
    path::Path,
    time::{Duration, Instant},
};

const CONTRACT: &str = "sw-installed-edit-control/1";
const REQUEST: &str = "sw-installed-edit-stop-request/1";
const RECEIPT: &str = "sw-installed-edit-stop-receipt/1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    contract: String,
    run_sha256: String,
    run_identity: (u64, u64),
    home_identity: (u64, u64),
    launcher_pid: u32,
    launcher_start: u64,
    manifest_fd: i32,
    config_sha256: String,
    native_token_sha256: String,
    instance_id: String,
    profile_sha256: String,
    host_session: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    contract: String,
    control_sha256: String,
    nonce: String,
    signature: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    contract: String,
    control_sha256: String,
    request_sha256: Option<String>,
    authority_revoked: bool,
    cleanup_confirmed: bool,
    reason: String,
    signature: String,
}
fn digest(bytes: &[u8]) -> String {
    crate::mcp::replace_file::content_sha256(bytes)
}
fn signature(domain: &[u8], value: &impl Serialize, key: &[u8]) -> Result<String> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(key)?;
    mac.update(domain);
    mac.update(&profile::canonical(value)?);
    Ok(URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes()))
}
fn authenticate(actual: &str, expected: &str) -> Result<()> {
    use subtle::ConstantTimeEq;
    ensure!(
        bool::from(actual.as_bytes().ct_eq(expected.as_bytes())),
        "edit_stop_authentication"
    );
    Ok(())
}
impl Request {
    fn mac(&self, key: &[u8]) -> Result<String> {
        signature(
            b"agentfw/edit-stop-request/v1\0",
            &(&self.contract, &self.control_sha256, &self.nonce),
            key,
        )
    }
}
impl Receipt {
    fn mac(&self, key: &[u8]) -> Result<String> {
        signature(
            b"agentfw/edit-stop-receipt/v1\0",
            &(
                &self.contract,
                &self.control_sha256,
                &self.request_sha256,
                self.authority_revoked,
                self.cleanup_confirmed,
                &self.reason,
            ),
            key,
        )
    }
}

struct Selected {
    dir: Dir,
    home: Dir,
    record: RunRecord,
    control: Control,
    bytes: Vec<u8>,
    key: Vec<u8>,
}
impl Selected {
    fn open(path: &Path) -> Result<Self> {
        let dir = Dir::open(path)?;
        let record_bytes = dir.read("run.json")?;
        let record: RunRecord = serde_json::from_slice(&record_bytes)?;
        ensure!(
            record.format == FORMAT && record.run == path && record.home.parent() == Some(path),
            "edit_stop_run_identity"
        );
        let name = record
            .home
            .file_name()
            .and_then(|n| n.to_str())
            .context("edit_stop_home")?;
        ensure!(
            name.len() == 43
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "edit_stop_home"
        );
        let home = dir.child(name)?;
        let bytes = dir.read("control.json")?;
        let control: Control = serde_json::from_slice(&bytes)?;
        let key = home.read("native-token")?;
        ensure!(
            control.contract == CONTRACT
                && control.run_sha256 == digest(&record_bytes)
                && control.run_identity == dir.identity()?
                && control.home_identity == home.identity()?
                && control.native_token_sha256 == digest(&key)
                && control.instance_id == record.instance_id
                && control.profile_sha256 == record.profile_sha256
                && control.host_session == record.host_session,
            "edit_stop_selection_changed"
        );
        Ok(Self {
            dir,
            home,
            record,
            control,
            bytes,
            key,
        })
    }
    fn request(&self) -> Result<Option<Vec<u8>>> {
        let Some(bytes) = self.dir.optional("stop-request.json")? else {
            return Ok(None);
        };
        let request: Request = serde_json::from_slice(&bytes)?;
        ensure!(
            request.contract == REQUEST
                && request.control_sha256 == digest(&self.bytes)
                && request.nonce.len() == 43,
            "edit_stop_request_identity"
        );
        authenticate(&request.signature, &request.mac(&self.key)?)?;
        Ok(Some(bytes))
    }
    fn receipt(&self) -> Result<Option<Receipt>> {
        let Some(bytes) = self.dir.optional("stop-receipt.json")? else {
            return Ok(None);
        };
        let receipt: Receipt = serde_json::from_slice(&bytes)?;
        ensure!(
            receipt.contract == RECEIPT
                && receipt.control_sha256 == digest(&self.bytes)
                && receipt.reason.len() <= 64,
            "edit_stop_receipt_identity"
        );
        authenticate(&receipt.signature, &receipt.mac(&self.key)?)?;
        if let Some(request) = &receipt.request_sha256 {
            ensure!(
                self.request()?
                    .is_some_and(|bytes| digest(&bytes) == *request),
                "edit_stop_receipt_request"
            );
        }
        Ok(Some(receipt))
    }
    fn live_owner(&self) -> Result<File> {
        let c = &self.control;
        let handle = crate::pilot_approval::process_handle(c.launcher_pid, c.launcher_start)?;
        crate::pilot_approval::verify_sealed_owner(
            c.launcher_pid,
            c.launcher_start,
            c.manifest_fd,
            &self.bytes,
        )?;
        let command = std::fs::read(format!("/proc/{}/cmdline", c.launcher_pid))?;
        ensure!(
            command.len() <= 16384
                && command.split(|b| *b == 0).nth(1) == Some(b"edit-session".as_slice())
                && command.split(|b| *b == 0).nth(2) == Some(b"run".as_slice()),
            "edit_stop_not_edit_owner"
        );
        Ok(handle)
    }
    fn daemon(&self) -> Result<()> {
        let bytes = self.home.read("config.yaml")?;
        ensure!(
            digest(&bytes) == self.control.config_sha256,
            "edit_stop_daemon_configuration_changed"
        );
        let cfg = crate::Config::from_yaml(std::str::from_utf8(&bytes)?)?;
        let address: std::net::SocketAddr = cfg.socket_address().parse()?;
        ensure!(address.ip().is_loopback(), "edit_stop_daemon_not_loopback");
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let client = reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(2))
                    .build()?;
                let mut response = client
                    .get(cfg.endpoint_url("/native/v1/instance"))
                    .bearer_auth(std::str::from_utf8(&self.key)?)
                    .send()
                    .await?
                    .error_for_status()?;
                let mut raw = Vec::new();
                while let Some(chunk) = response.chunk().await? {
                    ensure!(
                        raw.len().saturating_add(chunk.len()) <= super::control_io::CAP as usize,
                        "edit_stop_daemon_cap"
                    );
                    raw.extend_from_slice(&chunk);
                }
                let crate::mcp::admission::Strict(value) = serde_json::from_slice(&raw)?;
                ensure!(
                    value["instance_id"] == self.control.instance_id,
                    "edit_stop_daemon_epoch"
                );
                Ok(())
            })
    }
}

pub(super) struct Guard {
    selected: Selected,
    _manifest: File,
}
impl Guard {
    pub fn create(run: &Path, record: &RunRecord) -> Result<Self> {
        let dir = Dir::open(run)?;
        let home = dir.child(
            record
                .home
                .file_name()
                .and_then(|n| n.to_str())
                .context("edit_stop_home")?,
        )?;
        let mut manifest = crate::pilot_approval::manifest()?;
        let key = home.read("native-token")?;
        let control = Control {
            contract: CONTRACT.into(),
            run_sha256: digest(&dir.read("run.json")?),
            run_identity: dir.identity()?,
            home_identity: home.identity()?,
            launcher_pid: std::process::id(),
            launcher_start: crate::pilot_approval::process_start(std::process::id())?,
            manifest_fd: crate::pilot_approval::descriptor(&manifest),
            config_sha256: digest(&home.read("config.yaml")?),
            native_token_sha256: digest(&key),
            instance_id: record.instance_id.clone(),
            profile_sha256: record.profile_sha256.clone(),
            host_session: record.host_session.clone(),
        };
        // Refuse unavailable identity support before launching any host.
        crate::pilot_approval::process_handle(control.launcher_pid, control.launcher_start)?;
        let bytes = profile::canonical(&control)?;
        crate::pilot_approval::seal_bytes(&mut manifest, &bytes)?;
        dir.write_new("control.json", &bytes)?;
        Ok(Self {
            selected: Selected {
                dir,
                home,
                record: record.clone(),
                control,
                bytes,
                key,
            },
            _manifest: manifest,
        })
    }
    pub fn requested(&self) -> Result<bool> {
        Ok(self.selected.request()?.is_some())
    }
    pub fn finish(&self, revoked: bool, cleaned: bool, reason: &str) -> Result<()> {
        let s = &self.selected;
        let _lock = s.dir.lock()?;
        // Recheck the durable binding before issuing an owner receipt. A change
        // keeps the interrupted evidence and can never become a successful stop.
        ensure!(
            s.dir.read("control.json")? == s.bytes
                && digest(&s.dir.read("run.json")?) == s.control.run_sha256,
            "edit_stop_control_changed"
        );
        let request_sha256 = s.request()?.map(|bytes| digest(&bytes));
        let mut receipt = Receipt {
            contract: RECEIPT.into(),
            control_sha256: digest(&s.bytes),
            request_sha256,
            authority_revoked: revoked,
            cleanup_confirmed: cleaned,
            reason: reason.into(),
            signature: String::new(),
        };
        receipt.signature = receipt.mac(&s.key)?;
        s.dir
            .replace("stop-receipt.json", &profile::canonical(&receipt)?)
    }
}

fn operate(path: &Path, report: &mut Value) -> Result<()> {
    report["reason"] = json!("unsafe_or_unavailable_control");
    let selected = Selected::open(path)?;
    report["reason"] = json!("invalid_receipt");
    if let Some(receipt) = selected.receipt()? {
        if receipt.authority_revoked && receipt.cleanup_confirmed {
            report["status"] = json!("already_stopped");
            report["reason"] = json!(receipt.reason);
            report["revocation_confirmed"] = json!(true);
            report["cleanup_confirmed"] = json!(true);
            return Ok(());
        }
    }
    report["reason"] = json!("owner_identity_unverified");
    let handle = selected.live_owner()?;
    report["owner_verified"] = json!(true);
    report["profile_sha256"] = json!(selected.record.profile_sha256);
    report["instance_id"] = json!(selected.record.instance_id);
    // No credential goes to a changed destination, and no effect occurs if
    // daemon authentication fails. Loss after this point remains unconfirmed.
    report["reason"] = json!("daemon_unverified");
    selected.daemon()?;
    report["reason"] = json!("invalid_stop_request");
    {
        let _lock = selected.dir.lock()?;
        if selected.request()?.is_none() {
            let mut request = Request {
                contract: REQUEST.into(),
                control_sha256: digest(&selected.bytes),
                nonce: crate::token::generate(),
                signature: String::new(),
            };
            request.signature = request.mac(&selected.key)?;
            selected
                .dir
                .write_new("stop-request.json", &profile::canonical(&request)?)?;
        }
    }
    report["status"] = json!("requested_unconfirmed");
    report["reason"] = json!("owner_confirmation_unavailable");
    crate::pilot_approval::signal_launcher(&handle)?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(receipt) = selected.receipt()? {
            report["revocation_confirmed"] = json!(receipt.authority_revoked);
            report["cleanup_confirmed"] = json!(receipt.cleanup_confirmed);
            report["reason"] = json!(receipt.reason);
            if receipt.authority_revoked && receipt.cleanup_confirmed {
                report["status"] = json!("stopped");
                return Ok(());
            }
            report["status"] = json!("cleanup_incomplete");
            anyhow::bail!("edit_stop_incomplete");
        }
        ensure!(Instant::now() < deadline, "edit_stop_unconfirmed");
        std::thread::sleep(Duration::from_millis(25));
    }
}

pub(super) fn stop(run: &Path, output: Option<crate::pilot_approval::OutputFormat>) -> Result<()> {
    let mut report = json!({"format":"sw-installed-edit-stop-result/1", "operation":"stop",
        "status":"cleanup_incomplete", "reason":"ownership_unknown", "owner_verified":false,
        "revocation_confirmed":false, "cleanup_confirmed":false, "effects_may_remain_committed":true,
        "running_effects_rolled_back":false, "automatic_retry":false});
    let result = operate(run, &mut report);
    if output.is_some() {
        println!("{report}");
    } else {
        println!("edit-session stop: {}; {}; cleanup confirmed: {}; effects may remain committed; no automatic retry",
        report["status"].as_str().unwrap_or("cleanup_incomplete"), report["reason"].as_str().unwrap_or("unknown"), report["cleanup_confirmed"]);
    }
    ensure!(result.is_ok(), "edit_session_stop_unconfirmed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn request_and_receipt_authentication_cannot_cross_controls_or_domains() {
        let key = b"owned-private-test-key";
        let mut request = Request {
            contract: REQUEST.into(),
            control_sha256: "a".repeat(64),
            nonce: crate::token::generate(),
            signature: String::new(),
        };
        request.signature = request.mac(key).unwrap();
        let signed = request.signature.clone();
        request.control_sha256 = "b".repeat(64);
        assert!(authenticate(&signed, &request.mac(key).unwrap()).is_err());
        let mut receipt = Receipt {
            contract: RECEIPT.into(),
            control_sha256: "a".repeat(64),
            request_sha256: None,
            authority_revoked: true,
            cleanup_confirmed: false,
            reason: "cancelled".into(),
            signature: String::new(),
        };
        assert!(authenticate(&signed, &receipt.mac(key).unwrap()).is_err());
        let incomplete = receipt.mac(key).unwrap();
        receipt.cleanup_confirmed = true;
        assert!(authenticate(&incomplete, &receipt.mac(key).unwrap()).is_err());
        let bytes = profile::canonical(&request).unwrap();
        let duplicate =
            String::from_utf8(bytes)
                .unwrap()
                .replacen('{', "{\"nonce\":\"forged\",", 1);
        assert!(serde_json::from_str::<Request>(&duplicate).is_err());
    }

    #[test]
    fn sealed_edit_selection_refuses_changed_bytes_and_process_birth_identity() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let run = temp.path();
        let home = run.join(crate::token::generate());
        std::fs::create_dir(&home).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        super::super::launch::write(
            &home.join("native-token"),
            crate::token::generate().as_bytes(),
            0o600,
        )
        .unwrap();
        super::super::launch::write(&home.join("config.yaml"), b"enforce: true\n", 0o400).unwrap();
        let record = RunRecord {
            format: FORMAT.into(),
            run: run.into(),
            home,
            profile_sha256: "a".repeat(64),
            host_session: "owned-host".into(),
            instance_id: "owned-instance".into(),
        };
        super::super::launch::write(
            &run.join("run.json"),
            &profile::canonical(&record).unwrap(),
            0o400,
        )
        .unwrap();
        let guard = Guard::create(run, &record).unwrap();
        let selected = Selected::open(run).unwrap();
        let c = &selected.control;
        crate::pilot_approval::verify_sealed_owner(
            c.launcher_pid,
            c.launcher_start,
            c.manifest_fd,
            &selected.bytes,
        )
        .unwrap();
        assert!(crate::pilot_approval::verify_sealed_owner(
            c.launcher_pid,
            c.launcher_start + 1,
            c.manifest_fd,
            &selected.bytes
        )
        .is_err());
        assert!(crate::pilot_approval::verify_sealed_owner(
            c.launcher_pid,
            c.launcher_start,
            c.manifest_fd,
            b"edited local JSON"
        )
        .is_err());
        // The unit-test executable is not an edit-session run owner.
        assert!(selected.live_owner().is_err());
        guard.finish(true, false, "daemon_lost").unwrap();
        assert!(
            !Selected::open(run)
                .unwrap()
                .receipt()
                .unwrap()
                .unwrap()
                .cleanup_confirmed
        );
    }
}
