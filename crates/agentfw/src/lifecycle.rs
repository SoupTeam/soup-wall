// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const MANIFEST: &str = "lifecycle.json";
const MAX_CANDIDATE_BYTES: u64 = 512 * 1024 * 1024;
const START_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub version: String,
    pub digest: String,
    pub binary: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProcessRecord {
    pub pid: u32,
    pub instance: String,
    pub binary_digest: String,
    pub config_digest: String,
    pub port: u16,
    pub bind: String,
    pub launch_log: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedHealth {
    pub pid: u32,
    pub instance: String,
    pub binary_digest: String,
    pub config_digest: String,
}

impl ProcessRecord {
    fn matches(&self, health: &ManagedHealth) -> bool {
        self.pid == health.pid
            && self.instance == health.instance
            && self.binary_digest == health.binary_digest
            && self.config_digest == health.config_digest
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Operation {
    pub(crate) from: Record,
    pub(crate) to: Record,
    pub(crate) was_running: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PendingStage {
    stage: String,
    target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub(crate) struct State {
    pub(crate) active: Option<Record>,
    pub(crate) previous: Option<Record>,
    #[serde(default)]
    pub(crate) owned: Vec<Record>,
    pub(crate) process: Option<ProcessRecord>,
    pub(crate) operation: Option<Operation>,
    #[serde(default)]
    pub(crate) pending_stage: Option<PendingStage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Status {
    pub active: Option<Record>,
    pub previous: Option<Record>,
    pub process: Option<ProcessRecord>,
    pub running: bool,
    pub interrupted: bool,
    pub detail: String,
}

pub struct Manager {
    home: PathBuf,
    root: PathBuf,
}

impl Manager {
    pub fn new(home: impl Into<PathBuf>) -> Self {
        let home = home.into();
        let root = home.join("versions");
        Self { home, root }
    }

    pub fn install(
        &self,
        version: &str,
        candidate: &Path,
        expected_sha256: &str,
    ) -> Result<Record> {
        let _lock = self.lock()?;
        #[cfg(target_os = "linux")]
        crate::service::require_unregistered(&self.home)?;
        let mut state = self.load()?;
        ensure!(
            state.active.is_none(),
            "Agent is already installed; use upgrade"
        );
        ensure!(
            state.operation.is_none() && state.pending_stage.is_none(),
            "recover the interrupted operation first"
        );
        let record = self.stage(&mut state, version, candidate, expected_sha256)?;
        state.owned.push(record.clone());
        state.active = Some(record.clone());
        state.pending_stage = None;
        if let Err(error) = self.save(&state) {
            let _ = fs::remove_file(self.path_for(&record)?);
            return Err(error);
        }
        Ok(record)
    }

    pub fn upgrade(
        &self,
        version: &str,
        candidate: &Path,
        expected_sha256: &str,
    ) -> Result<Record> {
        #[cfg(target_os = "linux")]
        if crate::service::registered(&self.home) {
            return crate::service::Service::new(&self.home)?.upgrade(
                version,
                candidate,
                expected_sha256,
            );
        }
        let _lock = self.lock()?;
        #[cfg(target_os = "linux")]
        crate::service::require_unregistered(&self.home)?;
        let mut state = self.load()?;
        ensure!(
            state.operation.is_none() && state.pending_stage.is_none(),
            "recover the interrupted operation first"
        );
        let old = state.active.clone().context("Agent is not installed")?;
        self.verify(&old)?;
        let running = self.running(&state)?.is_some();
        if state.process.is_some() && !running {
            bail!("recorded process is not responding; run recover before upgrade");
        }
        let new = self.stage(&mut state, version, candidate, expected_sha256)?;
        state.owned.push(new.clone());
        state.operation = Some(Operation {
            from: old.clone(),
            to: new.clone(),
            was_running: running,
        });
        state.pending_stage = None;
        if let Err(error) = self.save(&state) {
            let _ = fs::remove_file(self.path_for(&new)?);
            return Err(error);
        }
        if running {
            self.stop_locked(&mut state)?;
        }
        state.active = Some(new.clone());
        state.previous = Some(old.clone());
        self.save(&state)?;
        let result = if running {
            self.start_locked(&mut state)
        } else {
            Ok(())
        };
        if let Err(error) = result {
            state.active = Some(old.clone());
            state.previous = Some(new);
            self.save(&state)?;
            if running {
                self.start_locked(&mut state)
                    .context("new version failed and the previous version could not restart")?;
            }
            state.operation = None;
            self.save(&state)?;
            bail!("upgrade failed and the previous version was restored: {error:#}");
        }
        state.operation = None;
        self.save(&state)?;
        Ok(new)
    }

    pub fn rollback(&self) -> Result<Record> {
        #[cfg(target_os = "linux")]
        if crate::service::registered(&self.home) {
            return crate::service::Service::new(&self.home)?.rollback();
        }
        let _lock = self.lock()?;
        #[cfg(target_os = "linux")]
        crate::service::require_unregistered(&self.home)?;
        let mut state = self.load()?;
        ensure!(
            state.operation.is_none() && state.pending_stage.is_none(),
            "recover the interrupted operation first"
        );
        let old = state.active.clone().context("Agent is not installed")?;
        let previous = state.previous.clone().context("no previous version")?;
        self.verify(&previous)?;
        let running = self.running(&state)?.is_some();
        if state.process.is_some() && !running {
            bail!("recorded process is not responding; run recover before rollback");
        }
        state.operation = Some(Operation {
            from: old.clone(),
            to: previous.clone(),
            was_running: running,
        });
        self.save(&state)?;
        if running {
            self.stop_locked(&mut state)?;
        }
        state.active = Some(previous.clone());
        state.previous = Some(old.clone());
        self.save(&state)?;
        if running {
            if let Err(error) = self.start_locked(&mut state) {
                state.active = Some(old);
                state.previous = Some(previous);
                self.save(&state)?;
                self.start_locked(&mut state)
                    .context("rollback failed and the original version could not restart")?;
                state.operation = None;
                self.save(&state)?;
                bail!("rollback failed and the original version was restored: {error:#}");
            }
        }
        state.operation = None;
        self.save(&state)?;
        state.active.context("rollback lost active version")
    }

    pub fn status(&self) -> Result<Status> {
        #[cfg(target_os = "linux")]
        if crate::service::registered(&self.home) {
            return crate::service::Service::new(&self.home)?.status();
        }
        let _lock = self.lock()?;
        let state = self.load()?;
        let health = self.running(&state)?;
        let config_changed = state.process.as_ref().is_some_and(|process| {
            self.config_digest().ok().as_deref() != Some(process.config_digest.as_str())
        });
        let version_changed = state.process.as_ref().is_some_and(|process| {
            state.active.as_ref().map(|record| record.digest.as_str())
                != Some(process.binary_digest.as_str())
        });
        let binary_changed = state
            .active
            .as_ref()
            .is_some_and(|record| self.verify(record).is_err());
        let foreign_port =
            state.process.is_none() && self.config().ok().is_some_and(|cfg| port_occupied(&cfg));
        let detail = if state.pending_stage.is_some() {
            "interrupted staging; run recover"
        } else if state.operation.is_some() {
            "interrupted operation; run recover"
        } else if state.process.is_some() && health.is_none() {
            "recorded process is not responding"
        } else if binary_changed {
            "installed binary has changed"
        } else if version_changed {
            "running binary does not match the active version"
        } else if config_changed {
            "running with changed config; restart to apply it"
        } else if health.is_some() {
            "running and verified"
        } else if foreign_port {
            "Agent port is occupied by an unowned process"
        } else if state.active.is_some() {
            "installed and stopped"
        } else {
            "not installed"
        };
        Ok(Status {
            active: state.active,
            previous: state.previous,
            process: state.process,
            running: health.is_some(),
            interrupted: state.operation.is_some() || state.pending_stage.is_some(),
            detail: detail.to_owned(),
        })
    }

    pub fn start(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        if crate::service::registered(&self.home) {
            return crate::service::Service::new(&self.home)?.start();
        }
        let _lock = self.lock()?;
        #[cfg(target_os = "linux")]
        crate::service::require_unregistered(&self.home)?;
        let mut state = self.load()?;
        ensure!(
            state.operation.is_none() && state.pending_stage.is_none(),
            "recover the interrupted operation first"
        );
        self.start_locked(&mut state)
    }

    pub fn stop(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        if crate::service::registered(&self.home) {
            return crate::service::Service::new(&self.home)?.stop();
        }
        let _lock = self.lock()?;
        #[cfg(target_os = "linux")]
        crate::service::require_unregistered(&self.home)?;
        let mut state = self.load()?;
        ensure!(
            state.operation.is_none() && state.pending_stage.is_none(),
            "recover the interrupted operation first"
        );
        self.stop_locked(&mut state)
    }

    pub fn restart(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        if crate::service::registered(&self.home) {
            return crate::service::Service::new(&self.home)?.restart();
        }
        let _lock = self.lock()?;
        #[cfg(target_os = "linux")]
        crate::service::require_unregistered(&self.home)?;
        let mut state = self.load()?;
        ensure!(
            state.operation.is_none() && state.pending_stage.is_none(),
            "recover the interrupted operation first"
        );
        self.stop_locked(&mut state)?;
        self.start_locked(&mut state)
    }

    pub fn recover(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        if crate::service::registered(&self.home) {
            return crate::service::Service::new(&self.home)?.recover();
        }
        let _lock = self.lock()?;
        #[cfg(target_os = "linux")]
        crate::service::require_unregistered(&self.home)?;
        let mut state = self.load()?;
        self.cleanup_pending_stage(&mut state)?;
        if let Some(process) = state.process.clone() {
            if self.running(&state)?.is_none() {
                ensure!(
                    !pid_alive(process.pid)?,
                    "recorded PID is live but identity cannot be verified; refusing recovery"
                );
                state.process = None;
                self.save(&state)?;
                let log = self.root.join(&process.launch_log);
                if log.exists() {
                    ensure_regular(&log)?;
                    fs::remove_file(log)?;
                }
            }
        }
        let Some(operation) = state.operation.clone() else {
            if let Some(active) = &state.active {
                self.verify(active)?;
            }
            return Ok(());
        };
        self.verify(&operation.from)?;
        if self.running(&state)?.is_some() {
            self.stop_locked(&mut state)?;
        }
        state.active = Some(operation.from);
        state.previous = Some(operation.to);
        self.save(&state)?;
        if operation.was_running {
            self.start_locked(&mut state)?;
        }
        state.operation = None;
        self.save(&state)
    }

    pub fn remove(&self) -> Result<()> {
        let _lock = self.lock()?;
        #[cfg(target_os = "linux")]
        crate::service::require_unregistered(&self.home)?;
        let mut state = self.load()?;
        ensure!(
            state.operation.is_none() && state.pending_stage.is_none(),
            "recover the interrupted operation first"
        );
        if state.process.is_some() {
            if self.running(&state)?.is_some() {
                self.stop_locked(&mut state)?;
            } else {
                bail!("recorded process is not responding; run recover before removal");
            }
        }
        for record in &state.owned {
            let path = self.path_for(record)?;
            if path.exists() {
                ensure_regular(&path)?;
                fs::remove_file(path)?;
            }
        }
        let manifest = self.root.join(MANIFEST);
        if manifest.exists() {
            ensure_regular(&manifest)?;
            fs::remove_file(manifest)?;
        }
        Ok(())
    }

    pub fn verify_managed_boot(&self, instance: &str, exe: &Path) -> Result<()> {
        let state = self.load()?;
        let process = state.process.context("no managed start is recorded")?;
        ensure!(
            process.instance == instance,
            "managed instance does not match"
        );
        let active = state.active.context("no active version")?;
        self.verify(&active)?;
        ensure!(
            exe.canonicalize()? == self.path_for(&active)?.canonicalize()?,
            "running binary does not match the active version"
        );
        ensure!(
            process.binary_digest == active.digest,
            "binary digest does not match"
        );
        ensure!(
            process.config_digest == self.config_digest()?,
            "config changed during startup"
        );
        Ok(())
    }

    // Shared by detached lifecycle startup and the foreground service launcher.
    // The caller owns the short state lock; waiting for readiness happens separately.
    fn prepare_launch(
        &self,
        state: &mut State,
        pid: u32,
    ) -> Result<(PathBuf, ProcessRecord, File)> {
        ensure!(
            state.process.is_none(),
            "Agent already has a recorded process"
        );
        let active = state.active.as_ref().context("Agent is not installed")?;
        self.verify(active)?;
        let cfg = self.config()?;
        ensure!(
            !port_occupied(&cfg),
            "Agent port is occupied by another process"
        );
        let binary = self.path_for(active)?;
        let process = ProcessRecord {
            pid,
            instance: crate::token::generate(),
            binary_digest: active.digest.clone(),
            config_digest: self.config_digest()?,
            port: cfg.port,
            bind: cfg.bind,
            launch_log: String::new(),
        };
        let mut process = process;
        process.launch_log = format!(".launch-{}.log", process.instance);
        let launch_log = self.root.join(&process.launch_log);
        let log = create_private(&launch_log)?;
        state.process = Some(process.clone());
        if let Err(error) = self.save(state) {
            state.process = None;
            let _ = fs::remove_file(&launch_log);
            return Err(error);
        }
        Ok((binary, process, log))
    }

    fn start_locked(&self, state: &mut State) -> Result<()> {
        let (binary, process, log) = self.prepare_launch(state, 0)?;
        let launch_log = self.root.join(&process.launch_log);
        let mut child = match Command::new(binary)
            .args([
                "lifecycle",
                "serve-managed",
                "--instance",
                &process.instance,
            ])
            .arg("--home")
            .arg(&self.home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                state.process = None;
                self.save(state)?;
                let _ = fs::remove_file(&launch_log);
                return Err(error.into());
            }
        };
        state.process.as_mut().unwrap().pid = child.id();
        if let Err(error) = self.save(state) {
            if child.try_wait()?.is_none() {
                child.kill()?;
            }
            child.wait()?;
            return Err(error);
        }
        let deadline = Instant::now() + START_TIMEOUT;
        while Instant::now() < deadline {
            if child.try_wait().ok().flatten().is_some() {
                break;
            }
            if matches!(self.running(state), Ok(Some(_))) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if child.try_wait()?.is_none() {
            child.kill()?;
        }
        child.wait()?;
        state.process = None;
        self.save(state)?;
        let diagnostic = fs::read_to_string(&launch_log).unwrap_or_default();
        let _ = fs::remove_file(&launch_log);
        bail!(
            "Agent did not pass managed health verification: {}",
            diagnostic.trim()
        );
    }

    fn stop_locked(&self, state: &mut State) -> Result<()> {
        let process = state.process.clone().context("Agent is not running")?;
        ensure!(
            self.running(state)?.is_some(),
            "recorded process identity cannot be verified; refusing to stop it"
        );
        self.request(&process, true)?
            .context("managed stop request was not accepted")?;
        let deadline = Instant::now() + START_TIMEOUT;
        while Instant::now() < deadline {
            if self.running(state)?.is_none() {
                state.process = None;
                self.save(state)?;
                let log = self.root.join(&process.launch_log);
                if log.exists() {
                    ensure_regular(&log)?;
                    fs::remove_file(log)?;
                }
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        bail!("managed Agent did not stop before the timeout")
    }

    fn running(&self, state: &State) -> Result<Option<ManagedHealth>> {
        let Some(process) = &state.process else {
            return Ok(None);
        };
        let Some(response) = self.request(process, false)? else {
            return Ok(None);
        };
        if !process.matches(&response) {
            return Ok(None);
        }
        Ok(Some(response))
    }

    fn request(&self, process: &ProcessRecord, stop: bool) -> Result<Option<ManagedHealth>> {
        let token_path = self.home.join("token");
        if !token_path.exists() {
            return Ok(None);
        }
        ensure_regular(&token_path)?;
        crate::token::restrict(&token_path)?;
        let token = match fs::read_to_string(token_path) {
            Ok(value) => value.trim().to_owned(),
            Err(_) => return Ok(None),
        };
        let host = if process.bind == "::1" {
            "[::1]"
        } else {
            &process.bind
        };
        let endpoint = format!("http://{host}:{}/lifecycle/v1", process.port);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_millis(500))
                .no_proxy()
                .build()?;
            let request = if stop {
                client.post(&endpoint)
            } else {
                client.get(&endpoint)
            };
            let response = match request
                .bearer_auth(&token)
                .header("x-agentfw-instance", &process.instance)
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => response,
                _ => return Ok(None),
            };
            if stop {
                return Ok(Some(ManagedHealth {
                    pid: process.pid,
                    instance: process.instance.clone(),
                    binary_digest: process.binary_digest.clone(),
                    config_digest: process.config_digest.clone(),
                }));
            }
            Ok(response.json::<ManagedHealth>().await.ok())
        })
    }

    fn stage(
        &self,
        state: &mut State,
        version: &str,
        candidate: &Path,
        expected_sha256: &str,
    ) -> Result<Record> {
        validate_version(version)?;
        validate_digest(expected_sha256)?;
        ensure_regular(candidate)?;
        let length = fs::metadata(candidate)?.len();
        ensure!(
            length > 0 && length <= MAX_CANDIDATE_BYTES,
            "candidate size must be between 1 and 512 MiB"
        );
        let file_name = format!("agentfw-{version}{}", std::env::consts::EXE_SUFFIX);
        let target = self.root.join(&file_name);
        match fs::symlink_metadata(&target) {
            Ok(_) => bail!("version already exists in managed storage"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let stage_name = format!(".{}.stage", crate::token::generate());
        let stage = self.root.join(&stage_name);
        state.pending_stage = Some(PendingStage {
            stage: stage_name,
            target: file_name.clone(),
        });
        self.save(state)?;
        let staged = (|| -> Result<String> {
            let input = File::open(candidate)?;
            let mut output = create_private(&stage)?;
            let copied = std::io::copy(&mut input.take(MAX_CANDIDATE_BYTES + 1), &mut output)?;
            ensure!(copied == length, "candidate changed while staging");
            output.sync_all()?;
            drop(output);
            let actual = sha256_file(&stage)?;
            ensure!(
                actual == expected_sha256,
                "candidate SHA-256 does not match the expected digest"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&stage, fs::Permissions::from_mode(0o700))?;
            }
            fs::rename(&stage, &target)?;
            Ok(actual)
        })();
        let actual = match staged {
            Ok(actual) => actual,
            Err(error) => {
                let _ = fs::remove_file(&stage);
                state.pending_stage = None;
                let _ = self.save(state);
                return Err(error);
            }
        };
        Ok(Record {
            version: version.to_owned(),
            digest: actual,
            binary: file_name,
        })
    }

    pub(crate) fn verify(&self, record: &Record) -> Result<()> {
        validate_digest(&record.digest)?;
        let path = self.path_for(record)?;
        ensure_regular(&path)?;
        ensure!(
            sha256_file(&path)? == record.digest,
            "stored binary digest mismatch"
        );
        Ok(())
    }

    pub(crate) fn path_for(&self, record: &Record) -> Result<PathBuf> {
        validate_version(&record.version)?;
        let expected = format!("agentfw-{}{}", record.version, std::env::consts::EXE_SUFFIX);
        ensure!(record.binary == expected, "managed binary name is invalid");
        Ok(self.root.join(expected))
    }

    fn config(&self) -> Result<crate::Config> {
        let path = self.home.join("config.yaml");
        match fs::read_to_string(path) {
            Ok(body) => crate::Config::from_yaml(&body),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(crate::Config::default())
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn config_digest(&self) -> Result<String> {
        let path = self.home.join("config.yaml");
        match fs::read(path) {
            Ok(bytes) => Ok(sha256(&bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(sha256(b"")),
            Err(error) => Err(error.into()),
        }
    }

    #[cfg(target_os = "linux")]
    pub fn direct_serve_guard(&self) -> Result<File> {
        let lock = self.lock()?;
        crate::service::require_unregistered(&self.home)?;
        Ok(lock)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn service_snapshot(&self) -> Result<(State, Option<ManagedHealth>)> {
        // Atomic manifest replacement permits a read without blocking the launcher.
        let state = self.load()?;
        let health = self.running(&state)?;
        Ok((state, health))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn service_prepare_upgrade(
        &self,
        version: &str,
        candidate: &Path,
        digest: &str,
        was_running: bool,
    ) -> Result<Record> {
        let _lock = self.lock()?;
        let mut state = self.load()?;
        ensure!(
            state.operation.is_none() && state.pending_stage.is_none(),
            "recover the interrupted operation first"
        );
        let from = state.active.clone().context("Agent is not installed")?;
        self.verify(&from)?;
        let to = self.stage(&mut state, version, candidate, digest)?;
        state.owned.push(to.clone());
        state.operation = Some(Operation {
            from,
            to: to.clone(),
            was_running,
        });
        state.pending_stage = None;
        self.save(&state)?;
        Ok(to)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn service_prepare_rollback(&self, was_running: bool) -> Result<Record> {
        let _lock = self.lock()?;
        let mut state = self.load()?;
        ensure!(
            state.operation.is_none() && state.pending_stage.is_none(),
            "recover the interrupted operation first"
        );
        let from = state.active.clone().context("Agent is not installed")?;
        let to = state.previous.clone().context("no previous version")?;
        self.verify(&from)?;
        self.verify(&to)?;
        state.operation = Some(Operation {
            from,
            to: to.clone(),
            was_running,
        });
        self.save(&state)?;
        Ok(to)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn service_recover_staging(&self) -> Result<()> {
        let _lock = self.lock()?;
        let mut state = self.load()?;
        self.cleanup_pending_stage(&mut state)
    }

    fn cleanup_pending_stage(&self, state: &mut State) -> Result<()> {
        if let Some(pending) = state.pending_stage.clone() {
            ensure!(
                !state
                    .owned
                    .iter()
                    .any(|record| record.binary == pending.target),
                "recorded staging target overlaps an installed version"
            );
            for name in [&pending.stage, &pending.target] {
                let path = self.root.join(name);
                match fs::symlink_metadata(&path) {
                    Ok(metadata) => {
                        ensure!(
                            metadata.file_type().is_file(),
                            "recorded stage is not a regular file"
                        );
                        fs::remove_file(path)?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
            state.pending_stage = None;
            self.save(state)?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn service_select(&self, selected: &Record) -> Result<()> {
        let _lock = self.lock()?;
        let mut state = self.load()?;
        ensure!(
            state.process.is_none(),
            "stop the service before switching versions"
        );
        let operation = state.operation.as_ref().context("no service transaction")?;
        ensure!(
            selected == &operation.from || selected == &operation.to,
            "selected version is outside the recorded transaction"
        );
        self.verify(selected)?;
        state.previous = Some(if selected == &operation.from {
            operation.to.clone()
        } else {
            operation.from.clone()
        });
        state.active = Some(selected.clone());
        self.save(&state)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn service_finish(&self) -> Result<()> {
        let _lock = self.lock()?;
        let mut state = self.load()?;
        ensure!(
            state.operation.is_some(),
            "no service transaction to finish"
        );
        state.operation = None;
        self.save(&state)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn service_launch(&self) -> Result<(PathBuf, ProcessRecord)> {
        let _lock = self.lock()?;
        let mut state = self.load()?;
        ensure!(
            state.operation.as_ref().is_none_or(|operation| {
                state.active.as_ref() == Some(&operation.from)
                    || state.active.as_ref() == Some(&operation.to)
            }),
            "active service version is outside the recorded transaction"
        );
        // A staged candidate never changes the running version. During a switch,
        // only the two journaled versions may boot; recovery restores `from`.
        // systemd has reaped the old main process before invoking a new launcher.
        // A reused/live PID is never cleared solely because the endpoint is down.
        self.clear_dead_record(&mut state)?;
        let (binary, process, _log) = self.prepare_launch(&mut state, std::process::id())?;
        Ok((binary, process))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn service_clear_dead(&self) -> Result<()> {
        let _lock = self.lock()?;
        let mut state = self.load()?;
        self.clear_dead_record(&mut state)
    }

    #[cfg(target_os = "linux")]
    fn clear_dead_record(&self, state: &mut State) -> Result<()> {
        if let Some(process) = &state.process {
            ensure!(
                !pid_alive(process.pid)?,
                "recorded PID is still live; refusing to clear its identity"
            );
            let log = self.root.join(&process.launch_log);
            if log.exists() {
                ensure_regular(&log)?;
                fs::remove_file(log)?;
            }
            state.process = None;
            self.save(state)?;
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn service_shutdown(&self, pid: u32) -> Result<()> {
        let (state, health) = self.service_snapshot()?;
        let Some(process) = state.process else {
            ensure!(pid == 0, "unrecorded service process");
            return Ok(());
        };
        if !pid_alive(process.pid)? {
            return Ok(());
        }
        ensure!(
            health.is_some() && process.pid == pid,
            "service process identity cannot be verified; refusing shutdown"
        );
        self.request(&process, true)?
            .context("authenticated shutdown was not accepted")?;
        let deadline = Instant::now() + Duration::from_secs(25);
        while Instant::now() < deadline {
            if !pid_alive(process.pid)? {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        bail!("authenticated shutdown timed out; systemd will bound cleanup to this unit")
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn service_installable(&self) -> Result<()> {
        let state = self.load()?;
        ensure!(
            state.process.is_none() && state.operation.is_none() && state.pending_stage.is_none(),
            "stop and recover lifecycle before registering a service"
        );
        self.verify(state.active.as_ref().context("Agent is not installed")?)
    }

    pub(crate) fn lock(&self) -> Result<File> {
        if self.home.exists() {
            ensure_dir(&self.home)?;
        } else {
            fs::create_dir_all(&self.home)?;
        }
        if self.root.exists() {
            ensure_dir(&self.root)?;
        } else {
            fs::create_dir(&self.root)?;
        }
        #[cfg(windows)]
        crate::private_file_windows::ensure_private_directory(&self.root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))?;
        }
        let path = self.root.join(".lock");
        if path.exists() {
            ensure_regular(&path)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        file.try_lock()
            .context("another lifecycle operation is in progress")?;
        Ok(file)
    }

    fn load(&self) -> Result<State> {
        let path = self.root.join(MANIFEST);
        if !path.exists() {
            return Ok(State::default());
        }
        ensure_regular(&path)?;
        let state: State = serde_json::from_slice(&fs::read(&path)?)
            .with_context(|| format!("invalid {}", path.display()))?;
        for record in [state.active.as_ref(), state.previous.as_ref()]
            .into_iter()
            .flatten()
        {
            self.path_for(record)?;
        }
        for record in &state.owned {
            self.path_for(record)?;
        }
        if let Some(process) = &state.process {
            ensure!(
                process.instance.len() == 43
                    && process
                        .instance
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                    && process.launch_log == format!(".launch-{}.log", process.instance)
                    && matches!(process.bind.as_str(), "127.0.0.1" | "::1" | "localhost")
                    && process.port != 0,
                "invalid managed process record"
            );
        }
        if let Some(operation) = &state.operation {
            self.path_for(&operation.from)?;
            self.path_for(&operation.to)?;
        }
        if let Some(pending) = &state.pending_stage {
            validate_stage_name(&pending.stage)?;
            validate_target_name(&pending.target)?;
        }
        Ok(state)
    }

    fn save(&self, state: &State) -> Result<()> {
        let temp = self.root.join(format!(".{}.tmp", crate::token::generate()));
        let mut file = create_private(&temp)?;
        file.write_all(&serde_json::to_vec_pretty(state)?)?;
        file.sync_all()?;
        drop(file);
        let target = self.root.join(MANIFEST);
        if target.exists() {
            ensure_regular(&target)?;
        }
        fs::rename(&temp, target)?;
        #[cfg(unix)]
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("read {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn validate_version(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            && value != "."
            && value != "..",
        "version must be 1-64 ASCII letters, digits, dots, hyphens, or underscores"
    );
    Ok(())
}

fn validate_digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "expected SHA-256 must be 64 lowercase hexadecimal characters"
    );
    Ok(())
}

fn validate_stage_name(value: &str) -> Result<()> {
    let token = value
        .strip_prefix('.')
        .and_then(|value| value.strip_suffix(".stage"))
        .context("invalid staged file name")?;
    ensure!(
        token.len() == 43
            && token
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_')),
        "invalid staged file name"
    );
    Ok(())
}

fn validate_target_name(value: &str) -> Result<()> {
    let version = value
        .strip_prefix("agentfw-")
        .and_then(|value| value.strip_suffix(std::env::consts::EXE_SUFFIX))
        .context("invalid staged target name")?;
    validate_version(version)
}

fn ensure_regular(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "{} is not a regular file",
        path.display()
    );
    Ok(())
}

fn ensure_dir(path: &Path) -> Result<()> {
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_dir(),
        "{} is not a regular directory",
        path.display()
    );
    Ok(())
}

fn create_private(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(windows)]
    crate::token::restrict(path)?;
    Ok(file)
}

fn port_occupied(config: &crate::Config) -> bool {
    use std::net::ToSocketAddrs;
    config
        .socket_address()
        .to_socket_addrs()
        .ok()
        .is_some_and(|addresses| {
            addresses.into_iter().any(|address| {
                std::net::TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_ok()
            })
        })
}

pub(crate) fn pid_alive(pid: u32) -> Result<bool> {
    if pid == 0 {
        return Ok(false);
    }
    #[cfg(unix)]
    {
        ensure!(pid <= i32::MAX as u32, "recorded PID is out of range");
        // Signal zero probes existence without sending a signal. EPERM means
        // a live process owned by someone else, never evidence of a dead PID.
        let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if result == 0 {
            return Ok(true);
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::ESRCH) => Ok(false),
            Some(libc::EPERM) => Ok(true),
            _ => Err(std::io::Error::last_os_error().into()),
        }
    }
    #[cfg(windows)]
    {
        let command = format!("if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 1 }}");
        Ok(Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &command])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn service_switch_is_journaled_and_staging_failure_keeps_active_version() {
        let temp = tempfile::tempdir().unwrap();
        let manager = Manager::new(temp.path());
        let binary = temp.path().join("candidate");
        fs::write(&binary, b"synthetic executable").unwrap();
        let digest = sha256_file(&binary).unwrap();
        let original = manager.install("one", &binary, &digest).unwrap();
        assert!(manager
            .service_prepare_upgrade("bad", &binary, &"0".repeat(64), true)
            .is_err());
        let (state, _) = manager.service_snapshot().unwrap();
        assert_eq!(state.active, Some(original.clone()));
        assert!(state.pending_stage.is_none() && state.operation.is_none());
        let target = manager
            .service_prepare_upgrade("two", &binary, &digest, true)
            .unwrap();
        let (state, _) = manager.service_snapshot().unwrap();
        assert_eq!(state.active, Some(original.clone()));
        let operation = state.operation.unwrap();
        assert_eq!(operation.from, original);
        assert_eq!(operation.to, target);
        assert!(operation.was_running);
        // The coordinator releases the state lock before starting systemd.
        drop(manager.lock().unwrap());
        assert!(manager
            .service_prepare_upgrade("three", &binary, &digest, false)
            .is_err());
        let foreign = Record {
            version: "foreign".into(),
            binary: "agentfw-foreign".into(),
            digest,
        };
        assert!(manager.service_select(&foreign).is_err());
        manager.service_select(&target).unwrap();
        manager.service_select(&original).unwrap();
        manager.service_finish().unwrap();
        let (state, _) = manager.service_snapshot().unwrap();
        assert_eq!(state.active, Some(original));
        assert_eq!(state.previous, Some(target));
        assert!(state.operation.is_none());
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn stopped_service_rollback_and_interrupted_stage_keep_running_intent() {
        let temp = tempfile::tempdir().unwrap();
        let manager = Manager::new(temp.path());
        let candidate = temp.path().join("candidate");
        fs::write(&candidate, b"synthetic executable").unwrap();
        let digest = sha256_file(&candidate).unwrap();
        let first = manager.install("one", &candidate, &digest).unwrap();
        let second = manager
            .service_prepare_upgrade("two", &candidate, &digest, false)
            .unwrap();
        manager.service_select(&second).unwrap();
        manager.service_finish().unwrap();
        assert_eq!(manager.service_prepare_rollback(false).unwrap(), first);
        assert!(!manager.load().unwrap().operation.unwrap().was_running);
        manager.service_select(&first).unwrap();
        manager.service_finish().unwrap();
        let lock = manager.lock().unwrap();
        let mut state = manager.load().unwrap();
        let stage = format!(".{}.stage", crate::token::generate());
        fs::write(manager.root.join(&stage), b"partial").unwrap();
        state.pending_stage = Some(PendingStage {
            stage: stage.clone(),
            target: "agentfw-incomplete".into(),
        });
        manager.save(&state).unwrap();
        drop(lock);
        manager.service_recover_staging().unwrap();
        assert!(!manager.root.join(stage).exists());
        let state = manager.load().unwrap();
        assert_eq!(state.active, Some(first));
        assert!(state.process.is_none() && state.pending_stage.is_none());
    }

    #[test]
    fn managed_identity_requires_every_field() {
        let record = ProcessRecord {
            pid: 42,
            instance: "instance".into(),
            binary_digest: "binary".into(),
            config_digest: "config".into(),
            port: 1,
            bind: "127.0.0.1".into(),
            launch_log: "log".into(),
        };
        let health = ManagedHealth {
            pid: 42,
            instance: "instance".into(),
            binary_digest: "binary".into(),
            config_digest: "config".into(),
        };
        assert!(record.matches(&health));
        assert!(!record.matches(&ManagedHealth {
            pid: 43,
            ..health.clone()
        }));
        assert!(!record.matches(&ManagedHealth {
            instance: "old".into(),
            ..health.clone()
        }));
        assert!(!record.matches(&ManagedHealth {
            binary_digest: "other".into(),
            ..health.clone()
        }));
        assert!(!record.matches(&ManagedHealth {
            config_digest: "other".into(),
            ..health
        }));
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn service_refuses_to_clear_or_stop_a_live_unverified_pid() {
        let temp = tempfile::tempdir().unwrap();
        let manager = Manager::new(temp.path());
        let lock = manager.lock().unwrap();
        let instance = crate::token::generate();
        let state = State {
            process: Some(ProcessRecord {
                pid: std::process::id(),
                instance: instance.clone(),
                binary_digest: "0".repeat(64),
                config_digest: "0".repeat(64),
                port: 1,
                bind: "127.0.0.1".into(),
                launch_log: format!(".launch-{instance}.log"),
            }),
            ..State::default()
        };
        manager.save(&state).unwrap();
        drop(lock);
        assert!(manager.service_clear_dead().is_err());
        assert!(manager.service_shutdown(std::process::id()).is_err());
        assert!(pid_alive(std::process::id()).unwrap());
        assert_eq!(
            manager.load().unwrap().process.unwrap().pid,
            std::process::id()
        );
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn permission_denial_is_not_evidence_that_a_pid_is_dead() {
        assert!(pid_alive(1).unwrap());
        assert!(pid_alive(u32::MAX).is_err());
        assert!(!pid_alive(0).unwrap());
    }
}
