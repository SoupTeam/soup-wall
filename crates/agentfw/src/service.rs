// SPDX-License-Identifier: Apache-2.0
//! Opt-in Linux user services. State locks are never held across systemctl waits.

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::lifecycle::{sha256_file, Manager, Record};

const STATE: &str = "ownership.json";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const PROPERTIES: &str = "LoadState,FragmentPath,DropInPaths,Transient,NeedDaemonReload,MainPID,ActiveState,SubState,Result,ControlGroup,UnitFileState,NRestarts";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    device: u64,
    inode: u64,
    digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Ownership {
    format_version: u32,
    uid: u32,
    home: PathBuf,
    unit: PathBuf,
    unit_digest: String,
    launcher: PathBuf,
    launcher_digest: String,
    unit_identity: Option<Identity>,
    launcher_identity: Option<Identity>,
    phase: Phase,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Installing,
    Installed,
    Removing,
}

#[derive(Serialize)]
pub struct Preview {
    pub home: PathBuf,
    pub unit_name: String,
    pub unit_path: PathBuf,
    pub launcher: PathBuf,
    pub unit: String,
    pub starts_automatically: bool,
    pub transaction_protocol: u32,
}

pub struct Service {
    home: PathBuf,
    root: PathBuf,
    unit_dir: PathBuf,
    name: String,
}

/// Even an invalid ownership record reserves the profile until explicitly repaired.
pub fn registered(home: &Path) -> bool {
    fs::symlink_metadata(home.join("service").join(STATE)).is_ok()
}

pub fn require_unregistered(home: &Path) -> Result<()> {
    ensure!(!registered(home), "profile has a registered service; use agentfw service commands (uninstall before lifecycle removal or migration)");
    Ok(())
}

impl Service {
    pub fn new(home: &Path) -> Result<Self> {
        Self::with_unit_dir(home, user_home()?.join(".config/systemd/user"))
    }

    fn with_unit_dir(home: &Path, unit_dir: PathBuf) -> Result<Self> {
        check_directory(home)?;
        let home = home.canonicalize()?;
        let name = format!(
            "agentfw-{}.service",
            digest(home.as_os_str().as_encoded_bytes())
        );
        Ok(Self {
            root: home.join("service"),
            home,
            unit_dir,
            name,
        })
    }

    fn launcher(&self) -> PathBuf {
        self.root.join("agentfw-launcher")
    }
    fn unit_path(&self) -> PathBuf {
        self.unit_dir.join(&self.name)
    }
    fn manager(&self) -> Manager {
        Manager::new(&self.home)
    }

    pub fn preview(&self) -> Result<Preview> {
        let launcher = quote(&self.launcher())?;
        let home = quote(&self.home)?;
        let unit = format!("[Unit]\nDescription=Soup Wall Agent\nStartLimitIntervalSec=60s\nStartLimitBurst=3\n\n[Service]\nType=exec\nExecStart={launcher} service --home {home} launch\nExecStartPost={launcher} service --home {home} ready\nExecStop={launcher} service --home {home} shutdown\nRestart=always\nRestartSec=2s\nTimeoutStartSec=35s\nTimeoutStopSec=30s\nKillMode=control-group\nUMask=0077\nStandardOutput=null\nStandardError=null\n");
        Ok(Preview {
            home: self.home.clone(),
            unit_name: self.name.clone(),
            unit_path: self.unit_path(),
            launcher: self.launcher(),
            unit,
            starts_automatically: false,
            transaction_protocol: 1,
        })
    }

    pub fn install(&self) -> Result<()> {
        let _operation = self.operation_lock()?;
        manager_available()?;
        if registered(&self.home) {
            let record = self.load()?;
            ensure!(
                record.phase == Phase::Installed,
                "service installation is incomplete; uninstall its recorded files before retrying"
            );
            self.verify(&record)?;
            self.verify_loaded()?;
            return Ok(());
        }
        let status = self.manager().status()?;
        ensure!(
            status.detail == "installed and stopped" && !status.interrupted,
            "install and recover the Agent lifecycle first"
        );
        ensure!(
            status.process.is_none(),
            "stop or recover the existing lifecycle process before installing a service"
        );
        let existing = self.show()?;
        ensure!(
            property(&existing, "LoadState") == "not-found"
                && property(&existing, "DropInPaths").is_empty(),
            "a unit with this name already exists"
        );
        ensure!(
            !exists(&self.unit_path())? && !exists(&self.launcher())?,
            "unowned service files already exist"
        );
        make_directory(&self.unit_dir)?;
        let preview = self.preview()?;
        let source = std::env::current_exe()?;
        owned_file(&source)?;
        let mut record = Ownership {
            format_version: 1,
            uid: uid(),
            home: self.home.clone(),
            unit: self.unit_path(),
            unit_digest: digest(preview.unit.as_bytes()),
            launcher: self.launcher(),
            launcher_digest: sha256_file(&source)?,
            unit_identity: None,
            launcher_identity: None,
            phase: Phase::Installing,
        };
        let lifecycle = self.manager();
        let state_lock = lifecycle.lock()?;
        // Recheck under the same lock used by legacy lifecycle mutations.
        // The service record reserves this profile before that lock is released.
        require_unregistered(&self.home)?;
        lifecycle.service_installable()?;
        self.save(&record)?;
        drop(state_lock);
        let mut launcher = create_private(&record.launcher)?;
        record.launcher_identity = Some(identity(&record.launcher)?);
        self.save(&record)?;
        std::io::copy(&mut File::open(source)?, &mut launcher)?;
        launcher.set_permissions(fs::Permissions::from_mode(0o700))?;
        launcher.sync_all()?;
        let mut unit = create_private(&record.unit)?;
        record.unit_identity = Some(identity(&record.unit)?);
        self.save(&record)?;
        unit.write_all(preview.unit.as_bytes())?;
        unit.sync_all()?;
        record.launcher_identity = Some(identity(&record.launcher)?);
        record.unit_identity = Some(identity(&record.unit)?);
        self.verify(&record)?;
        self.save(&record)?;
        control(&["daemon-reload"])?;
        self.verify_loaded()?;
        record.phase = Phase::Installed;
        self.save(&record)
    }

    pub fn uninstall(&self) -> Result<()> {
        if !registered(&self.home) {
            return Ok(());
        }
        let _operation = self.operation_lock()?;
        let mut record = self.load()?;
        manager_available()?;
        self.verify_remaining(&record)?;
        let shown = self.show()?;
        if record.phase == Phase::Installed {
            self.idle()?;
            self.verify_loaded()?;
            self.stop_locked()?;
        } else {
            // Interrupted installation/removal may leave an invalid fragment or
            // a stale cached definition. Never stop an unidentified live unit.
            ensure!(property(&shown, "MainPID") == "0"
                && matches!(property(&shown, "ActiveState"), "inactive" | "failed")
                && property(&shown, "DropInPaths").is_empty()
                && property(&shown, "Transient") == "no"
                && (property(&shown, "FragmentPath").is_empty()
                    || property(&shown, "FragmentPath") == record.unit.to_str().context("unit path is not UTF-8")?),
                "incomplete service has a live process or foreign configuration; inspect before removal");
        }
        // Stop may wait for the Agent. Revalidate ownership after that wait,
        // then again immediately before unlinking each recorded artifact.
        self.verify_remaining(&record)?;
        // Keep Installing while deleting a partial copy: its recorded inode is
        // the cleanup authority even when the content never reached its hash.
        if record.phase != Phase::Installing {
            record.phase = Phase::Removing;
            self.save(&record)?;
        }
        for (path, hash, expected) in [
            (
                &record.unit,
                &record.unit_digest,
                record.unit_identity.as_ref(),
            ),
            (
                &record.launcher,
                &record.launcher_digest,
                record.launcher_identity.as_ref(),
            ),
        ] {
            if exists(path)? {
                verify_removable(record.phase, path, hash, expected)?;
                fs::remove_file(path)?;
            }
        }
        control(&["daemon-reload"])?;
        fs::remove_file(self.root.join(STATE))?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    fn require_transaction_launcher(&self) -> Result<()> {
        self.installed()?;
        let home = self.home.to_str().context("profile path is not UTF-8")?;
        let mut command = Command::new(self.launcher());
        command.args(["service", "--home", home, "preview"]);
        let output = command_output(command, false)
            .context("installed launcher predates service transactions; stop, uninstall and reinstall the service with this CLI first")?;
        let preview: serde_json::Value = serde_json::from_str(&output)?;
        ensure!(preview["transaction_protocol"] == 1,
            "installed launcher predates service transactions; stop, uninstall and reinstall the service with this CLI first");
        Ok(())
    }

    fn idle(&self) -> Result<()> {
        let (state, _) = self.manager().service_snapshot()?;
        ensure!(
            state.operation.is_none() && state.pending_stage.is_none(),
            "recover the interrupted operation first"
        );
        Ok(())
    }

    fn running_intent(&self) -> Result<bool> {
        self.installed()?;
        let shown = self.verify_loaded()?;
        if self.verified_health()?.is_some() {
            return Ok(true);
        }
        ensure!(
            property(&shown, "MainPID") == "0" && property(&shown, "ActiveState") == "inactive",
            "service is not verified running or explicitly stopped; recover it first"
        );
        self.manager().service_clear_dead()?;
        Ok(false)
    }

    pub fn upgrade(&self, version: &str, candidate: &Path, digest: &str) -> Result<Record> {
        let _operation = self.operation_lock()?;
        self.idle()?;
        self.require_transaction_launcher()?;
        let running = self.running_intent()?;
        // Verify and stage before stopping the healthy service.
        let target = self
            .manager()
            .service_prepare_upgrade(version, candidate, digest, running)?;
        self.switch_transaction(&target)?;
        Ok(target)
    }

    pub fn rollback(&self) -> Result<Record> {
        let _operation = self.operation_lock()?;
        self.idle()?;
        self.require_transaction_launcher()?;
        let running = self.running_intent()?;
        let target = self.manager().service_prepare_rollback(running)?;
        self.switch_transaction(&target)?;
        Ok(target)
    }

    pub fn recover(&self) -> Result<()> {
        let _operation = self.operation_lock()?;
        self.installed()?;
        self.verify_loaded()?;
        self.require_transaction_launcher()?;
        self.manager().service_recover_staging()?;
        let (state, _) = self.manager().service_snapshot()?;
        if state.operation.is_some() {
            return self.restore_transaction().context(
                "service recovery is incomplete; resolve the conflict and retry lifecycle recover",
            );
        }
        let shown = self.verify_loaded()?;
        if property(&shown, "MainPID") != "0" {
            ensure!(
                self.verified_health()?.is_some(),
                "live service identity cannot be verified; refusing recovery"
            );
        } else {
            self.manager().service_clear_dead()?;
        }
        self.manager()
            .verify(state.active.as_ref().context("Agent is not installed")?)
    }

    fn switch_transaction(&self, target: &Record) -> Result<()> {
        let (state, _) = self.manager().service_snapshot()?;
        let operation = state.operation.context("no service transaction")?;
        let changed = (|| -> Result<()> {
            self.stop_locked()?;
            self.manager().service_select(target)?;
            if operation.was_running {
                self.start_locked()?;
            }
            Ok(())
        })();
        if let Err(error) = changed {
            self.restore_transaction().context(
                "service update failed and recovery is incomplete; run lifecycle recover",
            )?;
            bail!("service update failed and the original version was restored: {error:#}");
        }
        self.manager().service_finish()
    }

    fn restore_transaction(&self) -> Result<()> {
        let (state, _) = self.manager().service_snapshot()?;
        let operation = state
            .operation
            .context("no interrupted service transaction")?;
        // Stop also cancels a queued automatic restart after a failed candidate.
        self.stop_locked()?;
        self.manager().service_select(&operation.from)?;
        if operation.was_running {
            let shown = self.verify_loaded()?;
            if property(&shown, "ActiveState") == "failed" {
                control(&["reset-failed", &self.name])?;
            }
            self.start_locked()?;
        }
        self.manager().service_finish()
    }

    pub fn start(&self) -> Result<()> {
        let _operation = self.operation_lock()?;
        self.idle()?;
        self.start_locked()
    }

    fn start_locked(&self) -> Result<()> {
        self.installed()?;
        let shown = self.verify_loaded()?;
        let (state, health) = self.manager().service_snapshot()?;
        if let Some(process) = &state.process {
            if crate::lifecycle::pid_alive(process.pid)? {
                ensure!(
                    health.is_some() && process.pid.to_string() == property(&shown, "MainPID"),
                    "existing process identity is not verified; inspect before starting"
                );
            } else {
                ensure!(
                    property(&shown, "MainPID") == "0",
                    "systemd is changing the main process; inspect before retrying"
                );
                self.manager().service_clear_dead()?;
            }
        }
        control(&["start", &self.name])?;
        ensure!(
            self.verified_health()?.is_some(),
            "systemd started the service without verified Agent readiness"
        );
        Ok(())
    }

    pub fn stop(&self) -> Result<()> {
        let _operation = self.operation_lock()?;
        self.idle()?;
        self.stop_locked()
    }

    fn stop_locked(&self) -> Result<()> {
        self.installed()?;
        let shown = self.verify_loaded()?;
        let main_pid: u32 = property(&shown, "MainPID").parse()?;
        if main_pid != 0 {
            let (_, health) = self.manager().service_snapshot()?;
            ensure!(
                health.is_some_and(|h| h.pid == main_pid)
                    || self.preparing_launcher(&shown, main_pid)?,
                "live process identity cannot be verified; refusing stop"
            );
        }
        control(&["stop", &self.name])?;
        let shown = self.verify_loaded()?;
        ensure!(
            property(&shown, "MainPID") == "0"
                && matches!(property(&shown, "ActiveState"), "inactive" | "failed"),
            "systemd did not stop the service"
        );
        self.manager().service_clear_dead()
    }

    fn preparing_launcher(&self, shown: &BTreeMap<String, String>, pid: u32) -> Result<bool> {
        // A restart can be in the owned launcher before any Agent/HTTP identity
        // exists. Confirm executable inode and the exact unit cgroup; never infer
        // ownership from a PID or a startup state alone.
        if !matches!(property(shown, "SubState"), "start" | "start-post") {
            return Ok(false);
        }
        let record = self.installed()?;
        let Some(expected) = record.launcher_identity else {
            return Ok(false);
        };
        let exe = format!("/proc/{pid}/exe");
        let Ok(path) = fs::read_link(&exe) else {
            return Ok(false);
        };
        if path != self.launcher() {
            return Ok(false);
        }
        let metadata = fs::metadata(&exe)?;
        let group = property(shown, "ControlGroup");
        Ok(metadata.dev() == expected.device
            && metadata.ino() == expected.inode
            && !group.is_empty()
            && fs::read_to_string(format!("/proc/{pid}/cgroup"))?
                .lines()
                .any(|line| line.rsplit_once(':').is_some_and(|(_, path)| path == group)))
    }

    pub fn restart(&self) -> Result<()> {
        let _operation = self.operation_lock()?;
        self.idle()?;
        self.stop_locked()?;
        self.start_locked()
    }

    fn installed(&self) -> Result<Ownership> {
        let record = self.load()?;
        ensure!(
            record.phase == Phase::Installed,
            "service operation is incomplete; inspect before recovery"
        );
        self.verify(&record)?;
        Ok(record)
    }

    fn internal(&self) -> Result<BTreeMap<String, String>> {
        let record = self.installed()?;
        ensure!(
            identity(&std::env::current_exe()?)?
                == record
                    .launcher_identity
                    .context("launcher has no recorded identity")?,
            "internal service command must use the owned launcher"
        );
        let shown = self.verify_loaded()?;
        let group = property(&shown, "ControlGroup");
        ensure!(
            !group.is_empty()
                && fs::read_to_string("/proc/self/cgroup")?
                    .lines()
                    .any(|line| line.rsplit_once(':').is_some_and(|(_, path)| path == group)),
            "internal service command must run in its systemd unit"
        );
        Ok(shown)
    }

    pub fn launch(&self) -> Result<()> {
        use std::os::unix::process::CommandExt;
        let shown = self.internal()?;
        ensure!(
            property(&shown, "MainPID") == std::process::id().to_string(),
            "launcher is not the systemd main process"
        );
        let (binary, process) = self.manager().service_launch()?;
        let error = Command::new(binary)
            .args([
                "lifecycle",
                "serve-managed",
                "--instance",
                &process.instance,
            ])
            .arg("--home")
            .arg(&self.home)
            .exec();
        Err(error).context("cannot exec the installed Agent")
    }

    pub fn verify_managed_process(&self, instance: &str) -> Result<()> {
        self.installed()?;
        let shown = self.verify_loaded()?;
        let (state, _) = self.manager().service_snapshot()?;
        let process = state.process.context("service has no recorded process")?;
        ensure!(
            process.pid == std::process::id()
                && process.instance == instance
                && process.pid.to_string() == property(&shown, "MainPID"),
            "managed process is not the recorded systemd main process"
        );
        Ok(())
    }

    fn verified_health(&self) -> Result<Option<crate::lifecycle::ManagedHealth>> {
        self.installed()?;
        let shown = self.verify_loaded()?;
        let manager = self.manager();
        let (state, health) = manager.service_snapshot()?;
        let Some(health) = health else {
            return Ok(None);
        };
        let active = state.active.context("service has no active version")?;
        manager.verify(&active)?;
        ensure!(
            health.binary_digest == active.digest
                && health.config_digest == manager.config_digest()?,
            "running Agent differs from the installed version or current configuration"
        );
        ensure!(
            property(&shown, "MainPID") == health.pid.to_string(),
            "Agent PID differs from systemd MainPID"
        );
        ensure!(
            fs::read_link(format!("/proc/{}/exe", health.pid))? == manager.path_for(&active)?,
            "systemd main executable differs from the installed Agent"
        );
        Ok(Some(health))
    }

    pub fn ready(&self) -> Result<()> {
        self.internal()?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if self.verified_health()?.is_some() {
                return Ok(());
            }
            let (state, _) = self.manager().service_snapshot()?;
            if let Some(process) = state.process {
                ensure!(
                    crate::lifecycle::pid_alive(process.pid)?,
                    "Agent exited before readiness"
                );
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        bail!("Agent did not pass authenticated readiness within 30 seconds")
    }

    pub fn shutdown(&self) -> Result<()> {
        let shown = self.internal()?;
        self.manager()
            .service_shutdown(property(&shown, "MainPID").parse()?)
    }

    pub fn status(&self) -> Result<crate::lifecycle::Status> {
        let (state, _) = self.manager().service_snapshot()?;
        let observation = self.inspect();
        let running = observation["ready"] == true;
        let interrupted = state.operation.is_some() || state.pending_stage.is_some();
        let detail = if interrupted {
            "interrupted operation; run lifecycle recover".into()
        } else if let Some(error) = observation["error"].as_str() {
            error.to_owned()
        } else if running {
            "running and verified by systemd".into()
        } else {
            "service is not verified ready; inspect service status".into()
        };
        Ok(crate::lifecycle::Status {
            active: state.active,
            previous: state.previous,
            process: state.process,
            running,
            interrupted,
            detail,
        })
    }

    pub fn inspect(&self) -> serde_json::Value {
        let mut report = serde_json::json!({"format_version":1, "home":self.home, "unit_name":self.name, "registered":registered(&self.home), "ready":false});
        let observed = (|| -> Result<()> {
            let (state, _) = self.manager().service_snapshot()?;
            report["interrupted"] =
                serde_json::json!(state.operation.is_some() || state.pending_stage.is_some());
            report["transaction"] = serde_json::to_value(&state.operation)?;
            let record = self.load()?;
            report["phase"] = serde_json::to_value(record.phase)?;
            self.verify(&record)?;
            let shown = self.verify_loaded()?;
            report["systemd"] = serde_json::to_value(shown)?;
            let health = self.verified_health()?;
            report["ready"] = serde_json::json!(health.is_some());
            report["health"] = serde_json::to_value(health)?;
            Ok(())
        })();
        if let Err(error) = observed {
            report["error"] = serde_json::json!(error.to_string());
        }
        report
    }

    fn operation_lock(&self) -> Result<File> {
        make_directory(&self.root)?;
        let path = self.root.join("operation.lock");
        if exists(&path)? {
            owned_file(&path)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        file.try_lock()
            .context("another service operation is in progress")?;
        Ok(file)
    }

    fn load(&self) -> Result<Ownership> {
        check_directory(&self.root)?;
        let path = self.root.join(STATE);
        owned_file(&path)?;
        let record: Ownership =
            serde_json::from_slice(&fs::read(path)?).context("invalid service ownership record")?;
        ensure!(
            record.format_version == 1
                && record.uid == uid()
                && record.home == self.home
                && record.unit == self.unit_path()
                && record.launcher == self.launcher(),
            "service ownership does not match this profile and user"
        );
        ensure!(
            record.unit_digest == digest(self.preview()?.unit.as_bytes()),
            "recorded unit does not match the supported service definition"
        );
        Ok(record)
    }

    fn save(&self, record: &Ownership) -> Result<()> {
        let temp = self.root.join(format!(".{}.tmp", crate::token::generate()));
        let mut file = create_private(&temp)?;
        file.write_all(&serde_json::to_vec_pretty(record)?)?;
        file.sync_all()?;
        let path = self.root.join(STATE);
        if exists(&path)? {
            owned_file(&path)?;
        }
        fs::rename(temp, path)?;
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    fn verify(&self, record: &Ownership) -> Result<()> {
        verify_file(
            &record.unit,
            &record.unit_digest,
            record.unit_identity.as_ref(),
        )?;
        verify_file(
            &record.launcher,
            &record.launcher_digest,
            record.launcher_identity.as_ref(),
        )
    }

    fn verify_remaining(&self, record: &Ownership) -> Result<()> {
        for (path, hash, id) in [
            (
                &record.unit,
                &record.unit_digest,
                record.unit_identity.as_ref(),
            ),
            (
                &record.launcher,
                &record.launcher_digest,
                record.launcher_identity.as_ref(),
            ),
        ] {
            if exists(path)? {
                verify_removable(record.phase, path, hash, id)?;
            } else {
                ensure!(
                    record.phase != Phase::Installed,
                    "owned service file is missing"
                );
            }
        }
        Ok(())
    }

    fn show(&self) -> Result<BTreeMap<String, String>> {
        let text = systemctl(&["show", &self.name, "--property", PROPERTIES], true)?;
        let mut values = BTreeMap::new();
        for line in text.lines() {
            let (key, value) = line
                .split_once('=')
                .context("invalid systemctl properties")?;
            ensure!(
                values.insert(key.to_owned(), value.to_owned()).is_none(),
                "duplicate systemctl property"
            );
        }
        for key in PROPERTIES.split(',') {
            ensure!(
                values.contains_key(key),
                "missing systemctl property: {key}"
            );
        }
        Ok(values)
    }

    fn verify_loaded(&self) -> Result<BTreeMap<String, String>> {
        let shown = self.show()?;
        ensure!(
            property(&shown, "LoadState") == "loaded"
                && property(&shown, "FragmentPath")
                    == self
                        .unit_path()
                        .to_str()
                        .context("unit path is not UTF-8")?,
            "systemd loaded a different or unavailable unit"
        );
        ensure!(
            property(&shown, "DropInPaths").is_empty()
                && property(&shown, "Transient") == "no"
                && property(&shown, "NeedDaemonReload") == "no",
            "unit has overrides or changed settings; refusing service management"
        );
        ensure!(
            property(&shown, "UnitFileState") == "static",
            "service has unexpected enablement or unit links"
        );
        Ok(shown)
    }
}

fn property<'a>(shown: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    shown.get(key).map(String::as_str).unwrap_or("")
}
fn uid() -> u32 {
    unsafe { libc::geteuid() }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn user_home() -> Result<PathBuf> {
    // Reentrant lookup avoids HOME overrides used for disposable Agent profiles.
    let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut buffer = vec![0u8; 65536];
    let mut result = std::ptr::null_mut();
    let code = unsafe {
        libc::getpwuid_r(
            uid(),
            record.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    ensure!(
        code == 0 && !result.is_null(),
        "cannot determine the current user's service directory"
    );
    let record = unsafe { record.assume_init() };
    let path = unsafe { std::ffi::CStr::from_ptr(record.pw_dir) }.to_str()?;
    Ok(PathBuf::from(path))
}

fn quote(path: &Path) -> Result<String> {
    let value = path.to_str().context("service paths must be UTF-8")?;
    ensure!(
        path.is_absolute() && !value.chars().any(char::is_control),
        "service paths must be absolute without control characters"
    );
    Ok(format!(
        "\"{}\"",
        value
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
            .replace('$', "$$")
    ))
}

fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
    }
}

fn check_parents(path: &Path) -> Result<()> {
    for parent in path.ancestors().skip(1) {
        if parent.as_os_str().is_empty() {
            continue;
        }
        let metadata = fs::symlink_metadata(parent)?;
        ensure!(
            metadata.is_dir(),
            "service path has a symlink or non-directory parent"
        );
        ensure!(
            metadata.mode() & 0o022 == 0
                || (metadata.uid() == 0 && metadata.mode() & libc::S_ISVTX != 0),
            "service path has a parent writable by another user"
        );
    }
    Ok(())
}

fn check_directory(path: &Path) -> Result<()> {
    check_parents(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir() && metadata.uid() == uid() && metadata.mode() & 0o022 == 0,
        "service directory must be owned by this user and not writable by others"
    );
    Ok(())
}

fn make_directory(path: &Path) -> Result<()> {
    if !exists(path)? {
        if let Some(parent) = path.parent() {
            if !exists(parent)? {
                make_directory(parent)?;
            }
        }
        fs::create_dir(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    check_directory(path)
}

fn owned_file(path: &Path) -> Result<fs::Metadata> {
    check_parents(path)?;
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == uid()
            && metadata.nlink() == 1
            && metadata.mode() & 0o022 == 0,
        "service file is foreign, linked, or writable by others: {}",
        path.display()
    );
    Ok(metadata)
}

fn create_private(path: &Path) -> Result<File> {
    Ok(OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?)
}

fn identity(path: &Path) -> Result<Identity> {
    let metadata = owned_file(path)?;
    Ok(Identity {
        device: metadata.dev(),
        inode: metadata.ino(),
        digest: sha256_file(path)?,
    })
}

fn verify_file(path: &Path, hash: &str, expected: Option<&Identity>) -> Result<()> {
    let actual = identity(path)?;
    ensure!(
        actual.digest == hash && expected.is_none_or(|value| value == &actual),
        "owned service file changed or was replaced: {}",
        path.display()
    );
    Ok(())
}

fn verify_removable(
    phase: Phase,
    path: &Path,
    hash: &str,
    expected: Option<&Identity>,
) -> Result<()> {
    if let (Phase::Installing, Some(expected)) = (phase, expected) {
        let actual = identity(path)?;
        ensure!(
            actual.device == expected.device && actual.inode == expected.inode,
            "partially installed service file was replaced; refusing cleanup"
        );
        Ok(())
    } else {
        verify_file(path, hash, expected)
    }
}

fn manager_available() -> Result<()> {
    systemctl(&["show", "--property=Version"], false)
        .context("user systemd manager is unavailable; run in a Linux user session")?;
    Ok(())
}
fn control(args: &[&str]) -> Result<()> {
    systemctl(args, false).map(|_| ())
}

fn systemctl(args: &[&str], allow_missing: bool) -> Result<String> {
    let mut command = Command::new(SYSTEMCTL);
    command
        .args(["--user", "--no-pager", "--no-ask-password"])
        .args(args);
    command_output(command, allow_missing)
}

fn command_output(mut command: Command, allow_missing: bool) -> Result<String> {
    let mut child = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("cannot execute systemctl --user")?;
    let mut stdout = child.stdout.take().context("missing systemctl output")?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        (&mut stdout)
            .take(65537)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(45);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("systemctl timed out; operation may be incomplete, inspect before retrying");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let bytes = reader
        .join()
        .map_err(|_| anyhow::anyhow!("systemctl output reader failed"))??;
    ensure!(
        status.success() || (allow_missing && status.code() == Some(4)),
        "systemctl operation failed ({status}); inspect the service state"
    );
    ensure!(
        bytes.len() <= 65536,
        "systemctl output exceeded the safety limit"
    );
    Ok(String::from_utf8(bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quoting_preserves_literals_and_rejects_controls() {
        assert_eq!(
            quote(Path::new("/tmp/a b%$\"\\")).unwrap(),
            "\"/tmp/a b%%$$\\\"\\\\\""
        );
        assert!(quote(Path::new("/tmp/a\nb")).is_err());
        assert!(quote(Path::new("relative")).is_err());
    }
    #[test]
    fn preview_is_nonmutating_and_profiles_are_distinct() {
        let temp = tempfile::tempdir().unwrap();
        let a = Service::with_unit_dir(temp.path(), temp.path().join("units")).unwrap();
        let preview = a.preview().unwrap();
        assert!(!a.root.exists());
        assert!(!preview.unit.contains("[Install]"));
        assert!(preview.unit.contains("Type=exec"));
        assert!(preview.unit.contains("Restart=always\nRestartSec=2s"));
        assert!(preview
            .unit
            .contains("StartLimitIntervalSec=60s\nStartLimitBurst=3"));
        assert!(preview.unit.contains("ExecStartPost="));
        assert!(preview.unit.contains("TimeoutStartSec=35s"));
        assert!(preview.unit.contains("KillMode=control-group"));
        assert!(!preview.unit.contains("lifecycle start"));
        let other = tempfile::tempdir().unwrap();
        assert_ne!(
            a.name,
            Service::with_unit_dir(other.path(), other.path().join("units"))
                .unwrap()
                .name
        );
    }
    #[test]
    fn invalid_ownership_still_blocks_legacy_operations() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir(temp.path().join("service")).unwrap();
        fs::write(temp.path().join("service/ownership.json"), "invalid").unwrap();
        let manager = Manager::new(temp.path());
        assert!(manager.start().is_err());
        assert!(manager
            .remove()
            .unwrap_err()
            .to_string()
            .contains("registered service"));
        assert!(manager.recover().is_err());
    }

    #[test]
    fn incomplete_copy_cleanup_requires_the_recorded_inode() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("partial");
        fs::write(&path, b"").unwrap();
        let id = identity(&path).unwrap();
        fs::write(&path, b"partial copy").unwrap();
        let expected_hash = digest(b"complete copy");
        assert!(verify_removable(Phase::Installed, &path, &expected_hash, Some(&id)).is_err());
        assert!(verify_removable(Phase::Installing, &path, &expected_hash, Some(&id)).is_ok());
        fs::rename(&path, temp.path().join("original")).unwrap();
        fs::write(&path, b"partial copy").unwrap();
        assert!(verify_removable(Phase::Installing, &path, &expected_hash, Some(&id)).is_err());
        // Old incomplete records without an inode only authorize a full hash match.
        assert!(verify_removable(Phase::Installing, &path, &expected_hash, None).is_err());
    }

    #[test]
    fn replaced_or_linked_files_are_never_owned() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("file");
        fs::write(&path, "owned").unwrap();
        let id = identity(&path).unwrap();
        fs::rename(&path, temp.path().join("old")).unwrap();
        fs::write(&path, "owned").unwrap();
        assert!(verify_file(&path, &id.digest, Some(&id)).is_err());
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(temp.path().join("old"), &path).unwrap();
        assert!(identity(&path).is_err());
    }
}
