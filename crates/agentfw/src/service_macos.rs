// SPDX-License-Identifier: Apache-2.0
//! Explicit current-user launchd jobs, composed with the existing lifecycle journal.
//! No LaunchAgents directory, enable/disable override, shell, or root service is used.

use anyhow::{bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::lifecycle::{sha256_file, Manager, Record};

const STATE: &str = "ownership.json";
const LAUNCHCTL: &str = "/bin/launchctl";
const RESTART_WINDOW: u64 = 60;
const MAX_STARTS: usize = 3;

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
    domain: String,
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
    pub backend: &'static str,
    pub home: PathBuf,
    pub unit_name: String,
    pub unit_path: PathBuf,
    pub launcher: PathBuf,
    pub unit: String,
    pub starts_automatically: bool,
    pub transaction_protocol: u32,
    pub instance_selection: bool,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RestartBudget {
    starts: Vec<u64>,
}

#[derive(Debug, Default, Serialize)]
struct Job {
    pid: u32,
    state: String,
    path: String,
    program: String,
    arguments: Vec<String>,
}

pub struct Service {
    home: PathBuf,
    root: PathBuf,
    name: String,
}

pub fn registered(home: &Path) -> bool {
    fs::symlink_metadata(home.join("service").join(STATE)).is_ok()
}

pub fn require_unregistered(home: &Path) -> Result<()> {
    ensure!(!registered(home), "profile has a registered service; use agentfw service commands (uninstall before lifecycle removal or migration)");
    Ok(())
}

impl Service {
    pub fn new(home: &Path) -> Result<Self> {
        ensure!(
            uid() != 0,
            "launchd Agent services require a non-root user session"
        );
        check_directory(home)?;
        let home = home.canonicalize()?;
        let name = format!(
            "org.soup-wall.agentfw.{}",
            digest(home.as_os_str().as_encoded_bytes())
        );
        Ok(Self {
            root: home.join("service"),
            home,
            name,
        })
    }

    fn launcher(&self) -> PathBuf {
        self.root.join("agentfw-launcher")
    }
    fn unit_path(&self) -> PathBuf {
        self.root.join(format!("{}.plist", self.name))
    }
    fn manager(&self) -> Manager {
        Manager::new(&self.home)
    }
    fn arguments(&self) -> Result<Vec<String>> {
        Ok(vec![
            path_text(&self.launcher())?,
            "service".into(),
            "--home".into(),
            path_text(&self.home)?,
            "launch".into(),
        ])
    }

    pub fn preview(&self) -> Result<Preview> {
        let arguments = self
            .arguments()?
            .iter()
            .map(|v| format!("<string>{}</string>", xml(v)))
            .collect::<Vec<_>>()
            .join("\n");
        // An exhausted launcher exits successfully, ending KeepAlive retries.
        // Installation writes this private plist but does NOT bootstrap it.
        let unit = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{}</string>\n<key>ProgramArguments</key><array>{arguments}</array>\n<key>RunAtLoad</key><true/>\n<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>\n<key>ThrottleInterval</key><integer>10</integer>\n<key>ExitTimeOut</key><integer>20</integer>\n<key>Umask</key><integer>63</integer>\n<key>StandardOutPath</key><string>/dev/null</string>\n<key>StandardErrorPath</key><string>/dev/null</string>\n</dict></plist>\n", self.name);
        Ok(Preview {
            backend: "launchd",
            home: self.home.clone(),
            unit_name: self.name.clone(),
            unit_path: self.unit_path(),
            launcher: self.launcher(),
            unit,
            starts_automatically: false,
            transaction_protocol: 2,
            instance_selection: true,
        })
    }

    pub fn install(&self) -> Result<()> {
        let _operation = self.operation_lock()?;
        if registered(&self.home) {
            let record = self.installed()?;
            self.job(&record)?;
            return Ok(());
        }
        let domain = select_domain()?;
        self.ensure_absent_everywhere()?;
        ensure!(
            !exists(&self.unit_path())? && !exists(&self.launcher())?,
            "unowned service artifacts already exist"
        );
        let preview = self.preview()?;
        let source = std::env::current_exe()?;
        owned_file(&source)?;
        let mut record = Ownership {
            format_version: 1,
            uid: uid(),
            home: self.home.clone(),
            domain,
            unit: self.unit_path(),
            unit_digest: digest(preview.unit.as_bytes()),
            launcher: self.launcher(),
            launcher_digest: sha256_file(&source)?,
            unit_identity: None,
            launcher_identity: None,
            phase: Phase::Installing,
        };
        let manager = self.manager();
        let state_lock = manager.lock()?;
        require_unregistered(&self.home)?;
        manager.service_installable()?;
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
        record.phase = Phase::Installed;
        self.save(&record)
    }

    pub fn uninstall(&self) -> Result<()> {
        let _operation = self.operation_lock()?;
        if !registered(&self.home) {
            return Ok(());
        }
        let mut record = self.load()?;
        self.verify_remaining(&record)?;
        if record.phase == Phase::Installed {
            self.idle()?;
            self.stop_locked()?;
        } else {
            self.ensure_absent_everywhere()?;
            self.manager().service_clear_dead()?;
        }
        self.verify_remaining(&record)?;
        if record.phase == Phase::Installed {
            record.phase = Phase::Removing;
            self.save(&record)?;
        }
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
                fs::remove_file(path)?;
            }
        }
        self.reset_budget()?;
        fs::remove_file(self.root.join(STATE))?;
        File::open(&self.root)?.sync_all()?;
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

    pub fn upgrade(&self, version: &str, candidate: &Path, digest: &str) -> Result<Record> {
        let _operation = self.operation_lock()?;
        self.idle()?;
        self.require_instance_launcher()?;
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
        self.require_instance_launcher()?;
        let running = self.running_intent()?;
        let target = self.manager().service_prepare_rollback(running)?;
        self.switch_transaction(&target)?;
        Ok(target)
    }

    pub fn recover(&self) -> Result<()> {
        let _operation = self.operation_lock()?;
        self.installed()?;
        self.require_instance_launcher()?;
        self.manager().service_recover_staging()?;
        let (state, _) = self.manager().service_snapshot()?;
        if state.operation.is_some() {
            return self.restore_transaction().context(
                "service recovery is incomplete; resolve the conflict and retry lifecycle recover",
            );
        }
        let record = self.installed()?;
        if self.job(&record)?.is_some_and(|j| j.pid != 0) {
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
            self.start_locked()?;
        }
        self.manager().service_finish()
    }

    pub fn restart_with_ownership_check(
        &self,
        expected_instance: Option<&str>,
        was_running: bool,
        candidate_instance: Option<&str>,
    ) -> Result<()> {
        let _operation = self.operation_lock()?;
        self.idle()?;
        if candidate_instance.is_some() {
            self.require_instance_launcher()?;
        }
        let (state, health) = self.manager().service_snapshot()?;
        if was_running {
            ensure!(
                health.is_some(),
                "conflict: daemon process died or is not responding before restart"
            );
            if let Some(expected) = expected_instance {
                let current_inst = state.process.as_ref().map(|p| p.instance.as_str());
                ensure!(
                    current_inst == Some(expected),
                    "conflict: daemon was restarted independently before profile restart (expected {expected}, got {current_inst:?})"
                );
            }
            self.stop_locked()?;
            if let Some(cand) = candidate_instance {
                self.manager().set_next_instance(Some(cand))?;
            }
            let res = self.start_locked();
            if res.is_err() {
                let _ = self.manager().set_next_instance(None);
            }
            res
        } else {
            self.manager().service_clear_dead()?;
            let (state, health) = self.manager().service_snapshot()?;
            ensure!(
                health.is_none() && state.process.is_none(),
                "conflict: an independent daemon was started before candidate launch"
            );
            if let Some(cand) = candidate_instance {
                self.manager().set_next_instance(Some(cand))?;
            }
            let res = self.start_locked();
            if res.is_err() {
                let _ = self.manager().set_next_instance(None);
            }
            res
        }
    }

    fn installed(&self) -> Result<Ownership> {
        let record = self.load()?;
        ensure!(
            record.phase == Phase::Installed,
            "service operation is incomplete; uninstall recorded artifacts before reinstalling"
        );
        self.verify(&record)?;
        Ok(record)
    }

    pub fn require_instance_launcher(&self) -> Result<()> {
        self.installed().map(|_| ())
    }

    fn running_intent(&self) -> Result<bool> {
        let record = self.installed()?;
        if self.verified_health()?.is_some() {
            return Ok(true);
        }
        ensure!(
            self.job(&record)?.is_none(),
            "loaded service is not verified; stop or recover it first"
        );
        self.manager().service_clear_dead()?;
        Ok(false)
    }

    pub fn start(&self) -> Result<()> {
        let _operation = self.operation_lock()?;
        self.idle()?;
        self.manager().set_next_instance(None)?;
        self.start_locked()
    }

    fn start_locked(&self) -> Result<()> {
        let record = self.installed()?;
        if self.job(&record)?.is_some() {
            ensure!(
                self.verified_health()?.is_some(),
                "loaded service is not verified; stop it before retrying"
            );
            return Ok(());
        }
        self.ensure_absent_everywhere()?;
        self.manager().service_clear_dead()?;
        self.reset_budget()?;
        control(&["bootstrap", &record.domain, &path_text(&record.unit)?])?;
        if let Err(error) = self.ready() {
            self.stop_locked()
                .context("startup failed; owned service cleanup requires retrying stop")?;
            return Err(error);
        }
        Ok(())
    }

    pub fn stop(&self) -> Result<()> {
        let _operation = self.operation_lock()?;
        self.idle()?;
        self.stop_locked()
    }

    fn stop_locked(&self) -> Result<()> {
        let record = self.installed()?;
        if let Some(job) = self.job(&record)? {
            if job.pid != 0 {
                ensure!(
                    self.owned_process(job.pid)?,
                    "live launchd process identity cannot be verified; refusing stop"
                );
            }
            // bootout removes KeepAlive demand before killing the owned job.
            // SIGTERM alone would request another launch after a crash.
            control(&["bootout", &format!("{}/{}", record.domain, self.name)])?;
            let deadline = Instant::now() + Duration::from_secs(25);
            loop {
                if self.job(&record)?.is_none()
                    && (job.pid == 0 || !crate::lifecycle::pid_alive(job.pid)?)
                {
                    break;
                }
                ensure!(
                    Instant::now() < deadline,
                    "launchd bootout did not finish within 25 seconds"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
        }
        self.manager().service_clear_dead()
    }

    pub fn restart(&self) -> Result<()> {
        let _operation = self.operation_lock()?;
        self.idle()?;
        self.manager().set_next_instance(None)?;
        self.stop_locked()?;
        self.start_locked()
    }

    fn internal(&self) -> Result<Ownership> {
        let record = self.installed()?;
        ensure!(
            Some(identity(&std::env::current_exe()?)?) == record.launcher_identity,
            "internal service command must use the recorded launcher"
        );
        let job = self.job(&record)?.context("launchd job is not loaded")?;
        ensure!(
            job.pid == std::process::id(),
            "launcher is not the launchd main process"
        );
        Ok(record)
    }

    pub fn launch(&self) -> Result<()> {
        use std::os::unix::process::CommandExt;
        if let Err(error) = self.internal() {
            // An invalid ownership record cannot authorize a budget write. Exit
            // successfully so KeepAlive does not retry this refusal forever.
            eprintln!("launchd ownership refused: {error:#}");
            return Ok(());
        }
        match self.consume_start() {
            Ok(true) => {}
            Ok(false) => return Ok(()),
            Err(error) => {
                // A damaged journal must not create an unbounded KeepAlive loop.
                eprintln!("launchd restart budget refused: {error:#}");
                return Ok(());
            }
        }
        let (binary, process) = self.manager().service_launch()?;
        let log_path = self.home.join("versions").join(&process.launch_log);
        private_file(&log_path)?;
        let log = OpenOptions::new()
            .append(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(log_path)?;
        let error = Command::new(binary)
            .args([
                "lifecycle",
                "serve-managed",
                "--instance",
                &process.instance,
            ])
            .arg("--home")
            .arg(&self.home)
            .stderr(Stdio::from(log))
            .exec();
        Err(error).context("cannot exec installed Agent")
    }

    pub fn verify_managed_process(&self, instance: &str) -> Result<()> {
        let record = self.installed()?;
        let job = self
            .job(&record)?
            .context("managed launchd job is absent")?;
        let (state, _) = self.manager().service_snapshot()?;
        let process = state.process.context("service has no recorded process")?;
        ensure!(
            process.pid == std::process::id()
                && process.pid == job.pid
                && process.instance == instance
                && self.owned_process(job.pid)?,
            "managed process is not the recorded launchd main process"
        );
        Ok(())
    }

    fn owned_process(&self, pid: u32) -> Result<bool> {
        let record = self.installed()?;
        let path = match process_path(pid) {
            Ok(path) => path,
            Err(_) if !crate::lifecycle::pid_alive(pid)? => return Ok(true),
            Err(error) => return Err(error),
        };
        if path == self.launcher() {
            return Ok(Some(identity(&path)?) == record.launcher_identity);
        }
        let (state, _) = self.manager().service_snapshot()?;
        let Some(active) = state.active else {
            return Ok(false);
        };
        let Some(process) = state.process else {
            return Ok(false);
        };
        self.manager().verify(&active)?;
        Ok(process.pid == pid
            && path == self.manager().path_for(&active)?
            && process.binary_digest == active.digest)
    }

    fn verified_health(&self) -> Result<Option<crate::lifecycle::ManagedHealth>> {
        let record = self.installed()?;
        let Some(job) = self.job(&record)? else {
            return Ok(None);
        };
        let manager = self.manager();
        let (state, health) = manager.service_snapshot()?;
        let Some(health) = health else {
            return Ok(None);
        };
        let active = state.active.context("service has no active version")?;
        manager.verify(&active)?;
        ensure!(
            health.binary_digest == active.digest
                && health.config_digest == manager.config_digest()?
                && health.pid == job.pid
                && process_path(job.pid)? == manager.path_for(&active)?,
            "launchd PID, binary or configuration differs from authenticated Agent identity"
        );
        Ok(Some(health))
    }

    pub fn ready(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(35);
        loop {
            if self.verified_health()?.is_some() {
                return Ok(());
            }
            ensure!(
                Instant::now() < deadline,
                "Agent did not pass authenticated readiness within 35 seconds"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    pub fn shutdown(&self) -> Result<()> {
        self.stop()
    }

    fn budget(&self) -> Result<RestartBudget> {
        let path = self.root.join("restart.json");
        if !exists(&path)? {
            return Ok(RestartBudget::default());
        }
        private_file(&path)?;
        let budget: RestartBudget = serde_json::from_slice(&fs::read(path)?)?;
        ensure!(budget.starts.len() <= MAX_STARTS, "invalid restart budget");
        Ok(budget)
    }

    fn reset_budget(&self) -> Result<()> {
        let path = self.root.join("restart.json");
        if exists(&path)? {
            self.budget()?;
            fs::remove_file(path)?;
        }
        Ok(())
    }

    fn consume_start(&self) -> Result<bool> {
        let mut budget = self.budget()?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        // A clock rollback cannot erase the start window.
        budget
            .starts
            .retain(|t| now.saturating_sub(*t) < RESTART_WINDOW);
        if budget.starts.len() >= MAX_STARTS {
            return Ok(false);
        }
        budget.starts.push(now);
        atomic_json(&self.root, "restart.json", &budget)?;
        Ok(true)
    }

    fn ensure_absent_everywhere(&self) -> Result<()> {
        let mut available = false;
        for domain in domains() {
            if domain_available(&domain)? {
                available = true;
                ensure!(
                    read_job(&domain, &self.name)?.is_none(),
                    "job label already exists in {domain}"
                );
            }
        }
        ensure!(available, "current-user launchd domain is unavailable");
        Ok(())
    }

    fn job(&self, record: &Ownership) -> Result<Option<Job>> {
        ensure!(
            domain_available(&record.domain)?,
            "recorded current-user launchd domain is unavailable"
        );
        for domain in domains().into_iter().filter(|d| d != &record.domain) {
            if domain_available(&domain)? {
                ensure!(
                    read_job(&domain, &self.name)?.is_none(),
                    "duplicate job in another user domain"
                );
            }
        }
        let job = read_job(&record.domain, &self.name)?;
        if let Some(job) = &job {
            ensure!(
                job.path == path_text(&record.unit)?
                    && job.program == path_text(&record.launcher)?
                    && job.arguments == self.arguments()?,
                "launchd loaded a foreign or edited job"
            );
        }
        Ok(job)
    }

    pub fn inspect(&self) -> serde_json::Value {
        let mut report = serde_json::json!({"format_version":1,"backend":"launchd","home":self.home,"unit_name":self.name,"registered":registered(&self.home),"installed":false,"loaded":false,"running":false,"verified":false,"ready":false,"available":false});
        let observed = (|| -> Result<()> {
            let record = self.load()?;
            report["phase"] = serde_json::to_value(record.phase)?;
            report["domain"] = serde_json::json!(record.domain);
            self.verify(&record)?;
            report["installed"] = serde_json::json!(record.phase == Phase::Installed);
            report["available"] = serde_json::json!(domain_available(&record.domain)?);
            let job = self.job(&record)?;
            report["loaded"] = serde_json::json!(job.is_some());
            report["running"] = serde_json::json!(job.as_ref().is_some_and(|j| j.pid != 0));
            report["launchd"] = serde_json::to_value(job)?;
            let (state, _) = self.manager().service_snapshot()?;
            report["transaction"] = serde_json::to_value(&state.operation)?;
            report["interrupted"] =
                serde_json::json!(state.operation.is_some() || state.pending_stage.is_some());
            let health = self.verified_health()?;
            report["ready"] = serde_json::json!(health.is_some());
            report["verified"] = report["ready"].clone();
            report["health"] = serde_json::to_value(health)?;
            report["restart_budget"] = serde_json::to_value(self.budget()?)?;
            Ok(())
        })();
        if let Err(error) = observed {
            report["error"] = serde_json::json!(error.to_string());
        }
        report
    }

    pub fn status(&self) -> Result<crate::lifecycle::Status> {
        let (state, _) = self.manager().service_snapshot()?;
        let report = self.inspect();
        let running = report["verified"] == true;
        let interrupted = state.operation.is_some() || state.pending_stage.is_some();
        let detail = if interrupted {
            "interrupted operation; run lifecycle recover".into()
        } else if let Some(error) = report["error"].as_str() {
            error.to_owned()
        } else if running {
            "running and verified by launchd".into()
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

    pub fn operation_lock(&self) -> Result<crate::lifecycle::OperationLock> {
        make_directory(&self.root)?;
        let path = self.root.join("operation.lock");
        if exists(&path)? {
            private_file(&path)?;
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
        Ok(crate::lifecycle::OperationLock::held(file))
    }

    fn load(&self) -> Result<Ownership> {
        check_directory(&self.root)?;
        let path = self.root.join(STATE);
        private_file(&path)?;
        let record: Ownership = serde_json::from_slice(&fs::read(path)?)?;
        ensure!(
            record.format_version == 1
                && record.uid == uid()
                && record.home == self.home
                && record.unit == self.unit_path()
                && record.launcher == self.launcher()
                && domains().contains(&record.domain),
            "service ownership does not match this profile and user"
        );
        ensure!(
            record.unit_digest == digest(self.preview()?.unit.as_bytes()),
            "recorded plist does not match supported definition"
        );
        Ok(record)
    }

    fn save(&self, record: &Ownership) -> Result<()> {
        atomic_json(&self.root, STATE, record)
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
}

fn domains() -> Vec<String> {
    vec![format!("gui/{}", uid()), format!("user/{}", uid())]
}
fn domain_available(domain: &str) -> Result<bool> {
    Ok(launchctl(&["print", domain])?.0 == 0)
}
fn select_domain() -> Result<String> {
    for domain in domains() {
        if domain_available(&domain)? {
            return Ok(domain);
        }
    }
    bail!("current-user launchd domain is unavailable; no detached-daemon fallback is used")
}

fn read_job(domain: &str, name: &str) -> Result<Option<Job>> {
    let (status, text) = launchctl(&["print", &format!("{domain}/{name}")])?;
    if matches!(status, 3 | 113) {
        return Ok(None);
    } // ESRCH: service absent, domain separately verified.
    ensure!(status == 0, "cannot inspect launchd job (exit {status})");
    Ok(Some(parse_job(&text)?))
}

fn parse_job(text: &str) -> Result<Job> {
    let mut fields = BTreeMap::new();
    let mut arguments = Vec::new();
    let mut depth = 0usize;
    let mut in_arguments = false;
    for line in text.lines() {
        let line = line.trim();
        if line == "}" {
            depth = depth.checked_sub(1).context("invalid launchd nesting")?;
            if depth == 1 {
                in_arguments = false;
            }
            continue;
        }
        if depth == 1 {
            if line == "arguments = {" {
                in_arguments = true;
            } else if let Some((key, value)) = line.split_once(" = ") {
                if matches!(key, "pid" | "state" | "path" | "program") {
                    ensure!(
                        fields.insert(key, value).is_none(),
                        "duplicate launchd field"
                    );
                }
            }
        } else if depth == 2 && in_arguments {
            arguments.push(line.to_owned());
        }
        if line.ends_with('{') {
            depth += 1;
        }
    }
    ensure!(depth == 0, "incomplete launchd output");
    Ok(Job {
        pid: fields
            .get("pid")
            .map(|v| v.parse())
            .transpose()?
            .unwrap_or(0),
        state: fields
            .get("state")
            .context("missing launchd state")?
            .to_string(),
        path: fields
            .get("path")
            .context("missing launchd path")?
            .to_string(),
        program: fields
            .get("program")
            .context("missing launchd program")?
            .to_string(),
        arguments,
    })
}

fn control(args: &[&str]) -> Result<()> {
    let (status, _) = launchctl(args)?;
    ensure!(
        status == 0,
        "launchctl {} failed (exit {status}); inspect service before retrying",
        args[0]
    );
    Ok(())
}

fn launchctl(args: &[&str]) -> Result<(i32, String)> {
    let mut child = Command::new(LAUNCHCTL)
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("cannot execute launchctl")?;
    let mut stdout = child.stdout.take().context("missing launchctl output")?;
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        (&mut stdout)
            .take(262145)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("launchctl timed out; inspect before retrying");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let bytes = reader
        .join()
        .map_err(|_| anyhow::anyhow!("launchctl reader failed"))??;
    ensure!(bytes.len() <= 262144, "launchctl output exceeded limit");
    Ok((status.code().unwrap_or(-1), String::from_utf8(bytes)?))
}

fn process_path(pid: u32) -> Result<PathBuf> {
    ensure!(pid > 0 && pid <= i32::MAX as u32, "invalid launchd PID");
    let mut bytes = vec![0u8; 4096];
    let length =
        unsafe { libc::proc_pidpath(pid as i32, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
    ensure!(length > 0, "cannot inspect launchd executable identity");
    let path = std::ffi::CStr::from_bytes_until_nul(&bytes)?.to_str()?;
    Ok(PathBuf::from(path))
}

fn path_text(path: &Path) -> Result<String> {
    let text = path.to_str().context("service path must be UTF-8")?;
    ensure!(
        path.is_absolute() && !text.chars().any(char::is_control),
        "service path must be absolute without control characters"
    );
    Ok(text.to_owned())
}
fn xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
fn uid() -> u32 {
    unsafe { libc::geteuid() }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn private_file(path: &Path) -> Result<()> {
    ensure!(
        owned_file(path)?.mode() & 0o077 == 0,
        "service journal must be owner-only"
    );
    Ok(())
}
fn atomic_json(root: &Path, name: &str, value: &impl Serialize) -> Result<()> {
    let target = root.join(name);
    if exists(&target)? {
        private_file(&target)?;
    }
    let temp = root.join(format!(".{}.tmp", crate::token::generate()));
    let mut file = create_private(&temp)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    fs::rename(temp, target)?;
    File::open(root)?.sync_all()?;
    Ok(())
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
                || (metadata.uid() == 0 && metadata.mode() & u32::from(libc::S_ISVTX) != 0),
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
    let expected =
        expected.context("service file has no recorded identity; refusing adoption or removal")?;
    let actual = identity(path)?;
    ensure!(
        actual.digest == hash && expected == &actual,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> (tempfile::TempDir, Service) {
        let temp = tempfile::tempdir().unwrap();
        // Darwin's /var alias is not an operator-created symlink.
        let home = temp.path().canonicalize().unwrap();
        let service = Service::new(&home).unwrap();
        (temp, service)
    }

    #[test]
    fn preview_is_private_nonmutating_and_has_no_login_installation() {
        let (_temp, service) = service();
        let preview = service.preview().unwrap();
        assert!(!service.root.exists());
        assert_eq!(preview.unit_path.parent(), Some(service.root.as_path()));
        assert!(!preview.starts_automatically);
        assert!(!preview.unit.contains("/bin/sh"));
        assert!(preview
            .unit
            .contains("<key>ThrottleInterval</key><integer>10</integer>"));
        assert!(preview.unit.contains("<key>SuccessfulExit</key><false/>"));
        assert!(preview.unit.contains("<key>ProgramArguments</key>"));
        assert_eq!(xml("a&<b>\"'"), "a&amp;&lt;b&gt;&quot;&apos;");
        assert!(path_text(Path::new("/private/tmp/bad\npath")).is_err());
    }

    #[test]
    fn runtime_parser_ignores_nested_pid_and_rejects_missing_or_duplicate_identity() {
        let text = "gui/501/test = {\n path = /private/test.plist\n state = running\n program = /private/agent\n arguments = {\n /private/agent\n service\n }\n environment = {\n pid = 99\n }\n pid = 123\n}\n";
        let job = parse_job(text).unwrap();
        assert_eq!(job.pid, 123);
        assert_eq!(job.arguments, ["/private/agent", "service"]);
        assert!(parse_job(&text.replace(" path = /private/test.plist\n", "")).is_err());
        assert!(parse_job(&text.replace(" pid = 123", " pid = 123\n pid = 124")).is_err());
        assert!(parse_job(text.trim_end().trim_end_matches('}')).is_err());
    }

    #[test]
    fn crash_budget_is_durable_bounded_and_rejects_foreign_journals() {
        let (_temp, service) = service();
        make_directory(&service.root).unwrap();
        for _ in 0..MAX_STARTS {
            assert!(service.consume_start().unwrap());
        }
        assert!(!Service::new(&service.home)
            .unwrap()
            .consume_start()
            .unwrap());
        service.reset_budget().unwrap();
        assert!(service.consume_start().unwrap());
        let path = service.root.join("restart.json");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(service.consume_start().is_err());
        assert!(service.reset_budget().is_err());
        assert!(path.exists());
    }

    #[test]
    fn linked_and_replaced_artifacts_cannot_be_adopted_or_removed() {
        let (_temp, service) = service();
        let path = service.home.join("artifact");
        fs::write(&path, b"original").unwrap();
        let expected = identity(&path).unwrap();
        for phase in [Phase::Installing, Phase::Installed, Phase::Removing] {
            assert!(verify_removable(phase, &path, &expected.digest, None).is_err());
        }
        assert!(verify_file(&path, &expected.digest, None).is_err());
        assert!(path.exists());
        let old = service.home.join("old");
        fs::rename(&path, &old).unwrap();
        fs::write(&path, b"original").unwrap();
        assert!(verify_file(&path, &expected.digest, Some(&expected)).is_err());
        assert!(
            verify_removable(Phase::Installing, &path, &expected.digest, Some(&expected)).is_err()
        );
        fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(&old, &path).unwrap();
        assert!(identity(&path).is_err());
        fs::remove_file(&path).unwrap();
        fs::hard_link(&old, &path).unwrap();
        assert!(identity(&path).is_err());
    }

    #[test]
    fn interrupted_partial_write_can_only_remove_its_recorded_inode() {
        let (_temp, service) = service();
        let path = service.home.join("partial");
        let mut file = create_private(&path).unwrap();
        let initial = identity(&path).unwrap();
        file.write_all(b"partial bytes").unwrap();
        assert!(verify_removable(
            Phase::Installing,
            &path,
            "expected-full-digest",
            Some(&initial)
        )
        .is_ok());
        assert!(verify_removable(Phase::Installing, &path, "expected-full-digest", None).is_err());
        assert!(verify_removable(
            Phase::Installed,
            &path,
            "expected-full-digest",
            Some(&initial)
        )
        .is_err());
    }

    #[test]
    fn damaged_registration_reserves_the_profile_against_direct_lifecycle() {
        let (_temp, service) = service();
        make_directory(&service.root).unwrap();
        fs::write(service.root.join(STATE), "invalid").unwrap();
        assert!(service.manager().start().is_err());
        assert!(service.manager().remove().is_err());
        assert!(service.manager().direct_serve_guard().is_err());
        // Refusal is a successful launcher exit for KeepAlive purposes, without
        // touching an unverified registration's restart budget.
        assert!(service.launch().is_ok());
        assert!(!service.root.join("restart.json").exists());
    }
}
