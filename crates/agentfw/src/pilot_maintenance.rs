//! Short admission gate at the actual owned host spawn boundary.
//!
//! The installed component's verified Python helper reuses the single strict
//! marker/journal/binding implementation. This process holds the same stable
//! gate through validation AND `cmd.spawn`; helper failure always closes launch.
use anyhow::{ensure, Context};
use serde_json::json;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::pilot_launcher::ValidatedConfig;

pub(crate) struct Guard {
    gate: File,
    home: PathBuf,
    root: File,
    parent: File,
}
fn same(a: &Metadata, b: &Metadata) -> bool {
    (a.dev(), a.ino(), a.uid(), a.gid(), a.mode(), a.nlink())
        == (b.dev(), b.ino(), b.uid(), b.gid(), b.mode(), b.nlink())
}
impl Guard {
    fn check(&self) -> anyhow::Result<()> {
        let parent = crate::private_export::open_dir(&self.home)?;
        let root = crate::private_export::open_dir(&self.home.join("pilot-maintenance"))?;
        let gate = open_gate(&self.home)?;
        ensure!(
            same(&parent.metadata()?, &self.parent.metadata()?)
                && same(&root.metadata()?, &self.root.metadata()?)
                && same(&gate.metadata()?, &self.gate.metadata()?),
            "maintenance_gate_replaced"
        );
        Ok(())
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        // Explicit unlock ends the shared open-file-description lock even if
        // a fork briefly inherited it; all descriptors are also close-on-exec.
        unsafe { libc::flock(self.gate.as_raw_fd(), libc::LOCK_UN) };
    }
}
fn open_gate(home: &Path) -> anyhow::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(home.join("pilot-maintenance/gate"))?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o777 == 0o600
            && meta.nlink() == 1,
        "maintenance_gate_invalid"
    );
    Ok(file)
}

pub(crate) fn admit(
    home: &Path,
    component_home: &Path,
    run: &str,
    config: &ValidatedConfig,
    deadline: Instant,
) -> anyhow::Result<Guard> {
    ensure!(
        run.len() == 32
            && run
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "maintenance_run_invalid"
    );
    let parent = crate::private_export::open_dir(home)?;
    let root = crate::private_export::open_dir(&home.join("pilot-maintenance"))?;
    for directory in [&parent, &root] {
        let meta = directory.metadata()?;
        ensure!(
            meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o777 == 0o700,
            "maintenance_home_invalid"
        );
    }
    let gate = open_gate(home)?;
    ensure!(
        unsafe { libc::flock(gate.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } == 0,
        "maintenance_transition_busy"
    );
    let guard = Guard {
        gate,
        home: home.to_owned(),
        root,
        parent,
    };
    guard.check()?;
    // current() verifies every installed component file, its shape, source and
    // interpreter hash. No caller-supplied script/interpreter is executed.
    let verified = crate::pilot_component::Store::new(component_home)
        .current()
        .map_err(|_| anyhow::anyhow!("maintenance_component_unavailable"))?;
    let helper = "scripts/pilot_maintenance_launch.py";
    ensure!(
        verified.manifest.files.iter().any(|f| f.path == helper),
        "maintenance_component_upgrade_required"
    );
    let expected = json!({
        "launcher_pid": std::process::id(), "launcher_parent_pid": unsafe { libc::getppid() },
        "component_home": component_home, "home": config.home_path,
        "agent_bin": config.agent_bin_path, "claude": config.claude_path,
        "workspace": config.workspace_path, "git_workspace": config.git_workspace_path,
        "fs_profile": config.fs_profile_path, "git_profile": config.git_profile_path,
        "policy": config.policy_path, "classifier": config.classifier_path
    });
    let mut child = Command::new(&verified.python.path)
        .args(["-I", "-B"])
        .arg(verified.tree.join(helper))
        .arg("--spawn-check")
        .arg("--home")
        .arg(home)
        .arg("--run")
        .arg(run)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .current_dir(component_home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("maintenance_verifier_start_failed")?;
    let verification = (|| -> anyhow::Result<()> {
        let mut input = child
            .stdin
            .take()
            .context("maintenance_verifier_input_unavailable")?;
        input.write_all(&serde_json::to_vec(&expected)?)?;
        drop(input);
        let deadline = deadline.min(Instant::now() + Duration::from_secs(15));
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            ensure!(Instant::now() < deadline, "maintenance_verifier_timeout");
            std::thread::sleep(Duration::from_millis(10));
        };
        ensure!(status.success(), "maintenance_spawn_refused");
        let mut response = Vec::new();
        child
            .stdout
            .take()
            .context("maintenance_verifier_output_unavailable")?
            .take(65)
            .read_to_end(&mut response)?;
        ensure!(
            response == b"maintenance_admitted\n",
            "maintenance_verifier_invalid_response"
        );
        guard.check()?;
        Ok(())
    })();
    if verification.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    verification?;
    Ok(guard)
}
