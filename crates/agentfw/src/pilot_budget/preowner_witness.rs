// SPDX-License-Identifier: Apache-2.0
//! Explicit native owner-first preparation and handback parent-loss controls.
use super::*;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const READY_ENV: &str = "SOU142_PREOWNER_CHILD_READY";
const CLEANUP_WINDOW_MILLIS: u64 = 3_000;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ready {
    leaf: String,
    device: u64,
    inode: u64,
    budget_sha256: String,
    #[serde(default)]
    started_monotonic_nanos: u64,
}

struct OwnedChild {
    child: Child,
    reaped: bool,
    cancel: PathBuf,
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if !self.reaped {
            // On setup failure, let the live helper drop its own real
            // boundary before killing a process whose leaf is unknown.
            let _ = fs::write(&self.cancel, []);
            let deadline = Instant::now() + Duration::from_millis(CLEANUP_WINDOW_MILLIS);
            loop {
                match self.child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    _ => break,
                }
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct OwnedLeaf {
    root: File,
    root_path: PathBuf,
    root_identity: RootIdentity,
    leaf: File,
    identity: Ready,
    removed: bool,
}

impl OwnedLeaf {
    fn open_at(directory: &File, name: &str, flags: i32) -> Result<File> {
        let name = CString::new(name)?;
        let raw = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if raw < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        Ok(unsafe { File::from_raw_fd(raw) })
    }

    fn verify(&self) -> Result<()> {
        ensure!(
            root_identity(&self.root_path)? == self.root_identity,
            "preowner_witness_root_replaced"
        );
        let held = self.leaf.metadata()?;
        let current = Self::open_at(
            &self.root,
            &self.identity.leaf,
            libc::O_RDONLY | libc::O_DIRECTORY,
        )?
        .metadata()?;
        ensure!(
            held.dev() == self.identity.device
                && held.ino() == self.identity.inode
                && current.dev() == held.dev()
                && current.ino() == held.ino(),
            "preowner_witness_leaf_replaced"
        );
        Ok(())
    }

    fn empty(&self) -> Result<()> {
        for name in ["cgroup.procs", "cgroup.events"] {
            let mut bytes = Vec::new();
            Self::open_at(&self.leaf, name, libc::O_RDONLY)?
                .take(MAX_BYTES + 1)
                .read_to_end(&mut bytes)?;
            ensure!(bytes.len() as u64 <= MAX_BYTES, "preowner_witness_overflow");
            let empty = if name == "cgroup.procs" {
                bytes.iter().all(u8::is_ascii_whitespace)
            } else {
                std::str::from_utf8(&bytes)?
                    .lines()
                    .any(|line| line == "populated 0")
            };
            ensure!(empty, "preowner_witness_leaf_populated");
        }
        ensure!(
            fs::read_dir(format!("/proc/self/fd/{}", self.leaf.as_raw_fd()))?
                .all(|entry| entry
                    .is_ok_and(|entry| entry.file_type().is_ok_and(|kind| !kind.is_dir()))),
            "preowner_witness_leaf_has_children"
        );
        Ok(())
    }

    fn remove(&mut self) -> Result<()> {
        self.verify()?;
        self.empty()?;
        self.verify()?;
        let name = CString::new(self.identity.leaf.as_bytes())?;
        ensure!(
            unsafe { libc::unlinkat(self.root.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
                == 0,
            "preowner_witness_owned_cleanup_failed"
        );
        self.removed = true;
        Ok(())
    }
}

impl Drop for OwnedLeaf {
    fn drop(&mut self) {
        if !self.removed {
            // Only this pinned empty inode is eligible, including when
            // the witness fails. Never kill, sweep or adopt a replacement.
            let _ = self.remove();
        }
    }
}

fn binary_identity(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    const LIMIT: u64 = 512 * 1024 * 1024;
    let mut file = File::open(path)?.take(LIMIT + 1);
    let mut count = 0_u64;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 65_536];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        ensure!(count <= LIMIT, "preowner_witness_binary_overflow");
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn matching_leaf_descriptors(pid: u32, leaf: &Ready) -> Result<usize> {
    let mut matches = 0;
    let mut inspected = 0;
    for descriptor in fs::read_dir(format!("/proc/{pid}/fd"))? {
        inspected += 1;
        ensure!(
            inspected <= 512,
            "owner_loss_witness_descriptor_bound_exceeded"
        );
        let path = descriptor?.path();
        match fs::metadata(path) {
            Ok(metadata) if metadata.dev() == leaf.device && metadata.ino() == leaf.inode => {
                matches += 1;
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(matches)
}

fn process_children(pid: u32) -> Result<Vec<u32>> {
    let mut children = std::collections::BTreeSet::new();
    let mut tasks = 0;
    for task in fs::read_dir(format!("/proc/{pid}/task"))? {
        tasks += 1;
        ensure!(tasks <= 256, "owner_loss_witness_task_bound_exceeded");
        let path = task?.path().join("children");
        let listing = match fs::read_to_string(path) {
            Ok(value) => value,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        ensure!(
            listing.len() <= 4096,
            "owner_loss_witness_child_bound_exceeded"
        );
        for child in listing.split_ascii_whitespace() {
            ensure!(
                children.len() < 16,
                "owner_loss_witness_child_bound_exceeded"
            );
            children.insert(child.parse::<u32>()?);
        }
    }
    ensure!(tasks > 0, "owner_loss_witness_task_inventory_empty");
    Ok(children.into_iter().collect())
}

pub(super) fn child() -> Result<()> {
    let Some(ready) = std::env::var_os(READY_ENV) else {
        return Ok(());
    };
    let path = std::env::var_os("SOU142_BUDGET_CONFIG")
        .ok_or_else(|| anyhow::anyhow!("explicit_owned_budget_required"))?;
    let config = Config::load_file(Path::new(&path))?;
    let root = root_identity(&config.delegation_root)?;
    let profile = std::env::var_os("SOU142_OWNER_PROFILE")
        .ok_or_else(|| anyhow::anyhow!("explicit_owned_profile_required"))?;
    let mut bytes = Vec::new();
    File::open(profile)?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_BYTES,
        "preowner_witness_profile_overflow"
    );
    let profile = crate::mcp::server_profile::ProfileConfig::read(&bytes)?;
    let prepared = crate::mcp::server_sandbox::prepare_with_budget(
        &profile,
        Some(&BoundConfig {
            config: config.clone(),
            root: (root.device, root.inode),
        }),
    )?;
    let ready = PathBuf::from(ready);
    if std::env::var("SOU142_TEST_COLLECTOR_STAGE").as_deref() == Ok("owner-loss") {
        // The selected original profile is prepared, but the owner pauses
        // before transferring any leaf descriptor or starting bubblewrap.
        std::env::set_var("SOU142_TEST_OWNER_BEFORE_HANDBACK", &ready);
        let outcome = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(prepared.spawn());
        let reason = outcome
            .err()
            .ok_or_else(|| anyhow::anyhow!("owner_loss_witness_unexpected_success"))?;
        write_json(
            &ready.with_extension("outcome"),
            &json!({
                "reason": reason.to_string(), "original_started": false
            }),
        )?;
        ensure!(
            reason.to_string() == "mcp_budget_owner_lost_before_handback_unsupported",
            "owner_loss_witness_wrong_outcome"
        );
        return Ok(());
    }
    if std::env::var("SOU142_TEST_COLLECTOR_STAGE").as_deref() == Ok("handoff") {
        // The candidate Agent image runs its ordinary owner code; the barrier
        // exists only in this libtest collector before its adoption ACK.
        std::env::set_var("SOU142_TEST_HANDOFF_BARRIER", &ready);
        return tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let _unexpected_started_sandbox = prepared.spawn().await?;
                anyhow::bail!("preowner_witness_sandbox_released_before_barrier")
            });
    }
    let staged = ready.with_extension("staged");
    write_json(
        &staged,
        &Ready {
            leaf: String::new(),
            device: 0,
            inode: 0,
            budget_sha256: config.identity(),
            started_monotonic_nanos: 0,
        },
    )?;
    fs::rename(staged, &ready)?;
    // A missing controller cannot strand this helper indefinitely.
    // Normal return drops only read-only preparation; the witness kills it first.
    let cancel = ready.with_extension("cancel");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !cancel.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(prepared);
    anyhow::bail!("preowner_witness_controller_did_not_kill_child")
}

pub(super) fn reproduce(handoff: bool) -> Result<()> {
    reproduce_case(handoff, false)
}

pub(super) fn reproduce_owner_loss() -> Result<()> {
    reproduce_case(true, true)
}

fn reproduce_case(handoff: bool, owner_loss: bool) -> Result<()> {
    let path = std::env::var_os("SOU142_BUDGET_CONFIG")
        .ok_or_else(|| anyhow::anyhow!("explicit_owned_budget_required"))?;
    let config = Config::load_file(Path::new(&path))?;
    let (root, identity) = lease_root(&config)?;
    let private = tempfile::tempdir()?;
    let ready_path = private.path().join("ready.json");
    let executable = std::env::current_exe()?;
    let binary_sha256 = binary_identity(&executable)?;
    let owner_image = std::env::var_os("SOU86_TEST_AGENTFW")
        .ok_or_else(|| anyhow::anyhow!("explicit_candidate_owner_image_required"))?;
    let owner_binary_sha256 = binary_identity(Path::new(&owner_image))?;
    let profile = std::env::var_os("SOU142_OWNER_PROFILE")
        .ok_or_else(|| anyhow::anyhow!("explicit_owned_profile_required"))?;
    let mut child = OwnedChild {
        child: Command::new(&executable)
            .env_clear()
            .env("SOU142_BUDGET_CONFIG", path)
            .env(READY_ENV, &ready_path)
            .env("SOU142_OWNER_PROFILE", profile)
            .env("SOU86_TEST_AGENTFW", owner_image)
            .env(
                "SOU142_TEST_COLLECTOR_STAGE",
                if owner_loss {
                    "owner-loss"
                } else if handoff {
                    "handoff"
                } else {
                    "prepared"
                },
            )
            .args([
                "--ignored",
                "--exact",
                "pilot_budget::tests::native_owner_first_collector_child",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
        reaped: false,
        cancel: ready_path.with_extension("cancel"),
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready_path.exists() {
        if child.child.try_wait()?.is_some() {
            child.reaped = true;
            anyhow::bail!("preowner_witness_child_failed_before_ready");
        }
        ensure!(Instant::now() < deadline, "preowner_witness_ready_timeout");
        std::thread::sleep(Duration::from_millis(10));
    }
    let ready: Ready = private_json(&ready_path)?;
    ensure!(
        ready.budget_sha256 == config.identity(),
        "preowner_witness_ready_invalid"
    );
    if !handoff {
        ensure!(
            ready.leaf.is_empty()
                && fs::read_dir(&config.delegation_root)?.all(|entry| entry
                    .is_ok_and(|entry| entry.file_type().is_ok_and(|kind| !kind.is_dir()))),
            "preowner_witness_prepare_created_leaf"
        );
        child.child.kill()?;
        let status = child.child.wait()?;
        child.reaped = true;
        ensure!(
            status.signal() == Some(libc::SIGKILL),
            "preowner_witness_not_sigkill"
        );
        ensure!(
            root_identity(&config.delegation_root)? == identity,
            "preowner_witness_root_replaced"
        );
        ensure!(
            fs::read_dir(&config.delegation_root)?
                .all(|entry| entry
                    .is_ok_and(|entry| entry.file_type().is_ok_and(|kind| !kind.is_dir()))),
            "preowner_witness_inventory_not_restored"
        );
        println!(
            "{}",
            json!({"format":"sou142-owner-first-parent-loss/1","status":"pass",
            "stage":"prepared-before-owner","binary_sha256":binary_sha256,
            "owner_binary_sha256":owner_binary_sha256,"budget_sha256":config.identity(),
            "leaf_created":false,"original_started":false,"owned_members":0,
            "production_cleanup_verified":true,"witness_cleanup_attempted":false})
        );
        return Ok(());
    }
    ensure!(
        ready.budget_sha256 == config.identity()
            && ready.leaf.strip_prefix("agentfw-mcp-").is_some_and(|id| {
                id.len() == 32
                    && id
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            }),
        "preowner_witness_ready_invalid"
    );
    let leaf = OwnedLeaf::open_at(&root, &ready.leaf, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let mut owned = OwnedLeaf {
        root,
        root_path: config.delegation_root.clone(),
        root_identity: identity,
        leaf,
        identity: ready,
        removed: false,
    };
    owned.verify()?;
    owned.empty()?;
    if owner_loss {
        let collector_pid = child.child.id();
        let pids = process_children(collector_pid)?;
        ensure!(
            pids.len() == 1,
            "owner_loss_witness_one_outside_owner_required"
        );
        let owner_pid = pids[0];
        ensure!(
            binary_identity(Path::new(&format!("/proc/{owner_pid}/exe")))? == owner_binary_sha256,
            "owner_loss_witness_owner_image_changed"
        );
        let args = fs::read(format!("/proc/{owner_pid}/cmdline"))?;
        ensure!(
            args.windows(b"--agentfw-mcp-owner-v1".len())
                .any(|part| part == b"--agentfw-mcp-owner-v1"),
            "owner_loss_witness_owner_command_changed"
        );
        let owner_children = process_children(owner_pid)?;
        ensure!(
            owner_children.is_empty(),
            "owner_loss_witness_original_process_started"
        );
        ensure!(
            matching_leaf_descriptors(owner_pid, &owned.identity)? >= 1,
            "owner_loss_witness_owner_did_not_hold_leaf"
        );
        ensure!(
            matching_leaf_descriptors(collector_pid, &owned.identity)? == 0,
            "owner_loss_witness_leaf_already_handed_back"
        );
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, owner_pid, 0) };
        ensure!(pidfd >= 0, "owner_loss_witness_pidfd_unavailable");
        let pidfd = unsafe { File::from_raw_fd(pidfd as i32) };
        ensure!(
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            } == 0,
            "owner_loss_witness_sigkill_failed"
        );
        let status = child.child.wait()?;
        child.reaped = true;
        if !status.success() {
            let outcome: serde_json::Value =
                private_json(&ready_path.with_extension("outcome")).unwrap_or_default();
            if outcome["reason"] == "mcp_owner_startup_failed" {
                anyhow::bail!("owner_loss_witness_generic_startup_failure");
            }
        }
        ensure!(status.success(), "owner_loss_witness_collector_failed");
        let outcome: serde_json::Value = private_json(&ready_path.with_extension("outcome"))?;
        ensure!(
            outcome["reason"] == "mcp_budget_owner_lost_before_handback_unsupported"
                && outcome["original_started"] == false,
            "owner_loss_witness_outcome_unverified"
        );
        owned.verify()?;
        owned.empty()?;
        // Production has no descriptor handback after owner SIGKILL. The
        // witness pins this exact inode before the kill and removes it only
        // as disposable test teardown, never as a production recovery claim.
        owned.remove()?;
        ensure!(
            root_identity(&config.delegation_root)? == owned.root_identity
                && fs::read_dir(&config.delegation_root)?.all(|entry| entry
                    .is_ok_and(|entry| entry.file_type().is_ok_and(|kind| !kind.is_dir()))),
            "owner_loss_witness_inventory_not_restored"
        );
        println!(
            "{}",
            json!({"format":"sou142-owner-first-parent-loss/1",
                "status":"unsupported-fail-closed",
                "stage":"owner-loss-before-descriptor-handback",
                "binary_sha256":binary_sha256,
                "owner_binary_sha256":owner_binary_sha256,
                "budget_sha256":config.identity(),
                "leaf_created":true,"original_started":false,"owned_members":0,
                "owner_held_leaf_descriptor":true,
                "collector_had_no_leaf_descriptor":true,
                "production_cleanup_verified":false,
                "witness_cleanup_attempted":true,"inventory_restored":true})
        );
        return Ok(());
    }
    child.child.kill()?;
    let status = child.child.wait()?;
    child.reaped = true;
    ensure!(
        status.signal() == Some(libc::SIGKILL),
        "preowner_witness_not_sigkill"
    );
    // Include both existing startup and cleanup windows, without changing their
    // limits. A controller's own fallback never counts as production cleanup.
    let deadline = Instant::now()
        + Duration::from_millis(
            crate::mcp::linux_owner::STARTUP_MILLIS + crate::mcp::linux_owner::CLEANUP_MILLIS,
        );
    let name = CString::new(owned.identity.leaf.as_bytes())?;
    let removed = loop {
        let raw = unsafe {
            libc::openat(
                owned.root.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            ensure!(
                std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
                "preowner_witness_cleanup_observation_failed"
            );
            let events = CString::new("cgroup.events")?;
            let control = unsafe {
                libc::openat(
                    owned.leaf.as_raw_fd(),
                    events.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if control < 0 {
                ensure!(
                    matches!(
                        std::io::Error::last_os_error().raw_os_error(),
                        Some(libc::ENOENT | libc::ENODEV)
                    ),
                    "preowner_witness_cleanup_observation_failed"
                );
                break true;
            }
            drop(unsafe { File::from_raw_fd(control) });
        } else {
            let current = unsafe { File::from_raw_fd(raw) }.metadata()?;
            ensure!(
                current.dev() == owned.identity.device && current.ino() == owned.identity.inode,
                "preowner_witness_leaf_replaced"
            );
            if let Err(error) = owned.empty() {
                let teardown = error
                    .downcast_ref::<std::io::Error>()
                    .and_then(std::io::Error::raw_os_error)
                    .is_some_and(|code| matches!(code, libc::ENOENT | libc::ENODEV));
                if !teardown {
                    return Err(error);
                }
                // The owner may remove the same empty leaf between metadata
                // and control reads. Only the next pinned-disappearance proof
                // can resolve these teardown errors; permissions still fail.
            }
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    ensure!(removed, "preowner_witness_production_cleanup_failed");
    owned.removed = true;
    ensure!(
        root_identity(&config.delegation_root)? == owned.root_identity,
        "preowner_witness_root_replaced"
    );
    ensure!(
        fs::read_dir(&config.delegation_root)?.all(
            |entry| entry.is_ok_and(|entry| entry.file_type().is_ok_and(|kind| !kind.is_dir()))
        ),
        "preowner_witness_inventory_not_restored"
    );
    let mut root_members = Vec::new();
    OwnedLeaf::open_at(&owned.root, "cgroup.procs", libc::O_RDONLY)?
        .take(MAX_BYTES + 1)
        .read_to_end(&mut root_members)?;
    ensure!(
        root_members.len() as u64 <= MAX_BYTES && root_members.iter().all(u8::is_ascii_whitespace),
        "preowner_witness_root_populated"
    );
    println!(
        "{}",
        json!({"format":"sou142-owner-first-parent-loss/1","status":"pass",
        "stage":"prepared-handback-before-adoption-ack","binary_sha256":binary_sha256,
        "owner_binary_sha256":owner_binary_sha256,"budget_sha256":config.identity(),
        "leaf_created":true,"original_started":false,"owned_members":0,
        "production_cleanup_verified":true,"witness_cleanup_attempted":false,
        "inventory_restored":true})
    );
    Ok(())
}

#[cfg(test)]
mod process_children_tests {
    use super::*;

    #[test]
    fn includes_child_spawned_by_non_leader_thread() -> Result<()> {
        let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
        let (done_sender, done_receiver) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || -> Result<()> {
            let mut child = Command::new("/usr/bin/sleep")
                .arg("5")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            ready_sender.send(child.id())?;
            let _ = done_receiver.recv();
            let _ = child.kill();
            let _ = child.wait();
            Ok(())
        });
        let child_pid = ready_receiver.recv_timeout(Duration::from_secs(2))?;
        let observed = process_children(std::process::id());
        let leader_listing =
            fs::read_to_string(format!("/proc/{0}/task/{0}/children", std::process::id()))?;
        let _ = done_sender.send(());
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("child_inventory_worker_panicked"))??;
        ensure!(
            !leader_listing
                .split_ascii_whitespace()
                .any(|value| value == child_pid.to_string()),
            "child_inventory_regression_not_exercised"
        );
        ensure!(
            observed?.contains(&child_pid),
            "child_inventory_missed_non_leader_thread"
        );
        Ok(())
    }
}
