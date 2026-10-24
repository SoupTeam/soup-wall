// SPDX-License-Identifier: Apache-2.0
//! Explicit native blocker reproduction; never an acceptance pass.
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
        ensure!(raw >= 0, "preowner_witness_control_unavailable");
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

pub(super) fn child() -> Result<()> {
    let Some(ready) = std::env::var_os(READY_ENV) else {
        return Ok(());
    };
    let path = std::env::var_os("SOU142_BUDGET_CONFIG")
        .ok_or_else(|| anyhow::anyhow!("explicit_owned_budget_required"))?;
    let config = Config::load_file(Path::new(&path))?;
    let root = root_identity(&config.delegation_root)?;
    let budget = crate::mcp::linux_budget::OwnedBudget::prepare_bound(&BoundConfig {
        config: config.clone(),
        root: (root.device, root.inode),
    })?;
    // Reuse the real engine's exact pinned cleanup capsule. Deliberately
    // do not create linux_owner: this is the production pre-owner stage.
    let (capsule, _capsule_files) = budget.crash_cleanup()?;
    let ready = PathBuf::from(ready);
    let staged = ready.with_extension("staged");
    write_json(
        &staged,
        &Ready {
            leaf: capsule.name,
            device: capsule.device,
            inode: capsule.inode,
            budget_sha256: config.identity(),
        },
    )?;
    fs::rename(staged, &ready)?;
    // A missing controller cannot strand this helper indefinitely.
    // Normal return drops the real budget; the witness kills it first.
    let cancel = ready.with_extension("cancel");
    let deadline = Instant::now() + Duration::from_secs(30);
    while !cancel.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(budget);
    anyhow::bail!("preowner_witness_controller_did_not_kill_child")
}

pub(super) fn reproduce() -> Result<()> {
    let path = std::env::var_os("SOU142_BUDGET_CONFIG")
        .ok_or_else(|| anyhow::anyhow!("explicit_owned_budget_required"))?;
    let config = Config::load_file(Path::new(&path))?;
    let (root, identity) = lease_root(&config)?;
    let private = tempfile::tempdir()?;
    let ready_path = private.path().join("ready.json");
    let executable = std::env::current_exe()?;
    let binary_sha256 = binary_identity(&executable)?;
    let mut child = OwnedChild {
        child: Command::new(&executable)
            .env_clear()
            .env("SOU142_BUDGET_CONFIG", path)
            .env(READY_ENV, &ready_path)
            .args([
                "--ignored",
                "--exact",
                "pilot_budget::tests::native_preowner_orphan_child",
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
    child.child.kill()?;
    let status = child.child.wait()?;
    child.reaped = true;
    ensure!(
        status.signal() == Some(libc::SIGKILL),
        "preowner_witness_not_sigkill"
    );
    std::thread::sleep(Duration::from_millis(CLEANUP_WINDOW_MILLIS));
    owned.verify()?;
    owned.empty()?;
    let mut evidence = json!({"format":"sou142-preowner-parent-loss/1","status":"blocked",
            "reason":"preowner_orphan_reproduced","acceptance_pass":false,
            "phase":"orphan-observed","stage":"bound-budget-prepared-before-owner",
            "binary_sha256":binary_sha256,"budget_sha256":config.identity(),
            "observation_millis":CLEANUP_WINDOW_MILLIS,"orphan_observed":true,
            "owned_members":0,"production_cleanup_verified":false,
            "witness_owned_empty_cleanup_verified":false,"inventory_restored":false});
    // Preserve the blocker even if the strictly owned cleanup fails.
    println!("{evidence}");
    owned.remove()?;
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
    evidence["phase"] = json!("owned-witness-cleanup");
    evidence["witness_owned_empty_cleanup_verified"] = json!(true);
    evidence["inventory_restored"] = json!(true);
    println!("{evidence}");
    Ok(())
}
