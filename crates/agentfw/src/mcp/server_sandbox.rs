// SPDX-License-Identifier: Apache-2.0

//! The process boundary for the selected, read-only filesystem MCP server.
//!
//! This is deliberately separate from the guarded-command sandbox. It does
//! not execute an arbitrary MCP command: the runtime and installed dependency
//! tree are operator-pinned, the entry point is fixed, and every host mount is
//! read-only. Unsupported systems and missing bubblewrap features fail closed.

use std::fs::File;
#[cfg(any(target_os = "linux", all(test, unix)))]
use std::path::Component;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Stdio;
use std::sync::Arc;

use anyhow::{bail, Context};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use tokio::process::Child;
#[cfg(target_os = "linux")]
use tokio::process::Command;

use super::server_profile::ProfileConfig;
#[cfg(all(test, target_os = "linux"))]
#[path = "git_local_clone_sandbox_tests.rs"]
mod git_local_clone_tests;
#[cfg(all(test, target_os = "linux"))]
#[path = "git_tracked_symlinks_sandbox_tests.rs"]
mod git_tracked_symlinks_tests;
#[cfg(target_os = "linux")]
use super::server_profile::{package_tree_sha256, SERVER_ENTRYPOINT};

/// The namespace layout is fixed independently of host installation paths.
pub(crate) const SANDBOX_WORKSPACE: &str = "/workspace";
pub(crate) const SANDBOX_PROFILE: &str = "sw-mcp/filesystem-readonly/linux-bwrap/1";

pub(crate) fn profile_name(format: &str) -> &'static str {
    if format == super::server_profile::filesystem_roots::FORMAT {
        "sw-mcp/filesystem-multi-root-readonly/linux-bwrap/1"
    } else if format == super::server_profile::git::FILE_READS_FORMAT {
        "sw-mcp/git-readonly-file-revisions/linux-bwrap-landlock/1"
    } else if format == super::server_profile::git_tracked_symlinks::FORMAT {
        "sw-mcp/git-tracked-symlinks-readonly/linux-bwrap-landlock/1"
    } else if format == super::server_profile::git_local_clone::FORMAT {
        "sw-mcp/git-local-clone-readonly/linux-bwrap-landlock/1"
    } else if format == super::server_profile::git::SHALLOW_FORMAT {
        "sw-mcp/git-readonly-shallow/linux-bwrap-landlock/1"
    } else if format == super::server_profile::git::LOCAL_REFS_FORMAT {
        "sw-mcp/git-readonly-local-refs/linux-bwrap-landlock/1"
    } else if format == super::server_profile::git::FORMAT {
        "sw-mcp/git-readonly/linux-bwrap-landlock/1"
    } else {
        SANDBOX_PROFILE
    }
}

/// File descriptors remain owned until the child has consumed its mount list.
/// The caller must use `spawn`, rather than extracting a command and dropping
/// the descriptors before the fork/exec boundary.
#[derive(Debug)]
pub(crate) struct PreparedServerSandbox {
    #[cfg(target_os = "linux")]
    command: Command,
    _pins: Vec<File>,
    workspace: PathBuf,
    git_view: Option<Arc<super::server_profile::git::SelectedView>>,
    filesystem_roots: Option<Arc<super::server_profile::filesystem_roots::Guard>>,
    #[cfg(target_os = "linux")]
    verified_git_snapshot: Option<Arc<super::server_profile::git::object_witness::Snapshot>>,
    #[cfg(target_os = "linux")]
    budget: Option<super::linux_owner::BudgetPrepare>,
    #[cfg(target_os = "linux")]
    bwrap_fd: std::os::fd::RawFd,
    #[cfg(target_os = "linux")]
    owner_executable_fd: std::os::fd::RawFd,
    #[cfg(target_os = "linux")]
    sealed_closure: Option<super::linux_owner::SealedClosure>,
}

impl PreparedServerSandbox {
    pub(crate) fn filesystem_roots(
        &self,
    ) -> Option<Arc<super::server_profile::filesystem_roots::Guard>> {
        self.filesystem_roots.clone()
    }

    pub(crate) fn git_view(&self) -> Option<Arc<super::server_profile::git::SelectedView>> {
        self.git_view.clone()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn verified_git_snapshot(
        &self,
    ) -> Option<Arc<super::server_profile::git::object_witness::Snapshot>> {
        self.verified_git_snapshot.clone()
    }

    pub(crate) fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub(crate) async fn spawn(
        mut self,
    ) -> anyhow::Result<(
        Child,
        Option<super::linux_budget::OwnedBudget>,
        super::linux_owner::OwnerGuard,
        u32,
    )> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            let inherited_fds: Vec<_> = self._pins.iter().map(AsRawFd::as_raw_fd).collect();
            let bwrap_args = self
                .command
                .as_std()
                .get_args()
                .map(|arg| {
                    arg.to_str()
                        .map(str::to_owned)
                        .context("mcp_owner_launch_invalid")
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let owner = super::linux_owner::spawn(super::linux_owner::LaunchSpec {
                sealed_closure: self.sealed_closure.take(),
                bwrap_fd: self.bwrap_fd,
                owner_executable_fd: self.owner_executable_fd,
                inherited_fds,
                bwrap_args,
                budget_attach_fd: None,
                budget_cleanup: None,
                budget_prepare: self.budget.take(),
            })
            .await?;
            Ok((owner.child, owner.budget, owner.guard, owner.sandbox_pid))
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = &mut self;
            bail!("mcp_owner_platform_unsupported")
        }
    }
}

/// Pin and verify the exact operator-installed runtime before any child runs.
/// There is no shell, PATH search, package download, or unsandboxed fallback.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn prepare(profile: &ProfileConfig) -> anyhow::Result<PreparedServerSandbox> {
    prepare_with_budget(profile, None)
}

pub(crate) fn prepare_with_budget(
    profile: &ProfileConfig,
    selected: Option<&super::linux_budget::BoundConfig>,
) -> anyhow::Result<PreparedServerSandbox> {
    #[cfg(target_os = "linux")]
    {
        prepare_linux(profile, selected, true)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = profile;
        if selected.is_some() || super::linux_budget::Config::load_from_env()?.is_some() {
            bail!("mcp_budget_platform_unsupported");
        }
        bail!("the selected MCP server profile requires Linux bubblewrap");
    }
}

/// Embedded daemon launches receive budget selection explicitly. They never
/// inherit a project's environment-selected budget or silently fall back to it.
pub(crate) fn prepare_explicit(
    profile: &ProfileConfig,
    selected: Option<&super::linux_budget::BoundConfig>,
) -> anyhow::Result<PreparedServerSandbox> {
    #[cfg(target_os = "linux")]
    {
        prepare_linux(profile, selected, false)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = profile;
        if selected.is_some() {
            bail!("mcp_budget_platform_unsupported");
        }
        bail!("the selected MCP server profile requires Linux bubblewrap");
    }
}

/// Only a daemon-selected immutable image can use this launch contract.
pub(crate) fn prepare_verified(
    profile: &ProfileConfig,
    selected: Option<&super::linux_budget::BoundConfig>,
    runtime: &super::verified_closure::Runtime,
) -> anyhow::Result<PreparedServerSandbox> {
    anyhow::ensure!(
        runtime.matches(profile),
        "verified_execution_profile_changed"
    );
    #[cfg(target_os = "linux")]
    {
        prepare_linux_command(
            profile,
            &[
                format!("/mcp-server/{SERVER_ENTRYPOINT}"),
                SANDBOX_WORKSPACE.to_owned(),
            ],
            selected,
            false,
            false,
            Some(runtime),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = selected;
        anyhow::bail!("verified_execution_platform_unsupported")
    }
}

/// Explicit daemon-owned Git execution. Default preparation/capture is unchanged.
/// Snapshot capture uses the exact opened workspace descriptor mounted below;
/// the retained snapshot, not another SelectedView, supplies both kind and mount.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn prepare_verified_git(
    profile: &ProfileConfig,
) -> anyhow::Result<PreparedServerSandbox> {
    anyhow::ensure!(
        super::verified_git::supports_profile(&profile.format),
        "verified execution requires a supported Git profile"
    );
    // Validate constructed configs as strictly as operator file configs.
    ProfileConfig::read(&serde_json::to_vec(profile)?)?;
    anyhow::ensure!(
        std::env::var_os(crate::pilot_budget::BINDING_ENV).is_none(),
        "verified Git requires an explicit prepared pilot budget API; ambient binding unsupported"
    );
    #[cfg(target_os = "linux")]
    {
        prepare_linux_command_inner(
            profile,
            &[
                "-I",
                "-B",
                "-m",
                "mcp_server_git",
                "--repository",
                SANDBOX_WORKSPACE,
            ]
            .map(str::to_owned),
            None,
            false,
            true,
            None,
            true,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("verified Git execution requires Linux");
    }
}

/// Prepare a *fresh* original filesystem server instance against an
/// already-created owner-private empty staging root, not the user workspace.
/// Only the new profile may acquire this writable host-backed namespace mount.
#[allow(dead_code)] // this Linux-only caller has no equivalent on unsupported targets
pub(crate) fn prepare_create_stage(
    profile: &ProfileConfig,
    stage: &Path,
) -> anyhow::Result<PreparedServerSandbox> {
    anyhow::ensure!(
        profile.format == super::server_profile::filesystem_create::FORMAT,
        "only the selected original-create profile can stage writes"
    );
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(stage)?;
        anyhow::ensure!(
            meta.file_type().is_dir()
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o777 == 0o700,
            "original-create staging directory is unsafe"
        );
        anyhow::ensure!(stage.is_absolute(), "staging path must be absolute");
        let mut isolated = profile.clone();
        isolated.workspace = stage.to_path_buf();
        isolated.workspace_identity = Some(
            super::server_profile::WorkspaceIdentity::from_metadata(&meta),
        );
        prepare_linux_command(
            &isolated,
            &[
                format!("/mcp-server/{SERVER_ENTRYPOINT}"),
                SANDBOX_WORKSPACE.to_owned(),
            ],
            None,
            true,
            true,
            None,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (profile, stage);
        anyhow::bail!("original-create sandbox requires Linux")
    }
}

/// Open and verify every pin of a selected profile (workspace, package tree,
/// runtime, bubblewrap, Git binaries, libraries and repository rules) without
/// starting anything. Used by setup previews before a launch is persisted.
#[cfg(target_os = "linux")]
pub(crate) fn verify(profile: &ProfileConfig) -> anyhow::Result<()> {
    prepare(profile).map(drop)
}

/// Kill and reap the outside owner's process group after attempting its private
/// cleanup acknowledgement. The trusted PID 1 lease and bubblewrap parent-death
/// chain stop descendants even if they create their own session/process group.
pub(crate) async fn terminate(child: &mut Child) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    let group_error = if let Some(pid) = child.id() {
        // `process_group(0)` creates a group whose id is this live child pid.
        // A live, unreaped child prevents pid/group reuse during this call.
        let result = unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            (error.raw_os_error() != Some(libc::ESRCH)).then_some(error)
        } else {
            None
        }
    } else {
        None
    };
    // An unexpected process-group error must not skip the individual kill or
    // reap attempt. Keep its failure for the final cleanup-verification result.
    let kill_error = child.start_kill().err();
    let reaped = tokio::time::timeout(std::time::Duration::from_secs(3), child.wait())
        .await
        .context("MCP sandbox cleanup is unverified: process did not exit within three seconds")?;
    reaped.context("failed to reap MCP sandbox")?;
    #[cfg(target_os = "linux")]
    if let Some(error) = group_error {
        return Err(error).context("MCP sandbox cleanup is unverified: process-group kill failed");
    }
    if let Some(error) = kill_error {
        return Err(error).context("MCP sandbox cleanup is unverified: individual kill failed");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.parent().is_some()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[cfg(any(target_os = "linux", all(test, unix)))]
fn valid_library_destination(path: &Path) -> bool {
    normalized_absolute(path)
        && ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]
            .iter()
            .any(|root| path.starts_with(root) && path != Path::new(root))
}

#[cfg(target_os = "linux")]
fn open_directory(path: &Path) -> anyhow::Result<(PathBuf, File)> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    if !normalized_absolute(path) {
        bail!("MCP sandbox directory must be a normalized absolute path");
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("MCP sandbox directory must not be a symlink");
    }
    let canonical = path.canonicalize()?;
    if canonical.parent().is_none() {
        bail!("MCP sandbox refuses the host filesystem root");
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&canonical)?;
    let opened = file.metadata()?;
    if metadata.dev() != opened.dev() || metadata.ino() != opened.ino() {
        bail!("MCP sandbox directory identity changed while preparing");
    }
    Ok((canonical, file))
}

#[cfg(target_os = "linux")]
fn hash_file(file: &File) -> anyhow::Result<String> {
    use std::os::unix::fs::FileExt;
    let mut hasher = Sha256::new();
    let mut offset = 0;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read_at(&mut buffer, offset)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        offset += read as u64;
        if offset > 256 * 1024 * 1024 {
            bail!("MCP sandbox runtime asset exceeds its size limit");
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(target_os = "linux")]
fn open_verified_file(path: &Path, expected: &str, executable: bool) -> anyhow::Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    if !normalized_absolute(path) {
        bail!("MCP sandbox asset must be a normalized absolute path");
    }
    // System loaders commonly have an intentional symlink at /lib64. The
    // descriptor pins the resolved regular file; the mount destination remains
    // the explicitly declared interpreter/library path.
    let canonical = path.canonicalize()?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(canonical)?;
    let before = file.metadata()?;
    if !before.is_file() || (executable && before.permissions().mode() & 0o111 == 0) {
        bail!("MCP sandbox runtime asset has an invalid file type or mode");
    }
    if hash_file(&file)? != expected {
        bail!("MCP sandbox runtime asset digest mismatch");
    }
    let after = file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        bail!("MCP sandbox runtime asset changed while hashing");
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn descriptor_path(file: &File) -> PathBuf {
    use std::os::fd::AsRawFd;
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

/// Deny all socket creation/connect/send operations, including pathname Unix
/// sockets that may exist in the read-only workspace. Network namespaces alone
/// do not isolate such filesystem sockets. Anonymous socketpair IPC stays usable.
#[cfg(target_os = "linux")]
fn filter_instructions(git_landlock: bool) -> anyhow::Result<Vec<(u16, u8, u8, u32)>> {
    filter_instructions_mode(git_landlock, false)
}

/// The writable variant is used only for an isolated ephemeral create-stage
/// mount; it never becomes a fallback for an installed read-only profile.
#[cfg(target_os = "linux")]
fn filter_instructions_mode(
    git_landlock: bool,
    writable_owned_stage: bool,
) -> anyhow::Result<Vec<(u16, u8, u8, u32)>> {
    anyhow::ensure!(
        !git_landlock || !writable_owned_stage,
        "invalid isolated stage flags"
    );
    #[cfg(target_arch = "x86_64")]
    let architecture = 0xc000_003e_u32;
    #[cfg(target_arch = "aarch64")]
    let architecture = 0xc000_00b7_u32;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let architecture = 0_u32;
    if architecture == 0 {
        bail!("MCP server sandbox architecture is unsupported");
    }
    let deny = 0x0005_0000 | libc::EACCES as u32;
    let mut instructions: Vec<(u16, u8, u8, u32)> = vec![
        (0x20, 0, 0, 4), // seccomp_data.arch
        (0x15, 1, 0, architecture),
        (0x06, 0, 0, 0x8000_0000), // KILL_PROCESS for another syscall ABI
        (0x20, 0, 0, 0),           // seccomp_data.nr
        (0x35, 0, 1, 0x4000_0000),
        (0x06, 0, 0, 0x8000_0000), // reject x32/unknown high syscall numbers
    ];
    for syscall in [
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_io_uring_setup,
        libc::SYS_openat2,
        // The selected read-only servers do not change scheduling class.
        // In particular they cannot escape fair-class CPU bandwidth accounting.
        libc::SYS_sched_setscheduler,
        libc::SYS_sched_setattr,
    ] {
        instructions.push((0x15, 0, 1, syscall as u32));
        instructions.push((0x06, 0, 0, deny));
    }
    // HugeTLB allocations are not included in memory.max on every supported
    // kernel. Block their explicit creation while preserving ordinary mmap,
    // memfd and SysV shared memory for the pinned runtimes.
    for (syscall, offset, flag) in [
        (libc::SYS_mmap, 40_u32, libc::MAP_HUGETLB as u32),
        (libc::SYS_memfd_create, 24_u32, libc::MFD_HUGETLB),
        (libc::SYS_shmget, 32_u32, libc::SHM_HUGETLB as u32),
    ] {
        instructions.extend([
            (0x15, 0, 4, syscall as u32),
            (0x20, 0, 0, offset),
            (0x45, 0, 1, flag),
            (0x06, 0, 0, deny),
            (0x20, 0, 0, 0), // Restore syscall number for subsequent rules.
        ]);
    }
    if git_landlock {
        // asyncio wakes its loop from worker threads through an anonymous
        // socketpair. No socket/connect/accept or inherited socket is available.
        // Permit sendto only without a destination (both pointer words zero).
        instructions.extend([
            (0x15, 0, 6, libc::SYS_sendto as u32),
            (0x20, 0, 0, 48),
            (0x15, 0, 3, 0),
            (0x20, 0, 0, 52),
            (0x15, 0, 1, 0),
            (0x06, 0, 0, 0x7fff_0000),
            (0x06, 0, 0, deny),
        ]);
    } else {
        instructions.push((0x15, 0, 1, libc::SYS_sendto as u32));
        instructions.push((0x06, 0, 0, deny));
    }
    #[cfg(target_arch = "x86_64")]
    {
        if !git_landlock && !writable_owned_stage {
            instructions.push((0x15, 0, 1, libc::SYS_creat as u32));
            instructions.push((0x06, 0, 0, deny));
        }
    }
    // The pinned Node/libuv opens its explicitly piped stdio with FIONBIO.
    // Permit that local nonblocking flag only on descriptors 0, 1 and 2.
    // No ioctl is admitted for workspace/device descriptors or another request.
    if git_landlock {
        // CPython's asyncio socketpair uses generic FIONBIO on non-stdio
        // descriptors. This only toggles O_NONBLOCK (already possible with
        // fcntl); no device-specific ioctl or new descriptor authority is granted.
        instructions.extend([
            (0x15, 0, 4, libc::SYS_ioctl as u32),
            (0x20, 0, 0, 24),
            (0x15, 0, 1, libc::FIONBIO as u32),
            (0x06, 0, 0, 0x7fff_0000),
            (0x06, 0, 0, deny),
        ]);
    } else {
        instructions.extend([
            (0x15, 0, 7, libc::SYS_ioctl as u32),
            (0x20, 0, 0, 16), // ioctl fd
            (0x25, 0, 1, 2),  // JGT: only explicit stdio descriptors
            (0x06, 0, 0, deny),
            (0x20, 0, 0, 24), // ioctl request
            (0x15, 0, 1, libc::FIONBIO as u32),
            (0x06, 0, 0, 0x7fff_0000),
            (0x06, 0, 0, deny),
        ]);
    }
    // Read-only bind mounts do not prevent writing to an existing FIFO or all
    // device effects. Deny writable opens independently of the mounted file
    // type. openat2 takes an indirect flags structure, so it is denied above.
    // O_TMPFILE also contains O_DIRECTORY: only its distinct high bit belongs
    // in this mask, preserving ordinary read-only directory opens.
    if git_landlock {
        // Only the pinned Git launcher may use this branch. Before original
        // Python/Git executes it installs mandatory Landlock ABI 3 write rules
        // allowing /dev/null alone. Socket/ioctl restrictions above stay intact.
        instructions.push((0x06, 0, 0, 0x7fff_0000));
        return Ok(instructions);
    }
    if writable_owned_stage {
        // Namespace mounts—not path name strings—confine writes: the only
        // host-backed writable mount is one owner-private, isolated stage.
        // Network/io_uring/ioctl and cross-ABI syscall denies stay active.
        instructions.push((0x06, 0, 0, 0x7fff_0000));
        return Ok(instructions);
    }
    let write_flags = (libc::O_WRONLY
        | libc::O_RDWR
        | libc::O_CREAT
        | libc::O_TRUNC
        | libc::O_APPEND
        | (libc::O_TMPFILE & !libc::O_DIRECTORY)) as u32;
    let open_calls = [
        (libc::SYS_openat, 32_u32),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_open, 24_u32),
    ];
    for (syscall, flags_offset) in open_calls {
        instructions.extend([
            (0x15, 0, 4, syscall as u32),
            (0x20, 0, 0, flags_offset), // low word of this syscall's flags
            (0x45, 0, 1, write_flags),  // JSET
            (0x06, 0, 0, deny),
            (0x06, 0, 0, 0x7fff_0000), // read-only open: ALLOW
        ]);
    }
    instructions.push((0x06, 0, 0, 0x7fff_0000)); // ALLOW
    Ok(instructions)
}

#[cfg(target_os = "linux")]
fn network_filter(git_landlock: bool) -> anyhow::Result<File> {
    network_filter_mode(git_landlock, false)
}

#[cfg(target_os = "linux")]
fn network_filter_mode(git_landlock: bool, writable_owned_stage: bool) -> anyhow::Result<File> {
    use std::io::{Seek, SeekFrom, Write};
    use std::os::fd::FromRawFd;

    let instructions = if writable_owned_stage {
        filter_instructions_mode(git_landlock, true)?
    } else {
        filter_instructions(git_landlock)?
    };
    let fd = unsafe {
        libc::memfd_create(
            c"sou62-network-filter".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to create MCP syscall filter");
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    for (code, yes, no, value) in instructions {
        file.write_all(&code.to_ne_bytes())?;
        file.write_all(&[yes, no])?;
        file.write_all(&value.to_ne_bytes())?;
    }
    file.seek(SeekFrom::Start(0))?;
    let sealed = unsafe {
        libc::fcntl(
            fd,
            libc::F_ADD_SEALS,
            libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL,
        )
    };
    if sealed < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to seal MCP syscall filter");
    }
    Ok(file)
}

#[cfg(any(target_os = "linux", all(test, unix)))]
const MAX_MOUNTINFO_BYTES: usize = 1024 * 1024;

/// Decode the kernel's escaped mount path without interpreting arbitrary shell
/// or JSON escapes. Every accepted path is absolute and normalized.
#[cfg(any(target_os = "linux", all(test, unix)))]
fn mount_path(encoded: &str) -> anyhow::Result<PathBuf> {
    use std::os::unix::ffi::OsStringExt;
    let invalid = || anyhow::anyhow!("mcp_budget_mount_observation_failed");
    let raw = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(raw.len());
    let mut position = 0;
    while position < raw.len() {
        if raw[position] == b'\\' {
            let escape = raw.get(position + 1..position + 4).ok_or_else(invalid)?;
            decoded.push(match escape {
                b"040" => b' ',
                b"011" => b'\t',
                b"012" => b'\n',
                b"134" => b'\\',
                _ => return Err(invalid()),
            });
            position += 4;
        } else {
            decoded.push(raw[position]);
            position += 1;
        }
    }
    let path = PathBuf::from(std::ffi::OsString::from_vec(decoded));
    if !path.is_absolute()
        || !path
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid());
    }
    Ok(path)
}

/// HugeTLB file mappings need not carry MAP_HUGETLB and are not charged to
/// memory.max on every kernel. Reject backing mounts exposed through either
/// recursive directory bind; unrelated host mounts are outside this sandbox.
#[cfg(any(target_os = "linux", all(test, unix)))]
fn validate_budget_mounts(bytes: &[u8], exposed_roots: &[&Path]) -> anyhow::Result<()> {
    let invalid = || anyhow::anyhow!("mcp_budget_mount_observation_failed");
    if bytes.is_empty() || bytes.len() > MAX_MOUNTINFO_BYTES || !bytes.ends_with(b"\n") {
        return Err(invalid());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    if text.contains('\0') {
        return Err(invalid());
    }
    for line in text.lines() {
        let words: Vec<_> = line.split_ascii_whitespace().collect();
        let separator = words
            .iter()
            .position(|word| *word == "-")
            .ok_or_else(invalid)?;
        if separator < 6
            || words.len() != separator + 4
            || words[0].parse::<u64>().is_err()
            || words[1].parse::<u64>().is_err()
        {
            return Err(invalid());
        }
        let (major, minor) = words[2].split_once(':').ok_or_else(invalid)?;
        if major.parse::<u64>().is_err() || minor.parse::<u64>().is_err() {
            return Err(invalid());
        }
        // The filesystem's show_path may emit an opaque root description:
        // nsfs legitimately uses "net:[inode]" rather than an absolute path.
        // Only the absolute mountpoint determines exposure to our bind roots.
        let mount = mount_path(words[4])?;
        if words[separator + 1] == "hugetlbfs"
            && exposed_roots
                .iter()
                .any(|root| mount.starts_with(root) || root.starts_with(&mount))
        {
            bail!("mcp_budget_hugetlb_mount_unsupported");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_budget_mount_support(exposed_roots: &[&Path], pins: &[&File]) -> anyhow::Result<()> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    let mut bytes = Vec::new();
    File::open("/proc/self/mountinfo")
        .map_err(|_| anyhow::anyhow!("mcp_budget_mount_observation_failed"))?
        .take(MAX_MOUNTINFO_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| anyhow::anyhow!("mcp_budget_mount_observation_failed"))?;
    validate_budget_mounts(&bytes, exposed_roots)?;
    for pin in pins {
        let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
        if unsafe { libc::fstatfs(pin.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
            bail!("mcp_budget_mount_observation_failed");
        }
        if unsafe { filesystem.assume_init() }.f_type == 0x9584_58f6_u32 as libc::c_long {
            bail!("mcp_budget_hugetlb_mount_unsupported");
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn prepare_linux(
    profile: &ProfileConfig,
    selected: Option<&super::linux_budget::BoundConfig>,
    inherit_environment: bool,
) -> anyhow::Result<PreparedServerSandbox> {
    if super::server_profile::git_selected(&profile.format) {
        return prepare_linux_command(
            profile,
            &[
                "-I",
                "-B",
                "-m",
                "mcp_server_git",
                "--repository",
                SANDBOX_WORKSPACE,
            ]
            .map(str::to_owned),
            selected,
            false,
            inherit_environment,
            None,
        );
    }
    let mut args = vec![format!("/mcp-server/{SERVER_ENTRYPOINT}")];
    if let Some(binding) = &profile.filesystem_roots {
        args.extend(binding.arguments());
    } else {
        args.push(SANDBOX_WORKSPACE.to_owned());
    }
    prepare_linux_command(profile, &args, selected, false, inherit_environment, None)
}

#[cfg(target_os = "linux")]
fn prepare_linux_command(
    profile: &ProfileConfig,
    node_args: &[String],
    selected: Option<&super::linux_budget::BoundConfig>,
    writable_owned_stage: bool,
    inherit_environment: bool,
    immutable: Option<&super::verified_closure::Runtime>,
) -> anyhow::Result<PreparedServerSandbox> {
    prepare_linux_command_inner(
        profile,
        node_args,
        selected,
        writable_owned_stage,
        inherit_environment,
        immutable,
        false,
    )
}

#[cfg(target_os = "linux")]
fn prepare_linux_command_inner(
    profile: &ProfileConfig,
    node_args: &[String],
    selected: Option<&super::linux_budget::BoundConfig>,
    writable_owned_stage: bool,
    inherit_environment: bool,
    immutable: Option<&super::verified_closure::Runtime>,
    verified_git: bool,
) -> anyhow::Result<PreparedServerSandbox> {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    let (workspace, workspace_pin) = open_directory(&profile.workspace)?;
    anyhow::ensure!(
        !writable_owned_stage || profile.format == super::server_profile::filesystem_create::FORMAT,
        "writable staging must use the separately selected original-create profile"
    );
    if let Some(expected) = &profile.workspace_identity {
        let metadata = workspace_pin.metadata()?;
        if super::server_profile::WorkspaceIdentity::from_metadata(&metadata) != *expected {
            bail!("selected workspace identity changed");
        }
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            bail!("selected workspace must remain owned and not shared writable");
        }
    }
    let git_profile = super::server_profile::git_selected(&profile.format);
    let clone_profile = profile.format == super::server_profile::git_local_clone::FORMAT;
    let link_profile = profile.format == super::server_profile::git_tracked_symlinks::FORMAT;
    let guarded_profile = clone_profile || link_profile;
    if git_profile {
        let root = descriptor_path(&workspace_pin).join(".");
        if link_profile {
            super::server_profile::git_tracked_symlinks::validate_repository(&root)?;
        } else if clone_profile {
            super::server_profile::git_local_clone::validate_repository(&root)?;
        } else if profile.format == super::server_profile::git::SHALLOW_FORMAT {
            super::server_profile::git::validate_repository_with_shallow(&root, true)?;
        } else {
            super::server_profile::git::validate_repository(&root)?;
        }
    }
    let verified_git_snapshot = if verified_git {
        Some(
            super::server_profile::git::object_witness::Snapshot::capture(
                &workspace_pin,
                &profile.format,
            )?,
        )
    } else {
        None
    };
    let git_view = if verified_git {
        None
    } else {
        super::server_profile::git::SelectedView::capture(&profile.format, &workspace_pin)?
    };
    let filesystem_roots = profile
        .filesystem_roots
        .as_ref()
        .map(super::server_profile::filesystem_roots::Guard::capture)
        .transpose()?
        .map(Arc::new);
    // The trusted namespace PID 1 is this exact running Agent image, never a
    // separately resolved pathname or an executable from the server package.
    #[cfg(not(test))]
    let owner_image = PathBuf::from("/proc/self/exe");
    // The ignored native probes execute in libtest, whose main entry point is
    // not the Agent CLI. Their driver supplies its exact candidate explicitly.
    #[cfg(test)]
    let owner_image = std::env::var_os("SOU86_TEST_AGENTFW")
        .map(PathBuf::from)
        .context("explicit candidate Agent image required for native owner probe")?;
    let owner_pin = File::open(owner_image).context("mcp_owner_image_unavailable")?;
    let owner_executable_fd = owner_pin.as_raw_fd();
    let mut pins = vec![workspace_pin, owner_pin];
    let mut mounts = vec![
        (0, PathBuf::from(SANDBOX_WORKSPACE)),
        (1, PathBuf::from("/mcp-runtime/owner")),
    ];
    let package_root;
    let bwrap_pin;
    if let Some(runtime) = immutable {
        anyhow::ensure!(
            runtime.matches(profile) && !git_profile && !writable_owned_stage,
            "verified_execution_profile_changed"
        );
        package_root = profile.package_root.clone();
        bwrap_pin = runtime.bwrap()?;
    } else {
        let (root, pin) = open_directory(&profile.package_root)?;
        package_root = root;
        if package_tree_sha256(&descriptor_path(&pin).join("."))? != profile.package_tree_sha256 {
            bail!("MCP server installed package tree digest mismatch");
        }
        mounts.push((pins.len(), PathBuf::from("/mcp-server")));
        pins.push(pin);
        let runtime_pin = open_verified_file(&profile.runtime_path, &profile.runtime_sha256, true)?;
        mounts.push((
            pins.len(),
            PathBuf::from(if git_profile {
                super::server_profile::git::PYTHON
            } else {
                "/mcp-runtime/node"
            }),
        ));
        pins.push(runtime_pin);
        bwrap_pin = open_verified_file(&profile.bwrap_path, &profile.bwrap_sha256, true)?;
    }
    if let Some(git) = &profile.git {
        let pin = open_verified_file(&git.path, &git.sha256, true)?;
        mounts.push((
            pins.len(),
            PathBuf::from(if guarded_profile {
                super::server_profile::git_local_clone::ORIGINAL_GIT
            } else {
                "/mcp-runtime/git"
            }),
        ));
        pins.push(pin);
    }
    if git_profile {
        let launcher = profile
            .git_launcher
            .as_ref()
            .context("Git Landlock launcher is required")?;
        let pin = open_verified_file(&launcher.path, &launcher.sha256, true)?;
        mounts.push((
            pins.len(),
            PathBuf::from("/mcp-runtime/git-profile-launcher"),
        ));
        pins.push(pin);
        if guarded_profile {
            // bubblewrap consumes each mount fd, so use a separate verified fd
            // for the same exact launcher image used as the per-Git guard.
            let pin = open_verified_file(&launcher.path, &launcher.sha256, true)?;
            mounts.push((
                pins.len(),
                PathBuf::from(if link_profile {
                    super::server_profile::git_tracked_symlinks::EXECUTABLE
                } else {
                    super::server_profile::git_local_clone::EXECUTABLE
                }),
            ));
            pins.push(pin);
        }
    }
    if profile.libraries.is_empty() || profile.libraries.len() > 32 {
        bail!("MCP sandbox requires a bounded, explicit library list");
    }
    let mut destinations = std::collections::BTreeSet::new();
    for library in profile.libraries.iter().filter(|_| immutable.is_none()) {
        if !valid_library_destination(&library.path) || !destinations.insert(library.path.clone()) {
            bail!("MCP sandbox library destination is invalid or duplicated");
        }
        let pin = open_verified_file(&library.path, &library.sha256, false)?;
        mounts.push((pins.len(), library.path.clone()));
        pins.push(pin);
    }

    // Executing a pinned fd avoids re-opening a substituted bwrap pathname.
    // The fd is CLOEXEC: the kernel consumes the executable before closing it.
    let mut command = Command::new(descriptor_path(&bwrap_pin));
    command.args([
        "--die-with-parent",
        "--as-pid-1",
        "--sync-fd",
        super::linux_owner::LEASE_FD_PLACEHOLDER,
        "--new-session",
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--assert-userns-disabled",
        "--clearenv",
        "--cap-drop",
        "ALL",
        "--hostname",
        "mcp-readonly",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--size",
        "67108864",
        "--tmpfs",
        "/tmp",
    ]);
    for (index, destination) in mounts {
        // Only the descriptor-pinned ephemeral staging directory is writable.
        // Read-only profile, runtime and all library/dependency mounts remain
        // unchanged. No actual user workspace is ever given a writable mount.
        if writable_owned_stage && index == 0 {
            command
                .arg("--bind-fd")
                .arg(pins[index].as_raw_fd().to_string())
                .arg(destination);
            continue;
        }
        // --ro-bind-fd consumes and closes the descriptor before exec. Older
        // bwrap versions without this primitive must fail closed: spelling the
        // source as /proc/self/fd/N with --ro-bind would leak host descriptors
        // into the untrusted server and bypass its read-only mount namespace.
        command
            .arg("--ro-bind-fd")
            .arg(pins[index].as_raw_fd().to_string())
            .arg(destination);
    }
    let sealed_closure = if let Some(runtime) = immutable {
        let mut images = runtime.mount(&mut command, &mut pins)?;
        images.push(bwrap_pin.as_raw_fd());
        Some(super::linux_owner::SealedClosure {
            format: super::verified_closure::FORMAT.into(),
            sha256: runtime.digest().into(),
            images,
        })
    } else {
        None
    };
    if let Some(snapshot) = &verified_git_snapshot {
        snapshot.mount(&mut command, &mut pins)?;
    } else if let Some(view) = &git_view {
        view.mount(&mut command, &mut pins)?;
    }
    if let Some(roots) = &filesystem_roots {
        roots.mount(&mut command, &mut pins)?;
    }
    let seccomp = if writable_owned_stage {
        network_filter_mode(git_profile, true)?
    } else {
        network_filter(git_profile)?
    };
    command
        .arg("--seccomp")
        .arg(seccomp.as_raw_fd().to_string());
    pins.push(seccomp);
    command.args([
        "--chdir",
        SANDBOX_WORKSPACE,
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "PATH",
        "/mcp-runtime",
        "--setenv",
        "UV_THREADPOOL_SIZE",
        "16",
    ]);
    if git_profile {
        for (name, value) in [
            (
                "GIT_PYTHON_GIT_EXECUTABLE",
                if link_profile {
                    super::server_profile::git_tracked_symlinks::EXECUTABLE
                } else {
                    "/mcp-runtime/git"
                },
            ),
            ("GIT_CONFIG_NOSYSTEM", "1"),
            ("GIT_CONFIG_GLOBAL", "/dev/null"),
            ("GIT_TERMINAL_PROMPT", "0"),
            ("GIT_OPTIONAL_LOCKS", "0"),
            ("GIT_EXEC_PATH", "/nonexistent"),
            ("GIT_PAGER", ""),
            ("GIT_CONFIG_COUNT", "3"),
            ("GIT_CONFIG_KEY_0", "core.hooksPath"),
            ("GIT_CONFIG_VALUE_0", "/nonexistent"),
            ("GIT_CONFIG_KEY_1", "core.fsmonitor"),
            ("GIT_CONFIG_VALUE_1", "false"),
            ("GIT_CONFIG_KEY_2", "protocol.allow"),
            ("GIT_CONFIG_VALUE_2", "never"),
        ] {
            command.args(["--setenv", name, value]);
        }
    }
    if writable_owned_stage {
        // The pinned original Node process defaults to 0666 & umask; make its
        // isolated-stage output owner-private before reading it back.
        unsafe {
            command.as_std_mut().pre_exec(|| {
                libc::umask(0o077);
                Ok(())
            });
        }
    }
    command
        .args([
            "--",
            "/mcp-runtime/owner",
            if immutable.is_some() {
                "--agentfw-mcp-pid1-v2"
            } else {
                "--agentfw-mcp-pid1-v1"
            },
            super::linux_owner::LEASE_FD_PLACEHOLDER,
            "--",
        ])
        .arg(if git_profile {
            "/mcp-runtime/git-profile-launcher"
        } else {
            "/mcp-runtime/node"
        });
    command
        .args(node_args)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let budget_config = match selected {
        Some(bound) => Some(bound.config.clone()),
        None if inherit_environment => super::linux_budget::Config::load_from_env()?,
        None => None,
    };
    if budget_config.is_some() {
        let budget_pins: Vec<_> = pins.iter().chain(std::iter::once(&bwrap_pin)).collect();
        if immutable.is_some() {
            require_budget_mount_support(&[&workspace], &budget_pins)?;
        } else {
            require_budget_mount_support(&[&workspace, &package_root], &budget_pins)?;
        }
    }
    let budget = match budget_config.as_ref() {
        Some(config) => {
            let (bound, root) =
                super::linux_budget::pin_bound(config, selected.map(|bound| bound.root))?;
            let root_fd = root.as_raw_fd();
            pins.push(root);
            Some(super::linux_owner::BudgetPrepare {
                config: bound.config,
                root: bound.root,
                root_fd,
            })
        }
        None => None,
    };
    // The synchronous outside owner performs the same trusted fork-stub
    // restrictions before bubblewrap exec, while retaining cleanup authority.
    let bwrap_fd = bwrap_pin.as_raw_fd();
    pins.push(bwrap_pin);
    Ok(PreparedServerSandbox {
        command,
        _pins: pins,
        workspace,
        git_view,
        filesystem_roots,
        verified_git_snapshot,
        budget,
        bwrap_fd,
        owner_executable_fd,
        sealed_closure,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_os = "linux")]
    fn pinned_existing_workspace_refuses_replacement() {
        use super::super::server_profile::{WorkspaceIdentity, FORMAT};
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().join("project");
        std::fs::create_dir(&root).unwrap();
        let identity = WorkspaceIdentity::from_metadata(&root.metadata().unwrap());
        let profile = ProfileConfig::read(serde_json::json!({
            "format": FORMAT, "workspace": root, "workspaceIdentity": identity,
            "runtimePath": temporary.path().join("node"), "runtimeSha256": "a".repeat(64),
            "packageRoot": temporary.path().join("package"), "packageTreeSha256": "b".repeat(64),
            "bwrapPath": temporary.path().join("bwrap"), "bwrapSha256": "c".repeat(64), "libraries": []
        }).to_string().as_bytes()).unwrap();
        std::fs::rename(&root, temporary.path().join("original")).unwrap();
        std::fs::create_dir(&root).unwrap();
        // Fails on the opened workspace fd, before any other assets or process.
        let error = prepare_linux_command(&profile, &[], None, false, true, None)
            .err()
            .unwrap();
        assert!(error
            .to_string()
            .contains("selected workspace identity changed"));
    }

    #[test]
    fn budget_mountinfo_accepts_regular_and_unexposed_hugetlb_filesystems() {
        let records = b"29 0 0:25 / / rw shared:1 - ext4 /dev/root rw\n30 29 0:26 / /path\\040with\\040space ro - tmpfs tmpfs ro,size=1024\n31 29 0:27 / /dev/hugepages rw - hugetlbfs hugetlbfs rw\n";
        validate_budget_mounts(records, &[Path::new("/workspace"), Path::new("/package")]).unwrap();
    }

    #[test]
    fn budget_mountinfo_accepts_nsfs_roots_and_still_refuses_exposed_hugetlbfs() {
        let namespace =
            b"32 29 0:28 net:[4026531993] /run/docker/netns/default rw shared:1 - nsfs nsfs rw\n";
        validate_budget_mounts(namespace, &[Path::new("/workspace")]).unwrap();
        let mut mixed = namespace.to_vec();
        mixed.extend_from_slice(b"33 29 0:29 / /workspace/nested rw - hugetlbfs hugetlbfs rw\n");
        assert_eq!(
            validate_budget_mounts(&mixed, &[Path::new("/workspace")])
                .unwrap_err()
                .to_string(),
            "mcp_budget_hugetlb_mount_unsupported"
        );
    }

    #[test]
    fn budget_mountinfo_refuses_exposed_hugetlbfs_without_logging_mount_paths() {
        for mount in [
            "/workspace",
            "/workspace/nested",
            "/package/nested",
            "/",
            "/workspace\\040space/huge",
        ] {
            let record = format!("29 0 0:25 / {mount} rw - hugetlbfs hugetlbfs rw\n");
            let error = validate_budget_mounts(
                record.as_bytes(),
                &[
                    Path::new("/workspace"),
                    Path::new("/package"),
                    Path::new("/workspace space"),
                ],
            )
            .unwrap_err()
            .to_string();
            assert_eq!(error, "mcp_budget_hugetlb_mount_unsupported");
            assert!(!error.contains("workspace"));
        }
        let ancestor = b"29 0 0:25 / /host rw - hugetlbfs hugetlbfs rw\n";
        assert!(validate_budget_mounts(ancestor, &[Path::new("/host/workspace")]).is_err());
        let sibling = b"29 0 0:25 / /workspace-other rw - hugetlbfs hugetlbfs rw\n";
        validate_budget_mounts(sibling, &[Path::new("/workspace")]).unwrap();
    }

    #[test]
    fn budget_mountinfo_refuses_partial_malformed_or_unbounded_observations() {
        for record in [
            b"".as_slice(),
            b"\n",
            b"29 0 0:25 / / rw ext4 /dev/root rw\n",
            b"29 0 0:25 / / rw - ext4 /dev/root rw",
            b"29 0 invalid / / rw - ext4 /dev/root rw\n",
            b"x 0 0:25 / / rw - ext4 /dev/root rw\n",
            b"29 0 0:25 / / rw - ext4 /dev/root rw extra\n",
            b"29 0 0:25 / / rw - ext4 /dev/root \xff\n",
            b"29 0 0:25 / /bad\\04 rw - ext4 /dev/root rw\n",
            b"29 0 0:25 / /bad\\057path rw - ext4 /dev/root rw\n",
        ] {
            assert!(validate_budget_mounts(record, &[Path::new("/workspace")]).is_err());
        }
        assert!(validate_budget_mounts(&vec![b'\n'; MAX_MOUNTINFO_BYTES + 1], &[]).is_err());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires explicit pinned Linux Git/Python profile and bubblewrap"]
    async fn selected_git_sandbox_isolates_real_python_and_git() {
        git_sandbox_boundary(false).await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires explicit pinned Linux BASE or file-revision Git profile and bubblewrap"]
    async fn verified_git_preparation_isolates_real_python_and_git() {
        git_sandbox_boundary(true).await;
    }

    #[cfg(target_os = "linux")]
    async fn git_sandbox_boundary(verified: bool) {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        use tokio::io::AsyncReadExt;
        let profile_path = std::env::var("SOU68_SANDBOX_TEST_PROFILE")
            .expect("explicit Git sandbox profile required");
        let profile = ProfileConfig::read(&std::fs::read(profile_path).unwrap()).unwrap();
        assert!(super::super::server_profile::git_selected(&profile.format));
        let owned = tempfile::tempdir().unwrap();
        let outside = owned.path().join("outside-secret");
        std::fs::write(&outside, b"outside unchanged").unwrap();
        let host_file = File::open(&outside).unwrap();
        let descriptor = unsafe { libc::fcntl(host_file.as_raw_fd(), libc::F_DUPFD, 3) };
        assert!(descriptor >= 0);
        let _ambient = unsafe { File::from_raw_fd(descriptor) };
        let receiver = TcpListener::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let address = receiver.local_addr().unwrap();
        let calibration = TcpStream::connect(address).unwrap();
        let pair = receiver.accept().unwrap();
        drop(calibration);
        drop(pair);
        let outside_json = serde_json::to_string(&outside).unwrap();
        let script = format!(
            r#"
import asyncio, ctypes, errno, json, os, pathlib, socket, subprocess
def denied(fn):
    try:
        fn()
        return False
    except OSError:
        return True
# The pinned portable Python build need not expose optional os wrappers.
# Call the actual native syscalls; the Rust test supplies this architecture's
# numbers rather than assuming an x86-64 ABI inside the Python fixture.
native_libc = ctypes.CDLL(None, use_errno=True)
native_libc.syscall.restype = ctypes.c_long
def native_call(number, *arguments):
    ctypes.set_errno(0)
    result = native_libc.syscall(ctypes.c_long(number), *arguments)
    if result == -1:
        raise OSError(ctypes.get_errno(), 'owned syscall probe failed')
    return result
def memfd(flags):
    return native_call({memfd_syscall}, ctypes.c_char_p(b'sou79-owned'), ctypes.c_uint(flags))
def ordinary_memfd():
    descriptor = memfd({memfd_cloexec})
    os.close(descriptor)
    return True
class SchedulingParameter(ctypes.Structure):
    _fields_ = [('sched_priority', ctypes.c_int)]
def scheduler_change():
    parameter = SchedulingParameter(0)
    native_call({scheduler_syscall}, ctypes.c_int(0), ctypes.c_int({normal_scheduler}), ctypes.byref(parameter))
def denied_by_filter(fn):
    try:
        descriptor = fn()
        if type(descriptor) is int:
            os.close(descriptor)
        return False
    except OSError as error:
        return error.errno == errno.EACCES
def descriptors():
    result = []
    for entry in pathlib.Path('/proc/self/fd').iterdir():
        try: result.append(os.readlink(entry))
        except OSError: pass
    return result
def null_open():
    fd = os.open('/dev/null', os.O_RDWR)
    os.close(fd)
    return True
git = subprocess.run(['/mcp-runtime/git', 'status', '--porcelain'], cwd='/workspace', capture_output=True, timeout=5)
loop = asyncio.new_event_loop()
assert loop.run_until_complete(asyncio.wait_for(asyncio.to_thread(lambda: 42), 3)) == 42
loop.close()
result = {{
 'asyncio_ready': True,
 'null_open_allowed': null_open(),
 'git_read': git.returncode == 0,
 'ordinary_memfd_allowed': ordinary_memfd(),
 'hugetlb_creation_denied': denied_by_filter(lambda: memfd({memfd_hugetlb})),
 'scheduler_change_denied': denied_by_filter(scheduler_change),
 'git_exit': git.returncode,
 'git_error': git.stderr[-2000:].decode('utf-8', 'replace'),
 'workspace_write_denied': denied(lambda: pathlib.Path('/workspace/sandbox-forbidden').write_text('denied')),
 'runtime_write_denied': denied(lambda: pathlib.Path('/mcp-runtime/git').open('wb')),
 'tmp_write_denied': denied(lambda: pathlib.Path('/tmp/forbidden').write_text('denied')),
 'other_device_write_denied': denied(lambda: pathlib.Path('/dev/zero').open('wb')),
 'fifo_write_denied': denied(lambda: os.open('/workspace/.sou68-runtime-probe.fifo', os.O_WRONLY | os.O_NONBLOCK)),
 'outside_read_denied': denied(lambda: pathlib.Path({outside_json}).read_bytes()),
 'outside_write_denied': denied(lambda: pathlib.Path({outside_json}).write_bytes(b'denied')),
 'egress_denied': denied(lambda: socket.create_connection(('127.0.0.1', {port}), 1)),
 'unix_socket_denied': denied(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)),
 'ambient_env_absent': 'SOU68_INHERITED_SECRET' not in os.environ,
 'home_absent': not pathlib.Path('/home').exists() and not pathlib.Path('/root').exists(),
 'descriptor_targets': descriptors(),
 'net_namespace': os.readlink('/proc/self/ns/net'),
 'pid_namespace': os.readlink('/proc/self/ns/pid'),
}}
print(json.dumps(result))
"#,
            port = address.port(),
            memfd_syscall = libc::SYS_memfd_create,
            scheduler_syscall = libc::SYS_sched_setscheduler,
            memfd_cloexec = libc::MFD_CLOEXEC,
            memfd_hugetlb = libc::MFD_HUGETLB,
            normal_scheduler = libc::SCHED_OTHER,
        );
        let args = vec!["-I".into(), "-B".into(), "-c".into(), script];
        let mut prepared = if verified {
            assert!(super::super::verified_git::supports_profile(
                &profile.format
            ));
            prepare_linux_command_inner(&profile, &args, None, false, true, None, true).unwrap()
        } else {
            prepare_linux_command(&profile, &args, None, false, true, None).unwrap()
        };
        // Add an owned FIFO after repository validation to prove that read-only
        // mounts alone are insufficient, and that Landlock still blocks IPC.
        let fifo_path = profile.workspace.join(".sou68-runtime-probe.fifo");
        assert!(!fifo_path.exists());
        let fifo_name = std::ffi::CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        let mut fifo_reader = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo_path)
            .unwrap();
        let mut calibration = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo_path)
            .unwrap();
        calibration.write_all(b"calibrate").unwrap();
        let mut marker = [0_u8; 9];
        fifo_reader.read_exact(&mut marker).unwrap();
        assert_eq!(&marker, b"calibrate");
        drop(calibration);
        prepared
            .command
            .env("SOU68_INHERITED_SECRET", "must-not-reach-server");
        let (mut child, mut budget, mut owner, _sandbox_pid) = prepared.spawn().await.unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        drop(child.stdin.take());
        let collected = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            let mut output = Vec::new();
            let mut errors = Vec::new();
            let (out, err) = tokio::join!(
                stdout.read_to_end(&mut output),
                stderr.read_to_end(&mut errors),
            );
            out.unwrap();
            err.unwrap();
            if let Some(budget) = budget.as_mut() {
                budget.finish().await.unwrap();
            }
            owner.finish().await.unwrap();
            (output, errors, child.wait().await.unwrap())
        })
        .await;
        let budget_cleanup = if let Some(budget) = budget.as_mut() {
            budget.finish().await
        } else {
            Ok(())
        };
        if collected.is_err() {
            terminate(&mut child).await.unwrap();
            panic!("real Git/Python sandbox timed out");
        }
        budget_cleanup.unwrap();
        owner.finish().await.unwrap();
        let (output, errors, status) = collected.unwrap();
        let mut forbidden_bytes = [0_u8; 32];
        assert_eq!(fifo_reader.read(&mut forbidden_bytes).unwrap(), 0);
        std::fs::remove_file(fifo_path).unwrap();
        assert!(status.success(), "{}", String::from_utf8_lossy(&errors));
        let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
        for key in [
            "null_open_allowed",
            "asyncio_ready",
            "git_read",
            "ordinary_memfd_allowed",
            "hugetlb_creation_denied",
            "scheduler_change_denied",
            "workspace_write_denied",
            "runtime_write_denied",
            "tmp_write_denied",
            "other_device_write_denied",
            "fifo_write_denied",
            "outside_read_denied",
            "outside_write_denied",
            "egress_denied",
            "unix_socket_denied",
            "ambient_env_absent",
            "home_absent",
        ] {
            assert_eq!(
                result[key], true,
                "Git boundary failed: {key}; owned probe: {result}"
            );
        }
        for namespace in ["net", "pid"] {
            let host = std::fs::read_link(format!("/proc/self/ns/{namespace}")).unwrap();
            assert_ne!(
                result[format!("{namespace}_namespace")].as_str().unwrap(),
                host.to_str().unwrap()
            );
        }
        for target in result["descriptor_targets"].as_array().unwrap() {
            for path in [
                &profile.workspace,
                &profile.package_root,
                &profile.runtime_path,
                &owned.path().to_path_buf(),
            ] {
                assert!(
                    !target.as_str().unwrap().starts_with(path.to_str().unwrap()),
                    "ambient host descriptor leaked"
                );
            }
        }
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside unchanged");
        assert!(!profile.workspace.join("sandbox-forbidden").exists());
        assert_eq!(
            receiver.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        println!("SOU68_SANDBOX_POSITIVE {}", result);
        if verified {
            // This is a syscall/confinement probe of the worker preparation
            // branch; original tools/call bytes are qualified separately.
            println!("SOU146_VERIFIED_PREPARATION_POSITIVE");
        }
    }

    #[cfg(unix)]
    #[test]
    fn accepts_only_exact_library_file_destinations() {
        assert!(valid_library_destination(Path::new(
            "/lib64/ld-linux-x86-64.so.2"
        )));
        assert!(valid_library_destination(Path::new(
            "/usr/lib/x86_64-linux-gnu/libc.so.6"
        )));
        for path in [
            "/",
            "/lib",
            "/lib64",
            "/usr/lib",
            "/usr/library/secret",
            "/home/user/key",
            "/lib/../etc/passwd",
            "lib/libc.so.6",
        ] {
            assert!(!valid_library_destination(Path::new(path)), "{path}");
        }
    }

    // Interpret the emitted classic-BPF instructions against actual seccomp
    // argument offsets. This checks branch targets and masks independently of
    // the kernel-backed real Node positive test below.
    #[cfg(target_os = "linux")]
    #[test]
    fn syscall_filter_preserves_read_opens_and_only_stdio_fionbio() {
        for git_landlock in [false, true] {
            let instructions = filter_instructions(git_landlock).unwrap();
            let evaluate_full =
                |syscall: i64, first: u32, second: u32, third: u32, fourth: u32, address: u64| {
                    let mut data = [0_u8; 64];
                    let architecture = instructions[1].3;
                    for (offset, value) in [
                        (0, syscall as u32),
                        (4, architecture),
                        (16, first),
                        (24, second),
                        (32, third),
                        (40, fourth),
                        (48, address as u32),
                        (52, (address >> 32) as u32),
                    ] {
                        data[offset..offset + 4].copy_from_slice(&value.to_ne_bytes());
                    }
                    let mut accumulator = 0;
                    let mut index = 0;
                    loop {
                        assert!(index < instructions.len(), "filter branch escaped program");
                        let (code, yes, no, value) = instructions[index];
                        let jump = match code {
                            0x20 => {
                                accumulator = u32::from_ne_bytes(
                                    data[value as usize..value as usize + 4].try_into().unwrap(),
                                );
                                None
                            }
                            0x15 => Some(accumulator == value),
                            0x25 => Some(accumulator > value),
                            0x35 => Some(accumulator >= value),
                            0x45 => Some(accumulator & value != 0),
                            0x06 => return value,
                            _ => panic!("unsupported classic-BPF instruction"),
                        };
                        index += 1 + jump.map_or(0, |taken| if taken { yes } else { no }) as usize;
                    }
                };
            let evaluate =
                |syscall, first, second, third| evaluate_full(syscall, first, second, third, 0, 0);
            let allow = 0x7fff_0000;
            let deny = 0x0005_0000 | libc::EACCES as u32;
            assert_eq!(
                evaluate(libc::SYS_sendto, 5, 0, 1),
                if git_landlock { allow } else { deny }
            );
            for address in [1, 1_u64 << 32, u64::MAX] {
                assert_eq!(evaluate_full(libc::SYS_sendto, 5, 0, 1, 0, address), deny);
            }
            assert_eq!(evaluate(libc::SYS_sendmsg, 5, 0, 0), deny);
            for syscall in [libc::SYS_sched_setscheduler, libc::SYS_sched_setattr] {
                for pid in [0, 1, u32::MAX] {
                    assert_eq!(evaluate(syscall, pid, 0, 0), deny);
                }
            }
            for extra in [0, 1, !(libc::MAP_HUGETLB as u32)] {
                assert_eq!(evaluate_full(libc::SYS_mmap, 0, 0, 0, extra, 0), allow);
                assert_eq!(
                    evaluate_full(libc::SYS_mmap, 0, 0, 0, extra | libc::MAP_HUGETLB as u32, 0),
                    deny
                );
            }
            for (syscall, flag, argument) in [
                (libc::SYS_memfd_create, libc::MFD_HUGETLB, 1),
                (libc::SYS_shmget, libc::SHM_HUGETLB as u32, 2),
            ] {
                for extra in [0, 1, !flag] {
                    let evaluate_flags = |flags| {
                        if argument == 1 {
                            evaluate(syscall, 0, flags, 0)
                        } else {
                            evaluate(syscall, 0, 0, flags)
                        }
                    };
                    assert_eq!(evaluate_flags(extra), allow);
                    assert_eq!(evaluate_flags(extra | flag), deny);
                }
            }
            for fd in [0, 1, 2] {
                assert_eq!(
                    evaluate(libc::SYS_ioctl, fd, libc::FIONBIO as u32, 0),
                    allow
                );
                assert_eq!(
                    evaluate(libc::SYS_ioctl, fd, libc::FIONREAD as u32, 0),
                    deny
                );
            }
            for fd in [3, 127, u32::MAX] {
                assert_eq!(
                    evaluate(libc::SYS_ioctl, fd, libc::FIONBIO as u32, 0),
                    if git_landlock { allow } else { deny }
                );
                assert_eq!(
                    evaluate(libc::SYS_ioctl, fd, libc::FIONREAD as u32, 0),
                    deny
                );
                assert_eq!(evaluate(libc::SYS_ioctl, fd, libc::TIOCSTI as u32, 0), deny);
            }
            for flags in [
                libc::O_RDONLY,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            ] {
                assert_eq!(evaluate(libc::SYS_openat, u32::MAX, 0, flags as u32), allow);
            }
            for flags in [
                libc::O_WRONLY,
                libc::O_RDWR,
                libc::O_CREAT,
                libc::O_TRUNC,
                libc::O_APPEND,
                libc::O_TMPFILE,
            ] {
                assert_eq!(
                    evaluate(libc::SYS_openat, u32::MAX, 0, flags as u32),
                    if git_landlock { allow } else { deny }
                );
                #[cfg(target_arch = "x86_64")]
                assert_eq!(
                    evaluate(libc::SYS_open, 0, flags as u32, 0),
                    if git_landlock { allow } else { deny }
                );
            }
            for syscall in [
                libc::SYS_openat2,
                libc::SYS_socket,
                libc::SYS_connect,
                libc::SYS_io_uring_setup,
            ] {
                assert_eq!(evaluate(syscall, 0, 0, 0), deny);
            }
            assert_eq!(evaluate(libc::SYS_read, 0, 0, 0), allow);
            assert_eq!(evaluate(libc::SYS_read | 0x4000_0000, 0, 0, 0), 0x8000_0000);
        }
    }

    /// The writable stage uses a different seccomp branch from read-only.
    /// Exercise that branch against independently calibrated receivers; an
    /// idle upstream server making no network calls is not an egress probe.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires SOU62_SANDBOX_TEST_PROFILE and real Linux namespaces"]
    async fn original_create_stage_confines_active_egress_and_runtime_writes() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::{UnixListener, UnixStream};
        use tokio::io::AsyncReadExt;

        let config = std::env::var_os("SOU62_SANDBOX_TEST_PROFILE").unwrap();
        let mut profile = ProfileConfig::read(&std::fs::read(config).unwrap()).unwrap();
        profile.format = super::super::server_profile::filesystem_create::FORMAT.to_owned();
        let owned = tempfile::tempdir().unwrap();
        let stage = owned.path().join("stage");
        std::fs::create_dir(&stage).unwrap();
        std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700)).unwrap();
        profile.workspace = stage.clone();
        let outside = owned.path().join("outside");
        std::fs::write(&outside, b"unchanged").unwrap();
        let receiver = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = receiver.local_addr().unwrap();
        let mut sender = TcpStream::connect(address).unwrap();
        sender.write_all(b"calibrate").unwrap();
        let (mut received, _) = receiver.accept().unwrap();
        let mut bytes = [0; 9];
        received.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"calibrate");
        drop((sender, received));
        receiver.set_nonblocking(true).unwrap();
        let socket_path = stage.join("egress.sock");
        let unix = UnixListener::bind(&socket_path).unwrap();
        let calibration = UnixStream::connect(&socket_path).unwrap();
        drop(unix.accept().unwrap());
        drop(calibration);
        unix.set_nonblocking(true).unwrap();
        let script = format!(
            r#"
const fs = require('node:fs'), net = require('node:net');
const denied = f => {{ try {{ f(); return false; }} catch {{ return true; }} }};
fs.writeFileSync('/workspace/created.txt', 'private stage');
const result = {{
  stageWrite: fs.readFileSync('/workspace/created.txt','utf8') === 'private stage',
  runtimeWriteDenied: denied(() => fs.writeFileSync('/mcp-runtime/node','bad')),
  packageWriteDenied: denied(() => fs.writeFileSync('/mcp-server/escape','bad')),
  outsideReadDenied: denied(() => fs.readFileSync({outside})),
  outsideWriteDenied: denied(() => fs.writeFileSync({outside},'bad')),
  inheritedSecretAbsent: process.env.SOU83_INHERITED_SECRET === undefined,
  netNamespace: fs.readlinkSync('/proc/self/ns/net'),
  pidNamespace: fs.readlinkSync('/proc/self/ns/pid')
}};
const probe = options => new Promise(resolve => {{
  let socket, done = false;
  const finish = denied => {{ if(done) return; done=true; if(socket) socket.destroy(); resolve(denied); }};
  try {{ socket = net.connect(options); socket.on('connect', () => finish(false));
    socket.on('error', () => finish(true)); socket.setTimeout(500, () => finish(true));
  }} catch {{ finish(true); }}
}});
Promise.all([probe({{host:'127.0.0.1',port:{port}}}),probe({{path:'/workspace/egress.sock'}})])
 .then(([tcp,unix]) => {{ result.tcpDenied=tcp; result.unixDenied=unix; console.log(JSON.stringify(result)); }});
"#,
            outside = serde_json::to_string(&outside).unwrap(),
            port = address.port()
        );
        let mut prepared =
            prepare_linux_command(&profile, &["-e".into(), script], None, true, true, None)
                .unwrap();
        prepared
            .command
            .env("SOU83_INHERITED_SECRET", "must-not-reach-stage");
        let (mut child, mut budget, mut owner, _) = prepared.spawn().await.unwrap();
        drop(child.stdin.take());
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let collected = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let mut output = Vec::new();
            let mut errors = Vec::new();
            let (out, err) = tokio::join!(
                stdout.read_to_end(&mut output),
                stderr.read_to_end(&mut errors)
            );
            out.unwrap();
            err.unwrap();
            // The owner intentionally stays alive until its explicit stop.
            // Do not wait for that process before completing the handshake.
            owner.quiesce().await.unwrap();
            if let Some(budget) = budget.as_mut() {
                budget.finish().await.unwrap();
            }
            owner.finish().await.unwrap();
            (output, errors, child.wait().await.unwrap())
        })
        .await;
        // Always stop the owner and reap the child, including on timeout.
        let budget_cleanup = if let Some(budget) = budget.as_mut() {
            budget.finish().await
        } else {
            Ok(())
        };
        let owner_cleanup = owner.finish().await;
        let child_cleanup = terminate(&mut child).await;
        budget_cleanup.unwrap();
        owner_cleanup.unwrap();
        child_cleanup.unwrap();
        let (output, errors, status) = collected.expect("bounded create-stage probe");
        assert!(status.success(), "{}", String::from_utf8_lossy(&errors));
        let result: serde_json::Value = serde_json::from_slice(&output).unwrap();
        for key in [
            "stageWrite",
            "runtimeWriteDenied",
            "packageWriteDenied",
            "outsideReadDenied",
            "outsideWriteDenied",
            "inheritedSecretAbsent",
            "tcpDenied",
            "unixDenied",
        ] {
            assert_eq!(result[key], true, "create sandbox boundary: {key}");
        }
        for namespace in ["net", "pid"] {
            assert_ne!(
                result[format!("{namespace}Namespace")].as_str().unwrap(),
                std::fs::read_link(format!("/proc/self/ns/{namespace}"))
                    .unwrap()
                    .to_str()
                    .unwrap()
            );
        }
        assert_eq!(std::fs::read(&outside).unwrap(), b"unchanged");
        assert_eq!(
            std::fs::read(stage.join("created.txt")).unwrap(),
            b"private stage"
        );
        assert_eq!(
            receiver.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            unix.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        println!("SOU83_CREATE_SANDBOX_POSITIVE {result}");
    }

    /// An explicitly invoked positive acceptance test. A missing runtime,
    /// bubblewrap feature, or namespace permission is a failure, never a skip.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires SOU62_SANDBOX_TEST_PROFILE and real Linux namespaces"]
    async fn selected_server_sandbox_isolates_real_node() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::time::Duration;
        use tokio::io::AsyncReadExt;

        let config_path = std::env::var_os("SOU62_SANDBOX_TEST_PROFILE")
            .expect("SOU62_SANDBOX_TEST_PROFILE is required for positive acceptance");
        let mut profile = ProfileConfig::read(&std::fs::read(config_path).unwrap()).unwrap();
        let owned = tempfile::tempdir().unwrap();
        let workspace = owned.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(workspace.join("allowed.txt"), b"allowed read").unwrap();
        let outside = owned.path().join("outside-secret.txt");
        std::fs::write(&outside, b"outside unchanged").unwrap();
        let outside_new = owned.path().join("outside-created.txt");
        profile.workspace = workspace.canonicalize().unwrap();
        let receiver = TcpListener::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let address = receiver.local_addr().unwrap();
        // Calibrate the independent egress witness on the host first.
        let calibration = TcpStream::connect(address).unwrap();
        let calibrated = loop {
            match receiver.accept() {
                Ok(pair) => break pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::yield_now()
                }
                Err(error) => panic!("receiver calibration failed: {error}"),
            }
        };
        drop(calibration);
        drop(calibrated);
        let unix_path = workspace.join("egress.sock");
        let unix_receiver = UnixListener::bind(&unix_path).unwrap();
        unix_receiver.set_nonblocking(true).unwrap();
        let unix_calibration = UnixStream::connect(&unix_path).unwrap();
        let unix_calibrated = unix_receiver.accept().unwrap();
        drop(unix_calibration);
        drop(unix_calibrated);
        let fifo_path = workspace.join("egress.fifo");
        let fifo_name = std::ffi::CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        let mut fifo_receiver = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo_path)
            .unwrap();
        let mut fifo_calibration = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo_path)
            .unwrap();
        fifo_calibration.write_all(b"calibrated").unwrap();
        let mut calibrated_bytes = [0_u8; 10];
        fifo_receiver.read_exact(&mut calibrated_bytes).unwrap();
        assert_eq!(&calibrated_bytes, b"calibrated");
        drop(fifo_calibration);
        // Deliberately supply one non-CLOEXEC host descriptor. The child-wide
        // close_range(CLOEXEC) must prevent this independent source from leaking.
        let host_file = File::open(&outside).unwrap();
        let ambient_fd = unsafe { libc::fcntl(host_file.as_raw_fd(), libc::F_DUPFD, 3) };
        assert!(ambient_fd >= 0);
        let _ambient = unsafe { File::from_raw_fd(ambient_fd) };
        let outside_json = serde_json::to_string(&outside).unwrap();
        let outside_new_json = serde_json::to_string(&outside_new).unwrap();
        let script = format!(
            r#"
const fs = require('node:fs');
const net = require('node:net');
const refused = (fn) => {{ try {{ fn(); return false; }} catch {{ return true; }} }};
const result = {{
  allowed: fs.readFileSync('/workspace/allowed.txt', 'utf8') === 'allowed read',
  workspaceWriteDenied: refused(() => fs.writeFileSync('/workspace/new.txt', 'denied')),
  workspaceReplaceDenied: refused(() => fs.writeFileSync('/workspace/allowed.txt', 'denied')),
  fifoWriteDenied: refused(() => {{ const fd=fs.openSync('/workspace/egress.fifo', fs.constants.O_WRONLY|fs.constants.O_NONBLOCK); try {{ fs.writeSync(fd,'host FIFO write'); }} finally {{ fs.closeSync(fd); }} }}),
  outsideReadDenied: refused(() => fs.readFileSync({outside_json})),
  outsideWriteDenied: refused(() => fs.writeFileSync({outside_json}, 'denied')),
  outsideCreateDenied: refused(() => fs.writeFileSync({outside_new_json}, 'denied')),
  hostHomeAbsent: !fs.existsSync('/home') && !fs.existsSync('/root'),
  inheritedSecretAbsent: process.env.SOU62_INHERITED_SECRET === undefined,
  cleanEnv: Object.keys(process.env).sort().join(',') === 'HOME,LANG,PATH,PWD,UV_THREADPOOL_SIZE',
  netNamespace: fs.readlinkSync('/proc/self/ns/net'),
  pidNamespace: fs.readlinkSync('/proc/self/ns/pid'),
  descriptorTargets: fs.readdirSync('/proc/self/fd').flatMap(fd => {{ try {{ return [fs.readlinkSync('/proc/self/fd/'+fd)]; }} catch {{ return []; }} }})
}};
const probe = options => new Promise(resolve => {{
  let done = false, socket;
  const finish = denied => {{ if(done) return; done=true; if(socket) socket.destroy(); resolve(denied); }};
  try {{
    socket = net.connect(options);
    socket.on('connect', () => finish(false));
    socket.on('error', () => finish(true));
    socket.setTimeout(500, () => finish(true));
  }} catch {{ finish(true); }}
}});
Promise.all([probe({{host:'127.0.0.1',port:{port}}}), probe({{path:'/workspace/egress.sock'}})]).then(([tcp,unix]) => {{
  result.egressDenied=tcp;
  result.unixSocketDenied=unix;
  console.log(JSON.stringify(result));
}});
"#,
            port = address.port()
        );
        let mut prepared = prepare_linux_command(
            &profile,
            &["-e".to_owned(), script],
            None,
            false,
            true,
            None,
        )
        .unwrap();
        prepared
            .command
            .env("SOU62_INHERITED_SECRET", "must-not-reach-server");
        let (mut child, mut budget, mut owner, _sandbox_pid) = prepared.spawn().await.unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        drop(child.stdin.take());
        let collected = tokio::time::timeout(Duration::from_secs(10), async {
            let mut output = Vec::new();
            let mut errors = Vec::new();
            let (read_out, read_err) = tokio::join!(
                stdout.read_to_end(&mut output),
                stderr.read_to_end(&mut errors),
            );
            read_out.unwrap();
            read_err.unwrap();
            if let Some(budget) = budget.as_mut() {
                budget.finish().await.unwrap();
            }
            owner.finish().await.unwrap();
            (output, errors, child.wait().await.unwrap())
        })
        .await;
        let budget_cleanup = if let Some(budget) = budget.as_mut() {
            budget.finish().await
        } else {
            Ok(())
        };
        if collected.is_err() {
            terminate(&mut child).await.unwrap();
            panic!("real Node sandbox positive acceptance timed out");
        }
        budget_cleanup.unwrap();
        owner.finish().await.unwrap();
        let (output, errors, status) = collected.unwrap();
        assert!(
            status.success(),
            "sandbox failed: {}",
            String::from_utf8_lossy(&errors)
        );
        let observed: serde_json::Value = serde_json::from_slice(&output).unwrap();
        for key in [
            "allowed",
            "workspaceWriteDenied",
            "workspaceReplaceDenied",
            "fifoWriteDenied",
            "outsideReadDenied",
            "outsideWriteDenied",
            "outsideCreateDenied",
            "hostHomeAbsent",
            "inheritedSecretAbsent",
            "cleanEnv",
            "egressDenied",
            "unixSocketDenied",
        ] {
            assert_eq!(observed[key], true, "sandbox boundary failed: {key}");
        }
        for namespace in ["net", "pid"] {
            let host = std::fs::read_link(format!("/proc/self/ns/{namespace}")).unwrap();
            assert_ne!(
                observed[format!("{namespace}Namespace")].as_str().unwrap(),
                host.to_str().unwrap()
            );
        }
        for target in observed["descriptorTargets"].as_array().unwrap() {
            let target = target.as_str().unwrap();
            for host_path in [
                profile.workspace.as_path(),
                profile.package_root.as_path(),
                profile.runtime_path.as_path(),
                owned.path(),
            ] {
                assert!(
                    !target.starts_with(host_path.to_str().unwrap()),
                    "host descriptor leaked into server"
                );
            }
        }
        assert_eq!(
            std::fs::read(workspace.join("allowed.txt")).unwrap(),
            b"allowed read"
        );
        assert!(!workspace.join("new.txt").exists());
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside unchanged");
        assert!(!outside_new.exists());
        assert_eq!(
            receiver.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            unix_receiver.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let mut unexpected_fifo_bytes = [0_u8; 64];
        assert_eq!(
            fifo_receiver.read(&mut unexpected_fifo_bytes).unwrap(),
            0,
            "host FIFO receiver observed a write"
        );
        println!("SOU62_SANDBOX_POSITIVE profile={SANDBOX_PROFILE} allowed_read=true workspace_write_denied=true outside_read_denied=true outside_write_denied=true egress_witness_calibrated=true egress_denied=true pathname_unix_socket_denied=true fifo_witness_calibrated=true fifo_write_denied=true inherited_env_absent=true host_descriptors_absent=true private_net_pid=true");
    }
}
