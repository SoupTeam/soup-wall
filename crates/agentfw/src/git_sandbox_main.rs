// SPDX-License-Identifier: Apache-2.0
//! Private selected-Git launcher, executed only after bubblewrap and seccomp.
//! Git unconditionally opens /dev/null O_RDWR. Landlock permits that device
//! alone while denying all filesystem mutations before original Python starts.

#[path = "mcp/server_profile/git_local_clone.rs"]
pub mod git_local_clone;
#[path = "mcp/server_profile/git_tracked_symlinks.rs"]
pub mod git_tracked_symlinks;

#[cfg(target_os = "linux")]
fn restrict(execution: bool) -> std::io::Result<()> {
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};

    const WRITE: u64 = 1 << 1;
    // ABI 3: every mutation right, including cross-directory rename and truncation.
    const MUTATIONS: u64 = WRITE | (((1 << 15) - 1) & !((1 << 4) - 1));
    #[repr(C)]
    struct Ruleset {
        handled_access_fs: u64,
    }
    #[repr(C)]
    struct PathRule {
        allowed_access: u64,
        parent_fd: i32,
        padding: u32,
    }
    let error = || std::io::Error::last_os_error();
    // Unsupported kernels fail closed, never silently omit a restriction.
    let abi = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<Ruleset>(),
            0,
            1,
        )
    };
    if abi < 3 {
        return Err(std::io::Error::other(
            "Git sandbox requires Landlock ABI >= 3",
        ));
    }
    let attributes = Ruleset {
        handled_access_fs: MUTATIONS | u64::from(execution),
    };
    let raw = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attributes as *const Ruleset,
            std::mem::size_of::<Ruleset>(),
            0,
        )
    };
    if raw < 0 {
        return Err(error());
    }
    let ruleset = unsafe { File::from_raw_fd(raw as i32) };
    if execution {
        let git = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(git_local_clone::ORIGINAL_GIT)?;
        if !git.metadata()?.is_file() {
            return Err(std::io::Error::other("git_clone_executable_type"));
        }
        let rule = PathRule {
            allowed_access: 1,
            parent_fd: git.as_raw_fd(),
            padding: 0,
        };
        if unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                1,
                &rule as *const PathRule,
                0,
            )
        } != 0
        {
            return Err(error());
        }
    }
    let null = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open("/dev/null")?;
    let metadata = null.metadata()?;
    if !metadata.file_type().is_char_device() || metadata.rdev() != libc::makedev(1, 3) {
        return Err(std::io::Error::other(
            "Git sandbox /dev/null is not the null device",
        ));
    }
    let rule = PathRule {
        allowed_access: WRITE,
        parent_fd: null.as_raw_fd(),
        padding: 0,
    };
    if unsafe {
        libc::syscall(
            libc::SYS_landlock_add_rule,
            ruleset.as_raw_fd(),
            1,
            &rule as *const PathRule,
            0,
        )
    } != 0
    {
        return Err(error());
    }
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(error());
    }
    if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) } != 0 {
        return Err(error());
    }
    // No pre-restriction writable descriptor or mount descriptor is inherited.
    drop(null);
    drop(ruleset);
    Ok(())
}

#[cfg(target_os = "linux")]
fn inspect_git(args: &[&str], limit: usize) -> anyhow::Result<Vec<u8>> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let mut child = Command::new(git_local_clone::ORIGINAL_GIT)
        .args(args)
        .current_dir("/workspace")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut output = Vec::new();
    let result = child
        .stdout
        .take()
        .expect("piped Git output")
        .take(limit as u64 + 1)
        .read_to_end(&mut output);
    if result.is_err() || output.len() > limit {
        let _ = child.kill();
        let _ = child.wait();
        anyhow::bail!("git_clone_inspection_bounds");
    }
    anyhow::ensure!(child.wait()?.success(), "git_clone_index_inspection_failed");
    Ok(output)
}

#[cfg(target_os = "linux")]
fn run() -> anyhow::Result<()> {
    use std::os::unix::process::CommandExt;
    let link_profile = std::env::args_os().next().as_deref()
        == Some(std::ffi::OsStr::new(git_tracked_symlinks::EXECUTABLE));
    let guarded = link_profile
        || std::env::args_os().next().as_deref()
            == Some(std::ffi::OsStr::new(git_local_clone::EXECUTABLE));
    restrict(guarded)?;
    if link_profile {
        git_tracked_symlinks::validate_invocation(std::path::Path::new("/workspace"), inspect_git)?;
    } else if guarded {
        // This is the same mounted workspace the original server sees. Every
        // Git invocation rechecks it, including GitPython's startup probes.
        git_local_clone::validate_repository(std::path::Path::new("/workspace"))?;
        let index = inspect_git(&["ls-files", "--stage", "-z"], 4 * 1024 * 1024)?;
        let mut bytes = 0;
        for oid in git_local_clone::attribute_objects(&index)? {
            let blob = inspect_git(&["cat-file", "blob", &oid], 8192)?;
            bytes += blob.len();
            anyhow::ensure!(bytes <= 262144, "git_clone_attributes_bounds");
            git_local_clone::validate_attributes(&blob)?;
        }
        // Detect sequential substitutions during the index/blob inspection.
        // Landlock exec restrictions and seccomp remain authoritative if an
        // external writer races the subsequent unmodified Git execution.
        git_local_clone::validate_repository(std::path::Path::new("/workspace"))?;
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    Err(std::process::Command::new(if guarded {
        git_local_clone::ORIGINAL_GIT
    } else {
        "/mcp-server/python/bin/python3.11"
    })
    .args(args)
    .exec()
    .into())
}

fn main() {
    #[cfg(target_os = "linux")]
    let error = run().expect_err("exec must replace the launcher or fail");
    #[cfg(not(target_os = "linux"))]
    let error = std::io::Error::other("Git sandbox requires Linux Landlock");
    eprintln!("Git sandbox restriction failed: {error}");
    std::process::exit(1);
}
