// SPDX-License-Identifier: Apache-2.0
//! Private selected-Git launcher, executed only after bubblewrap and seccomp.
//! Git unconditionally opens /dev/null O_RDWR. Landlock permits that device
//! alone while denying all filesystem mutations before original Python starts.

#[cfg(target_os = "linux")]
fn run() -> std::io::Result<()> {
    use std::fs::File;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt};
    use std::os::unix::process::CommandExt;

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
        handled_access_fs: MUTATIONS,
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
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    Err(
        std::process::Command::new("/mcp-server/python/bin/python3.11")
            .args(args)
            .exec(),
    )
}

fn main() {
    #[cfg(target_os = "linux")]
    let error = run().expect_err("exec must replace the launcher or fail");
    #[cfg(not(target_os = "linux"))]
    let error = std::io::Error::other("Git sandbox requires Linux Landlock");
    eprintln!("Git sandbox restriction failed: {error}");
    std::process::exit(1);
}
