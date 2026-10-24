// SPDX-License-Identifier: Apache-2.0
//! Inherited, execute-only Landlock restriction over pinned selected files.
//! No directory-wide allow, project program, shell or host utility is admitted.
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

const EXECUTE: u64 = 1;

#[repr(C)]
struct Ruleset {
    handled_access_fs: u64,
}

#[repr(C)]
struct Rule {
    allowed_access: u64,
    parent_fd: i32,
    padding: u32,
}

pub(super) fn install(command: &mut Command, paths: &[PathBuf]) -> std::io::Result<()> {
    let error = std::io::Error::last_os_error;
    if paths.is_empty() || paths.len() > 128 {
        return Err(std::io::Error::other(
            "bounded selected executable inventory required",
        ));
    }
    let attributes = Ruleset {
        handled_access_fs: EXECUTE,
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
    let mut identities = std::collections::BTreeSet::new();
    for path in paths {
        use std::os::unix::fs::MetadataExt;
        let canonical = path.canonicalize()?;
        let file = File::options()
            .read(true)
            .custom_flags(libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(canonical)?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(std::io::Error::other("selected executable must be a file"));
        }
        if !identities.insert((meta.dev(), meta.ino())) {
            continue;
        }
        let rule = Rule {
            allowed_access: EXECUTE,
            parent_fd: file.as_raw_fd(),
            padding: 0,
        };
        if unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                1,
                &rule as *const Rule,
                0,
            )
        } != 0
        {
            return Err(error());
        }
    }
    // Landlock retains inode references, so path replacement never grants a
    // replacement executable. The ruleset is CLOEXEC and no pin reaches Claude.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}
