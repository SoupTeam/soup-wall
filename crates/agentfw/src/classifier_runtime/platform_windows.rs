// SPDX-License-Identifier: Apache-2.0
//! Native Windows platform layer for the classifier package and its worker (SOU-81).
//!
//! Scope: a directly mapped local NTFS volume, x86_64. Every object the package
//! store owns is created with a protected owner-only DACL and is re-verified
//! through an open handle (owner, protected DACL with only the current user and
//! SYSTEM, no reparse point, no extra hard link, not pending deletion) before it
//! is trusted. Paths are never trusted by name alone: ancestors are walked with
//! the pinned, reparse-refusing traversal already used by the audit store.
//! Nothing here emulates Unix permission bits.

use std::fs::File;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::process::Child;
use std::ptr::null_mut;
use std::time::{Duration, Instant};

use anyhow::{ensure, Context, Result};
use windows_sys::Win32::Foundation::{
    ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FileIdInfo, FileStandardInfo, GetFileInformationByHandleEx,
    CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_STANDARD_INFO, FILE_TRAVERSE, OPEN_EXISTING, READ_CONTROL,
};

use crate::private_file_windows::{verify_retention_security, PrivateAcl};
use crate::windows_read::CreateParent;

fn wide(path: &Path) -> Result<Vec<u16>> {
    let units: Vec<u16> = path.as_os_str().encode_wide().collect();
    ensure!(!units.contains(&0), "classifier path contains NUL");
    Ok(units.into_iter().chain(Some(0)).collect())
}

/// Plain `C:\...` form of a canonicalized path. `canonicalize` yields the
/// verbatim `\\?\C:\...` spelling, which some programs (Python's prefix
/// detection among them) treat differently from the ordinary path. Verbatim UNC
/// and device paths are left untouched and are refused by the traversal check.
pub fn plain_path(path: PathBuf) -> PathBuf {
    match path.to_str().and_then(|text| text.strip_prefix("\\\\?\\")) {
        Some(rest)
            if rest.len() >= 3
                && rest.as_bytes()[0].is_ascii_alphabetic()
                && rest.as_bytes()[1] == b':'
                && rest.as_bytes()[2] == b'\\' =>
        {
            PathBuf::from(rest)
        }
        _ => path,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Identity {
    volume: u64,
    id: [u8; 16],
}

/// Verify the object behind `file` and return its stable identity.
fn identity(file: &File, directory: bool) -> Result<Identity> {
    let handle = file.as_raw_handle() as HANDLE;
    verify_retention_security(handle, directory)
        .context("not private to the current user (owner or ACL check failed)")?;
    let mut id = FILE_ID_INFO::default();
    let mut standard = FILE_STANDARD_INFO::default();
    ensure!(
        // SAFETY: `handle` is open and `id` is a writable FILE_ID_INFO.
        unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileIdInfo,
                (&mut id as *mut FILE_ID_INFO).cast(),
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
        } != 0,
        "file identity is unavailable"
    );
    ensure!(
        // SAFETY: `handle` is open and `standard` is a writable FILE_STANDARD_INFO.
        unsafe {
            GetFileInformationByHandleEx(
                handle,
                FileStandardInfo,
                (&mut standard as *mut FILE_STANDARD_INFO).cast(),
                std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
            )
        } != 0,
        "file metadata is unavailable"
    );
    ensure!(
        directory || standard.NumberOfLinks == 1,
        "file has an additional hard link"
    );
    ensure!(!standard.DeletePending, "object is pending deletion");
    Ok(Identity {
        volume: id.VolumeSerialNumber,
        id: id.FileId.Identifier,
    })
}

fn open_directory(path: &Path) -> Result<File> {
    let name = wide(path)?;
    // SAFETY: `name` is NUL terminated; no data access is requested and a final
    // reparse point is opened itself (then refused by `identity`).
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_TRAVERSE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("cannot open {}", path.display()));
    }
    // SAFETY: CreateFileW returned a new owned handle.
    Ok(unsafe { File::from_raw_handle(raw) })
}

/// Reparse-refusing walk of every ancestor of `path` (which must exist), on a
/// local NTFS volume, followed by a re-check that the pinned identities held.
pub fn check_ancestors(path: &Path) -> Result<()> {
    let walk = CreateParent::prepare_connection(path, path)
        .with_context(|| format!("{} is not on a plain local NTFS path", path.display()))?;
    walk.revalidate()
        .with_context(|| format!("{} changed during verification", path.display()))
}

/// A private directory: owner-only protected DACL, no reparse point.
pub fn verify_dir(path: &Path) -> Result<()> {
    let handle = open_directory(path)?;
    identity(&handle, true)
        .with_context(|| format!("{} must be a private directory", path.display()))?;
    Ok(())
}

/// Create one private directory (its parent must exist). Never adopts an
/// existing object: an existing path is verified by `verify_dir` instead.
pub fn create_dir(path: &Path) -> Result<()> {
    let acl = PrivateAcl::for_directory()?;
    let attributes = acl.attributes();
    let name = wide(path)?;
    // SAFETY: `name` is NUL terminated and `attributes` outlives the call.
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("cannot create {}", path.display()));
    }
    verify_dir(path)
}

/// Create a new private file (never opens or truncates an existing one), write
/// `bytes`, flush to disk, and confirm the kernel-assigned security.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let acl = PrivateAcl::new()?;
    let attributes = acl.attributes();
    let name = wide(path)?;
    // SAFETY: all pointers outlive the call; CREATE_NEW cannot follow or replace.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE | READ_CONTROL,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        let error = std::io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(code)
            if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32)
        {
            anyhow::bail!("{} already exists", path.display());
        }
        return Err(error).with_context(|| format!("cannot create {}", path.display()));
    }
    // SAFETY: CreateFileW returned a new owned handle.
    let mut file = unsafe { File::from_raw_handle(raw) };
    identity(&file, false)
        .with_context(|| format!("{} did not receive a private ACL", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Bounded read of a private regular file through one pinned handle.
/// `replaceable` lets an atomic pointer replacement proceed while a reader holds
/// the file; package payload files are not replaceable while being read.
pub fn read_private(path: &Path, limit: usize, replaceable: bool) -> Result<Vec<u8>> {
    let name = wide(path)?;
    let share = if replaceable {
        FILE_SHARE_READ | FILE_SHARE_DELETE
    } else {
        FILE_SHARE_READ
    };
    // SAFETY: `name` is NUL terminated; a final reparse point is opened itself
    // and then refused by `identity`.
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | READ_CONTROL,
            share,
            null_mut(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("missing {}", path.display()));
    }
    // SAFETY: CreateFileW returned a new owned handle.
    let mut file = unsafe { File::from_raw_handle(raw) };
    let before = identity(&file, false)
        .with_context(|| format!("{} is not a private regular file", path.display()))?;
    let mut bytes = Vec::new();
    (&mut file).take(limit as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "{} exceeds the size limit",
        path.display()
    );
    ensure!(
        identity(&file, false)? == before,
        "{} changed while it was read",
        path.display()
    );
    Ok(bytes)
}

/// Write a temporary private file next to `path`, then replace `path` with it.
/// A reader sees either the old complete file or the new complete file.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension(format!("tmp-{}", crate::token::generate()));
    write_private(&tmp, bytes)?;
    if let Err(error) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error).with_context(|| format!("cannot replace {}", path.display()));
    }
    Ok(())
}

/// The interpreter must be an ordinary file, not an app-execution alias or other
/// reparse point whose bytes are not the program that will run.
pub fn ensure_plain_file(path: &Path) -> Result<()> {
    use std::os::windows::fs::MetadataExt;
    const REPARSE_POINT: u32 = 0x400;
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect {}", path.display()))?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & REPARSE_POINT == 0,
        "{} is not a plain file (links, app-execution aliases and reparse points are refused)",
        path.display()
    );
    Ok(())
}

// ------------------------------------------------------------ process tree

/// A Job Object that owns a worker process and everything it starts. Launching
/// uses a suspended process so nothing runs, and no descendant can exist, before
/// the process is inside the job.
pub struct JobTree {
    job: OwnedHandle,
}

impl JobTree {
    pub fn new() -> Result<Self> {
        use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
        use windows_sys::Win32::System::JobObjects::*;
        // SAFETY: no name and no inheritable security attributes.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        ensure!(!raw.is_null(), "cannot create the worker job object");
        // SAFETY: a successful CreateJobObjectW transfers an owned kernel handle.
        let job = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
        let limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                ..Default::default()
            },
            ..Default::default()
        };
        // SAFETY: `job` is owned and `limits` is the complete initialized type.
        ensure!(
            unsafe { SetHandleInformation(job.as_raw_handle().cast(), HANDLE_FLAG_INHERIT, 0) }
                != 0
                && unsafe {
                    SetInformationJobObject(
                        job.as_raw_handle().cast(),
                        JobObjectExtendedLimitInformation,
                        (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                        std::mem::size_of_val(&limits) as u32,
                    )
                } != 0,
            "cannot configure the worker job object"
        );
        Ok(Self { job })
    }

    /// Put the suspended `child` into the job and resume its only thread.
    pub fn assign_and_resume(&self, child: &Child) -> Result<()> {
        use windows_sys::Win32::Foundation::{GetLastError, ERROR_NO_MORE_FILES};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
        use windows_sys::Win32::System::Threading::*;
        let process = child.as_raw_handle();
        let pid = child.id();
        // SAFETY: both handles are valid; the primary thread is still suspended.
        ensure!(
            unsafe { AssignProcessToJobObject(self.job.as_raw_handle().cast(), process.cast()) }
                != 0,
            "cannot assign the worker to its job"
        );
        // SAFETY: a read-only, non-inheritable system thread snapshot.
        let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        ensure!(
            raw != INVALID_HANDLE_VALUE,
            "cannot snapshot the worker threads"
        );
        // SAFETY: a successful snapshot is an owned kernel handle.
        let snapshot = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..Default::default()
        };
        let mut found = None;
        let mut seen = 0usize;
        let deadline = Instant::now() + Duration::from_millis(500);
        // SAFETY: `snapshot` is owned and `entry.dwSize` is initialized.
        let mut next = unsafe { Thread32First(snapshot.as_raw_handle().cast(), &mut entry) };
        while next != 0 {
            seen += 1;
            ensure!(
                seen <= 65_536 && Instant::now() < deadline,
                "worker thread lookup exceeded its bound"
            );
            if entry.th32OwnerProcessID == pid && found.replace(entry.th32ThreadID).is_some() {
                anyhow::bail!("worker has more than one thread before it started");
            }
            // SAFETY: as above.
            next = unsafe { Thread32Next(snapshot.as_raw_handle().cast(), &mut entry) };
        }
        // SAFETY: reads the calling thread's last error only.
        ensure!(
            unsafe { GetLastError() } == ERROR_NO_MORE_FILES,
            "worker thread snapshot failed"
        );
        let id = found.context("worker primary thread was not found")?;
        // SAFETY: plain OpenThread with minimal rights.
        let raw = unsafe {
            OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                0,
                id,
            )
        };
        ensure!(!raw.is_null(), "cannot open the worker primary thread");
        // SAFETY: OpenThread succeeded and returned an owned handle.
        let thread = unsafe { OwnedHandle::from_raw_handle(raw.cast()) };
        // SAFETY: `thread` is owned and valid.
        ensure!(
            unsafe { GetProcessIdOfThread(thread.as_raw_handle().cast()) } == pid,
            "worker thread belongs to another process"
        );
        // Exactly one suspension belongs to this launch.
        // SAFETY: `thread` is owned and valid.
        ensure!(
            unsafe { ResumeThread(thread.as_raw_handle().cast()) } == 1,
            "worker thread was not in the expected suspended state"
        );
        Ok(())
    }

    /// Terminate every process in the job. True when the request was accepted.
    pub fn terminate(&self) -> bool {
        // SAFETY: only this unnamed owned job can be affected by the handle.
        unsafe {
            windows_sys::Win32::System::JobObjects::TerminateJobObject(
                self.job.as_raw_handle().cast(),
                1,
            ) != 0
        }
    }

    /// Wait (bounded) until the job holds no live process.
    pub fn wait_empty(&self, limit: Duration) -> bool {
        use windows_sys::Win32::System::JobObjects::*;
        let deadline = Instant::now() + limit;
        loop {
            let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            // SAFETY: `job` is owned and `info` is the matching writable type.
            let ok = unsafe {
                QueryInformationJobObject(
                    self.job.as_raw_handle().cast(),
                    JobObjectBasicAccountingInformation,
                    (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                    std::mem::size_of_val(&info) as u32,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return false;
            }
            if info.ActiveProcesses == 0 {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
