// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Metadata-first, handle-relative Windows document reads.
//!
//! This executor deliberately supports only ordinary, exactly named files on
//! local NTFS volumes. Every directory from the drive root and the leaf stay
//! open without write/delete sharing from preparation through the read.
//! Pins require directory traversal and leaf execute permission in addition to
//! attributes: this access participates in Windows sharing checks, unlike an
//! attributes-only open. The executor never executes or maps the file. It does
//! not request FILE_READ_DATA or read contents until `read_bounded` after Allow.
//!
//! Native API contracts: Microsoft Learn's `NtCreateFile`, `OBJECT_ATTRIBUTES`
//! (WDK), `GetFileInformationByHandleEx`, `GetFinalPathNameByHandleW`, and
//! `CancelIoEx`. In particular, cancellation must complete before its buffer
//! and OVERLAPPED storage can be released; the timeout requests cancellation
//! but cannot promise a deadline against a stalled kernel/storage driver.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, ensure, Context};
use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{
    ERROR_HANDLE_EOF, ERROR_IO_PENDING, HANDLE, INVALID_HANDLE_VALUE, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileAttributeTagInfo, FileIdInfo, FileStandardInfo, GetFileInformationByHandleEx, GetFileType,
    GetFinalPathNameByHandleW, GetVolumeInformationByHandleW, QueryDosDeviceW, ReadFile,
    FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_EXECUTE, FILE_ID_INFO,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_READ, FILE_STANDARD_INFO, FILE_TRAVERSE,
    FILE_TYPE_DISK, SYNCHRONIZE,
};
use windows_sys::Win32::System::Threading::CreateEventW;
use windows_sys::Win32::System::IO::{
    CancelIoEx, GetOverlappedResult, GetOverlappedResultEx, OVERLAPPED,
};

const OBJ_DONT_REPARSE: u32 = 0x1000;
const FILE_OPEN: u32 = 1;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_COMPLETE_IF_OPLOCKED: u32 = 0x0000_0100;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_OPEN_NO_RECALL: u32 = 0x0040_0000;
const FILE_FS_DEVICE_INFORMATION_CLASS: u32 = 4;
const FILE_DEVICE_DISK: u32 = 7;
const FILE_REMOTE_DEVICE: u32 = 0x10;
const MAX_PATH_UNITS: usize = 4096;
const READ_TIMEOUT: Duration = Duration::from_secs(5);

// These C layouts are the documented winternl/ntdef/wdm structures. Keeping
// this small declaration avoids exposing the broad WDK API surface elsewhere.
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
#[derive(Default)]
struct IoStatusBlock {
    // The first C member is a union of NTSTATUS and PVOID.
    status_or_pointer: usize,
    information: usize,
}

#[repr(C)]
#[derive(Default)]
struct FsDeviceInformation {
    device_type: u32,
    characteristics: u32,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        handle: *mut HANDLE,
        desired_access: u32,
        attributes: *const ObjectAttributes,
        io_status: *mut IoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        disposition: u32,
        options: u32,
        ea_buffer: *const c_void,
        ea_length: u32,
    ) -> i32;
    fn NtQueryVolumeInformationFile(
        handle: HANDLE,
        io_status: *mut IoStatusBlock,
        information: *mut c_void,
        length: u32,
        class: u32,
    ) -> i32;
}

/// Values included in native admission's immutable resource binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ReadIdentity {
    pub root_volume_serial: u64,
    pub root_file_id: [u8; 16],
    pub leaf_volume_serial: u64,
    pub leaf_file_id: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Identity {
    volume: u64,
    id: [u8; 16],
}

#[derive(Debug)]
struct PinnedDirectory {
    file: File,
    path: String,
    identity: Identity,
}

/// A prepared read owns pin handles without FILE_READ_DATA and no file contents.
/// The ACL must grant directory traversal and leaf execute permission as well
/// as attributes; the executor never performs an execute or mapping operation.
/// The caller must retain it across native admission and call `read_bounded`
/// only after the correlated native Allow. It owns its blocking worker.
#[derive(Debug)]
pub(crate) struct PreparedRead {
    directories: Vec<PinnedDirectory>,
    leaf: File,
    leaf_name: String,
    canonical: String,
    identity: ReadIdentity,
}

struct CancelRead(Arc<AtomicBool>);

impl Drop for CancelRead {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

impl PreparedRead {
    pub(crate) fn prepare(
        workspace: &Path,
        cwd: &Path,
        original: &str,
        expected_canonical: &str,
    ) -> anyhow::Result<Self> {
        let workspace = trusted_absolute(workspace)?;
        let cwd = trusted_absolute(cwd)?;
        ensure!(
            is_within(&cwd, &workspace),
            "Windows read cwd outside workspace"
        );
        let requested = original_target(&cwd, original)?;
        ensure!(
            requested != workspace && is_within(&requested, &workspace),
            "Windows read target outside workspace"
        );
        let expected = trusted_absolute(Path::new(expected_canonical))?;
        ensure!(requested == expected, "Windows read path alias refused");

        let drive = &workspace[..3];
        let file = open_drive(drive)?;
        check_local_ntfs(&file)?;
        let mut directories = vec![pin_directory(file, drive)?];
        for name in workspace[3..].split('\\') {
            let parent = directories.last().expect("drive pinned");
            let path = append_component(&parent.path, name);
            let file = open_child(&parent.file, name, true, false)?;
            directories.push(pin_directory(file, &path)?);
        }
        let root = directories
            .last()
            .expect("workspace pinned")
            .identity
            .clone();
        let relative = &requested[workspace.len() + 1..];
        let mut components = relative.split('\\').peekable();
        while let Some(name) = components.next() {
            let parent = directories.last().expect("workspace pinned");
            if components.peek().is_none() {
                let leaf = open_child(&parent.file, name, false, false)?;
                let leaf_identity = check_regular_file(&leaf)?;
                ensure!(
                    leaf_identity.volume == root.volume,
                    "Windows read volume changed"
                );
                exact_name(&leaf, &requested)?;
                return Ok(Self {
                    directories,
                    leaf,
                    leaf_name: name.to_owned(),
                    canonical: requested,
                    identity: ReadIdentity {
                        root_volume_serial: root.volume,
                        root_file_id: root.id,
                        leaf_volume_serial: leaf_identity.volume,
                        leaf_file_id: leaf_identity.id,
                    },
                });
            }
            let path = append_component(&parent.path, name);
            let file = open_child(&parent.file, name, true, false)?;
            let directory = pin_directory(file, &path)?;
            ensure!(
                directory.identity.volume == root.volume,
                "Windows read volume changed"
            );
            directories.push(directory);
        }
        bail!("Windows read target must be a file")
    }

    pub(crate) fn identity(&self) -> &ReadIdentity {
        &self.identity
    }

    pub(crate) async fn read_bounded(self, max_bytes: usize) -> anyhow::Result<String> {
        let canceled = Arc::new(AtomicBool::new(false));
        // If overlap/cancellation drops this future, the worker owns every
        // kernel buffer and pinned handle until its canceled I/O completes.
        let _cancel_on_drop = CancelRead(Arc::clone(&canceled));
        tokio::task::spawn_blocking(move || self.read_on_worker(max_bytes, &canceled))
            .await
            .context("Windows read worker failed")?
    }

    fn read_on_worker(self, max_bytes: usize, canceled: &AtomicBool) -> anyhow::Result<String> {
        ensure!(
            max_bytes > 0 && max_bytes <= crate::sandbox::MAX_RESOURCE_READ_BYTES,
            "Windows read byte bound invalid"
        );
        // Recheck retained metadata before requesting FILE_READ_DATA. Attribute
        // write handles can change attributes without sharing checks.
        for directory in &self.directories {
            ensure!(!canceled.load(Ordering::Acquire), "Windows read canceled");
            let current = check_directory(&directory.file)?;
            ensure!(
                current == directory.identity,
                "Windows read directory changed"
            );
            exact_name(&directory.file, &directory.path)?;
        }
        self.check_leaf(&self.leaf)?;
        let parent = &self.directories.last().expect("parent pinned").file;
        // This is one relative component, never a reopened absolute path. The
        // retained leaf forbids replacement while this data handle is opened.
        ensure!(!canceled.load(Ordering::Acquire), "Windows read canceled");
        let data = open_child(parent, &self.leaf_name, false, true)?;
        ensure!(!canceled.load(Ordering::Acquire), "Windows read canceled");
        self.check_leaf(&data)?;
        let standard: FILE_STANDARD_INFO = query_info(&data, FileStandardInfo)?;
        ensure!(
            standard.EndOfFile >= 0 && standard.EndOfFile as u64 <= max_bytes as u64,
            "resource file content exceeds maximum allowed size"
        );
        let bytes = read_overlapped(&data, max_bytes, canceled)?;
        self.check_leaf(&data)?;
        self.check_leaf(&self.leaf)?;
        String::from_utf8(bytes).context("resource content is not valid UTF-8")
    }

    fn check_leaf(&self, file: &File) -> anyhow::Result<()> {
        let identity = check_regular_file(file)?;
        ensure!(
            identity.volume == self.identity.leaf_volume_serial
                && identity.id == self.identity.leaf_file_id,
            "Windows read leaf identity changed"
        );
        exact_name(file, &self.canonical)
    }
}

/// Narrow create-only reuse of the accepted read traversal. This retains the
/// original metadata/traverse handles and never requests create, write, delete,
/// data-read, mapping, or execute operations. Read preparation is unchanged.
#[derive(Debug)]
pub(crate) struct CreateParent {
    directories: Vec<PinnedDirectory>,
}

impl CreateParent {
    pub(crate) fn prepare_workspace(workspace: &Path, cwd: &Path) -> anyhow::Result<Self> {
        let workspace = trusted_absolute(workspace)?;
        let cwd = trusted_absolute(cwd)?;
        ensure!(workspace == cwd, "Windows create cwd must equal workspace");
        let drive = &workspace[..3];
        let file = open_drive(drive)?;
        check_local_ntfs(&file)?;
        let mut directories = vec![pin_directory(file, drive)?];
        for name in workspace[3..].split('\\') {
            let parent = directories.last().expect("drive pinned");
            let path = append_component(&parent.path, name);
            let file = open_child(&parent.file, name, true, false)?;
            let pinned = pin_directory(file, &path)?;
            ensure!(
                pinned.identity.volume == directories[0].identity.volume,
                "Windows create workspace volume changed"
            );
            directories.push(pinned);
        }
        let parent = Self { directories };
        parent.check_case_insensitive()?;
        Ok(parent)
    }

    fn check_case_insensitive(&self) -> anyhow::Result<()> {
        // FileCaseSensitiveInfo (23), FILE_CASE_SENSITIVE_INFO { ULONG Flags }.
        // Creating a case alias must remain impossible even if an operator
        // enabled per-directory NTFS case-sensitive behavior. Older kernels
        // without this query are unsupported; there is no path-only fallback.
        let flags: u32 = query_info(self.root(), 23)?;
        ensure!(
            flags == 0,
            "Windows create case-sensitive workspace refused"
        );
        Ok(())
    }

    pub(crate) fn prepare(
        workspace: &Path,
        cwd: &Path,
        original: &str,
        expected_canonical: &str,
    ) -> anyhow::Result<(Self, String)> {
        // Reject raw namespace aliases before the first filesystem operation.
        let workspace_text = trusted_absolute(workspace)?;
        let cwd_text = trusted_absolute(cwd)?;
        ensure!(
            workspace_text == cwd_text,
            "Windows create cwd must equal workspace"
        );
        let requested = original_target(&cwd_text, original)?;
        let expected = trusted_absolute(Path::new(expected_canonical))?;
        ensure!(requested == expected, "Windows create path alias refused");
        let leaf = requested
            .strip_prefix(&format!("{workspace_text}\\"))
            .filter(|leaf| !leaf.contains('\\'))
            .context("Windows create requires one direct workspace child")?;
        ensure!(
            leaf.encode_utf16().count() <= 255,
            "Windows create leaf is oversized"
        );
        validate_components(leaf)?;
        let parent = Self::prepare_workspace(workspace, cwd)?;
        Ok((parent, leaf.to_owned()))
    }

    pub(crate) fn canonical(&self) -> &str {
        &self.directories.last().expect("workspace pinned").path
    }

    pub(crate) fn root(&self) -> &File {
        &self.directories.last().expect("workspace pinned").file
    }

    pub(crate) fn identity(&self) -> (u64, [u8; 16]) {
        let identity = &self.directories.last().expect("workspace pinned").identity;
        (identity.volume, identity.id)
    }

    pub(crate) fn revalidate(&self) -> anyhow::Result<()> {
        self.check_case_insensitive()?;
        for directory in &self.directories {
            ensure!(
                check_directory(&directory.file)? == directory.identity,
                "Windows create parent identity changed"
            );
            exact_name(&directory.file, &directory.path)?;
        }
        Ok(())
    }
}

pub(crate) fn checked_create_stage(file: &File, expected: &str) -> anyhow::Result<(u64, [u8; 16])> {
    let identity = check_regular_file(file)?;
    exact_name(file, expected)?;
    Ok((identity.volume, identity.id))
}

fn trusted_absolute(path: &Path) -> anyhow::Result<String> {
    let text = path.to_str().context("Windows read path is not Unicode")?;
    // canonicalize() produces this prefix. It is admitted only for trusted
    // executor paths and the extractor's expected value, never raw arguments.
    let text = text.strip_prefix("\\\\?\\").unwrap_or(text);
    validate_absolute(text, false)?;
    Ok(text.to_owned())
}

fn original_target(cwd: &str, original: &str) -> anyhow::Result<String> {
    ensure!(
        !original.starts_with(['\\', '/']) && !original.contains('/'),
        "Windows read namespace or separator alias refused"
    );
    if original.as_bytes().get(1) == Some(&b':') {
        validate_absolute(original, true)?;
        return Ok(original.to_owned());
    }
    validate_components(original)?;
    Ok(append_component(cwd, original))
}

fn validate_absolute(text: &str, allow_volume_root: bool) -> anyhow::Result<()> {
    let bytes = text.as_bytes();
    ensure!(
        bytes.len() >= 3
            && bytes[0].is_ascii_uppercase()
            && bytes[1] == b':'
            && bytes[2] == b'\\'
            && !text.contains('/'),
        "Windows read requires an exact drive path"
    );
    if text.len() == 3 {
        ensure!(allow_volume_root, "Windows read volume root refused");
        return Ok(());
    }
    validate_components(&text[3..])
}

fn validate_components(text: &str) -> anyhow::Result<()> {
    ensure!(
        !text.is_empty() && text.encode_utf16().count() <= MAX_PATH_UNITS,
        "Windows read path is empty or oversized"
    );
    for name in text.split('\\') {
        ensure!(
            !name.is_empty()
                && name != "."
                && name != ".."
                && !name.ends_with(['.', ' '])
                && !name
                    .chars()
                    .any(|c| c.is_control() || "<>:\"/|?*~".contains(c)),
            "Windows read path component or alias refused"
        );
        let base = name.split('.').next().unwrap_or("").to_uppercase();
        let numbered_device = base
            .strip_prefix("COM")
            .or_else(|| base.strip_prefix("LPT"));
        ensure!(
            !matches!(
                base.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
            ) && !numbered_device.is_some_and(|n| matches!(
                n,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )),
            "Windows read device name refused"
        );
    }
    Ok(())
}

fn is_within(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|rest| rest.starts_with('\\'))
}

fn append_component(parent: &str, name: &str) -> String {
    if parent.ends_with('\\') {
        format!("{parent}{name}")
    } else {
        format!("{parent}\\{name}")
    }
}

fn open_drive(drive: &str) -> anyhow::Result<File> {
    let mapping = drive_mapping(drive)?;
    let name = volume_root_name(&mapping)?;
    // Open the already validated NT volume directly. Re-resolving the drive
    // letter here could follow a newly shadowed remote DOS-device mapping
    // before a subsequent identity check gets the opportunity to refuse it.
    let file = open_native(None, &name, true, false)?;
    let mut actual = vec![0; MAX_PATH_UNITS + 8];
    // VOLUME_NAME_NT returns the physical object-manager volume name. Compare
    // the opened drive root itself with the pre-open DOS mapping, so a SUBST
    // directory or a changed device mapping cannot stand in for a volume root.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            actual.as_mut_ptr(),
            actual.len() as u32,
            2,
        )
    } as usize;
    let expected: Vec<u16> = name.encode_utf16().collect();
    ensure!(
        length > 0 && length < actual.len() && actual[..length] == expected,
        "Windows read drive mapping alias refused"
    );
    ensure!(
        drive_mapping(drive)? == mapping,
        "Windows read drive mapping changed"
    );
    Ok(file)
}

fn drive_mapping(drive: &str) -> anyhow::Result<String> {
    let name: Vec<u16> = format!("{}\0", &drive[..2]).encode_utf16().collect();
    let mut target = [0; 1024];
    let count = unsafe { QueryDosDeviceW(name.as_ptr(), target.as_mut_ptr(), target.len() as u32) };
    ensure!(count > 0, "Windows read drive mapping unavailable");
    let end = target
        .iter()
        .position(|c| *c == 0)
        .context("Windows read drive mapping invalid")?;
    let mapping =
        String::from_utf16(&target[..end]).context("Windows read drive mapping invalid")?;
    volume_root_name(&mapping)?;
    Ok(mapping)
}

fn volume_root_name(mapping: &str) -> anyhow::Result<String> {
    let number = mapping
        .strip_prefix("\\Device\\HarddiskVolume")
        .unwrap_or("");
    ensure!(
        !number.is_empty() && number.bytes().all(|c| c.is_ascii_digit()),
        "Windows read requires direct local volume mapping"
    );
    Ok(format!("{mapping}\\"))
}

fn open_child(parent: &File, name: &str, directory: bool, data: bool) -> anyhow::Result<File> {
    open_native(Some(parent), name, directory, data)
}

fn open_native(
    parent: Option<&File>,
    name: &str,
    directory: bool,
    data: bool,
) -> anyhow::Result<File> {
    if parent.is_none() {
        ensure!(
            directory && !data,
            "Windows read absolute open must be volume metadata"
        );
        let mapping = name
            .strip_suffix('\\')
            .context("Windows read volume root name invalid")?;
        ensure!(
            volume_root_name(mapping)? == name,
            "Windows read volume root name invalid"
        );
    } else {
        ensure!(
            !name.contains(['\\', '/', ':']),
            "Windows read child must be one component"
        );
        validate_components(name)?;
    }
    let mut encoded: Vec<u16> = name.encode_utf16().collect();
    ensure!(
        !encoded.is_empty() && encoded.len() <= MAX_PATH_UNITS,
        "Windows read child name invalid"
    );
    let mut unicode = UnicodeString {
        length: (encoded.len() * 2) as u16,
        maximum_length: (encoded.len() * 2) as u16,
        buffer: encoded.as_mut_ptr(),
    };
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: parent.map_or(null_mut(), AsRawHandle::as_raw_handle),
        object_name: &mut unicode,
        attributes: OBJ_DONT_REPARSE,
        security_descriptor: null_mut(),
        security_quality_of_service: null_mut(),
    };
    let mut status = IoStatusBlock::default();
    let mut handle = null_mut();
    // Sharing checks ignore attributes-only opens. The 0x20 pin right is
    // FILE_TRAVERSE on directories and FILE_EXECUTE on the regular leaf, so
    // FILE_SHARE_READ excludes write/delete opens throughout admission. This
    // needs the corresponding ACL permission but grants no ReadFile access.
    // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fsa/8c0e3f4f-0729-49f4-a14d-7f7add593819
    let access = FILE_READ_ATTRIBUTES
        | SYNCHRONIZE
        | if data {
            FILE_READ_DATA
        } else if directory {
            FILE_TRAVERSE
        } else {
            FILE_EXECUTE
        };
    // FILE_DIRECTORY_FILE has a narrower documented set of compatible options.
    // Open directory candidates without a type flag to retain no-follow,
    // no-recall, and immediate oplock completion together. pin_directory checks
    // the resulting handle's type before it can become a traversal parent.
    let options = FILE_OPEN_REPARSE_POINT
        | FILE_OPEN_NO_RECALL
        | FILE_COMPLETE_IF_OPLOCKED
        | if data {
            0
        } else {
            FILE_SYNCHRONOUS_IO_NONALERT
        }
        | if directory {
            0
        } else {
            FILE_NON_DIRECTORY_FILE
        };
    let class = if parent.is_none() {
        "volume-metadata"
    } else if directory {
        "directory-metadata"
    } else if data {
        "leaf-data"
    } else {
        "leaf-metadata"
    };
    // No synchronous I/O option on data handles: post-Allow ReadFile uses
    // overlapped I/O. Metadata opens never request FILE_READ_DATA.
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut status,
            null(),
            0,
            FILE_SHARE_READ,
            FILE_OPEN,
            options,
            null(),
            0,
        )
    };
    // Create requests are inherently synchronous, including when the returned
    // handle supports later asynchronous I/O. NtCreateFile's IO_STATUS_BLOCK
    // contains the final result on return. Only final STATUS_SUCCESS is
    // admitted; alternate completions such as OPLOCK_BREAK_IN_PROGRESS refuse.
    // https://learn.microsoft.com/windows-hardware/drivers/kernel/dispatchcreate--dispatchclose--and-dispatchcreateclose-routines
    if result != 0 {
        if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
            // SAFETY: any returned handle must be closed even on refusal.
            drop(unsafe { File::from_raw_handle(handle) });
        }
        bail!(
            "Windows read component open refused: class={class} access={access:#010x} options={options:#010x} attributes={OBJ_DONT_REPARSE:#010x} NTSTATUS={result:#010x}"
        );
    }
    ensure!(
        !handle.is_null() && handle != INVALID_HANDLE_VALUE,
        "Windows read invalid handle"
    );
    // SAFETY: successful NtCreateFile transfers one uniquely owned handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

fn query_info<T: Copy>(file: &File, class: i32) -> anyhow::Result<T> {
    // SAFETY: the callers pair T with its documented FILE_INFO_BY_HANDLE_CLASS.
    // All output structures used here consist entirely of integer fields.
    let mut information: T = unsafe { zeroed() };
    let ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            (&mut information as *mut T).cast(),
            size_of::<T>() as u32,
        )
    };
    ensure!(ok != 0, "Windows read metadata query failed");
    Ok(information)
}

fn check_object(file: &File, directory: bool) -> anyhow::Result<Identity> {
    ensure!(
        unsafe { GetFileType(file.as_raw_handle()) } == FILE_TYPE_DISK,
        "Windows read requires disk file"
    );
    let tag: FILE_ATTRIBUTE_TAG_INFO = query_info(file, FileAttributeTagInfo)?;
    ensure!(
        tag.FileAttributes
            & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_OFFLINE)
            == 0
            && tag.ReparseTag == 0
            && (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) == directory,
        "Windows read reparse or nonregular object refused"
    );
    let standard: FILE_STANDARD_INFO = query_info(file, FileStandardInfo)?;
    ensure!(
        !standard.DeletePending && standard.Directory == directory,
        "Windows read pending or wrong object type"
    );
    if !directory {
        ensure!(
            standard.NumberOfLinks == 1,
            "Windows read hard links refused"
        );
    }
    let id: FILE_ID_INFO = query_info(file, FileIdInfo)?;
    Ok(Identity {
        volume: id.VolumeSerialNumber,
        id: id.FileId.Identifier,
    })
}

fn check_directory(file: &File) -> anyhow::Result<Identity> {
    check_object(file, true)
}

fn check_regular_file(file: &File) -> anyhow::Result<Identity> {
    check_object(file, false)
}

fn pin_directory(file: File, path: &str) -> anyhow::Result<PinnedDirectory> {
    let identity = check_directory(&file)?;
    exact_name(&file, path)?;
    Ok(PinnedDirectory {
        file,
        path: path.to_owned(),
        identity,
    })
}

fn exact_name(file: &File, expected: &str) -> anyhow::Result<()> {
    let expected: Vec<u16> = format!("\\\\?\\{expected}").encode_utf16().collect();
    let mut actual = vec![0; MAX_PATH_UNITS + 8];
    // FILE_NAME_NORMALIZED | VOLUME_NAME_DOS = 0. Exact UTF-16 comparison
    // refuses case folding, short names, and path normalization.
    let length = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle(),
            actual.as_mut_ptr(),
            actual.len() as u32,
            0,
        )
    } as usize;
    ensure!(
        length > 0 && length < actual.len() && actual[..length] == expected,
        "Windows read normalized path alias refused"
    );
    Ok(())
}

fn check_local_ntfs(file: &File) -> anyhow::Result<()> {
    let mut device = FsDeviceInformation::default();
    let mut status = IoStatusBlock::default();
    let result = unsafe {
        NtQueryVolumeInformationFile(
            file.as_raw_handle(),
            &mut status,
            (&mut device as *mut FsDeviceInformation).cast(),
            size_of::<FsDeviceInformation>() as u32,
            FILE_FS_DEVICE_INFORMATION_CLASS,
        )
    };
    ensure!(
        result == 0
            && device.device_type == FILE_DEVICE_DISK
            && device.characteristics & FILE_REMOTE_DEVICE == 0,
        "Windows read requires local disk volume"
    );
    let mut filesystem = [0u16; 32];
    let ok = unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            null_mut(),
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    };
    ensure!(
        ok != 0 && filesystem[..5] == [78, 84, 70, 83, 0],
        "Windows read requires NTFS"
    );
    Ok(())
}

fn read_overlapped(
    file: &File,
    max_bytes: usize,
    canceled: &AtomicBool,
) -> anyhow::Result<Vec<u8>> {
    let mut bytes = vec![0; max_bytes + 1];
    let mut used = 0usize;
    let deadline = Instant::now() + READ_TIMEOUT;
    while used < bytes.len() {
        ensure!(!canceled.load(Ordering::Acquire), "Windows read canceled");
        ensure!(Instant::now() < deadline, "Windows read timeout");
        let mut overlapped: OVERLAPPED = unsafe { zeroed() };
        let event_handle = unsafe { CreateEventW(null(), 1, 0, null()) };
        ensure!(
            !event_handle.is_null(),
            "Windows read event creation failed"
        );
        // SAFETY: this event is unique and stays alive until pending I/O drains.
        let event = unsafe { OwnedHandle::from_raw_handle(event_handle) };
        overlapped.hEvent = event.as_raw_handle();
        // The bounded contract fits in the low 32 bits of a file offset.
        overlapped.Anonymous.Anonymous.Offset = used as u32;
        let mut transferred = 0;
        let ok = unsafe {
            ReadFile(
                file.as_raw_handle(),
                bytes[used..].as_mut_ptr(),
                (bytes.len() - used) as u32,
                &mut transferred,
                &mut overlapped,
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) {
                break;
            }
            ensure!(
                error.raw_os_error() == Some(ERROR_IO_PENDING as i32),
                "Windows read failed"
            );
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let cancel = canceled.load(Ordering::Acquire);
                if cancel || remaining.is_zero() {
                    // Always drain pending I/O before freeing its stack
                    // OVERLAPPED and Vec, including when cancellation races EOF.
                    unsafe {
                        CancelIoEx(file.as_raw_handle(), &overlapped);
                        GetOverlappedResult(file.as_raw_handle(), &overlapped, &mut transferred, 1);
                    }
                    bail!(if cancel {
                        "Windows read canceled"
                    } else {
                        "Windows read timeout"
                    });
                }
                let wait_ms = remaining.as_millis().clamp(1, 50) as u32;
                let ok = unsafe {
                    GetOverlappedResultEx(
                        file.as_raw_handle(),
                        &overlapped,
                        &mut transferred,
                        wait_ms,
                        0,
                    )
                };
                if ok != 0 {
                    break;
                }
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) {
                    transferred = 0;
                    break;
                }
                if error.raw_os_error() == Some(WAIT_TIMEOUT as i32) {
                    continue;
                }
                unsafe {
                    CancelIoEx(file.as_raw_handle(), &overlapped);
                    GetOverlappedResult(file.as_raw_handle(), &overlapped, &mut transferred, 1);
                }
                bail!("Windows read completion failed");
            }
        }
        ensure!(!canceled.load(Ordering::Acquire), "Windows read canceled");
        if transferred == 0 {
            break;
        }
        used += transferred as usize;
        ensure!(
            used <= max_bytes,
            "resource file content exceeds maximum allowed size"
        );
        ensure!(Instant::now() < deadline, "Windows read timeout");
    }
    bytes.truncate(used);
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    // A real pending FSCTL, never a production race hook. The fixture owns its
    // OVERLAPPED storage until cancellation/completion has been drained.
    struct ExclusiveOplock {
        file: File,
        overlapped: Box<OVERLAPPED>,
        _event: OwnedHandle,
        pending: bool,
    }

    impl ExclusiveOplock {
        fn acquire(path: &Path) -> Self {
            let file = fs::OpenOptions::new()
                .read(true)
                .share_mode(FILE_SHARE_READ)
                .custom_flags(0x4000_0000) // FILE_FLAG_OVERLAPPED
                .open(path)
                .unwrap();
            let handle = unsafe { CreateEventW(null(), 1, 0, null()) };
            assert!(!handle.is_null());
            let event = unsafe { OwnedHandle::from_raw_handle(handle) };
            let mut overlapped: Box<OVERLAPPED> = Box::new(unsafe { zeroed() });
            overlapped.hEvent = event.as_raw_handle();
            let mut lock = Self {
                file,
                overlapped,
                _event: event,
                pending: false,
            };
            let mut returned = 0;
            let ok = unsafe {
                DeviceIoControl(
                    lock.file.as_raw_handle(),
                    0x0009_0000, // FSCTL_REQUEST_OPLOCK_LEVEL_1
                    null(),
                    0,
                    null_mut(),
                    0,
                    &mut returned,
                    lock.overlapped.as_mut(),
                )
            };
            let error = io::Error::last_os_error();
            lock.pending = ok == 0 && error.raw_os_error() == Some(ERROR_IO_PENDING as i32);
            assert!(
                lock.pending,
                "exclusive oplock fixture was not granted: {error}"
            );
            lock
        }
    }

    impl Drop for ExclusiveOplock {
        fn drop(&mut self) {
            if self.pending {
                let mut transferred = 0;
                unsafe {
                    CancelIoEx(self.file.as_raw_handle(), self.overlapped.as_ref());
                    GetOverlappedResult(
                        self.file.as_raw_handle(),
                        self.overlapped.as_ref(),
                        &mut transferred,
                        1,
                    );
                }
            }
        }
    }

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        fs::create_dir(root.join("Workspace")).unwrap();
        (temp, root.join("Workspace"))
    }

    fn prepare(root: &Path, path: &str) -> anyhow::Result<PreparedRead> {
        let expected = root.join(path).canonicalize()?;
        PreparedRead::prepare(root, root, path, expected.to_str().unwrap())
    }

    fn junction(path: &Path, target: &Path) {
        fs::create_dir(path).unwrap();
        let target = trusted_absolute(target).unwrap();
        let substitute: Vec<u16> = format!("\\??\\{target}").encode_utf16().collect();
        let print: Vec<u16> = target.encode_utf16().collect();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&0xa000_0003u32.to_le_bytes()); // IO_REPARSE_TAG_MOUNT_POINT
        let data_length = 8 + (substitute.len() + print.len() + 2) * 2;
        buffer.extend_from_slice(&(data_length as u16).to_le_bytes());
        buffer.extend_from_slice(&0u16.to_le_bytes());
        buffer.extend_from_slice(&0u16.to_le_bytes()); // SubstituteNameOffset
        buffer.extend_from_slice(&((substitute.len() * 2) as u16).to_le_bytes());
        buffer.extend_from_slice(&(((substitute.len() + 1) * 2) as u16).to_le_bytes());
        buffer.extend_from_slice(&((print.len() * 2) as u16).to_le_bytes());
        for unit in substitute.into_iter().chain([0]).chain(print).chain([0]) {
            buffer.extend_from_slice(&unit.to_le_bytes());
        }
        let directory = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(7)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .unwrap();
        let mut returned = 0;
        let ok = unsafe {
            DeviceIoControl(
                directory.as_raw_handle(),
                0x0009_00a4,
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                null_mut(),
                0,
                &mut returned,
                null_mut(),
            )
        };
        assert_ne!(
            ok,
            0,
            "junction fixture failed: {}",
            io::Error::last_os_error()
        );
    }

    #[tokio::test]
    async fn reads_exact_regular_utf8_and_binds_identity() {
        let (_temp, root) = fixture();
        fs::create_dir(root.join("Docs")).unwrap();
        fs::write(root.join("Docs\\Readme.txt"), "hello\n世界").unwrap();
        let first = prepare(&root, "Docs\\Readme.txt").unwrap();
        let second = prepare(&root, "Docs\\Readme.txt").unwrap();
        assert_eq!(first.identity(), second.identity());
        assert_eq!(first.read_bounded(64).await.unwrap(), "hello\n世界");
    }

    #[tokio::test]
    async fn bounded_utf8_contract_refuses_binary_and_oversize() {
        let (_temp, root) = fixture();
        fs::write(root.join("Binary.txt"), [0xff]).unwrap();
        fs::write(root.join("Large.txt"), b"12345").unwrap();
        assert!(prepare(&root, "Binary.txt")
            .unwrap()
            .read_bounded(64)
            .await
            .is_err());
        assert!(prepare(&root, "Large.txt")
            .unwrap()
            .read_bounded(4)
            .await
            .is_err());
        assert_eq!(
            prepare(&root, "Large.txt")
                .unwrap()
                .read_bounded(5)
                .await
                .unwrap(),
            "12345"
        );
    }

    #[test]
    fn refuses_original_aliases_before_opening() {
        for path in [
            "",
            ".\\File",
            "..\\File",
            "Dir\\..\\File",
            "Dir\\.\\File",
            "Dir\\\\File",
            "File.",
            "File ",
            "File:secret",
            "C:File",
            "c:\\File",
            "\\File",
            "\\\\host\\share\\File",
            "\\\\?\\C:\\File",
            "Dir/File",
            "NUL.txt",
            "COM1",
            "LPT¹",
            "READM~1.TXT",
        ] {
            assert!(
                original_target("C:\\Workspace", path).is_err(),
                "accepted {path:?}"
            );
        }
    }

    #[test]
    fn volume_root_open_uses_validated_nt_mapping() {
        for mapping in [
            "\\\\host\\share",
            "\\??\\UNC\\host\\share",
            "\\Device\\Mup\\host\\share",
            "\\??\\C:",
            "\\Device\\HarddiskVolume1\\Other",
            "\\Device\\HarddiskVolume",
            "\\Device\\HarddiskVolume1:stream",
            "\\device\\HarddiskVolume1",
        ] {
            assert!(volume_root_name(mapping).is_err(), "accepted {mapping:?}");
        }
        let (_temp, root) = fixture();
        let root = trusted_absolute(&root).unwrap();
        let drive = &root[..3];
        let mapping = drive_mapping(drive).unwrap();
        let name = volume_root_name(&mapping).unwrap();
        assert_eq!(name, format!("{mapping}\\"));
        // The acquisition function takes this fixed NT name with no DOS root
        // handle. It has no drive-letter name left to resolve during the open.
        let direct = open_native(None, &name, true, false).unwrap();
        assert_eq!(
            check_directory(&direct).unwrap(),
            check_directory(&open_drive(drive).unwrap()).unwrap()
        );
    }

    #[test]
    fn refuses_case_aliases_and_hard_links() {
        let (_temp, root) = fixture();
        fs::write(root.join("Readme.txt"), b"inside").unwrap();
        assert!(prepare(&root, "README.TXT").is_err());
        fs::hard_link(root.join("Readme.txt"), root.join("Alias.txt")).unwrap();
        assert!(prepare(&root, "Readme.txt").is_err());
        assert!(prepare(&root, "Alias.txt").is_err());
    }

    #[test]
    fn refuses_nonregular_and_outside_targets() {
        let (_temp, root) = fixture();
        fs::create_dir(root.join("Directory")).unwrap();
        assert!(prepare(&root, "Directory").is_err());
        let outside = root.parent().unwrap().join("Outside.txt");
        fs::write(&outside, b"outside").unwrap();
        let raw_outside = trusted_absolute(&outside).unwrap();
        assert!(
            PreparedRead::prepare(&root, &root, &raw_outside, outside.to_str().unwrap()).is_err()
        );
        assert!(
            PreparedRead::prepare(&root, &root, "..\\Outside.txt", outside.to_str().unwrap())
                .is_err()
        );
    }

    #[tokio::test]
    async fn metadata_pin_prevents_root_ancestor_leaf_swap_and_writer() {
        let (_temp, root) = fixture();
        fs::create_dir(root.join("Docs")).unwrap();
        fs::write(root.join("Docs\\Readme.txt"), b"inside").unwrap();
        let prepared = prepare(&root, "Docs\\Readme.txt").unwrap();
        let outer = root.parent().unwrap();
        assert!(fs::rename(outer, outer.with_file_name("MovedFixture")).is_err());
        assert!(fs::rename(&root, root.with_file_name("MovedWorkspace")).is_err());
        assert!(fs::rename(root.join("Docs"), root.join("MovedDocs")).is_err());
        assert!(fs::rename(root.join("Docs\\Readme.txt"), root.join("Moved.txt")).is_err());
        assert!(fs::OpenOptions::new()
            .write(true)
            .open(root.join("Docs\\Readme.txt"))
            .is_err());
        // The pin's FILE_EXECUTE right permits sharing enforcement, but no
        // FILE_READ_DATA is granted. The executor never maps or executes the
        // file, and an actual ReadFile through this handle must be denied.
        let mut byte = [0];
        let mut transferred = 0;
        let ok = unsafe {
            ReadFile(
                prepared.leaf.as_raw_handle(),
                byte.as_mut_ptr(),
                1,
                &mut transferred,
                null_mut(),
            )
        };
        assert_eq!(ok, 0);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(5));
        assert_eq!(prepared.read_bounded(64).await.unwrap(), "inside");
    }

    #[test]
    fn standard_user_junction_is_refused_as_root_and_ancestor() {
        let (_temp, root) = fixture();
        let outside = root.parent().unwrap().join("Outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("Secret.txt"), b"outside").unwrap();
        let link = root.join("Junction");
        junction(&link, &outside);
        let expected = link.join("Secret.txt");
        assert!(PreparedRead::prepare(
            &root,
            &root,
            "Junction\\Secret.txt",
            expected.to_str().unwrap()
        )
        .is_err());
        assert!(
            PreparedRead::prepare(&link, &link, "Secret.txt", expected.to_str().unwrap()).is_err()
        );
    }

    #[test]
    fn leaf_replaced_before_prepare_is_bound_to_new_identity() {
        let (_temp, root) = fixture();
        let leaf = root.join("Readme.txt");
        fs::write(&leaf, b"first").unwrap();
        let identity = prepare(&root, "Readme.txt").unwrap().identity().clone();
        fs::rename(&leaf, root.join("Retained.txt")).unwrap();
        fs::write(&leaf, b"replacement").unwrap();
        assert_ne!(prepare(&root, "Readme.txt").unwrap().identity(), &identity);
    }

    #[test]
    fn canceled_worker_refuses_before_acquiring_data_access() {
        let (_temp, root) = fixture();
        fs::write(root.join("Readme.txt"), b"inside").unwrap();
        let prepared = prepare(&root, "Readme.txt").unwrap();
        let canceled = AtomicBool::new(true);
        assert!(prepared
            .read_on_worker(64, &canceled)
            .unwrap_err()
            .to_string()
            .contains("canceled"));
        let token = Arc::new(AtomicBool::new(false));
        drop(CancelRead(Arc::clone(&token)));
        assert!(token.load(Ordering::Acquire));
    }

    #[test]
    fn refuses_existing_write_or_delete_handles() {
        let (_temp, root) = fixture();
        let path = root.join("Readme.txt");
        fs::write(&path, b"inside").unwrap();
        let writer = fs::OpenOptions::new()
            .write(true)
            .share_mode(7)
            .open(&path)
            .unwrap();
        assert!(prepare(&root, "Readme.txt").is_err());
        drop(writer);
        let deleter = fs::OpenOptions::new()
            .access_mode(0x0001_0000)
            .share_mode(7)
            .open(&path)
            .unwrap();
        assert!(prepare(&root, "Readme.txt").is_err());
        drop(deleter);
        assert!(prepare(&root, "Readme.txt").is_ok());
    }

    #[test]
    fn oplock_does_not_stall_metadata_preparation_or_data_open() {
        let (_temp, root) = fixture();
        let path = root.join("Readme.txt");
        fs::write(&path, b"inside").unwrap();
        let canonical = path.canonicalize().unwrap().to_str().unwrap().to_owned();
        let lock = ExclusiveOplock::acquire(&path);
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker_root = root.clone();
        let worker = std::thread::spawn(move || {
            sender
                .send(PreparedRead::prepare(
                    &worker_root,
                    &worker_root,
                    "Readme.txt",
                    &canonical,
                ))
                .unwrap();
        });
        // A share-counted leaf pin includes FILE_EXECUTE, so an existing
        // exclusive oplock must refuse promptly before its owner acknowledges.
        let prepared = receiver.recv_timeout(Duration::from_secs(2));
        if prepared.is_err() {
            drop(lock);
            worker.join().unwrap();
            panic!("metadata preparation stalled behind an exclusive oplock");
        }
        worker.join().unwrap();
        let error = prepared.unwrap().unwrap_err().to_string();
        assert!(
            error.contains("class=leaf-metadata") && error.contains("NTSTATUS=0x00000108"),
            "{error}"
        );
        drop(lock);

        // Independently exercise the same production data-open helper with a
        // retained parent chain, while this target has no admitted leaf pin.
        // A real admitted pin would already have refused the exclusive oplock.
        fs::write(root.join("Anchor.txt"), b"anchor").unwrap();
        let pinned_parent = prepare(&root, "Anchor.txt").unwrap();
        let parent = pinned_parent
            .directories
            .last()
            .unwrap()
            .file
            .try_clone()
            .unwrap();
        let lock = ExclusiveOplock::acquire(&path);
        let (sender, receiver) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            sender
                .send(open_child(&parent, "Readme.txt", false, true))
                .unwrap();
        });
        let result = receiver.recv_timeout(Duration::from_secs(2));
        if result.is_err() {
            drop(lock);
            worker.join().unwrap();
            panic!("data open stalled instead of refusing an unacknowledged oplock break");
        }
        worker.join().unwrap();
        let error = result.unwrap().unwrap_err().to_string();
        assert!(
            error.contains("class=leaf-data") && error.contains("NTSTATUS=0x00000108"),
            "{error}"
        );
        drop(lock);
    }

    #[test]
    #[ignore = "requires Windows Developer Mode or SeCreateSymbolicLinkPrivilege; junction coverage is mandatory"]
    fn refuses_symlink_when_creation_is_available() {
        let (_temp, root) = fixture();
        fs::write(root.join("Readme.txt"), b"inside").unwrap();
        std::os::windows::fs::symlink_file(root.join("Readme.txt"), root.join("Link.txt")).unwrap();
        assert!(prepare(&root, "Link.txt").is_err());
    }
}
