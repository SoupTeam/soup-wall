// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! One exact, new root child on local NTFS, using retained native handles.
//!
//! Preparation is metadata-only. After the caller's correlated native Allow,
//! staging creates one exclusive, unpredictable FILE_DELETE_ON_CLOSE file,
//! writes complete bounded UTF-8 bytes, and flushes them. Publication is a
//! separate capability: a detached staging worker cannot publish anything.
//!
//! NtSetInformationFile(FileLinkInformation), ReplaceIfExists = FALSE and a
//! single same-parent name, atomically publishes the complete file without
//! replacing a racing creator. The owned source handle remains delete-on-close
//! throughout: closing it removes only its original temporary link. A killed
//! process therefore loses its temporary link but retains any published link.
//! We never clear deletion disposition or unlink a pathname. Holding every
//! parent pin prevents an ancestor or the workspace from being relocated.
//!
//! Windows does not provide the Linux executor's directory-fsync guarantee.
//! Successful file flushing is reported separately from namespace durability;
//! abrupt power loss is not claimed durable. Cancellation cannot undo a
//! successful publication, and a killed collector's publication-attempt marker
//! must remain indeterminate until an independent filesystem witness resolves it.
//!
//! Native contracts:
//! https://learn.microsoft.com/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_link_information
//! https://learn.microsoft.com/openspecs/windows_protocols/ms-fsa/d142c93a-72bc-4b05-9d96-8e00371c3308

use std::ffi::c_void;
use std::fmt;
use std::fs::File;
use std::io::Write;
use std::mem::{offset_of, size_of};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::ptr::{null, null_mut};

use serde::{Deserialize, Serialize};
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_READ_ATTRIBUTES, FILE_WRITE_DATA, READ_CONTROL, SYNCHRONIZE, WRITE_DAC,
};

use crate::mcp::create_file::{CreateFileCommit, CreateFileError, MAX_CREATE_BYTES};
use crate::private_file_windows::PrivateAcl;
use crate::windows_read::{checked_create_stage, CreateParent};

const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const OBJ_DONT_REPARSE: u32 = 0x1000;
const DELETE: u32 = 0x0001_0000;
const FILE_OPEN: u32 = 1;
const FILE_CREATE: u32 = 2;
const FILE_WRITE_THROUGH: u32 = 0x0000_0002;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x0000_0020;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_COMPLETE_IF_OPLOCKED: u32 = 0x0000_0100;
const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_OPEN_NO_RECALL: u32 = 0x0040_0000;
const FILE_LINK_INFORMATION_CLASS: u32 = 11;
const STATUS_OBJECT_NAME_NOT_FOUND: i32 = 0xc000_0034u32 as i32;
const STATUS_OBJECT_NAME_COLLISION: i32 = 0xc000_0035u32 as i32;

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
    status_or_pointer: usize,
    information: usize,
}

// The post-RS5 union is four bytes. Its zero value is also the older BOOLEAN
// ReplaceIfExists FALSE, with all padding initialized. Native pointer alignment
// and offset_of make the layout correct on both 32-bit and 64-bit Windows.
#[repr(C)]
struct LinkInformation {
    flags: u32,
    root_directory: HANDLE,
    file_name_length: u32,
    file_name: [u16; 1],
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
    fn NtSetInformationFile(
        handle: HANDLE,
        io_status: *mut IoStatusBlock,
        information: *const c_void,
        length: u32,
        class: u32,
    ) -> i32;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CreateIdentity {
    pub root_volume_serial: u64,
    pub root_file_id: [u8; 16],
}

pub(crate) struct PreparedCreate {
    parent: CreateParent,
    leaf: String,
    content: Vec<u8>,
    identity: CreateIdentity,
}

#[must_use = "drop to clean only the owned temporary link, or publish after the execution gate"]
pub(crate) struct StagedCreate {
    prepared: PreparedCreate,
    file: Option<File>,
    stage_name: String,
    staged_bytes: usize,
    committed: bool,
    stage_identity: Option<(u64, [u8; 16])>,
    cleanup_verified: Option<bool>,
}

impl fmt::Debug for PreparedCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedCreate").finish_non_exhaustive()
    }
}

impl fmt::Debug for StagedCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StagedCreate").finish_non_exhaustive()
    }
}

#[derive(Clone, Copy)]
enum Fault {
    None,
    #[cfg(test)]
    PartialWrite(usize),
    #[cfg(test)]
    ProbePrivacy,
    #[cfg(test)]
    Flush,
    #[cfg(test)]
    BeforePublish,
    #[cfg(test)]
    AfterPublish,
}

fn error(code: &'static str) -> CreateFileError {
    CreateFileError {
        code,
        committed: false,
        staged_bytes: 0,
        committed_bytes: 0,
        errno: None,
    }
}

fn nt_error(code: &'static str, status: i32) -> CreateFileError {
    let mut result = error(code);
    // Native NTSTATUS, not an invented Win32 errno. The privacy-safe display
    // omits this field; diagnostics may retain its exact signed integer value.
    result.errno = Some(status);
    result
}

impl PreparedCreate {
    pub(crate) fn prepare(
        workspace: &Path,
        cwd: &Path,
        original: &str,
        expected_canonical: &str,
        content: &str,
    ) -> Result<Self, CreateFileError> {
        if content.len() > MAX_CREATE_BYTES {
            return Err(error("content_too_large"));
        }
        let (parent, leaf) = CreateParent::prepare(workspace, cwd, original, expected_canonical)
            .map_err(|_| error("windows_create_path_or_parent_refused"))?;
        let (root_volume_serial, root_file_id) = parent.identity();
        let prepared = Self {
            parent,
            leaf,
            content: content.as_bytes().to_vec(),
            identity: CreateIdentity {
                root_volume_serial,
                root_file_id,
            },
        };
        prepared.require_absent(&prepared.leaf)?;
        Ok(prepared)
    }

    pub(crate) fn identity(&self) -> &CreateIdentity {
        &self.identity
    }

    pub(crate) fn stage(self) -> Result<StagedCreate, CreateFileError> {
        self.stage_with_fault(Fault::None)
    }

    fn revalidate(&self) -> Result<(), CreateFileError> {
        self.parent
            .revalidate()
            .map_err(|_| error("windows_create_parent_changed"))
    }

    fn require_absent(&self, leaf: &str) -> Result<(), CreateFileError> {
        // FILE_OPEN + attributes only has no filesystem effects and no data
        // access. Case-insensitive lookup refuses an existing case alias too;
        // the created/published spelling itself remains exact and one component.
        match open_relative(self.parent.root(), leaf, false) {
            Ok(file) => {
                drop(file);
                Err(error("target_exists"))
            }
            Err(status) if status == STATUS_OBJECT_NAME_NOT_FOUND => Ok(()),
            Err(status) => Err(nt_error("windows_create_target_lookup_refused", status)),
        }
    }

    fn stage_with_fault(self, fault: Fault) -> Result<StagedCreate, CreateFileError> {
        self.revalidate()?;
        self.require_absent(&self.leaf)?;
        let stage_acl =
            PrivateAcl::empty().map_err(|_| error("windows_create_stage_acl_failed"))?;
        let final_acl = PrivateAcl::new().map_err(|_| error("windows_create_final_acl_failed"))?;
        let mut created = None;
        // A collision is never opened or removed. Retry with a fresh random
        // 128-bit name, then fail closed rather than touching foreign objects.
        for _ in 0..8 {
            let name = format!(".soup-wall-create-{:032x}.tmp", rand::random::<u128>());
            match open_relative_with_descriptor(
                self.parent.root(),
                &name,
                true,
                stage_acl.descriptor(),
            ) {
                Ok(file) => {
                    created = Some((name, file));
                    break;
                }
                Err(status) if status == STATUS_OBJECT_NAME_COLLISION => continue,
                Err(status) => return Err(nt_error("windows_create_stage_open_failed", status)),
            }
        }
        let (stage_name, file) = created.ok_or_else(|| error("windows_create_stage_collision"))?;
        let mut staged = StagedCreate {
            prepared: self,
            file: Some(file),
            stage_name,
            staged_bytes: 0,
            committed: false,
            stage_identity: None,
            cleanup_verified: None,
        };
        eprintln!(
            "{}",
            serde_json::json!({"event":"mcp_windows_create_stage_created",
                "stage_created":true,"delete_on_close":true})
        );
        let path = format!(
            "{}\\{}",
            staged.prepared.parent.canonical(),
            staged.stage_name
        );
        let identity = checked_create_stage(staged.file(), &path, 0)
            .map_err(|_| staged.effects(error("windows_create_stage_identity_refused")))?;
        if identity.0 != staged.prepared.identity.root_volume_serial {
            return Err(staged.effects(error("windows_create_stage_volume_changed")));
        }
        staged.stage_identity = Some(identity);
        PrivateAcl::verify_empty(staged.file().as_raw_handle()).map_err(|cause| {
            let mut result = error("windows_create_stage_acl_unverified");
            result.errno = cause.raw_os_error();
            staged.effects(result)
        })?;
        eprintln!(
            "{}",
            serde_json::json!({
                "event":"mcp_windows_create_stage_security",
                "stage_dacl_empty":true,"stage_dacl_protected":true,
                "stage_owner_matches":true,"staged_bytes":0
            })
        );
        while staged.staged_bytes < staged.prepared.content.len() {
            #[cfg(test)]
            if matches!(fault, Fault::ProbePrivacy) && staged.staged_bytes >= 3 {
                tests::assert_partial_stage_privacy(&staged);
                return Err(staged.effects(error("stage_privacy_probe_complete")));
            }
            #[cfg(test)]
            if matches!(fault, Fault::PartialWrite(limit) if staged.staged_bytes >= limit) {
                return Err(staged.effects(error("stage_write_failed")));
            }
            let end = {
                #[cfg(test)]
                {
                    match fault {
                        Fault::PartialWrite(limit) => staged.prepared.content.len().min(limit),
                        Fault::ProbePrivacy => staged.prepared.content.len().min(3),
                        _ => staged.prepared.content.len(),
                    }
                }
                #[cfg(not(test))]
                {
                    let _ = fault;
                    staged.prepared.content.len()
                }
            };
            let start = staged.staged_bytes;
            let bytes = &staged.prepared.content[start..end];
            let result = staged.file.as_mut().expect("stage owned").write(bytes);
            match result {
                Ok(0) => return Err(staged.effects(error("stage_write_failed"))),
                Ok(count) => staged.staged_bytes += count,
                Err(cause) if cause.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(cause) => {
                    let mut result = error("stage_write_failed");
                    result.errno = cause.raw_os_error();
                    return Err(staged.effects(result));
                }
            }
        }
        #[cfg(test)]
        if matches!(fault, Fault::Flush) {
            return Err(staged.effects(error("stage_sync_failed")));
        }
        staged.file().sync_all().map_err(|cause| {
            let mut result = error("stage_sync_failed");
            result.errno = cause.raw_os_error();
            staged.effects(result)
        })?;
        staged.check_stage()?;
        // No content write follows the DACL restoration. Data access granted
        // by the final owner DACL reaches only complete, flushed bytes.
        final_acl
            .apply(staged.file().as_raw_handle())
            .map_err(|cause| {
                let mut result = error("windows_create_final_acl_failed");
                result.errno = cause.raw_os_error();
                staged.effects(result)
            })?;
        staged
            .prepared
            .revalidate()
            .map_err(|cause| staged.effects(cause))?;
        Ok(staged)
    }
}

impl StagedCreate {
    fn file(&self) -> &File {
        self.file.as_ref().expect("owned stage open")
    }

    fn effects(&self, mut result: CreateFileError) -> CreateFileError {
        result.staged_bytes = self.staged_bytes;
        result.committed = self.committed;
        result.committed_bytes = if self.committed { self.staged_bytes } else { 0 };
        result
    }

    fn check_stage(&self) -> Result<(), CreateFileError> {
        let path = format!("{}\\{}", self.prepared.parent.canonical(), self.stage_name);
        let identity = checked_create_stage(self.file(), &path, self.staged_bytes)
            .map_err(|_| self.effects(error("windows_create_stage_changed")))?;
        if self.stage_identity != Some(identity)
            || identity.0 != self.prepared.identity.root_volume_serial
            || self.staged_bytes != self.prepared.content.len()
        {
            return Err(self.effects(error("windows_create_stage_changed")));
        }
        Ok(())
    }

    fn close_owned_stage(&mut self) -> Result<(), CreateFileError> {
        let verified = if let Some(verified) = self.cleanup_verified {
            verified
        } else {
            // Close only the exact owned FILE_CREATE handle. A later lookup is
            // observation only; neither a final leaf nor a foreign recreation
            // is ever submitted to a deletion API.
            drop(self.file.take());
            let verified = self.prepared.require_absent(&self.stage_name).is_ok();
            self.cleanup_verified = Some(verified);
            eprintln!(
                "{}",
                serde_json::json!({
                    "event":"mcp_windows_create_stage_cleanup","stage_created":true,
                    "staged_bytes":self.staged_bytes,"committed":self.committed,
                    "committed_bytes":if self.committed { self.staged_bytes } else { 0 },
                    "cleanup_verified":verified
                })
            );
            verified
        };
        if verified {
            Ok(())
        } else {
            Err(self.effects(error("windows_create_stage_cleanup_unverified")))
        }
    }

    pub(crate) fn publish(self) -> Result<CreateFileCommit, CreateFileError> {
        self.publish_with_fault(Fault::None)
    }

    fn link(&mut self) -> Result<(), CreateFileError> {
        let name: Vec<u16> = self.prepared.leaf.encode_utf16().collect();
        let name_offset = offset_of!(LinkInformation, file_name);
        let length = (name_offset + name.len() * 2).max(size_of::<LinkInformation>());
        // A Vec<usize> gives native pointer alignment, unlike casting Vec<u8>.
        // Zero initialization fixes ReplaceIfExists=FALSE, RootDirectory=NULL,
        // all padding and any spare storage before the native call.
        let mut storage = vec![0usize; length.div_ceil(size_of::<usize>())];
        let information = storage.as_mut_ptr().cast::<LinkInformation>();
        unsafe {
            (*information).file_name_length = (name.len() * 2) as u32;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                storage
                    .as_mut_ptr()
                    .cast::<u8>()
                    .add(name_offset)
                    .cast::<u16>(),
                name.len(),
            );
        }
        let mut io_status = IoStatusBlock::default();
        // RootDirectory=NULL with one simple name is documented to create the
        // link in this open file's directory. It never consults process cwd or
        // reopens a DOS pathname. The original parent stays pinned throughout.
        eprintln!(
            "{}",
            serde_json::json!({
                "event":"mcp_windows_create_publication_syscall",
                "publication_attempted":true,"staged_bytes":self.staged_bytes,
                "outcome":"indeterminate_until_completion"
            })
        );
        let status = unsafe {
            NtSetInformationFile(
                self.file().as_raw_handle(),
                &mut io_status,
                information.cast(),
                length as u32,
                FILE_LINK_INFORMATION_CLASS,
            )
        };
        if status != 0 {
            return Err(self.effects(if status == STATUS_OBJECT_NAME_COLLISION {
                error("target_exists")
            } else {
                nt_error("publish_failed", status)
            }));
        }
        // Set this before any fallible operation. Result suppression, later
        // flush failure and cancellation cannot undo an already-created link.
        self.committed = true;
        Ok(())
    }

    fn publish_with_fault(mut self, fault: Fault) -> Result<CreateFileCommit, CreateFileError> {
        self.prepared
            .revalidate()
            .map_err(|cause| self.effects(cause))?;
        #[cfg(test)]
        if matches!(fault, Fault::BeforePublish) {
            return Err(self.effects(error("publish_failed")));
        }
        #[cfg(not(test))]
        let _ = fault;
        self.check_stage()?;
        self.link()?;
        #[cfg(test)]
        if matches!(fault, Fault::AfterPublish) {
            return Err(self.effects(error("published_sync_failed")));
        }
        self.file().sync_all().map_err(|cause| {
            let mut result = error("published_sync_failed");
            result.errno = cause.raw_os_error();
            self.effects(result)
        })?;
        let bytes_written = self.staged_bytes;
        // Publication already happened. Unverified cleanup is an error with
        // committed=true, never a false success or a rollback claim.
        self.close_owned_stage()?;
        Ok(CreateFileCommit {
            committed: true,
            bytes_written,
            file_synced: true,
            directory_synced: false,
        })
    }
}

impl Drop for StagedCreate {
    fn drop(&mut self) {
        // Cancellation/error fallback cannot return a result, so it retains the
        // explicit audit. Normal success closes and verifies through Result.
        let _ = self.close_owned_stage();
    }
}

fn open_relative(parent: &File, name: &str, create_stage: bool) -> Result<File, i32> {
    open_relative_with_descriptor(parent, name, create_stage, null_mut())
}

fn open_relative_with_descriptor(
    parent: &File,
    name: &str,
    create_stage: bool,
    descriptor: *mut c_void,
) -> Result<File, i32> {
    debug_assert!(!name.is_empty() && !name.contains(['\\', '/', ':']));
    let mut encoded: Vec<u16> = name.encode_utf16().collect();
    let mut unicode = UnicodeString {
        length: (encoded.len() * 2) as u16,
        maximum_length: (encoded.len() * 2) as u16,
        buffer: encoded.as_mut_ptr(),
    };
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root_directory: parent.as_raw_handle(),
        object_name: &mut unicode,
        attributes: OBJ_DONT_REPARSE | OBJ_CASE_INSENSITIVE,
        security_descriptor: descriptor,
        security_quality_of_service: null_mut(),
    };
    let mut status = IoStatusBlock::default();
    let mut handle = null_mut();
    let access = FILE_READ_ATTRIBUTES
        | SYNCHRONIZE
        | if create_stage {
            FILE_WRITE_DATA | DELETE | READ_CONTROL | WRITE_DAC
        } else {
            0
        };
    let options = FILE_OPEN_REPARSE_POINT
        | FILE_OPEN_NO_RECALL
        | FILE_COMPLETE_IF_OPLOCKED
        | FILE_SYNCHRONOUS_IO_NONALERT
        | if create_stage {
            FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE | FILE_WRITE_THROUGH
        } else {
            0
        };
    let result = unsafe {
        NtCreateFile(
            &mut handle,
            access,
            &attributes,
            &mut status,
            null(),
            0,
            0, // Exclusive source; no other data/execute/write/delete opens.
            if create_stage { FILE_CREATE } else { FILE_OPEN },
            options,
            null(),
            0,
        )
    };
    if result != 0 {
        if !handle.is_null() && handle != INVALID_HANDLE_VALUE {
            drop(unsafe { File::from_raw_handle(handle) });
        }
        return Err(result);
    }
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(0xc000_0008u32 as i32); // STATUS_INVALID_HANDLE
    }
    // SAFETY: successful native create transfers exactly one unique handle.
    Ok(unsafe { File::from_raw_handle(handle) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::OwnedHandle;
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Barrier};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    };
    use windows_sys::Win32::System::IO::DeviceIoControl;

    fn fixture() -> (tempfile::TempDir, std::path::PathBuf) {
        let temporary = tempfile::tempdir().unwrap();
        let parent = temporary.path().canonicalize().unwrap();
        let workspace = parent.join("Workspace");
        fs::create_dir(&workspace).unwrap();
        (temporary, workspace)
    }

    fn prepare(root: &Path, leaf: &str, content: &str) -> Result<PreparedCreate, CreateFileError> {
        PreparedCreate::prepare(root, root, leaf, root.join(leaf).to_str().unwrap(), content)
    }

    fn entries(root: &Path) -> Vec<String> {
        let mut result: Vec<_> = fs::read_dir(root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        result.sort();
        result
    }

    fn junction(path: &Path, target: &Path) {
        fs::create_dir(path).unwrap();
        let target = target
            .to_str()
            .unwrap()
            .strip_prefix("\\\\?\\")
            .unwrap_or(target.to_str().unwrap());
        let substitute: Vec<u16> = format!("\\??\\{target}").encode_utf16().collect();
        let print: Vec<u16> = target.encode_utf16().collect();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&0xa000_0003u32.to_le_bytes());
        let data_length = 8 + (substitute.len() + print.len() + 2) * 2;
        buffer.extend_from_slice(&(data_length as u16).to_le_bytes());
        buffer.extend_from_slice(&0u16.to_le_bytes());
        buffer.extend_from_slice(&0u16.to_le_bytes());
        buffer.extend_from_slice(&((substitute.len() * 2) as u16).to_le_bytes());
        buffer.extend_from_slice(&(((substitute.len() + 1) * 2) as u16).to_le_bytes());
        buffer.extend_from_slice(&((print.len() * 2) as u16).to_le_bytes());
        for unit in substitute.into_iter().chain([0]).chain(print).chain([0]) {
            buffer.extend_from_slice(&unit.to_le_bytes());
        }
        let directory = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .unwrap();
        let mut returned = 0;
        assert_ne!(
            unsafe {
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
            },
            0,
            "junction fixture: {}",
            std::io::Error::last_os_error()
        );
    }

    fn link_to(file: &File, parent: &File, name: &str) -> i32 {
        let target: Vec<u16> = name.encode_utf16().collect();
        let offset = offset_of!(LinkInformation, file_name);
        let length = (offset + target.len() * 2).max(size_of::<LinkInformation>());
        let mut words = vec![0usize; length.div_ceil(size_of::<usize>())];
        let information = words.as_mut_ptr().cast::<LinkInformation>();
        unsafe {
            (*information).root_directory = parent.as_raw_handle();
            (*information).file_name_length = (target.len() * 2) as u32;
            std::ptr::copy_nonoverlapping(
                target.as_ptr(),
                words.as_mut_ptr().cast::<u8>().add(offset).cast::<u16>(),
                target.len(),
            );
        }
        let mut result = IoStatusBlock::default();
        unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut result,
                information.cast(),
                length as u32,
                FILE_LINK_INFORMATION_CLASS,
            )
        }
    }

    fn open_stage_with_access(staged: &StagedCreate, access: u32) -> Result<File, i32> {
        let mut name: Vec<u16> = staged.stage_name.encode_utf16().collect();
        let mut unicode = UnicodeString {
            length: (name.len() * 2) as u16,
            maximum_length: (name.len() * 2) as u16,
            buffer: name.as_mut_ptr(),
        };
        let attributes = ObjectAttributes {
            length: size_of::<ObjectAttributes>() as u32,
            root_directory: staged.prepared.parent.root().as_raw_handle(),
            object_name: &mut unicode,
            attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
            security_descriptor: null_mut(),
            security_quality_of_service: null_mut(),
        };
        let mut status = IoStatusBlock::default();
        let mut raw = null_mut();
        let opened = unsafe {
            NtCreateFile(
                &mut raw,
                access,
                &attributes,
                &mut status,
                null(),
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE
                    | FILE_OPEN_REPARSE_POINT
                    | FILE_OPEN_NO_RECALL
                    | FILE_COMPLETE_IF_OPLOCKED,
                null(),
                0,
            )
        };
        eprintln!(
            "{}",
            serde_json::json!({
                "event":"windows_create_stage_access_probe","desired_access":access,
                "open_ntstatus":opened,"partial_bytes":staged.staged_bytes
            })
        );
        if opened != 0 {
            if !raw.is_null() && raw != INVALID_HANDLE_VALUE {
                drop(unsafe { File::from_raw_handle(raw) });
            }
            return Err(opened);
        }
        assert!(!raw.is_null() && raw != INVALID_HANDLE_VALUE);
        Ok(unsafe { File::from_raw_handle(raw) })
    }

    fn assert_no_data_or_link(file: &File, outside: &File, access: u32, leaf: &str) {
        let mut byte = [0u8; 1];
        let mut read = 0;
        let event =
            unsafe { windows_sys::Win32::System::Threading::CreateEventW(null(), 1, 0, null()) };
        assert!(!event.is_null());
        let event = unsafe { OwnedHandle::from_raw_handle(event) };
        let mut overlapped: windows_sys::Win32::System::IO::OVERLAPPED =
            unsafe { std::mem::zeroed() };
        overlapped.hEvent = event.as_raw_handle();
        let ok = unsafe {
            windows_sys::Win32::Storage::FileSystem::ReadFile(
                file.as_raw_handle(),
                byte.as_mut_ptr(),
                1,
                &mut read,
                &mut overlapped,
            )
        };
        let read_error = std::io::Error::last_os_error().raw_os_error();
        if ok == 0 && read_error == Some(997) {
            // Even unexpected pending I/O must drain before test buffers and
            // OVERLAPPED storage are destroyed.
            unsafe {
                windows_sys::Win32::System::IO::CancelIoEx(file.as_raw_handle(), &overlapped);
                windows_sys::Win32::System::IO::GetOverlappedResult(
                    file.as_raw_handle(),
                    &overlapped,
                    &mut read,
                    1,
                );
            }
        }
        assert_eq!(ok, 0, "metadata/zero-access handle read partial data");
        assert_eq!(read_error, Some(5));
        assert_eq!(read, 0);
        let linked = link_to(file, outside, leaf);
        eprintln!(
            "{}",
            serde_json::json!({
                "event":"windows_create_stage_access_probe","desired_access":access,
                "link_ntstatus":linked,"partial_bytes":3
            })
        );
        assert_ne!(linked, 0,
            "metadata/zero-access source linked a partial private stage outside its authorized root");
    }

    pub(super) fn assert_partial_stage_privacy(staged: &StagedCreate) {
        assert_eq!(staged.staged_bytes, 3);
        let outside_path = Path::new(staged.prepared.parent.canonical())
            .parent()
            .unwrap()
            .join("ForeignDirectory");
        // This independent sibling was made before preparation. It is not a
        // pinned ancestor; a control link proves target permissions and sharing
        // cannot manufacture a false-negative source-security result.
        let outside = fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&outside_path)
            .unwrap();
        let control = File::open(outside_path.join("Control.txt")).unwrap();
        assert_eq!(
            link_to(&control, &outside, "ControlLink.txt"),
            0,
            "independent target control link failed"
        );
        // Neither probe requests SYNCHRONIZE or a synchronous-I/O option.
        // DesiredAccess=0 is distinct: ACLs cannot deny an empty access mask,
        // and FileLinkInformation documents no specific source right.
        for (access, leaf) in [
            (FILE_READ_ATTRIBUTES, "ForeignAttributes.txt"),
            (0, "ForeignZero.txt"),
            (0x100, "ForeignWriteAttributes.txt"),
        ] {
            match open_stage_with_access(staged, access) {
                Ok(file) => {
                    assert_no_data_or_link(&file, &outside, access, leaf);
                    assert_ne!(
                        access, 0x100,
                        "private partial stage granted FILE_WRITE_ATTRIBUTES"
                    );
                }
                Err(status) => {
                    assert_eq!(
                        status, 0xc000_0022u32 as i32,
                        "source refusal was not the expected ACL denial"
                    );
                }
            }
            assert!(!outside_path.join(leaf).exists());
        }
    }

    #[test]
    fn partial_stage_acl_denies_data_and_foreign_link() {
        let (_temporary, root) = fixture();
        let foreign = root.parent().unwrap().join("ForeignDirectory");
        fs::create_dir(&foreign).unwrap();
        fs::write(foreign.join("Control.txt"), b"control bytes").unwrap();
        let result = prepare(&root, "New.txt", "abcdef")
            .unwrap()
            .stage_with_fault(Fault::ProbePrivacy)
            .unwrap_err();
        assert_eq!(result.code, "stage_privacy_probe_complete");
        assert_eq!(result.staged_bytes, 3);
        assert!(!result.committed);
        assert!(entries(&root).is_empty());
        assert!(!foreign.join("ForeignAttributes.txt").exists());
        assert!(!foreign.join("ForeignZero.txt").exists());
        assert!(!foreign.join("ForeignWriteAttributes.txt").exists());
    }

    #[test]
    fn preparation_has_no_effects_and_binds_exact_root() {
        let (_temporary, root) = fixture();
        let first = prepare(&root, "New.txt", "not yet written").unwrap();
        let second = prepare(&root, "New.txt", "not yet written").unwrap();
        assert_eq!(first.identity(), second.identity());
        assert!(entries(&root).is_empty());
        drop(first);
        drop(second);
        assert!(entries(&root).is_empty());
        // Startup authority validation deliberately accepts existing targets;
        // the separate per-call prepare still refuses them without mutations.
        fs::write(root.join("Existing.txt"), b"original").unwrap();
        let (_parent, leaf) = CreateParent::prepare(
            &root,
            &root,
            "Existing.txt",
            root.join("Existing.txt").to_str().unwrap(),
        )
        .unwrap();
        assert_eq!(leaf, "Existing.txt");
        assert!(prepare(&root, "Existing.txt", "replacement").is_err());
        assert_eq!(fs::read(root.join("Existing.txt")).unwrap(), b"original");
    }

    #[test]
    fn publishes_complete_utf8_empty_and_bounded_bytes() {
        let (_temporary, root) = fixture();
        for (leaf, content) in [
            ("Unicode.txt", "Привет\n世界".to_owned()),
            ("Empty.txt", String::new()),
            ("Bound.txt", "x".repeat(MAX_CREATE_BYTES)),
        ] {
            let staged = prepare(&root, leaf, &content).unwrap().stage().unwrap();
            assert!(!root.join(leaf).exists());
            assert_eq!(
                entries(&root)
                    .iter()
                    .filter(|name| name.starts_with(".soup-wall-create-"))
                    .count(),
                1
            );
            let result = staged.publish().unwrap();
            assert!(result.committed && result.file_synced);
            assert!(!result.directory_synced);
            assert_eq!(result.bytes_written, content.len());
            assert_eq!(fs::read_to_string(root.join(leaf)).unwrap(), content);
            assert!(!entries(&root)
                .iter()
                .any(|name| name.starts_with(".soup-wall-create-")));
        }
        let error =
            prepare(&root, "TooLarge.txt", &"é".repeat(MAX_CREATE_BYTES / 2 + 1)).unwrap_err();
        assert_eq!(error.code, "content_too_large");
        assert!(!error.committed);
        assert!(!root.join("TooLarge.txt").exists());
    }

    #[test]
    fn prepared_content_is_immutable_and_absolute_path_is_exact() {
        let (_temporary, root) = fixture();
        let mut content = "approved original".to_owned();
        let absolute = root.join("Absolute.txt");
        let original = absolute
            .to_str()
            .unwrap()
            .strip_prefix("\\\\?\\")
            .unwrap_or(absolute.to_str().unwrap());
        let prepared =
            PreparedCreate::prepare(&root, &root, original, absolute.to_str().unwrap(), &content)
                .unwrap();
        content.clear();
        content.push_str("substitution");
        prepared.stage().unwrap().publish().unwrap();
        assert_eq!(fs::read(absolute).unwrap(), b"approved original");
        assert!(PreparedCreate::prepare(
            &root,
            &root,
            "Other.txt",
            root.join("Alias.txt").to_str().unwrap(),
            "no"
        )
        .is_err());
    }

    #[test]
    fn refuses_namespace_aliases_nested_and_outside_paths_without_effects() {
        let (_temporary, root) = fixture();
        for leaf in [
            "",
            ".",
            "..",
            "..\\Outside.txt",
            ".\\New.txt",
            "Dir\\New.txt",
            "Dir/Name.txt",
            "New.txt.",
            "New.txt ",
            "New.txt:stream",
            "NUL.txt",
            "COM1",
            "LPT¹",
            "NEWFIL~1.TXT",
            "\\New.txt",
            "C:New.txt",
            "\\\\host\\share\\New.txt",
            "\\\\?\\C:\\New.txt",
        ] {
            assert!(prepare(&root, leaf, "no").is_err(), "accepted {leaf:?}");
            assert!(entries(&root).is_empty());
        }
        let parent = root.parent().unwrap();
        assert!(PreparedCreate::prepare(
            &root,
            parent,
            "New.txt",
            parent.join("New.txt").to_str().unwrap(),
            "no"
        )
        .is_err());
        assert!(prepare(&root, &"x".repeat(256), "no").is_err());
        assert!(entries(&root).is_empty());
    }

    #[test]
    fn refuses_existing_case_alias_directory_hardlink_and_junction() {
        let (_temporary, root) = fixture();
        fs::write(root.join("Existing.txt"), b"preserved").unwrap();
        fs::hard_link(root.join("Existing.txt"), root.join("Hard.txt")).unwrap();
        fs::create_dir(root.join("Directory")).unwrap();
        let outside = root.parent().unwrap().join("Outside");
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("Witness.txt"), b"outside unchanged").unwrap();
        junction(&root.join("Junction"), &outside);
        for leaf in [
            "Existing.txt",
            "EXISTING.TXT",
            "Hard.txt",
            "Directory",
            "Junction",
        ] {
            assert!(
                prepare(&root, leaf, "overwrite").is_err(),
                "accepted {leaf}"
            );
        }
        assert_eq!(fs::read(root.join("Existing.txt")).unwrap(), b"preserved");
        assert_eq!(
            fs::read(outside.join("Witness.txt")).unwrap(),
            b"outside unchanged"
        );
        assert!(!entries(&root)
            .iter()
            .any(|name| name.starts_with(".soup-wall-create-")));
    }

    #[test]
    fn parent_and_ancestor_replacement_are_excluded_by_retained_pins() {
        let (_temporary, root) = fixture();
        let parent = root.parent().unwrap();
        let prepared = prepare(&root, "New.txt", "inside").unwrap();
        assert!(fs::rename(&root, parent.join("MovedWorkspace")).is_err());
        assert!(fs::rename(parent, parent.with_extension("moved")).is_err());
        let writer = fs::OpenOptions::new()
            .access_mode(FILE_WRITE_DATA)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(&root);
        assert!(
            writer.is_err(),
            "write-sharing pin did not exclude parent writer"
        );
        prepared.stage().unwrap().publish().unwrap();
        assert_eq!(fs::read(root.join("New.txt")).unwrap(), b"inside");
    }

    #[test]
    fn racing_creator_survives_without_partial_or_replaced_target() {
        for competitor in ["Race.txt", "RACE.TXT"] {
            let (_temporary, root) = fixture();
            let staged = prepare(&root, "Race.txt", "our complete content")
                .unwrap()
                .stage()
                .unwrap();
            fs::write(root.join(competitor), b"competing complete content").unwrap();
            let result = staged.publish().unwrap_err();
            assert_eq!(result.code, "target_exists");
            assert!(!result.committed);
            assert_eq!(result.staged_bytes, "our complete content".len());
            assert_eq!(result.committed_bytes, 0);
            assert_eq!(
                fs::read(root.join(competitor)).unwrap(),
                b"competing complete content"
            );
            assert_eq!(entries(&root), [competitor]);
        }
    }

    #[test]
    fn concurrent_publications_have_exactly_one_complete_winner() {
        let (_temporary, root) = fixture();
        let first = prepare(&root, "Race.txt", &"a".repeat(MAX_CREATE_BYTES))
            .unwrap()
            .stage()
            .unwrap();
        let second = prepare(&root, "Race.txt", &"b".repeat(MAX_CREATE_BYTES))
            .unwrap()
            .stage()
            .unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let waiting = Arc::clone(&barrier);
        let first = std::thread::spawn(move || {
            waiting.wait();
            first.publish()
        });
        let second = std::thread::spawn(move || {
            barrier.wait();
            second.publish()
        });
        let outcomes = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| outcome
                    .as_ref()
                    .is_err_and(|error| error.code == "target_exists" && !error.committed))
                .count(),
            1
        );
        let bytes = fs::read(root.join("Race.txt")).unwrap();
        assert_eq!(bytes.len(), MAX_CREATE_BYTES);
        assert!(bytes.iter().all(|byte| *byte == b'a') || bytes.iter().all(|byte| *byte == b'b'));
        assert_eq!(entries(&root), ["Race.txt"]);
    }

    #[test]
    fn partial_write_failure_accounts_real_bytes_and_removes_only_owned_stage() {
        let (_temporary, root) = fixture();
        fs::write(root.join(".soup-wall-create-foreign.tmp"), b"foreign").unwrap();
        let result = prepare(&root, "New.txt", "abcdef")
            .unwrap()
            .stage_with_fault(Fault::PartialWrite(3))
            .unwrap_err();
        assert_eq!(result.code, "stage_write_failed");
        assert_eq!(result.staged_bytes, 3);
        assert!(!result.committed);
        assert_eq!(result.committed_bytes, 0);
        assert_eq!(entries(&root), [".soup-wall-create-foreign.tmp"]);
        assert_eq!(
            fs::read(root.join(".soup-wall-create-foreign.tmp")).unwrap(),
            b"foreign"
        );
    }

    #[test]
    fn flush_and_publication_failures_leave_no_target_and_account_staging() {
        let (_temporary, root) = fixture();
        let content = "complete but not published";
        let flush = prepare(&root, "New.txt", content)
            .unwrap()
            .stage_with_fault(Fault::Flush)
            .unwrap_err();
        assert_eq!(flush.code, "stage_sync_failed");
        assert_eq!(flush.staged_bytes, content.len());
        assert!(!flush.committed && entries(&root).is_empty());
        let publish = prepare(&root, "New.txt", content)
            .unwrap()
            .stage()
            .unwrap()
            .publish_with_fault(Fault::BeforePublish)
            .unwrap_err();
        assert_eq!(publish.code, "publish_failed");
        assert_eq!(publish.staged_bytes, content.len());
        assert!(!publish.committed && entries(&root).is_empty());
    }

    #[test]
    fn post_publication_failure_keeps_complete_effect_and_true_accounting() {
        let (_temporary, root) = fixture();
        let result = prepare(&root, "New.txt", "actual effect")
            .unwrap()
            .stage()
            .unwrap()
            .publish_with_fault(Fault::AfterPublish)
            .unwrap_err();
        assert_eq!(result.code, "published_sync_failed");
        assert!(result.committed);
        assert_eq!(result.staged_bytes, "actual effect".len());
        assert_eq!(result.committed_bytes, "actual effect".len());
        assert_eq!(fs::read(root.join("New.txt")).unwrap(), b"actual effect");
        assert_eq!(entries(&root), ["New.txt"]);
    }

    #[test]
    fn canceled_stage_is_exclusive_then_cleaned_and_continuation_is_useful() {
        let (_temporary, root) = fixture();
        let staged = prepare(&root, "New.txt", "canceled content")
            .unwrap()
            .stage()
            .unwrap();
        let temporary_name = entries(&root).pop().unwrap();
        assert!(fs::write(root.join(&temporary_name), b"replacement").is_err());
        assert!(fs::rename(root.join(&temporary_name), root.join("Stolen.txt")).is_err());
        assert!(!root.join("New.txt").exists());
        drop(staged);
        assert!(entries(&root).is_empty());
        // A foreign object reusing a former temporary spelling is never deleted
        // by a later operation: cleanup has no pathname deletion operation.
        fs::write(root.join(&temporary_name), b"foreign reuse").unwrap();
        prepare(&root, "New.txt", "useful continuation")
            .unwrap()
            .stage()
            .unwrap()
            .publish()
            .unwrap();
        assert_eq!(
            fs::read(root.join("New.txt")).unwrap(),
            b"useful continuation"
        );
        assert_eq!(
            fs::read(root.join(temporary_name)).unwrap(),
            b"foreign reuse"
        );
        // A real metadata-only handle can delay original-link DOC cleanup.
        // Publication still happened: the error must retain committed bytes.
        let staged = prepare(&root, "Cleanup.txt", "committed despite held metadata")
            .unwrap()
            .stage()
            .unwrap();
        let owned_name = staged.stage_name.clone();
        let held = open_stage_with_access(&staged, 0).unwrap();
        let result = staged.publish().unwrap_err();
        assert_eq!(result.code, "windows_create_stage_cleanup_unverified");
        assert!(result.committed);
        assert_eq!(
            result.committed_bytes,
            "committed despite held metadata".len()
        );
        drop(held);
        assert!(!root.join(owned_name).exists());
        assert_eq!(
            fs::read(root.join("Cleanup.txt")).unwrap(),
            b"committed despite held metadata"
        );
    }

    #[test]
    fn process_interruption_cleans_stage_and_preserves_published_link() {
        // These variables exist only in this cfg(test) function, never in the
        // production executor. The same libtest entry is a real killable child.
        if let Some(root) = std::env::var_os("SOU60_CREATE_TEST_CHILD_WORKSPACE") {
            let root = std::path::PathBuf::from(root);
            let mode = std::env::var("SOU60_CREATE_TEST_CHILD_MODE").unwrap();
            let mut staged = prepare(&root, "New.txt", "complete interrupted bytes")
                .unwrap()
                .stage()
                .unwrap();
            if mode == "published" {
                staged.link().unwrap();
            }
            fs::write(root.parent().unwrap().join("Ready.txt"), mode).unwrap();
            // Hold all handles and temp link live until parent TerminateProcess.
            std::hint::black_box(&staged);
            loop {
                std::thread::park();
            }
        }
        for mode in ["stage", "published"] {
            let (_temporary, root) = fixture();
            let ready = root.parent().unwrap().join("Ready.txt");
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "windows_create::tests::process_interruption_cleans_stage_and_preserves_published_link", "--nocapture"])
                .env("SOU60_CREATE_TEST_CHILD_WORKSPACE", &root)
                .env("SOU60_CREATE_TEST_CHILD_MODE", mode)
                .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
                .spawn().unwrap();
            let deadline = Instant::now() + Duration::from_secs(20);
            while !ready.exists() && Instant::now() < deadline {
                if let Some(status) = child.try_wait().unwrap() {
                    panic!("native interruption child exited before witness: {status}");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            if !ready.exists() {
                let _ = child.kill();
                let _ = child.wait();
                panic!("native interruption witness timed out");
            }
            assert_eq!(fs::read_to_string(&ready).unwrap(), mode);
            assert!(entries(&root)
                .iter()
                .any(|entry| entry.starts_with(".soup-wall-create-")));
            child.kill().unwrap();
            assert!(!child.wait().unwrap().success());
            if mode == "published" {
                assert_eq!(
                    fs::read(root.join("New.txt")).unwrap(),
                    b"complete interrupted bytes"
                );
                assert_eq!(entries(&root), ["New.txt"]);
            } else {
                assert!(entries(&root).is_empty());
            }
        }
    }
}
