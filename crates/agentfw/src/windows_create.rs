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
mod tests;
