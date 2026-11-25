// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Owner-only Windows files for the daemon token and audit log.
//!
//! A new file receives a protected DACL in the `CreateFileW` call, before any
//! secret is written. An existing file is secured through its open handle before
//! its contents are read or appended. Failures are fatal to daemon startup.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::ptr::{null, null_mut, NonNull};

use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetSecurityInfo, SetSecurityInfo, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    GetSecurityDescriptorDacl, GetTokenInformation, IsValidAcl, TokenUser, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    CREATE_NEW, FILE_APPEND_DATA, FILE_ATTRIBUTE_DEVICE, FILE_ATTRIBUTE_DIRECTORY,
    FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_OFFLINE, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA, OPEN_EXISTING,
    READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
use windows_sys::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

fn copy_acl_bytes(pointer: *const c_void, buffer: &mut [u8]) -> io::Result<()> {
    let mut copied = 0usize;
    if unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            pointer,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut copied,
        )
    } == 0
        || copied != buffer.len()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "audit retention DACL contains an unreadable entry",
        ));
    }
    Ok(())
}

struct LocalMemory(*mut c_void);

impl Drop for LocalMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: Both SDDL conversion functions return LocalAlloc memory.
            unsafe { LocalFree(self.0) };
        }
    }
}

struct TokenHandle(HANDLE);

impl Drop for TokenHandle {
    fn drop(&mut self) {
        // SAFETY: OpenProcessToken returned this owned handle.
        unsafe { CloseHandle(self.0) };
    }
}

pub(crate) struct PrivateAcl {
    descriptor: LocalMemory,
    dacl: *mut ACL,
}

impl PrivateAcl {
    pub(crate) fn new() -> io::Result<Self> {
        let sid = current_user_sid()?;
        let sddl = format!("O:{sid}D:P(A;;GA;;;{sid})(A;;GA;;;SY)");
        Self::from_sddl(&sddl)
    }

    /// A protected empty DACL for a new create stage. It grants no future
    /// content or write-attributes access; Windows may still grant metadata
    /// access. The original handle retains its creation rights. This is not a
    /// process sandbox against the file owner.
    pub(crate) fn empty() -> io::Result<Self> {
        let sid = current_user_sid()?;
        Self::from_sddl(&format!("O:{sid}D:P"))
    }

    pub(crate) fn descriptor(&self) -> *mut c_void {
        self.descriptor.0
    }

    /// Verify the kernel-assigned stage security before its first content write.
    /// Outputs only booleans; account identifiers and ACL bytes stay private.
    pub(crate) fn verify_empty(handle: HANDLE) -> io::Result<()> {
        let mut owner: PSID = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let code = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        let descriptor = LocalMemory(descriptor);
        if descriptor.0.is_null() || owner.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "stage security descriptor is incomplete",
            ));
        }
        let dacl = NonNull::new(dacl).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "stage security descriptor has no DACL",
            )
        })?;
        // GetSecurityInfo owns the ACL storage inside descriptor until this
        // function returns. Validate it through the supported ACL APIs instead
        // of dereferencing a returned FFI structure in Rust.
        if unsafe { IsValidAcl(dacl.as_ptr()) } == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "stage security descriptor has an invalid DACL",
            ));
        }
        let mut acl_information = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        if unsafe {
            GetAclInformation(
                dacl.as_ptr(),
                (&mut acl_information as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut control = 0u16;
        let mut revision = 0u32;
        if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if control & SE_DACL_PROTECTED == 0
            || acl_information.AceCount != 0
            || sid_to_string(owner)? != current_user_sid()?
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "stage is not protected with its creator's empty DACL",
            ));
        }
        Ok(())
    }

    pub(crate) fn for_directory() -> io::Result<Self> {
        let sid = current_user_sid()?;
        // OI and CI let files and subdirectories created beneath .agentfw
        // inherit the owner-only ACL too. The directory itself is protected.
        let sddl = format!("O:{sid}D:P(A;OICI;GA;;;{sid})(A;OICI;GA;;;SY)");
        Self::from_sddl(&sddl)
    }

    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let wide: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // SAFETY: `wide` is NUL-terminated and `descriptor` receives an owned
        // LocalAlloc allocation when the conversion succeeds.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let descriptor = LocalMemory(descriptor);
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = null_mut();
        // SAFETY: The returned security descriptor remains alive in `descriptor`.
        if unsafe {
            GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted)
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        if present == 0 || dacl.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private security descriptor has no DACL",
            ));
        }
        Ok(Self { descriptor, dacl })
    }

    pub(crate) fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.descriptor.0,
            bInheritHandle: 0,
        }
    }

    pub(crate) fn apply(&self, handle: HANDLE) -> io::Result<()> {
        // SAFETY: The handle is open with WRITE_DAC. `dacl` points into the
        // security descriptor held by `self` for the duration of this call.
        let code = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                self.dacl,
                null(),
            )
        };
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code as i32));
        }
        Ok(())
    }
}

/// Audit retention never repairs an existing object. Unlike legacy token and
/// audit files, every retained file and the store directory must already have
/// the expected owner and a protected DACL with only user/System allow ACEs.
pub(crate) fn verify_retention_security(handle: HANDLE, directory: bool) -> io::Result<()> {
    check_kind(handle, directory)?;
    let mut file_info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(handle, &mut file_info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if file_info.dwFileAttributes & (FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_OFFLINE) != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "audit retention object is offline or a device",
        ));
    }
    let user = current_user_sid()?;
    if owner_sid(handle)? != user {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "audit retention object has a foreign owner",
        ));
    }
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let code = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    let descriptor = LocalMemory(descriptor);
    if descriptor.0.is_null() || dacl.is_null() || unsafe { IsValidAcl(dacl) } == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "audit retention DACL is absent or invalid",
        ));
    }
    let mut control = 0u16;
    let mut revision = 0u32;
    if unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if control & SE_DACL_PROTECTED == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "audit retention DACL is not protected",
        ));
    }
    let mut info = ACL_SIZE_INFORMATION {
        AceCount: 0,
        AclBytesInUse: 0,
        AclBytesFree: 0,
    };
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if info.AceCount != 2 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "audit retention DACL has unexpected entries",
        ));
    }
    let mut seen_user = false;
    let mut seen_system = false;
    for index in 0..info.AceCount {
        let mut raw: *mut c_void = null_mut();
        if unsafe { GetAce(dacl, index, &mut raw) } == 0 || raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        // GetAce returns a pointer into the descriptor. Copy through a checked
        // process-memory read before inspecting untrusted ACE bytes.
        let mut header = [0u8; 4];
        copy_acl_bytes(raw.cast(), &mut header)?;
        let ace_size = u16::from_le_bytes([header[2], header[3]]) as usize;
        if header[0] != 0 || !(16..=info.AclBytesInUse as usize).contains(&ace_size) {
            // ACCESS_ALLOWED_ACE_TYPE
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "audit retention DACL contains an invalid allow entry",
            ));
        }
        let mut ace = vec![0u8; ace_size];
        copy_acl_bytes(raw.cast(), &mut ace)?;
        if ace[..4] != header {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "audit retention DACL changed during inspection",
            ));
        }
        let sub_authorities = ace[9] as usize;
        if ace[8] != 1 || sub_authorities > 15 || 16 + 4 * sub_authorities > ace.len() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "audit retention DACL contains an invalid SID",
            ));
        }
        let trustee = sid_to_string(ace[8..].as_ptr().cast_mut().cast())?;
        if trustee == user && !seen_user {
            seen_user = true;
        } else if trustee == "S-1-5-18" && !seen_system {
            seen_system = true;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "audit retention DACL contains a foreign or duplicate entry",
            ));
        }
    }
    if !seen_user || !seen_system {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "audit retention DACL lacks trusted entries",
        ));
    }
    Ok(())
}

pub(crate) fn current_user_sid() -> io::Result<String> {
    let mut raw_token: HANDLE = null_mut();
    // SAFETY: The process pseudo-handle is valid and `raw_token` is writable.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = TokenHandle(raw_token);
    let mut needed = 0;
    // SAFETY: The first call asks Windows for the required buffer size.
    unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed) };
    if needed < std::mem::size_of::<TOKEN_USER>() as u32 {
        return Err(io::Error::last_os_error());
    }
    // `Vec<usize>` gives the TOKEN_USER structure pointer-sized alignment.
    let words = (needed as usize).div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0usize; words];
    // SAFETY: `buffer` has at least `needed` bytes and remains alive while the
    // returned TOKEN_USER and its embedded SID pointer are used.
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: GetTokenInformation(TokenUser) filled an aligned TOKEN_USER.
    let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
    sid_to_string(user.User.Sid)
}

pub(crate) fn sid_to_string(sid: PSID) -> io::Result<String> {
    if sid.is_null() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "missing SID"));
    }
    let mut sid_wide = null_mut();
    // SAFETY: The caller keeps the SID memory alive for this call. The API
    // returns a NUL-terminated string allocated with LocalAlloc.
    if unsafe { ConvertSidToStringSidW(sid, &mut sid_wide) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let _sid_memory = LocalMemory(sid_wide.cast());
    let length = (0..256)
        .find(|&index| unsafe { *sid_wide.add(index) == 0 })
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SID string too long"))?;
    // SAFETY: The NUL terminator was found within the allocated SID string.
    let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_wide, length) })
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(sid)
}

fn owner_sid(handle: HANDLE) -> io::Result<String> {
    let mut owner: PSID = null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    // SAFETY: The handle was opened with READ_CONTROL. Windows returns the
    // owner pointer within the LocalAlloc security descriptor held below.
    let code = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        )
    };
    if code != 0 {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    if descriptor.is_null() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "owner query returned no security descriptor",
        ));
    }
    let _descriptor = LocalMemory(descriptor);
    sid_to_string(owner)
}

fn owner_is_trusted(owner: &str, current_user: &str) -> bool {
    owner == current_user || owner == "S-1-5-18" // LocalSystem
}

fn check_owner(handle: HANDLE) -> io::Result<()> {
    let owner = owner_sid(handle)?;
    let current_user = current_user_sid()?;
    if !owner_is_trusted(&owner, &current_user) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("private file or directory has an untrusted owner: {owner}"),
        ));
    }
    Ok(())
}

fn wide_path(path: &Path) -> io::Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "path contains a NUL character",
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn check_kind(handle: HANDLE, directory: bool) -> io::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is open and `info` is writable.
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private file path is a reparse point",
        ));
    }
    if (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private path has the wrong file type",
        ));
    }
    Ok(())
}

fn open_private(path: &Path, access: u32, create: bool) -> io::Result<File> {
    let wide = wide_path(path)?;
    let acl = PrivateAcl::new()?;
    let attributes = acl.attributes();
    let flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT;
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE;
    let raw = if create {
        // SAFETY: All pointers remain live for the call. CREATE_NEW never opens
        // or truncates an existing file, including a final-component symlink.
        unsafe {
            CreateFileW(
                wide.as_ptr(),
                access,
                share,
                &attributes,
                CREATE_NEW,
                flags,
                null_mut(),
            )
        }
    } else {
        INVALID_HANDLE_VALUE
    };
    let raw = if raw == INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        if !create
            || matches!(
                error.raw_os_error(),
                Some(code) if code == ERROR_FILE_EXISTS as i32 || code == ERROR_ALREADY_EXISTS as i32
            )
        {
            // SAFETY: OPEN_EXISTING does not create or truncate. The reparse
            // flag makes the opened handle refer to the link itself for checks.
            unsafe {
                CreateFileW(
                    wide.as_ptr(),
                    access,
                    share,
                    null(),
                    OPEN_EXISTING,
                    flags,
                    null_mut(),
                )
            }
        } else {
            return Err(error);
        }
    } else {
        raw
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned a unique owned file handle. `File` closes it
    // on all subsequent error and success paths.
    let file = unsafe { File::from_raw_handle(raw) };
    check_kind(raw, false)?;
    check_owner(raw)?;
    // Even on a new file, verify that the filesystem accepts a protected DACL
    // before any data is written. A filesystem without ACL support fails closed.
    acl.apply(raw)?;
    check_owner(raw)?;
    Ok(file)
}

pub fn open_token(path: &Path) -> io::Result<File> {
    open_private(
        path,
        FILE_READ_DATA | FILE_WRITE_DATA | READ_CONTROL | WRITE_DAC,
        true,
    )
}

pub fn open_audit(path: &Path) -> io::Result<File> {
    open_private(path, FILE_APPEND_DATA | READ_CONTROL | WRITE_DAC, true)
}

pub fn restrict_existing(path: &Path) -> io::Result<()> {
    let wide = wide_path(path)?;
    let flags = FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT;
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    let access = READ_CONTROL | WRITE_DAC | WRITE_OWNER;
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            access,
            share,
            null(),
            OPEN_EXISTING,
            flags,
            null_mut(),
        )
    };
    let (raw, has_write_owner) = if raw != INVALID_HANDLE_VALUE {
        (raw, true)
    } else {
        let fallback_access = READ_CONTROL | WRITE_DAC;
        let fallback_raw = unsafe {
            CreateFileW(
                wide.as_ptr(),
                fallback_access,
                share,
                null(),
                OPEN_EXISTING,
                flags,
                null_mut(),
            )
        };
        if fallback_raw == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        (fallback_raw, false)
    };
    // SAFETY: CreateFileW returned one owned handle, closed with File on every
    // return path.
    let _file = unsafe { File::from_raw_handle(raw) };
    check_kind(raw, false)?;
    if has_write_owner && owner_sid(raw).map(|o| o == "S-1-5-32-544").unwrap_or(false) {
        set_current_owner(raw)?;
    }
    check_owner(raw)?;
    let acl = PrivateAcl::new()?;
    acl.apply(raw)?;
    check_owner(raw)?;
    Ok(())
}

/// Create or tighten the default .agentfw directory before resolving any
/// token, audit, grant, or manifest path beneath it.
pub fn ensure_private_directory(path: &Path) -> io::Result<()> {
    let wide = wide_path(path)?;
    let acl = PrivateAcl::for_directory()?;
    let attributes = acl.attributes();
    // SAFETY: The path and security descriptor remain live for this call.
    // Existing directories are never replaced or modified here.
    let created = unsafe { CreateDirectoryW(wide.as_ptr(), &attributes) } != 0;
    if !created {
        let error = io::Error::last_os_error();
        if !matches!(
            error.raw_os_error(),
            Some(code) if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32
        ) {
            return Err(error);
        }
    }
    let raw = open_directory_handle(&wide)?;
    // SAFETY: CreateFileW returned one owned handle, closed with File on every
    // return path. Backup semantics permit opening directories as files.
    let _directory = unsafe { File::from_raw_handle(raw) };
    check_kind(raw, true)?;
    if created || owner_sid(raw).map(|o| o == "S-1-5-32-544").unwrap_or(false) {
        set_current_owner(raw)?;
    }
    check_owner(raw)?;
    acl.apply(raw)?;
    check_owner(raw)?;
    Ok(())
}

fn set_current_owner(handle: HANDLE) -> io::Result<()> {
    let sid = current_user_sid()?;
    let wide: Vec<u16> = sid.encode_utf16().chain(Some(0)).collect();
    let mut raw_sid: PSID = null_mut();
    if unsafe { ConvertStringSidToSidW(wide.as_ptr(), &mut raw_sid) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sid_memory = LocalMemory(raw_sid.cast());
    let code = unsafe {
        SetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            raw_sid,
            null_mut(),
            null_mut(),
            null(),
        )
    };
    drop(sid_memory);
    if code != 0 {
        return Err(io::Error::from_raw_os_error(code as i32));
    }
    Ok(())
}

fn open_directory_handle(wide: &[u16]) -> io::Result<HANDLE> {
    // SAFETY: `wide` is a NUL-terminated path. The reparse flag opens the final
    // link itself so the caller can reject it, never the link's target.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_READ_ATTRIBUTES | READ_CONTROL | WRITE_DAC | WRITE_OWNER,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        Ok(raw)
    }
}

#[cfg(test)]
mod tests;
