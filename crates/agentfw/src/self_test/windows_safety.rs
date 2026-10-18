// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus};
use std::ptr::{null, null_mut, NonNull};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use crate::private_file_windows::{current_user_sid, sid_to_string, PrivateAcl};
use crate::windows_read::CreateParent;
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::*,
    System::{Console::*, Diagnostics::ToolHelp::*, JobObjects::*, Threading::*},
};

pub(super) static INTERRUPTED: AtomicBool = AtomicBool::new(false);
pub(super) static OVERFLOW: AtomicBool = AtomicBool::new(false);

unsafe extern "system" fn on_control(code: u32) -> i32 {
    if matches!(
        code,
        CTRL_C_EVENT | CTRL_BREAK_EVENT | CTRL_CLOSE_EVENT | CTRL_SHUTDOWN_EVENT
    ) {
        INTERRUPTED.store(true, Ordering::SeqCst);
        1
    } else {
        0
    }
}

pub(super) fn install_control_handler() -> io::Result<()> {
    if unsafe { SetConsoleCtrlHandler(Some(on_control), 1) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub(crate) fn standard_user() -> io::Result<()> {
    let mut raw = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut elevation = TOKEN_ELEVATION::default();
    let mut length = 0;
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of_val(&elevation) as u32,
            &mut length,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if elevation.TokenIsElevated != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "a non-elevated standard-user token is required",
        ));
    }
    Ok(())
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message)
}

pub(super) fn absolute(path: &Path) -> io::Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let text = path
        .to_str()
        .ok_or_else(|| invalid("Unicode disk path required"))?;
    if text.starts_with(r"\\") || text.contains('/') || text.contains('\0') {
        return Err(invalid("path namespace or alias refused"));
    }
    Ok(path.components().collect())
}

pub(super) fn pin(path: &Path) -> io::Result<CreateParent> {
    CreateParent::prepare_connection(path, path)
        .map_err(|_| invalid("unsafe directory path refused"))
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn open(path: &Path, directory: bool, create: bool) -> io::Result<File> {
    let acl = PrivateAcl::new()?;
    let attributes = acl.attributes();
    let access = READ_CONTROL
        | FILE_READ_ATTRIBUTES
        | if create {
            FILE_WRITE_DATA
        } else {
            FILE_READ_DATA
        };
    let raw = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            if create { &attributes } else { null() },
            if create { CREATE_NEW } else { OPEN_EXISTING },
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    FILE_ATTRIBUTE_NORMAL
                },
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(raw) };
    verify(&file, directory)?;
    Ok(file)
}

pub(super) fn verify(file: &File, directory: bool) -> io::Result<()> {
    verify_security(file, directory, true)
}

fn verify_security(file: &File, directory: bool, private: bool) -> io::Result<()> {
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    if info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
        || (!directory && info.nNumberOfLinks != 1)
    {
        return Err(invalid("linked or unexpected file type refused"));
    }
    let mut owner = null_mut();
    let mut dacl = null_mut();
    let mut descriptor = null_mut();
    let result = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor,
        )
    };
    if result != 0 {
        return Err(io::Error::from_raw_os_error(result as i32));
    }
    struct Memory(PSECURITY_DESCRIPTOR);
    impl Drop for Memory {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
    let _memory = Memory(descriptor);
    if descriptor.is_null() || owner.is_null() || dacl.is_null() {
        return Err(invalid("missing owner or private DACL"));
    }
    let sid = current_user_sid()?;
    if sid_to_string(owner)? != sid || unsafe { IsValidAcl(dacl) } == 0 {
        return Err(invalid("foreign owner or invalid DACL"));
    }
    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || (private && control & SE_DACL_PROTECTED == 0)
    {
        return Err(invalid("protected DACL required"));
    }
    let mut size = ACL_SIZE_INFORMATION::default();
    if unsafe {
        GetAclInformation(
            dacl,
            (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
            std::mem::size_of_val(&size) as u32,
            AclSizeInformation,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut offset = std::mem::size_of::<ACL>();
    let mut own_access = false;
    for index in 0..size.AceCount {
        let mut raw = null_mut();
        if unsafe { GetAce(dacl, index, &mut raw) } == 0 {
            return Err(invalid("invalid ACL entry"));
        }
        let raw = NonNull::new(raw).ok_or_else(|| invalid("missing ACL entry"))?;
        if offset + std::mem::size_of::<ACE_HEADER>() > size.AclBytesInUse as usize {
            return Err(invalid("ACL bounds exceeded"));
        }
        let header = unsafe { std::ptr::read_unaligned(raw.cast::<ACE_HEADER>().as_ptr()) };
        let bytes = header.AceSize as usize;
        if header.AceType != 0
            || bytes < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
            || offset + bytes > size.AclBytesInUse as usize
        {
            return Err(invalid("unsupported ACL entry"));
        }
        let ace = unsafe { std::ptr::read_unaligned(raw.cast::<ACCESS_ALLOWED_ACE>().as_ptr()) };
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        let sid_header = unsafe {
            std::ptr::read_unaligned(raw.as_ptr().cast::<u8>().add(sid_offset).cast::<[u8; 8]>())
        };
        if sid_header[0] != 1
            || sid_header[1] > 15
            || sid_offset + 8 + 4 * sid_header[1] as usize > bytes
        {
            return Err(invalid("invalid ACL trustee bounds"));
        }
        let trustee = sid_to_string(unsafe { raw.as_ptr().cast::<u8>().add(sid_offset).cast() })?;
        let inherited_only = u32::from(header.AceFlags) & INHERIT_ONLY_ACE != 0;
        let trusted = trustee == sid || trustee == "S-1-5-18";
        let unsafe_access = GENERIC_ALL
            | GENERIC_WRITE
            | WRITE_DAC
            | WRITE_OWNER
            | DELETE
            | FILE_DELETE_CHILD
            | FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_EA
            | FILE_WRITE_ATTRIBUTES;
        let permitted = trusted
            || (!private
                && (inherited_only || trustee == "S-1-5-32-544" || ace.Mask & unsafe_access == 0));
        if !permitted {
            return Err(invalid("DACL grants another account access"));
        }
        own_access |=
            !inherited_only && trustee == sid && ace.Mask & (GENERIC_ALL | FILE_ALL_ACCESS) != 0;
        offset += bytes;
    }
    if !own_access {
        return Err(invalid("owner access missing"));
    }
    Ok(())
}

pub(super) fn check_private(path: &Path, directory: bool) -> io::Result<File> {
    open(path, directory, false)
}

pub(crate) fn new_file(path: &Path) -> io::Result<File> {
    let text = path
        .to_str()
        .ok_or_else(|| invalid("Unicode file path required"))?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid("file parent missing"))?;
    let _pin = CreateParent::prepare(parent, parent, text, text)
        .map_err(|_| invalid("unsafe file name or parent"))?;
    open(path, false, true)
}

pub(crate) fn new_directory(path: &Path) -> io::Result<()> {
    let sid = current_user_sid()?;
    let sddl: Vec<u16> = format!("O:{sid}D:P(A;OICI;GA;;;{sid})(A;OICI;GA;;;SY)")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let mut descriptor = null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let created = unsafe { CreateDirectoryW(wide(path).as_ptr(), &attributes) };
    let error = io::Error::last_os_error();
    unsafe {
        LocalFree(descriptor);
    }
    if created == 0 {
        return Err(error);
    }
    check_private(path, true)?;
    Ok(())
}

pub(super) fn check_parent(path: &Path) -> io::Result<()> {
    let raw = unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            READ_CONTROL | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_handle(raw) };
    verify_security(&file, true, false)
}

pub(super) struct Owned {
    pub child: Child,
    job: Arc<OwnedHandle>,
    monitor_done: Arc<AtomicBool>,
    monitor: Option<std::thread::JoinHandle<()>>,
    status: Option<ExitStatus>,
    logs: Vec<std::sync::mpsc::Receiver<bool>>,
    logs_ok: bool,
    log_bytes: Arc<std::sync::atomic::AtomicUsize>,
}

pub(super) struct StopRecord {
    pub reaped: bool,
    pub group_empty: bool,
    pub exit: Option<i32>,
}

impl Owned {
    pub fn spawn(mut command: Command) -> io::Result<Self> {
        let raw = unsafe { CreateJobObjectW(null(), null()) };
        if raw.is_null() {
            return Err(io::Error::last_os_error());
        }
        let job = Arc::new(unsafe { OwnedHandle::from_raw_handle(raw) });
        let limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            BasicLimitInformation: JOBOBJECT_BASIC_LIMIT_INFORMATION {
                LimitFlags: JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                ..Default::default()
            },
            ..Default::default()
        };
        if unsafe { SetHandleInformation(raw, HANDLE_FLAG_INHERIT, 0) } == 0
            || unsafe {
                SetInformationJobObject(
                    raw,
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                    std::mem::size_of_val(&limits) as u32,
                )
            } == 0
        {
            return Err(io::Error::last_os_error());
        }
        command.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
        let mut child = command.spawn()?;
        let assigned = unsafe { AssignProcessToJobObject(raw, child.as_raw_handle()) } != 0;
        if !assigned || resume(&child).is_err() {
            unsafe {
                TerminateJobObject(raw, 1);
            }
            let _ = child.kill();
            let _ = child.wait();
            return Err(invalid("cannot assign and resume owned process job"));
        }
        let monitor_done = Arc::new(AtomicBool::new(false));
        let done = monitor_done.clone();
        let watched = job.clone();
        let monitor = std::thread::spawn(move || {
            while !done.load(Ordering::SeqCst) {
                if INTERRUPTED.load(Ordering::SeqCst) || OVERFLOW.load(Ordering::SeqCst) {
                    unsafe {
                        TerminateJobObject(watched.as_raw_handle(), 1);
                    }
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        Ok(Self {
            child,
            job,
            monitor_done,
            monitor: Some(monitor),
            status: None,
            logs: Vec::new(),
            logs_ok: true,
            log_bytes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }
    pub fn pid(&self) -> u32 {
        self.child.id()
    }
    pub fn log(&mut self, mut source: impl io::Read + Send + 'static, mut file: File) {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        self.logs.push(receiver);
        let total = self.log_bytes.clone();
        std::thread::spawn(move || {
            use io::Write;
            let result = (|| -> io::Result<()> {
                let mut bytes = [0u8; 8192];
                loop {
                    let count = source.read(&mut bytes)?;
                    if count == 0 {
                        return file.sync_all();
                    }
                    if total.fetch_add(count, Ordering::SeqCst) + count > 8 * 1024 * 1024 {
                        OVERFLOW.store(true, Ordering::SeqCst);
                        return Err(invalid("process log limit exceeded"));
                    }
                    file.write_all(&bytes[..count])?;
                }
            })();
            let _ = sender.send(result.is_ok());
        });
    }
    pub fn running(&self) -> bool {
        self.status.is_none()
            && unsafe { WaitForSingleObject(self.child.as_raw_handle(), 0) } == WAIT_TIMEOUT
    }
    pub fn wait_exit(&self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline && !INTERRUPTED.load(Ordering::SeqCst) {
            if !self.running() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        !self.running()
    }
    fn empty(&self) -> bool {
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        (unsafe {
            QueryInformationJobObject(
                self.job.as_raw_handle(),
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
                null_mut(),
            )
        } != 0
            && info.ActiveProcesses == 0)
    }
    pub fn stop(&mut self) -> StopRecord {
        let terminated = unsafe { TerminateJobObject(self.job.as_raw_handle(), 1) } != 0;
        let deadline = Instant::now() + Duration::from_secs(10);
        while self.running() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if !self.running() && self.status.is_none() {
            self.status = self.child.try_wait().ok().flatten();
        }
        while !self.empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        self.monitor_done.store(true, Ordering::SeqCst);
        if let Some(monitor) = self.monitor.take() {
            let _ = monitor.join();
        }
        for result in self.logs.drain(..) {
            self.logs_ok &= result.recv_timeout(Duration::from_secs(2)).unwrap_or(false);
        }
        StopRecord {
            reaped: self.status.is_some(),
            group_empty: terminated && self.empty() && self.logs_ok,
            exit: self.status.and_then(|s| s.code()),
        }
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn resume(child: &Child) -> io::Result<()> {
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut found = None;
    let mut count = 0;
    let deadline = Instant::now() + Duration::from_millis(500);
    let mut next = unsafe { Thread32First(snapshot.as_raw_handle(), &mut entry) };
    while next != 0 {
        count += 1;
        if count > 65_536 || Instant::now() >= deadline {
            return Err(invalid("thread enumeration bound exceeded"));
        }
        if entry.th32OwnerProcessID == child.id() && found.replace(entry.th32ThreadID).is_some() {
            return Err(invalid("ambiguous suspended process threads"));
        }
        next = unsafe { Thread32Next(snapshot.as_raw_handle(), &mut entry) };
    }
    if unsafe { GetLastError() } != ERROR_NO_MORE_FILES {
        return Err(io::Error::last_os_error());
    }
    let id = found.ok_or_else(|| invalid("missing suspended process thread"))?;
    let raw = unsafe {
        OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
            0,
            id,
        )
    };
    if raw.is_null() {
        return Err(io::Error::last_os_error());
    }
    let thread = unsafe { OwnedHandle::from_raw_handle(raw) };
    if unsafe { GetProcessIdOfThread(thread.as_raw_handle()) } != child.id()
        || unsafe { ResumeThread(thread.as_raw_handle()) } != 1
    {
        return Err(invalid("suspended process thread identity mismatch"));
    }
    Ok(())
}
