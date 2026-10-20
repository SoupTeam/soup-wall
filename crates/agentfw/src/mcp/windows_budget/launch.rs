// SPDX-License-Identifier: Apache-2.0
//! Budgeted Windows launch primitive for the existing OwnedChild owner.
//!
//! Job-list process creation closes the suspended-create/assignment crash gap.
//! No helper process, second process manager or nightly Rust API is used.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::windows::{
    ffi::OsStrExt,
    io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle},
    process::ExitStatusExt,
};
use std::path::{Component, Prefix};
use std::time::Duration;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::{
    Foundation::{
        GetLastError, SetHandleInformation, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
        GENERIC_READ, GENERIC_WRITE, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE,
        WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, OPEN_EXISTING, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT,
    },
    System::{JobObjects::IsProcessInJob, Threading::*},
};

fn wide(value: &OsStr) -> Result<Vec<u16>, &'static str> {
    let mut value: Vec<u16> = value.encode_wide().collect();
    if value.contains(&0) || value.len() > 32766 {
        return Err("windows_budget_launch_input_invalid");
    }
    value.push(0);
    Ok(value)
}

fn quote(value: &OsStr) -> Result<Vec<u16>, &'static str> {
    let value = wide(value)?;
    let mut out = vec![b'"' as u16];
    let mut slashes = 0;
    for &unit in &value[..value.len() - 1] {
        if unit == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        out.extend(std::iter::repeat_n(
            b'\\' as u16,
            if unit == b'"' as u16 {
                slashes * 2 + 1
            } else {
                slashes
            },
        ));
        out.push(unit);
        slashes = 0;
    }
    out.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    out.push(b'"' as u16);
    Ok(out)
}

// This private primitive receives the native collector builder only: inherited
// environment plus explicit additions/removals, never env_clear/raw_arg. Keep
// that narrow contract at the call site; std does not expose an env_clear flag.
fn environment(command: &std::process::Command) -> Result<Vec<u16>, &'static str> {
    fn key(value: &OsStr) -> Result<String, &'static str> {
        let value = value
            .to_str()
            .ok_or("windows_budget_environment_unsupported")?;
        let drive = value.len() == 3
            && value.starts_with('=')
            && value.as_bytes()[1].is_ascii_alphabetic()
            && value.ends_with(':');
        if value.is_empty()
            || !value.is_ascii()
            || (!drive && value.contains('='))
            || value.contains('\0')
        {
            return Err("windows_budget_environment_unsupported");
        }
        Ok(value.to_ascii_uppercase())
    }
    let mut variables: BTreeMap<String, (OsString, OsString)> = BTreeMap::new();
    for (name, value) in std::env::vars_os() {
        variables.insert(key(&name)?, (name, value));
    }
    for (name, value) in command.get_envs() {
        let canonical = key(name)?;
        if let Some(value) = value {
            variables.insert(canonical, (name.to_owned(), value.to_owned()));
        } else {
            variables.remove(&canonical);
        }
    }
    let mut block = Vec::new();
    for (_, (name, value)) in variables {
        let name = wide(&name)?;
        block.extend_from_slice(&name[..name.len() - 1]);
        block.push(b'=' as u16);
        block.extend(wide(&value)?);
        if block.len() > 65535 {
            return Err("windows_budget_environment_unsupported");
        }
    }
    if block.is_empty() {
        block.push(0)
    }
    block.push(0);
    Ok(block)
}

fn pipe(parent_reads: bool) -> Result<(NamedPipeServer, OwnedHandle), &'static str> {
    let name = format!(r"\\.\pipe\sw-mcp-budget-{:032x}", rand::random::<u128>());
    let acl = crate::private_file_windows::PrivateAcl::new()
        .map_err(|_| "windows_budget_pipe_security")?;
    let mut attributes = acl.attributes();
    let parent = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .access_inbound(parent_reads)
            .access_outbound(!parent_reads)
            .create_with_security_attributes_raw(
                &name,
                (&mut attributes as *mut windows_sys::Win32::Security::SECURITY_ATTRIBUTES).cast(),
            )
    }
    .map_err(|_| "windows_budget_pipe_create")?;
    if unsafe { SetHandleInformation(parent.as_raw_handle().cast(), HANDLE_FLAG_INHERIT, 0) } == 0 {
        return Err("windows_budget_pipe_security");
    }
    attributes.bInheritHandle = 1;
    let name = wide(OsStr::new(&name))?;
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            if parent_reads {
                GENERIC_WRITE
            } else {
                GENERIC_READ
            },
            0,
            &attributes,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | SECURITY_IDENTIFICATION | SECURITY_SQOS_PRESENT,
            std::ptr::null_mut(),
        )
    };
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err("windows_budget_pipe_create");
    }
    // SAFETY: CreateFileW returned an owned pipe handle. Only this child end is
    // inheritable, and process creation uses an explicit three-handle whitelist.
    Ok((parent, unsafe { OwnedHandle::from_raw_handle(raw.cast()) }))
}

struct Attributes {
    storage: Vec<u128>,
    initialized: bool,
}
impl Attributes {
    fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
    fn new() -> Result<Self, &'static str> {
        let mut bytes = 0;
        unsafe {
            InitializeProcThreadAttributeList(std::ptr::null_mut(), 2, 0, &mut bytes);
        }
        if bytes == 0 || bytes > 16384 {
            return Err("windows_budget_launch_attributes");
        }
        let mut list = Self {
            storage: vec![0; bytes.div_ceil(std::mem::size_of::<u128>())],
            initialized: false,
        };
        if unsafe { InitializeProcThreadAttributeList(list.pointer(), 2, 0, &mut bytes) } == 0 {
            return Err("windows_budget_launch_attributes");
        }
        list.initialized = true;
        Ok(list)
    }
    fn set(&mut self, attribute: u32, handles: &[HANDLE]) -> Result<(), &'static str> {
        if unsafe {
            UpdateProcThreadAttribute(
                self.pointer(),
                0,
                attribute as usize,
                handles.as_ptr().cast(),
                std::mem::size_of_val(handles),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        } == 0
        {
            return Err("windows_budget_launch_attributes");
        }
        Ok(())
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.pointer());
            }
        }
    }
}

pub(crate) struct Process {
    process: OwnedHandle,
    thread: OwnedHandle,
    pid: u32,
    waited: bool,
}
impl Process {
    pub(crate) fn id(&self) -> u32 {
        self.pid
    }
    pub(crate) fn raw_handle(&self) -> RawHandle {
        self.process.as_raw_handle()
    }
    pub(crate) fn resume(&mut self, job: &OwnedHandle) -> Result<(), &'static str> {
        let mut member = 0;
        if unsafe {
            IsProcessInJob(
                self.process.as_raw_handle().cast(),
                job.as_raw_handle().cast(),
                &mut member,
            )
        } == 0
            || member == 0
        {
            return Err("native_child_job_membership");
        }
        if unsafe { ResumeThread(self.thread.as_raw_handle().cast()) } != 1 {
            return Err("native_child_thread_resume");
        }
        Ok(())
    }
    pub(crate) fn start_kill(&mut self) -> std::io::Result<()> {
        if unsafe { TerminateProcess(self.process.as_raw_handle().cast(), 1) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    pub(crate) async fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        loop {
            match unsafe { WaitForSingleObject(self.process.as_raw_handle().cast(), 0) } {
                WAIT_OBJECT_0 => {
                    let mut code = 0;
                    if unsafe { GetExitCodeProcess(self.process.as_raw_handle().cast(), &mut code) }
                        == 0
                    {
                        return Err(std::io::Error::last_os_error());
                    }
                    self.waited = true;
                    return Ok(std::process::ExitStatus::from_raw(code));
                }
                WAIT_TIMEOUT => tokio::time::sleep(Duration::from_millis(10)).await,
                _ => return Err(std::io::Error::last_os_error()),
            }
        }
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if !self.waited {
            let _ = self.start_kill();
        }
    }
}

fn create(
    command: &std::process::Command,
    job: &OwnedHandle,
    stdio: &[HANDLE; 3],
) -> Result<Process, &'static str> {
    if usize::BITS != 64 {
        return Err("windows_budget_architecture_unsupported");
    }
    let program = std::path::Path::new(command.get_program());
    let local_disk = matches!(program.components().next(), Some(Component::Prefix(prefix))
        if matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)));
    if !program.is_absolute()
        || !local_disk
        || !program
            .extension()
            .is_some_and(|extension| extension.to_string_lossy().eq_ignore_ascii_case("exe"))
    {
        return Err("windows_budget_program_unsupported");
    }
    let application = wide(command.get_program())?;
    let directory = command
        .get_current_dir()
        .map(|path| wide(path.as_os_str()))
        .transpose()?;
    let mut line = quote(command.get_program())?;
    for argument in command.get_args() {
        line.push(b' ' as u16);
        line.extend(quote(argument)?);
    }
    if line.len() > 32766 {
        return Err("windows_budget_launch_input_invalid");
    }
    line.push(0);
    let mut environment = environment(command)?;
    let jobs = [job.as_raw_handle().cast()];
    let mut attributes = Attributes::new()?;
    attributes.set(PROC_THREAD_ATTRIBUTE_JOB_LIST, &jobs)?;
    attributes.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, stdio)?;
    let startup = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: stdio[0],
            hStdOutput: stdio[1],
            hStdError: stdio[2],
            ..Default::default()
        },
        lpAttributeList: attributes.pointer(),
    };
    let mut info = PROCESS_INFORMATION::default();
    // SAFETY: all writable buffers, attribute backing values and private handles
    // live through CreateProcessW. Only stdin/out/err are inherited; the Job
    // handle is a creation attribute, never a child-visible inherited handle.
    let ok = unsafe {
        CreateProcessW(
            application.as_ptr(),
            line.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_SUSPENDED
                | CREATE_NO_WINDOW
                | CREATE_UNICODE_ENVIRONMENT
                | EXTENDED_STARTUPINFO_PRESENT,
            environment.as_ptr().cast(),
            directory
                .as_ref()
                .map_or(std::ptr::null(), |value| value.as_ptr()),
            &startup.StartupInfo,
            &mut info,
        )
    };
    let error = unsafe { GetLastError() };
    environment.fill(0);
    if ok == 0 {
        return Err(
            if matches!(error, ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND) {
                "native_child_spawn"
            } else {
                "windows_budget_launch_refused"
            },
        );
    }
    // SAFETY: successful CreateProcessW transfers both process/thread handles.
    Ok(Process {
        process: unsafe { OwnedHandle::from_raw_handle(info.hProcess.cast()) },
        thread: unsafe { OwnedHandle::from_raw_handle(info.hThread.cast()) },
        pid: info.dwProcessId,
        waited: false,
    })
}

pub(crate) async fn spawn_suspended(
    command: &std::process::Command,
    job: &OwnedHandle,
) -> Result<super::super::native_child::Child, &'static str> {
    let (stdin, child_in) = pipe(false)?;
    let (stdout, child_out) = pipe(true)?;
    let (stderr, child_err) = pipe(true)?;
    for parent in [&stdin, &stdout, &stderr] {
        tokio::time::timeout(Duration::from_secs(1), parent.connect())
            .await
            .map_err(|_| "windows_budget_pipe_connect")?
            .map_err(|_| "windows_budget_pipe_connect")?;
    }
    let process = create(
        command,
        job,
        &[
            child_in.as_raw_handle().cast(),
            child_out.as_raw_handle().cast(),
            child_err.as_raw_handle().cast(),
        ],
    )?;
    drop((child_in, child_out, child_err));
    Ok(super::super::native_child::Child::budgeted(
        process, stdin, stdout, stderr,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_preserves_empty_unicode_quotes_and_trailing_backslashes() {
        for (input, expected) in [
            ("", "\"\""),
            ("two words", "\"two words\""),
            ("café", "\"café\""),
            ("a\"b", "\"a\\\"b\""),
            ("C:\\end\\", "\"C:\\end\\\\\""),
        ] {
            assert_eq!(
                String::from_utf16(&quote(OsStr::new(input)).unwrap()).unwrap(),
                expected
            );
        }
        assert!(quote(OsStr::new("embedded\0nul")).is_err());
    }

    #[test]
    fn environment_applies_case_insensitive_removal_and_preserves_unicode() {
        let mut command = std::process::Command::new("unused.exe");
        command.env_remove("pAtH").env("SOU96_VALUE", "café=ok");
        let block = environment(&command).unwrap();
        assert!(block.ends_with(&[0, 0]));
        let entries: Vec<String> = block
            .split(|unit| *unit == 0)
            .filter(|entry| !entry.is_empty())
            .map(|entry| String::from_utf16(entry).unwrap())
            .collect();
        assert!(entries
            .iter()
            .all(|entry| !entry.to_ascii_uppercase().starts_with("PATH=")));
        assert!(entries.iter().any(|entry| entry == "SOU96_VALUE=café=ok"));
    }
}
