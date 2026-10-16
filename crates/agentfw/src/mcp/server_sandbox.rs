// SPDX-License-Identifier: Apache-2.0

//! The process boundary for the selected, read-only filesystem MCP server.
//!
//! This is deliberately separate from the guarded-command sandbox. It does
//! not execute an arbitrary MCP command: the runtime and installed dependency
//! tree are operator-pinned, the entry point is fixed, and every host mount is
//! read-only. Unsupported systems and missing bubblewrap features fail closed.

use std::fs::File;
#[cfg(any(target_os = "linux", test))]
use std::path::Component;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Stdio;

use anyhow::{bail, Context};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use tokio::process::{Child, Command};

use super::server_profile::ProfileConfig;
#[cfg(target_os = "linux")]
use super::server_profile::{package_tree_sha256, SERVER_ENTRYPOINT};

/// The namespace layout is fixed independently of host installation paths.
pub(crate) const SANDBOX_WORKSPACE: &str = "/workspace";
pub(crate) const SANDBOX_PROFILE: &str = "sw-mcp/filesystem-readonly/linux-bwrap/1";

/// File descriptors remain owned until the child has consumed its mount list.
/// The caller must use `spawn`, rather than extracting a command and dropping
/// the descriptors before the fork/exec boundary.
#[derive(Debug)]
pub(crate) struct PreparedServerSandbox {
    command: Command,
    _pins: Vec<File>,
    workspace: PathBuf,
}

impl PreparedServerSandbox {
    pub(crate) fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub(crate) fn spawn(mut self) -> anyhow::Result<Child> {
        self.command
            .spawn()
            .context("failed to start the selected MCP server sandbox")
    }
}

/// Pin and verify the exact operator-installed runtime before any child runs.
/// There is no shell, PATH search, package download, or unsandboxed fallback.
pub(crate) fn prepare(profile: &ProfileConfig) -> anyhow::Result<PreparedServerSandbox> {
    #[cfg(target_os = "linux")]
    {
        prepare_linux(profile)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = profile;
        bail!("the selected MCP server profile requires Linux bubblewrap");
    }
}

/// Kill the outer process group and reap bubblewrap. Bubblewrap's strict PID
/// namespace and `--die-with-parent` terminate descendants even if they create
/// their own session/process group. Call this before dropping transport tasks.
pub(crate) async fn terminate(child: &mut Child) -> anyhow::Result<()> {
    #[cfg(target_os = "linux")]
    let group_error = if let Some(pid) = child.id() {
        // `process_group(0)` creates a group whose id is this live child pid.
        // A live, unreaped child prevents pid/group reuse during this call.
        let result = unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            (error.raw_os_error() != Some(libc::ESRCH)).then_some(error)
        } else {
            None
        }
    } else {
        None
    };
    // An unexpected process-group error must not skip the individual kill or
    // reap attempt. Keep its failure for the final cleanup-verification result.
    let kill_error = child.start_kill().err();
    let reaped = tokio::time::timeout(std::time::Duration::from_secs(3), child.wait())
        .await
        .context("MCP sandbox cleanup is unverified: process did not exit within three seconds")?;
    reaped.context("failed to reap MCP sandbox")?;
    #[cfg(target_os = "linux")]
    if let Some(error) = group_error {
        return Err(error).context("MCP sandbox cleanup is unverified: process-group kill failed");
    }
    if let Some(error) = kill_error {
        return Err(error).context("MCP sandbox cleanup is unverified: individual kill failed");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn normalized_absolute(path: &Path) -> bool {
    path.is_absolute()
        && path.parent().is_some()
        && path
            .components()
            .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[cfg(any(target_os = "linux", test))]
fn valid_library_destination(path: &Path) -> bool {
    normalized_absolute(path)
        && ["/lib", "/lib64", "/usr/lib", "/usr/lib64"]
            .iter()
            .any(|root| path.starts_with(root) && path != Path::new(root))
}

#[cfg(target_os = "linux")]
fn open_directory(path: &Path) -> anyhow::Result<(PathBuf, File)> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    if !normalized_absolute(path) {
        bail!("MCP sandbox directory must be a normalized absolute path");
    }
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("MCP sandbox directory must not be a symlink");
    }
    let canonical = path.canonicalize()?;
    if canonical.parent().is_none() {
        bail!("MCP sandbox refuses the host filesystem root");
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&canonical)?;
    let opened = file.metadata()?;
    if metadata.dev() != opened.dev() || metadata.ino() != opened.ino() {
        bail!("MCP sandbox directory identity changed while preparing");
    }
    Ok((canonical, file))
}

#[cfg(target_os = "linux")]
fn hash_file(file: &File) -> anyhow::Result<String> {
    use std::os::unix::fs::FileExt;
    let mut hasher = Sha256::new();
    let mut offset = 0;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read_at(&mut buffer, offset)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        offset += read as u64;
        if offset > 256 * 1024 * 1024 {
            bail!("MCP sandbox runtime asset exceeds its size limit");
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(target_os = "linux")]
fn open_verified_file(path: &Path, expected: &str, executable: bool) -> anyhow::Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    if !normalized_absolute(path) {
        bail!("MCP sandbox asset must be a normalized absolute path");
    }
    // System loaders commonly have an intentional symlink at /lib64. The
    // descriptor pins the resolved regular file; the mount destination remains
    // the explicitly declared interpreter/library path.
    let canonical = path.canonicalize()?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(canonical)?;
    let before = file.metadata()?;
    if !before.is_file() || (executable && before.permissions().mode() & 0o111 == 0) {
        bail!("MCP sandbox runtime asset has an invalid file type or mode");
    }
    if hash_file(&file)? != expected {
        bail!("MCP sandbox runtime asset digest mismatch");
    }
    let after = file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        bail!("MCP sandbox runtime asset changed while hashing");
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn descriptor_path(file: &File) -> PathBuf {
    use std::os::fd::AsRawFd;
    PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()))
}

/// Deny all socket creation/connect/send operations, including pathname Unix
/// sockets that may exist in the read-only workspace. Network namespaces alone
/// do not isolate such filesystem sockets. Anonymous socketpair IPC stays usable.
#[cfg(target_os = "linux")]
fn network_filter() -> anyhow::Result<File> {
    use std::io::{Seek, SeekFrom, Write};
    use std::os::fd::FromRawFd;

    #[cfg(target_arch = "x86_64")]
    let architecture = 0xc000_003e_u32;
    #[cfg(target_arch = "aarch64")]
    let architecture = 0xc000_00b7_u32;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let architecture = 0_u32;
    if architecture == 0 {
        bail!("MCP server sandbox architecture is unsupported");
    }
    let deny = 0x0005_0000 | libc::EACCES as u32;
    let mut instructions: Vec<(u16, u8, u8, u32)> = vec![
        (0x20, 0, 0, 4), // seccomp_data.arch
        (0x15, 1, 0, architecture),
        (0x06, 0, 0, 0x8000_0000), // KILL_PROCESS for another syscall ABI
        (0x20, 0, 0, 0),           // seccomp_data.nr
        (0x35, 0, 1, 0x4000_0000),
        (0x06, 0, 0, 0x8000_0000), // reject x32/unknown high syscall numbers
    ];
    for syscall in [
        libc::SYS_socket,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_io_uring_setup,
        libc::SYS_openat2,
        libc::SYS_ioctl,
    ] {
        instructions.push((0x15, 0, 1, syscall as u32));
        instructions.push((0x06, 0, 0, deny));
    }
    #[cfg(target_arch = "x86_64")]
    {
        instructions.push((0x15, 0, 1, libc::SYS_creat as u32));
        instructions.push((0x06, 0, 0, deny));
    }
    // Read-only bind mounts do not prevent writing to an existing FIFO or all
    // device effects. Deny writable opens independently of the mounted file
    // type. openat2 takes an indirect flags structure, so it is denied above.
    // O_TMPFILE also contains O_DIRECTORY: only its distinct high bit belongs
    // in this mask, preserving ordinary read-only directory opens.
    let write_flags = (libc::O_WRONLY
        | libc::O_RDWR
        | libc::O_CREAT
        | libc::O_TRUNC
        | libc::O_APPEND
        | (libc::O_TMPFILE & !libc::O_DIRECTORY)) as u32;
    let open_calls = [
        (libc::SYS_openat, 32_u32),
        #[cfg(target_arch = "x86_64")]
        (libc::SYS_open, 24_u32),
    ];
    for (syscall, flags_offset) in open_calls {
        instructions.extend([
            (0x15, 0, 4, syscall as u32),
            (0x20, 0, 0, flags_offset), // low word of this syscall's flags
            (0x45, 0, 1, write_flags),  // JSET
            (0x06, 0, 0, deny),
            (0x06, 0, 0, 0x7fff_0000), // read-only open: ALLOW
        ]);
    }
    instructions.push((0x06, 0, 0, 0x7fff_0000)); // ALLOW
    let fd = unsafe {
        libc::memfd_create(
            c"sou62-network-filter".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to create MCP syscall filter");
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    for (code, yes, no, value) in instructions {
        file.write_all(&code.to_ne_bytes())?;
        file.write_all(&[yes, no])?;
        file.write_all(&value.to_ne_bytes())?;
    }
    file.seek(SeekFrom::Start(0))?;
    let sealed = unsafe {
        libc::fcntl(
            fd,
            libc::F_ADD_SEALS,
            libc::F_SEAL_WRITE | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_SEAL,
        )
    };
    if sealed < 0 {
        return Err(std::io::Error::last_os_error()).context("failed to seal MCP syscall filter");
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn prepare_linux(profile: &ProfileConfig) -> anyhow::Result<PreparedServerSandbox> {
    prepare_linux_command(
        profile,
        &[
            format!("/mcp-server/{SERVER_ENTRYPOINT}"),
            SANDBOX_WORKSPACE.to_owned(),
        ],
    )
}

#[cfg(target_os = "linux")]
fn prepare_linux_command(
    profile: &ProfileConfig,
    node_args: &[String],
) -> anyhow::Result<PreparedServerSandbox> {
    use std::os::fd::AsRawFd;

    let (workspace, workspace_pin) = open_directory(&profile.workspace)?;
    let (_, package_pin) = open_directory(&profile.package_root)?;
    if package_tree_sha256(&descriptor_path(&package_pin).join("."))? != profile.package_tree_sha256
    {
        bail!("MCP server installed package tree digest mismatch");
    }
    let runtime_pin = open_verified_file(&profile.runtime_path, &profile.runtime_sha256, true)?;
    let bwrap_pin = open_verified_file(&profile.bwrap_path, &profile.bwrap_sha256, true)?;
    let mut pins = vec![workspace_pin, package_pin, runtime_pin];
    let mut mounts = vec![
        (0, PathBuf::from(SANDBOX_WORKSPACE)),
        (1, PathBuf::from("/mcp-server")),
        (2, PathBuf::from("/mcp-runtime/node")),
    ];
    if profile.libraries.is_empty() || profile.libraries.len() > 32 {
        bail!("MCP sandbox requires a bounded, explicit library list");
    }
    let mut destinations = std::collections::BTreeSet::new();
    for library in &profile.libraries {
        if !valid_library_destination(&library.path) || !destinations.insert(library.path.clone()) {
            bail!("MCP sandbox library destination is invalid or duplicated");
        }
        let pin = open_verified_file(&library.path, &library.sha256, false)?;
        mounts.push((pins.len(), library.path.clone()));
        pins.push(pin);
    }

    // Executing a pinned fd avoids re-opening a substituted bwrap pathname.
    // The fd is CLOEXEC: the kernel consumes the executable before closing it.
    let mut command = Command::new(descriptor_path(&bwrap_pin));
    command.args([
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--unshare-user",
        "--disable-userns",
        "--assert-userns-disabled",
        "--clearenv",
        "--cap-drop",
        "ALL",
        "--hostname",
        "mcp-readonly",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--size",
        "67108864",
        "--tmpfs",
        "/tmp",
    ]);
    for (index, destination) in mounts {
        // --ro-bind-fd consumes and closes the descriptor before exec. Older
        // bwrap versions without this primitive must fail closed: spelling the
        // source as /proc/self/fd/N with --ro-bind would leak host descriptors
        // into the untrusted server and bypass its read-only mount namespace.
        command
            .arg("--ro-bind-fd")
            .arg(pins[index].as_raw_fd().to_string())
            .arg(destination);
    }
    let seccomp = network_filter()?;
    command
        .arg("--seccomp")
        .arg(seccomp.as_raw_fd().to_string());
    pins.push(seccomp);
    command.args([
        "--chdir",
        SANDBOX_WORKSPACE,
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "PATH",
        "/mcp-runtime",
        "--setenv",
        "UV_THREADPOOL_SIZE",
        "16",
        "--",
        "/mcp-runtime/node",
    ]);
    command
        .args(node_args)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0);
    let fds: Vec<_> = pins.iter().map(AsRawFd::as_raw_fd).collect();
    // Only async-signal-safe syscalls run in the forked child. Parent descriptor
    // flags remain CLOEXEC, avoiding cross-spawn inheritance in other threads.
    unsafe {
        command.pre_exec(move || {
            // Mark every ambient non-stdio descriptor CLOEXEC, including any
            // supplied by foreign libraries. Only the explicit, consumed mount
            // and filter descriptors below survive into bubblewrap.
            if libc::syscall(libc::SYS_close_range, 3_u32, u32::MAX, 4_u32) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            let no_core = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &no_core) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            for fd in &fds {
                if libc::fcntl(*fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    pins.push(bwrap_pin);
    Ok(PreparedServerSandbox {
        command,
        _pins: pins,
        workspace,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_exact_library_file_destinations() {
        assert!(valid_library_destination(Path::new(
            "/lib64/ld-linux-x86-64.so.2"
        )));
        assert!(valid_library_destination(Path::new(
            "/usr/lib/x86_64-linux-gnu/libc.so.6"
        )));
        for path in [
            "/",
            "/lib",
            "/lib64",
            "/usr/lib",
            "/usr/library/secret",
            "/home/user/key",
            "/lib/../etc/passwd",
            "lib/libc.so.6",
        ] {
            assert!(!valid_library_destination(Path::new(path)), "{path}");
        }
    }

    /// An explicitly invoked positive acceptance test. A missing runtime,
    /// bubblewrap feature, or namespace permission is a failure, never a skip.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires SOU62_SANDBOX_TEST_PROFILE and real Linux namespaces"]
    async fn selected_server_sandbox_isolates_real_node() {
        use std::io::{Read, Write};
        use std::net::{TcpListener, TcpStream};
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::net::{UnixListener, UnixStream};
        use std::time::Duration;
        use tokio::io::AsyncReadExt;

        let config_path = std::env::var_os("SOU62_SANDBOX_TEST_PROFILE")
            .expect("SOU62_SANDBOX_TEST_PROFILE is required for positive acceptance");
        let mut profile = ProfileConfig::read(&std::fs::read(config_path).unwrap()).unwrap();
        let owned = tempfile::tempdir().unwrap();
        let workspace = owned.path().join("workspace");
        std::fs::create_dir(&workspace).unwrap();
        std::fs::write(workspace.join("allowed.txt"), b"allowed read").unwrap();
        let outside = owned.path().join("outside-secret.txt");
        std::fs::write(&outside, b"outside unchanged").unwrap();
        let outside_new = owned.path().join("outside-created.txt");
        profile.workspace = workspace.canonicalize().unwrap();
        let receiver = TcpListener::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let address = receiver.local_addr().unwrap();
        // Calibrate the independent egress witness on the host first.
        let calibration = TcpStream::connect(address).unwrap();
        let calibrated = loop {
            match receiver.accept() {
                Ok(pair) => break pair,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::yield_now()
                }
                Err(error) => panic!("receiver calibration failed: {error}"),
            }
        };
        drop(calibration);
        drop(calibrated);
        let unix_path = workspace.join("egress.sock");
        let unix_receiver = UnixListener::bind(&unix_path).unwrap();
        unix_receiver.set_nonblocking(true).unwrap();
        let unix_calibration = UnixStream::connect(&unix_path).unwrap();
        let unix_calibrated = unix_receiver.accept().unwrap();
        drop(unix_calibration);
        drop(unix_calibrated);
        let fifo_path = workspace.join("egress.fifo");
        let fifo_name = std::ffi::CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        let mut fifo_receiver = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo_path)
            .unwrap();
        let mut fifo_calibration = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo_path)
            .unwrap();
        fifo_calibration.write_all(b"calibrated").unwrap();
        let mut calibrated_bytes = [0_u8; 10];
        fifo_receiver.read_exact(&mut calibrated_bytes).unwrap();
        assert_eq!(&calibrated_bytes, b"calibrated");
        drop(fifo_calibration);
        // Deliberately supply one non-CLOEXEC host descriptor. The child-wide
        // close_range(CLOEXEC) must prevent this independent source from leaking.
        let host_file = File::open(&outside).unwrap();
        let ambient_fd = unsafe { libc::fcntl(host_file.as_raw_fd(), libc::F_DUPFD, 3) };
        assert!(ambient_fd >= 0);
        let _ambient = unsafe { File::from_raw_fd(ambient_fd) };
        let outside_json = serde_json::to_string(&outside).unwrap();
        let outside_new_json = serde_json::to_string(&outside_new).unwrap();
        let script = format!(
            r#"
const fs = require('node:fs');
const net = require('node:net');
const refused = (fn) => {{ try {{ fn(); return false; }} catch {{ return true; }} }};
const result = {{
  allowed: fs.readFileSync('/workspace/allowed.txt', 'utf8') === 'allowed read',
  workspaceWriteDenied: refused(() => fs.writeFileSync('/workspace/new.txt', 'denied')),
  workspaceReplaceDenied: refused(() => fs.writeFileSync('/workspace/allowed.txt', 'denied')),
  fifoWriteDenied: refused(() => {{ const fd=fs.openSync('/workspace/egress.fifo', fs.constants.O_WRONLY|fs.constants.O_NONBLOCK); try {{ fs.writeSync(fd,'host FIFO write'); }} finally {{ fs.closeSync(fd); }} }}),
  outsideReadDenied: refused(() => fs.readFileSync({outside_json})),
  outsideWriteDenied: refused(() => fs.writeFileSync({outside_json}, 'denied')),
  outsideCreateDenied: refused(() => fs.writeFileSync({outside_new_json}, 'denied')),
  hostHomeAbsent: !fs.existsSync('/home') && !fs.existsSync('/root'),
  inheritedSecretAbsent: process.env.SOU62_INHERITED_SECRET === undefined,
  cleanEnv: Object.keys(process.env).sort().join(',') === 'HOME,LANG,PATH,PWD,UV_THREADPOOL_SIZE',
  netNamespace: fs.readlinkSync('/proc/self/ns/net'),
  pidNamespace: fs.readlinkSync('/proc/self/ns/pid'),
  descriptorTargets: fs.readdirSync('/proc/self/fd').flatMap(fd => {{ try {{ return [fs.readlinkSync('/proc/self/fd/'+fd)]; }} catch {{ return []; }} }})
}};
const probe = options => new Promise(resolve => {{
  let done = false, socket;
  const finish = denied => {{ if(done) return; done=true; if(socket) socket.destroy(); resolve(denied); }};
  try {{
    socket = net.connect(options);
    socket.on('connect', () => finish(false));
    socket.on('error', () => finish(true));
    socket.setTimeout(500, () => finish(true));
  }} catch {{ finish(true); }}
}});
Promise.all([probe({{host:'127.0.0.1',port:{port}}}), probe({{path:'/workspace/egress.sock'}})]).then(([tcp,unix]) => {{
  result.egressDenied=tcp;
  result.unixSocketDenied=unix;
  console.log(JSON.stringify(result));
}});
"#,
            port = address.port()
        );
        let mut prepared = prepare_linux_command(&profile, &["-e".to_owned(), script]).unwrap();
        prepared
            .command
            .env("SOU62_INHERITED_SECRET", "must-not-reach-server");
        let mut child = prepared.spawn().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();
        drop(child.stdin.take());
        let collected = tokio::time::timeout(Duration::from_secs(10), async {
            let mut output = Vec::new();
            let mut errors = Vec::new();
            let (read_out, read_err, status) = tokio::join!(
                stdout.read_to_end(&mut output),
                stderr.read_to_end(&mut errors),
                child.wait(),
            );
            read_out.unwrap();
            read_err.unwrap();
            (output, errors, status.unwrap())
        })
        .await;
        if collected.is_err() {
            terminate(&mut child).await.unwrap();
            panic!("real Node sandbox positive acceptance timed out");
        }
        let (output, errors, status) = collected.unwrap();
        assert!(
            status.success(),
            "sandbox failed: {}",
            String::from_utf8_lossy(&errors)
        );
        let observed: serde_json::Value = serde_json::from_slice(&output).unwrap();
        for key in [
            "allowed",
            "workspaceWriteDenied",
            "workspaceReplaceDenied",
            "fifoWriteDenied",
            "outsideReadDenied",
            "outsideWriteDenied",
            "outsideCreateDenied",
            "hostHomeAbsent",
            "inheritedSecretAbsent",
            "cleanEnv",
            "egressDenied",
            "unixSocketDenied",
        ] {
            assert_eq!(observed[key], true, "sandbox boundary failed: {key}");
        }
        for namespace in ["net", "pid"] {
            let host = std::fs::read_link(format!("/proc/self/ns/{namespace}")).unwrap();
            assert_ne!(
                observed[format!("{namespace}Namespace")].as_str().unwrap(),
                host.to_str().unwrap()
            );
        }
        for target in observed["descriptorTargets"].as_array().unwrap() {
            let target = target.as_str().unwrap();
            for host_path in [
                profile.workspace.as_path(),
                profile.package_root.as_path(),
                profile.runtime_path.as_path(),
                owned.path(),
            ] {
                assert!(
                    !target.starts_with(host_path.to_str().unwrap()),
                    "host descriptor leaked into server"
                );
            }
        }
        assert_eq!(
            std::fs::read(workspace.join("allowed.txt")).unwrap(),
            b"allowed read"
        );
        assert!(!workspace.join("new.txt").exists());
        assert_eq!(std::fs::read(&outside).unwrap(), b"outside unchanged");
        assert!(!outside_new.exists());
        assert_eq!(
            receiver.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert_eq!(
            unix_receiver.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        let mut unexpected_fifo_bytes = [0_u8; 64];
        assert_eq!(
            fifo_receiver.read(&mut unexpected_fifo_bytes).unwrap(),
            0,
            "host FIFO receiver observed a write"
        );
        println!("SOU62_SANDBOX_POSITIVE profile={SANDBOX_PROFILE} allowed_read=true workspace_write_denied=true outside_read_denied=true outside_write_denied=true egress_witness_calibrated=true egress_denied=true pathname_unix_socket_denied=true fifo_witness_calibrated=true fifo_write_denied=true inherited_env_absent=true host_descriptors_absent=true private_net_pid=true");
    }
}
