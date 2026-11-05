// SPDX-License-Identifier: Apache-2.0
//! Shared bounded real-runtime exercises. Legacy native tests call these too.
use super::*;
use tokio::io::AsyncReadExt;

/// Always collect the existing owner's authenticated cleanup result, including
/// timeout, output-limit and interruption paths. No failed run becomes a skip.
async fn collect(prepared: PreparedServerSandbox) -> anyhow::Result<(Vec<u8>, serde_json::Value)> {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let (mut child, mut budget, mut owner, _) = prepared
        .spawn()
        .await
        .context("exercise_prerequisite_failed")?;
    let stdout = child
        .stdout
        .take()
        .context("exercise_observation_invalid")?;
    let stderr = child
        .stderr
        .take()
        .context("exercise_observation_invalid")?;
    let mut stdout = stdout.take(65537);
    let mut stderr = stderr.take(65537);
    drop(child.stdin.take());
    let collected = tokio::select! {
        _ = tokio::signal::ctrl_c() => Err(anyhow::anyhow!("exercise_interrupted")),
        _ = term.recv() => Err(anyhow::anyhow!("exercise_interrupted")),
        result = tokio::time::timeout(std::time::Duration::from_secs(15), async {
            let mut output = Vec::new();
            let mut errors = Vec::new();
            let (out, err) = tokio::join!(
                stdout.read_to_end(&mut output),
                stderr.read_to_end(&mut errors),
            );
            out?; err?;
            anyhow::ensure!(output.len() <= 65536 && errors.len() <= 65536, "exercise_output_limit");
            Ok(output)
        }) => result.context("exercise_timeout").and_then(|result| result),
    };
    let owner_cleanup = owner.finish().await;
    let budget_cleanup = if let Some(budget) = budget.as_mut() {
        budget.finish().await
    } else {
        Ok(())
    };
    if owner_cleanup.is_err() || budget_cleanup.is_err() {
        let _ = terminate(&mut child).await;
        anyhow::bail!("exercise_cleanup_unconfirmed");
    }
    let reaped = tokio::time::timeout(std::time::Duration::from_secs(2), child.wait()).await;
    anyhow::ensure!(matches!(reaped, Ok(Ok(_))), "exercise_cleanup_unconfirmed");
    let output = collected.context("exercise_cleanup_confirmed")?;
    anyhow::ensure!(
        matches!(reaped, Ok(Ok(status)) if status.success()),
        "exercise_runtime_failed"
    );
    let cleanup = owner.metadata();
    Ok((output, cleanup))
}

pub(crate) async fn git(
    profile: ProfileConfig,
    verified: bool,
) -> anyhow::Result<serde_json::Value> {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    anyhow::ensure!(
        super::super::server_profile::git_selected(&profile.format),
        "exercise_profile_kind_mismatch"
    );
    let owned = tempfile::tempdir().context("exercise_observation_invalid")?;
    let outcome = async {
    let outside = owned.path().join("outside-secret");
    std::fs::write(&outside, b"outside unchanged").context("exercise_observation_invalid")?;
    let host_file = File::open(&outside).context("exercise_observation_invalid")?;
    let descriptor = unsafe { libc::fcntl(host_file.as_raw_fd(), libc::F_DUPFD, 3) };
    anyhow::ensure!(descriptor >= 0, "exercise_witness_failed");
    let _ambient = unsafe { File::from_raw_fd(descriptor) };
    let receiver = TcpListener::bind("127.0.0.1:0").context("exercise_observation_invalid")?;
    receiver
        .set_nonblocking(true)
        .context("exercise_observation_invalid")?;
    let address = receiver
        .local_addr()
        .context("exercise_observation_invalid")?;
    let calibration = TcpStream::connect(address).context("exercise_observation_invalid")?;
    let pair = receiver.accept().context("exercise_observation_invalid")?;
    drop(calibration);
    drop(pair);
    let outside_json = serde_json::to_string(&outside).context("exercise_observation_invalid")?;
    let script = format!(
        r#"
import asyncio, ctypes, errno, json, os, pathlib, socket, subprocess
def denied(fn):
    try:
        fn()
        return False
    except OSError:
        return True
# The pinned portable Python build need not expose optional os wrappers.
# Call the actual native syscalls; the Rust test supplies this architecture's
# numbers rather than assuming an x86-64 ABI inside the Python fixture.
native_libc = ctypes.CDLL(None, use_errno=True)
native_libc.syscall.restype = ctypes.c_long
def native_call(number, *arguments):
    ctypes.set_errno(0)
    result = native_libc.syscall(ctypes.c_long(number), *arguments)
    if result == -1:
        raise OSError(ctypes.get_errno(), 'owned syscall probe failed')
    return result
def memfd(flags):
    return native_call({memfd_syscall}, ctypes.c_char_p(b'sou79-owned'), ctypes.c_uint(flags))
def ordinary_memfd():
    descriptor = memfd({memfd_cloexec})
    os.close(descriptor)
    return True
class SchedulingParameter(ctypes.Structure):
    _fields_ = [('sched_priority', ctypes.c_int)]
def scheduler_change():
    parameter = SchedulingParameter(0)
    native_call({scheduler_syscall}, ctypes.c_int(0), ctypes.c_int({normal_scheduler}), ctypes.byref(parameter))
def denied_by_filter(fn):
    try:
        descriptor = fn()
        if type(descriptor) is int:
            os.close(descriptor)
        return False
    except OSError as error:
        return error.errno == errno.EACCES
def descriptors():
    result = []
    for entry in pathlib.Path('/proc/self/fd').iterdir():
        try: result.append(os.readlink(entry))
        except OSError: pass
    return result
def null_open():
    fd = os.open('/dev/null', os.O_RDWR)
    os.close(fd)
    return True
git = subprocess.run(['/mcp-runtime/git', 'status', '--porcelain'], cwd='/workspace', capture_output=True, timeout=5)
loop = asyncio.new_event_loop()
assert loop.run_until_complete(asyncio.wait_for(asyncio.to_thread(lambda: 42), 3)) == 42
loop.close()
result = {{
 'asyncio_ready': True,
 'null_open_allowed': null_open(),
 'git_read': git.returncode == 0,
 'ordinary_memfd_allowed': ordinary_memfd(),
 'hugetlb_creation_denied': denied_by_filter(lambda: memfd({memfd_hugetlb})),
 'scheduler_change_denied': denied_by_filter(scheduler_change),
 'git_exit': git.returncode,
 'git_error': git.stderr[-2000:].decode('utf-8', 'replace'),
 'workspace_write_denied': denied(lambda: pathlib.Path('/workspace/sandbox-forbidden').write_text('denied')),
 'runtime_write_denied': denied(lambda: pathlib.Path('/mcp-runtime/git').open('wb')),
 'tmp_write_denied': denied(lambda: pathlib.Path('/tmp/forbidden').write_text('denied')),
 'other_device_write_denied': denied(lambda: pathlib.Path('/dev/zero').open('wb')),
 'fifo_write_denied': denied(lambda: os.open('/workspace/.sou68-runtime-probe.fifo', os.O_WRONLY | os.O_NONBLOCK)),
 'outside_read_denied': denied(lambda: pathlib.Path({outside_json}).read_bytes()),
 'outside_write_denied': denied(lambda: pathlib.Path({outside_json}).write_bytes(b'denied')),
 'egress_denied': denied(lambda: socket.create_connection(('127.0.0.1', {port}), 1)),
 'unix_socket_denied': denied(lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)),
 'ambient_env_absent': 'SOU68_INHERITED_SECRET' not in os.environ,
 'home_absent': not pathlib.Path('/home').exists() and not pathlib.Path('/root').exists(),
 'descriptor_targets': descriptors(),
 'net_namespace': os.readlink('/proc/self/ns/net'),
 'pid_namespace': os.readlink('/proc/self/ns/pid'),
}}
import time
time.sleep(0.25)
print(json.dumps(result))
"#,
        port = address.port(),
        memfd_syscall = libc::SYS_memfd_create,
        scheduler_syscall = libc::SYS_sched_setscheduler,
        memfd_cloexec = libc::MFD_CLOEXEC,
        memfd_hugetlb = libc::MFD_HUGETLB,
        normal_scheduler = libc::SCHED_OTHER,
    );
    let args = vec!["-I".into(), "-B".into(), "-c".into(), script];
    let mut prepared = if verified {
        anyhow::ensure!(
            super::super::verified_git::supports_profile(&profile.format),
            "exercise_witness_failed"
        );
        prepare_linux_command_inner(&profile, &args, None, false, true, None, true)
            .context("exercise_observation_invalid")?
    } else {
        prepare_linux_command(&profile, &args, None, false, true, None)
            .context("exercise_observation_invalid")?
    };
    // Add an owned FIFO after repository validation to prove that read-only
    // mounts alone are insufficient, and that Landlock still blocks IPC.
    let fifo_path = profile.workspace.join(".sou68-runtime-probe.fifo");
    anyhow::ensure!(!fifo_path.exists(), "exercise_witness_failed");
    let fifo_name = std::ffi::CString::new(fifo_path.as_os_str().as_bytes())
        .context("exercise_observation_invalid")?;
    anyhow::ensure!(
        (unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }) == (0),
        "exercise_witness_failed"
    );
    let mut fifo_reader = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo_path)
        .context("exercise_observation_invalid")?;
    let mut calibration = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo_path)
        .context("exercise_observation_invalid")?;
    calibration
        .write_all(b"calibrate")
        .context("exercise_observation_invalid")?;
    let mut marker = [0_u8; 9];
    fifo_reader
        .read_exact(&mut marker)
        .context("exercise_observation_invalid")?;
    anyhow::ensure!((&marker) == (b"calibrate"), "exercise_witness_failed");
    drop(calibration);
    prepared
        .command
        .env("SOU68_INHERITED_SECRET", "must-not-reach-server");
    let (output, _cleanup) = collect(prepared).await?;
    let mut forbidden_bytes = [0_u8; 32];
    anyhow::ensure!(
        (fifo_reader
            .read(&mut forbidden_bytes)
            .context("exercise_observation_invalid")?)
            == (0),
        "exercise_witness_failed"
    );
    std::fs::remove_file(fifo_path).context("exercise_observation_invalid")?;
    let result: serde_json::Value =
        serde_json::from_slice(&output).context("exercise_observation_invalid")?;
    for key in [
        "null_open_allowed",
        "asyncio_ready",
        "git_read",
        "ordinary_memfd_allowed",
        "hugetlb_creation_denied",
        "scheduler_change_denied",
        "workspace_write_denied",
        "runtime_write_denied",
        "tmp_write_denied",
        "other_device_write_denied",
        "fifo_write_denied",
        "outside_read_denied",
        "outside_write_denied",
        "egress_denied",
        "unix_socket_denied",
        "ambient_env_absent",
        "home_absent",
    ] {
        anyhow::ensure!((result[key]) == (true), "exercise_witness_failed");
    }
    for namespace in ["net", "pid"] {
        let host = std::fs::read_link(format!("/proc/self/ns/{namespace}"))
            .context("exercise_observation_invalid")?;
        anyhow::ensure!(
            (result[format!("{namespace}_namespace")]
                .as_str()
                .context("exercise_observation_invalid")?)
                != (host.to_str().context("exercise_observation_invalid")?),
            "exercise_witness_failed"
        );
    }
    for target in result["descriptor_targets"]
        .as_array()
        .context("exercise_observation_invalid")?
    {
        for path in [
            &profile.workspace,
            &profile.package_root,
            &profile.runtime_path,
            &owned.path().to_path_buf(),
        ] {
            anyhow::ensure!(
                !target
                    .as_str()
                    .context("exercise_observation_invalid")?
                    .starts_with(path.to_str().context("exercise_observation_invalid")?),
                "exercise_witness_failed"
            );
        }
    }
    anyhow::ensure!(
        (std::fs::read(&outside).context("exercise_observation_invalid")?)
            == (b"outside unchanged"),
        "exercise_witness_failed"
    );
    anyhow::ensure!(
        !profile.workspace.join("sandbox-forbidden").exists(),
        "exercise_witness_failed"
    );
    anyhow::ensure!(
        (receiver
            .accept()
            .err()
            .context("exercise_egress_observed")?
            .kind())
            == (std::io::ErrorKind::WouldBlock),
        "exercise_witness_failed"
    );
    Ok(result)
    }.await;
    owned.close().context("exercise_cleanup_unconfirmed")?;
    outcome
}

pub(crate) async fn filesystem(mut profile: ProfileConfig) -> anyhow::Result<serde_json::Value> {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::net::{UnixListener, UnixStream};

    let owned = tempfile::tempdir().context("exercise_observation_invalid")?;
    let outcome = async {
    let workspace = owned.path().join("workspace");
    std::fs::create_dir(&workspace).context("exercise_observation_invalid")?;
    std::fs::write(workspace.join("allowed.txt"), b"allowed read")
        .context("exercise_observation_invalid")?;
    let outside = owned.path().join("outside-secret.txt");
    std::fs::write(&outside, b"outside unchanged").context("exercise_observation_invalid")?;
    let outside_new = owned.path().join("outside-created.txt");
    profile.workspace = workspace
        .canonicalize()
        .context("exercise_observation_invalid")?;
    profile.workspace_identity = None;
    let receiver = TcpListener::bind("127.0.0.1:0").context("exercise_observation_invalid")?;
    receiver
        .set_nonblocking(true)
        .context("exercise_observation_invalid")?;
    let address = receiver
        .local_addr()
        .context("exercise_observation_invalid")?;
    // Calibrate the independent egress witness on the host first.
    let calibration = TcpStream::connect(address).context("exercise_observation_invalid")?;
    let calibrated = receiver.accept().context("exercise_calibration_failed")?;
    drop(calibration);
    drop(calibrated);
    let unix_path = workspace.join("egress.sock");
    let unix_receiver = UnixListener::bind(&unix_path).context("exercise_observation_invalid")?;
    unix_receiver
        .set_nonblocking(true)
        .context("exercise_observation_invalid")?;
    let unix_calibration =
        UnixStream::connect(&unix_path).context("exercise_observation_invalid")?;
    let unix_calibrated = unix_receiver
        .accept()
        .context("exercise_observation_invalid")?;
    drop(unix_calibration);
    drop(unix_calibrated);
    let fifo_path = workspace.join("egress.fifo");
    let fifo_name = std::ffi::CString::new(fifo_path.as_os_str().as_bytes())
        .context("exercise_observation_invalid")?;
    anyhow::ensure!(
        (unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }) == (0),
        "exercise_witness_failed"
    );
    let mut fifo_receiver = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo_path)
        .context("exercise_observation_invalid")?;
    let mut fifo_calibration = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(&fifo_path)
        .context("exercise_observation_invalid")?;
    fifo_calibration
        .write_all(b"calibrated")
        .context("exercise_observation_invalid")?;
    let mut calibrated_bytes = [0_u8; 10];
    fifo_receiver
        .read_exact(&mut calibrated_bytes)
        .context("exercise_observation_invalid")?;
    anyhow::ensure!(
        (&calibrated_bytes) == (b"calibrated"),
        "exercise_witness_failed"
    );
    drop(fifo_calibration);
    // Deliberately supply one non-CLOEXEC host descriptor. The child-wide
    // close_range(CLOEXEC) must prevent this independent source from leaking.
    let host_file = File::open(&outside).context("exercise_observation_invalid")?;
    let ambient_fd = unsafe { libc::fcntl(host_file.as_raw_fd(), libc::F_DUPFD, 3) };
    anyhow::ensure!(ambient_fd >= 0, "exercise_witness_failed");
    let _ambient = unsafe { File::from_raw_fd(ambient_fd) };
    let outside_json = serde_json::to_string(&outside).context("exercise_observation_invalid")?;
    let outside_new_json =
        serde_json::to_string(&outside_new).context("exercise_observation_invalid")?;
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
  setTimeout(() => console.log(JSON.stringify(result)), 250);
}});
"#,
        port = address.port()
    );
    let mut prepared = prepare_linux_command(
        &profile,
        &["-e".to_owned(), script],
        None,
        false,
        true,
        None,
    )
    .context("exercise_observation_invalid")?;
    prepared
        .command
        .env("SOU62_INHERITED_SECRET", "must-not-reach-server");
    let (output, _cleanup) = collect(prepared).await?;
    let observed: serde_json::Value =
        serde_json::from_slice(&output).context("exercise_observation_invalid")?;
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
        anyhow::ensure!((observed[key]) == (true), "exercise_witness_failed");
    }
    for namespace in ["net", "pid"] {
        let host = std::fs::read_link(format!("/proc/self/ns/{namespace}"))
            .context("exercise_observation_invalid")?;
        anyhow::ensure!(
            (observed[format!("{namespace}Namespace")]
                .as_str()
                .context("exercise_observation_invalid")?)
                != (host.to_str().context("exercise_observation_invalid")?),
            "exercise_witness_failed"
        );
    }
    for target in observed["descriptorTargets"]
        .as_array()
        .context("exercise_observation_invalid")?
    {
        let target = target.as_str().context("exercise_observation_invalid")?;
        for host_path in [
            profile.workspace.as_path(),
            profile.package_root.as_path(),
            profile.runtime_path.as_path(),
            owned.path(),
        ] {
            anyhow::ensure!(
                !target.starts_with(host_path.to_str().context("exercise_observation_invalid")?),
                "exercise_witness_failed"
            );
        }
    }
    anyhow::ensure!(
        (std::fs::read(workspace.join("allowed.txt")).context("exercise_observation_invalid")?)
            == (b"allowed read"),
        "exercise_witness_failed"
    );
    anyhow::ensure!(
        !workspace.join("new.txt").exists(),
        "exercise_witness_failed"
    );
    anyhow::ensure!(
        (std::fs::read(&outside).context("exercise_observation_invalid")?)
            == (b"outside unchanged"),
        "exercise_witness_failed"
    );
    anyhow::ensure!(!outside_new.exists(), "exercise_witness_failed");
    anyhow::ensure!(
        (receiver
            .accept()
            .err()
            .context("exercise_egress_observed")?
            .kind())
            == (std::io::ErrorKind::WouldBlock),
        "exercise_witness_failed"
    );
    anyhow::ensure!(
        (unix_receiver
            .accept()
            .err()
            .context("exercise_egress_observed")?
            .kind())
            == (std::io::ErrorKind::WouldBlock),
        "exercise_witness_failed"
    );
    let mut unexpected_fifo_bytes = [0_u8; 64];
    anyhow::ensure!(
        (fifo_receiver
            .read(&mut unexpected_fifo_bytes)
            .context("exercise_observation_invalid")?)
            == (0),
        "exercise_witness_failed"
    );
    Ok(observed)
    }.await;
    owned.close().context("exercise_cleanup_unconfirmed")?;
    outcome
}
