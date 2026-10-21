// SPDX-License-Identifier: Apache-2.0
use super::*;

#[tokio::test]
#[ignore = "requires the explicit pinned Linux local-clone profile"]
async fn selected_local_clone_denies_actual_helper_execution_and_network() {
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    use tokio::io::AsyncReadExt;
    let profile =
        ProfileConfig::read(&std::fs::read(std::env::var("SOU107_TEST_PROFILE").unwrap()).unwrap())
            .unwrap();
    assert_eq!(
        profile.format,
        super::super::server_profile::git_local_clone::FORMAT
    );
    let marker = profile.workspace.join("helper-read-marker");
    let helper = profile.workspace.join("owned-helper.py");
    let other = profile.workspace.join("owned-helper-other.py");
    std::fs::write(&marker, b"owned execution witness").unwrap();
    let receiver = TcpListener::bind("127.0.0.1:0").unwrap();
    receiver.set_nonblocking(true).unwrap();
    let address = receiver.local_addr().unwrap();
    let code = format!("import pathlib,socket\npathlib.Path(__file__).with_name('helper-read-marker').read_bytes()\nsocket.create_connection(('127.0.0.1',{}),timeout=1).close()\nprint('owned helper executed')\n", address.port());
    std::fs::write(&helper, code).unwrap();
    std::fs::write(&other, b"# different owned fixture\n").unwrap();
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    assert!(fd >= 0);
    let mut watcher = unsafe { File::from_raw_fd(fd) };
    let path = std::ffi::CString::new(marker.as_os_str().as_bytes()).unwrap();
    assert!(
        unsafe { libc::inotify_add_watch(watcher.as_raw_fd(), path.as_ptr(), libc::IN_OPEN) } >= 0
    );
    let calibrated = std::process::Command::new(&profile.git.as_ref().unwrap().path)
        .env("GIT_EXTERNAL_DIFF", &profile.runtime_path)
        .args(["diff", "--no-index", "--ext-diff"])
        .arg(&helper)
        .arg(&other)
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&calibrated.stdout).contains("owned helper executed"));
    let mut buffer = [0; 4096];
    assert!(watcher.read(&mut buffer).unwrap() > 0);
    drop(receiver.accept().unwrap());
    // Independent direct connection confirms receiver readiness as well.
    drop(TcpStream::connect(address).unwrap());
    drop(receiver.accept().unwrap());
    let script = format!(
        r#"
import json,os,pathlib,socket,subprocess
env=dict(os.environ,GIT_CONFIG_COUNT='4',GIT_CONFIG_KEY_3='diff.external',GIT_CONFIG_VALUE_3='/mcp-server/python/bin/python3.11')
p=subprocess.run(['/mcp-runtime/git','diff','--no-index','--ext-diff','/workspace/owned-helper.py','/workspace/owned-helper-other.py'],cwd='/workspace',env=env,capture_output=True,timeout=20)
assert p.returncode != 0 and b'Permission denied' in p.stderr, (p.returncode,p.stdout,p.stderr)
def denied(fn):
    try: fn(); return False
    except OSError: return True
assert denied(lambda: pathlib.Path('/workspace/forbidden-write').write_text('x'))
assert denied(lambda: socket.create_connection(('127.0.0.1',{}),timeout=1))
print(json.dumps({{'helper_exec_denied':True,'network_denied':True,'write_denied':True}}))
"#,
        address.port()
    );
    let prepared =
        prepare_linux_command(&profile, &["-I".into(), "-B".into(), "-c".into(), script]).unwrap();
    let (mut child, mut budget, mut owner, _pid) = prepared.spawn().await.unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    drop(child.stdin.take());
    let mut out = Vec::new();
    let mut err = Vec::new();
    let result = tokio::time::timeout(std::time::Duration::from_secs(40), async {
        let (a, b) = tokio::join!(stdout.read_to_end(&mut out), stderr.read_to_end(&mut err));
        a.unwrap();
        b.unwrap();
        if let Some(budget) = budget.as_mut() {
            budget.finish().await.unwrap();
        }
        owner.finish().await.unwrap();
        child.wait().await.unwrap()
    })
    .await;
    if result.is_err() {
        terminate(&mut child).await.unwrap();
    }
    if let Some(budget) = budget.as_mut() {
        budget.finish().await.unwrap();
    }
    owner.finish().await.unwrap();
    let result = result.expect("bounded local clone sandbox probe");
    assert!(result.success(), "{}", String::from_utf8_lossy(&err));
    assert!(String::from_utf8_lossy(&out).contains("helper_exec_denied"));
    assert_eq!(
        watcher.read(&mut buffer).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        receiver.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(!profile.workspace.join("forbidden-write").exists());
    std::fs::remove_file(helper).unwrap();
    std::fs::remove_file(other).unwrap();
    std::fs::remove_file(marker).unwrap();
    println!("SOU107_HELPER_NETWORK_WITNESSES_PASSED");
}
