// SPDX-License-Identifier: Apache-2.0
//! Deliberately bypass the parser: the kernel must contain late link changes.
use super::*;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::{ffi::OsStrExt, fs::symlink};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::io::AsyncReadExt;

struct LinkRestore(PathBuf, PathBuf);
impl Drop for LinkRestore {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        symlink(&self.1, &self.0).expect("restore only the owned fixture link");
    }
}
struct Writer {
    stop: Arc<AtomicBool>,
    count: Arc<AtomicUsize>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Drop for Writer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}

#[tokio::test]
#[ignore = "requires the explicit pinned Linux tracked-symlink profile"]
async fn selected_tracked_symlinks_late_and_racing_outside_reads_are_os_contained() {
    let profile =
        ProfileConfig::read(&std::fs::read(std::env::var("SOU150_TEST_PROFILE").unwrap()).unwrap())
            .unwrap();
    assert_eq!(
        profile.format,
        super::super::server_profile::git_tracked_symlinks::FORMAT
    );
    let link = profile.workspace.join("tracked-link");
    assert_eq!(std::fs::read_link(&link).unwrap(), Path::new("notes.txt"));
    let _restore = LinkRestore(link.clone(), PathBuf::from("notes.txt"));
    let outside = tempfile::Builder::new()
        .prefix("sou150-os-owned-")
        .tempdir_in(profile.workspace.parent().unwrap())
        .unwrap();
    let marker = outside.path().join("marker");
    let unrelated = outside.path().join("unrelated");
    std::fs::write(&marker, b"SOU150 owned external marker").unwrap();
    std::fs::write(&unrelated, b"unrelated state unchanged").unwrap();
    let relative = PathBuf::from("..")
        .join(outside.path().file_name().unwrap())
        .join("marker");
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    assert!(fd >= 0);
    let mut watcher = unsafe { File::from_raw_fd(fd) };
    let name = std::ffi::CString::new(marker.as_os_str().as_bytes()).unwrap();
    assert!(
        unsafe { libc::inotify_add_watch(watcher.as_raw_fd(), name.as_ptr(), libc::IN_OPEN) } >= 0
    );
    let mut buffer = [0; 4096];
    for round in 0..3 {
        std::fs::remove_file(&link).unwrap();
        symlink("notes.txt", &link).unwrap();
        let script = format!(
            r#"
import json,pathlib,time
expected=pathlib.Path('/workspace/notes.txt').read_bytes()
assert expected
for attempt in range(256):
    try:
        data=pathlib.Path('/workspace/tracked-link').read_bytes()
        assert {racing} and data == expected, 'outside bytes disclosed'
    except OSError:
        pass
    time.sleep(0.002)
try:
    pathlib.Path({marker:?}).read_bytes()
    raise AssertionError('outside direct read succeeded')
except OSError:
    pass
print(json.dumps({{'late_link_contained':True,'useful_read':True}}))
"#,
            racing = if round == 2 { "True" } else { "False" },
            marker = marker.to_str().unwrap()
        );
        // Capture descriptors on a valid tracked link, then replace it. Python
        // reads directly; neither the Rust parser nor the Git guard can refuse.
        let prepared =
            prepare_linux_command(&profile, &["-I".into(), "-B".into(), "-c".into(), script])
                .unwrap();
        std::fs::remove_file(&link).unwrap();
        symlink(if round == 0 { &marker } else { &relative }, &link).unwrap();
        assert_eq!(
            std::fs::read(&link).unwrap(),
            b"SOU150 owned external marker"
        );
        assert!(
            watcher.read(&mut buffer).unwrap() > 0,
            "real IN_OPEN calibration required"
        );
        let writer = if round == 2 {
            let stop = Arc::new(AtomicBool::new(false));
            let count = Arc::new(AtomicUsize::new(0));
            let (stopping, counting, link, marker) =
                (stop.clone(), count.clone(), link.clone(), marker.clone());
            let thread = std::thread::spawn(move || {
                let temporary = link.with_file_name("sou150-atomic-new");
                assert!(!temporary.exists());
                while !stopping.load(Ordering::SeqCst) {
                    let n = counting.fetch_add(1, Ordering::SeqCst);
                    symlink(
                        if n.is_multiple_of(2) {
                            Path::new("notes.txt")
                        } else {
                            marker.as_path()
                        },
                        &temporary,
                    )
                    .unwrap();
                    std::fs::rename(&temporary, &link).unwrap();
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
            });
            Some(Writer {
                stop,
                count,
                thread: Some(thread),
            })
        } else {
            None
        };
        let (mut child, mut budget, mut owner, _pid) = prepared.spawn().await.unwrap();
        let (mut stdout, mut stderr) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
        drop(child.stdin.take());
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = tokio::time::timeout(std::time::Duration::from_secs(40), async {
            let (a, b) = tokio::join!(stdout.read_to_end(&mut out), stderr.read_to_end(&mut err));
            a.unwrap();
            b.unwrap();
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
        if let Some(writer) = &writer {
            assert!(writer.count.load(Ordering::SeqCst) > 1);
        }
        drop(writer);
        assert!(
            result.expect("bounded owned link probe").success(),
            "{}",
            String::from_utf8_lossy(&err)
        );
        assert!(String::from_utf8_lossy(&out).contains("late_link_contained"));
        assert_eq!(
            watcher.read(&mut buffer).unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "outside marker opened under restriction"
        );
    }
    assert_eq!(
        std::fs::read(&unrelated).unwrap(),
        b"unrelated state unchanged"
    );
    println!("SOU150_LATE_RACE_OS_MARKER_PASSED");
}
