// SPDX-License-Identifier: Apache-2.0
#[cfg(unix)]
#[test]
fn workspace_root_open_race_never_rebinds_outside_authority() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let dir = tempfile::tempdir().unwrap();
    let ws = dir.path().join("workspace");
    let moved = dir.path().join("prior");
    let outside = dir.path().join("outside");
    std::fs::create_dir(&ws).unwrap();
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(ws.join("input.txt"), "inside").unwrap();
    std::fs::write(outside.join("input.txt"), "outside owned canary").unwrap();
    let first = agentfw::sandbox::PinnedWorkspace::open(&ws).unwrap();
    assert_eq!(first.read_file(&ws.join("input.txt")).unwrap(), "inside");
    let stop = Arc::new(AtomicBool::new(false));
    let signal = stop.clone();
    let root = ws.clone();
    let out = outside.clone();
    let handle = std::thread::spawn(move || {
        while !signal.load(Ordering::Relaxed) {
            std::fs::rename(&root, &moved).unwrap();
            std::os::unix::fs::symlink(&out, &root).unwrap();
            std::thread::yield_now();
            std::fs::remove_file(&root).unwrap();
            std::fs::rename(&moved, &root).unwrap();
        }
    });
    let mut leaked = false;
    let mut authorized = 0;
    for _ in 0..50000 {
        if let Ok(p) = agentfw::sandbox::PinnedWorkspace::open(&ws) {
            authorized += 1;
            if let Ok(c) = p.read_file(&ws.join("input.txt")) {
                if c == "outside owned canary" {
                    leaked = true;
                    break;
                }
            }
        }
    }
    stop.store(true, Ordering::Relaxed);
    handle.join().unwrap();
    println!(
        "REVIEW107_ROOT_OPEN_RACE authorized={} outside_canary={}",
        authorized, leaked
    );
    assert!(
        !leaked,
        "root substitution during pinning must not authorize outside canary"
    );
}
