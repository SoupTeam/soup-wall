// SPDX-License-Identifier: Apache-2.0
//! Conservative read-only active-use evidence. Missing/hidden records block;
//! never stop, signal, query a provider or execute selected code.
use super::{ensure, selected_roots, Budget, Dir, Plan, Result};
use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

fn bounded(path: &Path, cap: u64) -> Result<Vec<u8>> {
    let mut raw = vec![];
    fs::File::open(path)?.take(cap + 1).read_to_end(&mut raw)?;
    ensure!(raw.len() as u64 <= cap, "removal_process_inventory_cap");
    Ok(raw)
}
fn referenced(raw: &[u8], roots: &[PathBuf]) -> bool {
    raw.split(|c| matches!(c, b'\0' | b'\n')).any(|v| {
        let value = String::from_utf8_lossy(v);
        let value = value.strip_suffix(" (deleted)").unwrap_or(&value);
        let value = value.split_once('=').map_or(value, |(_, v)| v);
        roots.iter().any(|p| Path::new(value).starts_with(p))
    })
}
pub(super) fn blockers(plan: &Plan, b: &mut Budget) -> Result<Vec<&'static str>> {
    b.tick(0)?;
    let mut blockers = vec![];
    let roots = selected_roots(&plan.selected);
    let objects: BTreeSet<_> = std::iter::once((plan.root.device, plan.root.inode))
        .chain(
            plan.entries
                .iter()
                .map(|e| (e.identity.device, e.identity.inode)),
        )
        .collect();
    // Custom state is explicit. Every direct run must have accepted completed
    // evidence. A directory name/absent PID alone never proves inactivity.
    for state in &plan.selected.state {
        let d = Dir::open(state)?;
        let names = d.names()?;
        ensure!(names.len() <= 32, "removal_run_inventory_cap");
        for n in names {
            if !n.starts_with("edit-")
                || crate::edit_session::removal_inactive(&state.join(n)).is_err()
            {
                blockers.push("active_or_unverified_retained_run");
            }
        }
    }
    let home = Dir::open(&plan.selected.home)?;
    if home.optional("pilot-runs")?.is_some() {
        let runs = Dir::open(&plan.selected.home.join("pilot-runs"))?;
        if !runs.names()?.is_empty() {
            blockers.push("active_or_unverified_read_only_run");
        }
    }
    // Exact process namespace and kernel proc are part of the stated boundary.
    // An unreadable same-user process is uncertainty, including unrelated work.
    let uid_map = bounded(Path::new("/proc/self/uid_map"), 4096)?;
    ensure!(
        std::str::from_utf8(&uid_map)?
            .split_whitespace()
            .collect::<Vec<_>>()
            == ["0", "0", "4294967295"],
        "removal_host_user_namespace_required"
    );
    let mut count = 0;
    for entry in fs::read_dir("/proc")? {
        b.tick(0)?;
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == std::process::id() {
            continue;
        }
        count += 1;
        ensure!(count <= 4096, "removal_process_inventory_cap");
        let p = entry.path();
        let inspected = (|| -> Result<bool> {
            let m = fs::metadata(&p)?;
            if m.uid() != unsafe { libc::geteuid() } {
                return Ok(false);
            }
            let before = bounded(&p.join("stat"), 8192)?;
            let tail = before
                .rsplit(|c| *c == b')')
                .next()
                .ok_or_else(|| anyhow::anyhow!("removal_process_invalid"))?;
            if tail.split(|c| *c == b' ').find(|p| !p.is_empty()) == Some(b"Z") {
                return Ok(false);
            }
            for leaf in ["cwd", "exe", "root"] {
                let path = fs::read_link(p.join(leaf))?;
                let m = fs::metadata(p.join(leaf))?;
                if objects.contains(&(m.dev(), m.ino()))
                    || roots.iter().any(|root| path.starts_with(root))
                {
                    return Ok(true);
                }
            }
            for leaf in ["cmdline", "environ"] {
                let raw = bounded(&p.join(leaf), 1024 * 1024)?;
                b.tick(raw.len())?;
                if referenced(&raw, &roots) {
                    return Ok(true);
                }
            }
            let raw = bounded(&p.join("maps"), 1024 * 1024)?;
            b.tick(raw.len())?;
            for line in std::str::from_utf8(&raw)?.lines() {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                if fields.len() >= 5 {
                    let numbers = fields[3].split_once(':').and_then(|(a, c)| {
                        Some((
                            u32::from_str_radix(a, 16).ok()?,
                            u32::from_str_radix(c, 16).ok()?,
                        ))
                    });
                    if let (Some((major, minor)), Ok(inode)) = (numbers, fields[4].parse::<u64>()) {
                        if objects.iter().any(|(dev, ino)| {
                            *ino == inode
                                && libc::major(*dev) == major
                                && libc::minor(*dev) == minor
                        }) {
                            return Ok(true);
                        }
                    }
                }
                if let Some(i) = line.find('/') {
                    if referenced(line[i..].as_bytes(), &roots) {
                        return Ok(true);
                    }
                }
            }
            let mut fds = 0;
            for fd in fs::read_dir(p.join("fd"))? {
                fds += 1;
                ensure!(fds <= 1024, "removal_process_inventory_cap");
                let fdpath = fd?.path();
                let path = match fs::read_link(&fdpath) {
                    Ok(p) => p,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e.into()),
                };
                let by_inode = match fs::metadata(&fdpath) {
                    Ok(m) => objects.contains(&(m.dev(), m.ino())),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                    Err(e) => return Err(e.into()),
                };
                if by_inode || roots.iter().any(|root| path.starts_with(root)) {
                    return Ok(true);
                }
            }
            let after = bounded(&p.join("stat"), 8192)?;
            // Process stat has live counters; pin PID/start ticks, not bytes.
            let start = |v: &[u8]| {
                v.rsplit(|c| *c == b')')
                    .next()
                    .and_then(|t| {
                        t.split(|c| c.is_ascii_whitespace())
                            .filter(|p| !p.is_empty())
                            .nth(19)
                    })
                    .map(|v| v.to_vec())
            };
            ensure!(
                start(&before).is_some() && start(&before) == start(&after),
                "removal_process_changed"
            );
            Ok(false)
        })();
        match inspected {
            Ok(true) => blockers.push("live_process_references_selected_scope"),
            Ok(false) => {}
            Err(_) => {
                // A process that actually vanished cannot be active. Any still
                // present but uninspectable object remains a blocker.
                if fs::symlink_metadata(&p).is_ok() {
                    blockers.push("process_evidence_unavailable_or_inconsistent");
                }
            }
        }
    }
    blockers.sort();
    blockers.dedup();
    Ok(blockers)
}
