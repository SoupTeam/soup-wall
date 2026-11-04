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

fn bounded(path: &Path, cap: u64, b: &mut Budget) -> Result<Vec<u8>> {
    let limit = b.read_limit(cap)?;
    let mut raw = vec![];
    fs::File::open(path)?.take(limit).read_to_end(&mut raw)?;
    ensure!(
        limit > cap || (raw.len() as u64) < limit,
        "removal_read_cap"
    );
    b.tick(raw.len())?;
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
    ensure!(
        host_user_namespace(b)?,
        "removal_host_user_namespace_required"
    );
    blockers.extend(
        scan(
            Path::new("/proc"),
            &roots,
            &objects,
            b,
            unsafe { libc::geteuid() },
            std::process::id(),
        )?
        .into_iter()
        .map(|code| {
            if code == "live_process_references_selected_scope" {
                code
            } else {
                "process_evidence_unavailable_or_inconsistent"
            }
        }),
    );
    blockers.sort();
    blockers.dedup();
    Ok(blockers)
}

pub(super) fn host_user_namespace(b: &mut Budget) -> Result<bool> {
    let raw = bounded(Path::new("/proc/self/uid_map"), 4096, b)?;
    Ok(std::str::from_utf8(&raw)?
        .split_whitespace()
        .collect::<Vec<_>>()
        == ["0", "0", "4294967295"])
}

pub(super) fn environment(b: &mut Budget) -> Result<Vec<&'static str>> {
    scan(
        Path::new("/proc"),
        &[],
        &BTreeSet::new(),
        b,
        unsafe { libc::geteuid() },
        std::process::id(),
    )
}

fn process_identity(raw: &[u8], pid: u32) -> Result<(&[u8], &[u8])> {
    let split = raw
        .iter()
        .rposition(|v| *v == b')')
        .ok_or_else(|| anyhow::anyhow!("process_identity_inconsistent"))?;
    let head = raw[..split]
        .split(|v| *v == b' ')
        .next()
        .unwrap_or_default();
    ensure!(
        head == pid.to_string().as_bytes(),
        "process_identity_inconsistent"
    );
    let fields = raw[split + 1..]
        .split(|v| v.is_ascii_whitespace())
        .filter(|v| !v.is_empty())
        .collect::<Vec<_>>();
    ensure!(
        fields.len() >= 20
            && fields[0].len() == 1
            && !fields[19].is_empty()
            && fields[19].iter().all(u8::is_ascii_digit),
        "process_identity_inconsistent"
    );
    Ok((fields[19], fields[0]))
}

fn credentials(raw: &[u8]) -> Result<Vec<u32>> {
    let rows = raw
        .split(|v| *v == b'\n')
        .filter_map(|line| line.strip_prefix(b"Uid:"))
        .collect::<Vec<_>>();
    ensure!(rows.len() == 1, "process_identity_inconsistent");
    let values = std::str::from_utf8(rows[0])?
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(values.len() == 4, "process_identity_inconsistent");
    Ok(values)
}

fn scan(
    proc_root: &Path,
    roots: &[PathBuf],
    objects: &BTreeSet<(u64, u64)>,
    b: &mut Budget,
    uid: u32,
    own_pid: u32,
) -> Result<Vec<&'static str>> {
    scan_observed(proc_root, roots, objects, b, uid, own_pid, |_| {})
}

fn scan_observed(
    proc_root: &Path,
    roots: &[PathBuf],
    objects: &BTreeSet<(u64, u64)>,
    b: &mut Budget,
    uid: u32,
    own_pid: u32,
    after_evidence: impl Fn(&Path),
) -> Result<Vec<&'static str>> {
    let mut blockers = vec![];
    let mut count = 0;
    for entry in fs::read_dir(proc_root)? {
        b.tick(0)?;
        let entry = entry?;
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == own_pid {
            continue;
        }
        count += 1;
        ensure!(count <= 4096, "removal_process_inventory_cap");
        let p = entry.path();
        let inspected = (|| -> Result<bool> {
            let m = fs::metadata(&p)?;
            let before = bounded(&p.join("stat"), 8192, b)?;
            let (start, state) = process_identity(&before, pid)?;
            let before_uids = credentials(&bounded(&p.join("status"), 16384, b)?)?;
            let owned = before_uids.contains(&uid) || m.uid() == uid;
            ensure!(
                !owned || before_uids == [uid; 4],
                "process_identity_inconsistent"
            );
            if owned && state != b"Z" {
                for leaf in ["cwd", "exe", "root"] {
                    ensure!(b.read_limit(8192)? > 8192, "removal_read_cap");
                    let path = fs::read_link(p.join(leaf))?;
                    b.tick(path.as_os_str().len())?;
                    let m = fs::metadata(p.join(leaf))?;
                    if objects.contains(&(m.dev(), m.ino()))
                        || roots.iter().any(|root| path.starts_with(root))
                    {
                        return Ok(true);
                    }
                }
                for leaf in ["cmdline", "environ"] {
                    let raw = bounded(&p.join(leaf), 1024 * 1024, b)?;
                    if referenced(&raw, roots) {
                        return Ok(true);
                    }
                }
                let raw = bounded(&p.join("maps"), 1024 * 1024, b)?;
                for line in std::str::from_utf8(&raw)?.lines() {
                    let fields = line.split_whitespace().collect::<Vec<_>>();
                    if fields.len() >= 5 {
                        let numbers = fields[3].split_once(':').and_then(|(a, c)| {
                            Some((
                                u32::from_str_radix(a, 16).ok()?,
                                u32::from_str_radix(c, 16).ok()?,
                            ))
                        });
                        if let (Some((major, minor)), Ok(inode)) =
                            (numbers, fields[4].parse::<u64>())
                        {
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
                        if referenced(&line.as_bytes()[i..], roots) {
                            return Ok(true);
                        }
                    }
                }
                let mut fds = 0;
                for fd in fs::read_dir(p.join("fd"))? {
                    fds += 1;
                    ensure!(fds <= 1024, "removal_process_inventory_cap");
                    ensure!(b.read_limit(8192)? > 8192, "removal_read_cap");
                    let fdpath = fd?.path();
                    let path = match fs::read_link(&fdpath) {
                        Ok(p) => p,
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(e) => return Err(e.into()),
                    };
                    b.tick(path.as_os_str().len())?;
                    let by_inode = match fs::metadata(&fdpath) {
                        Ok(m) => objects.contains(&(m.dev(), m.ino())),
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
                        Err(e) => return Err(e.into()),
                    };
                    if by_inode || roots.iter().any(|root| path.starts_with(root)) {
                        return Ok(true);
                    }
                }
            }
            after_evidence(&p);
            let after = bounded(&p.join("stat"), 8192, b)?;
            let after_meta = fs::metadata(&p)?;
            ensure!(
                before_uids == credentials(&bounded(&p.join("status"), 16384, b)?)?,
                "process_identity_inconsistent"
            );
            ensure!(
                start == process_identity(&after, pid)?.0
                    && (state != b"Z" || process_identity(&after, pid)?.1 == b"Z")
                    && m.uid() == after_meta.uid()
                    && m.dev() == after_meta.dev()
                    && m.ino() == after_meta.ino(),
                "process_identity_inconsistent"
            );
            Ok(false)
        })();
        match inspected {
            Ok(true) => blockers.push("live_process_references_selected_scope"),
            Ok(false) => {}
            Err(error) => {
                // Only a confirmed disappearance can be disregarded. Hidden or
                // inaccessible identity evidence never proves inactivity.
                if !matches!(fs::symlink_metadata(&p), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
                {
                    let code = if error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|e| e.kind() == std::io::ErrorKind::PermissionDenied)
                    {
                        "process_evidence_inaccessible"
                    } else if error.to_string() == "process_identity_inconsistent" {
                        "process_identity_inconsistent"
                    } else {
                        "process_evidence_unavailable_or_inconsistent"
                    };
                    blockers.push(code);
                }
            }
        }
    }
    blockers.sort();
    blockers.dedup();
    Ok(blockers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn record(pid: u32, start: u64, state: &str) -> String {
        format!(
            "{pid} (private canary (worker)) {state} {} {start}",
            ["0"; 18].join(" ")
        )
    }
    fn fixture() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        let p = root.path().join("41");
        fs::create_dir(&p).unwrap();
        fs::write(p.join("stat"), record(41, 100, "S")).unwrap();
        let uid = unsafe { libc::geteuid() };
        fs::write(p.join("status"), format!("Uid: {uid} {uid} {uid} {uid}\n")).unwrap();
        for leaf in ["cmdline", "environ", "maps"] {
            fs::write(p.join(leaf), b"private-canary").unwrap();
        }
        for leaf in ["cwd", "exe", "root"] {
            symlink(root.path(), p.join(leaf)).unwrap();
        }
        fs::create_dir(p.join("fd")).unwrap();
        root
    }
    fn observe(root: &Path) -> Vec<&'static str> {
        scan(
            root,
            &[],
            &BTreeSet::new(),
            &mut Budget::new(),
            unsafe { libc::geteuid() },
            99,
        )
        .unwrap()
    }
    #[test]
    fn pid_reuse_and_zombie_identity_changes_refuse() {
        for state in ["S", "Z"] {
            let root = fixture();
            fs::write(root.path().join("41/stat"), record(41, 100, state)).unwrap();
            let rows = scan_observed(
                root.path(),
                &[],
                &BTreeSet::new(),
                &mut Budget::new(),
                unsafe { libc::geteuid() },
                99,
                |p| fs::write(p.join("stat"), record(41, 101, "S")).unwrap(),
            )
            .unwrap();
            assert_eq!(rows, ["process_identity_inconsistent"]);
        }
    }
    #[test]
    fn disappearance_requires_missing_identity_and_malformed_stat_refuses() {
        let root = fixture();
        fs::write(root.path().join("41/stat"), record(42, 100, "S")).unwrap();
        assert_eq!(observe(root.path()), ["process_identity_inconsistent"]);
        let root = fixture();
        let rows = scan_observed(
            root.path(),
            &[],
            &BTreeSet::new(),
            &mut Budget::new(),
            unsafe { libc::geteuid() },
            99,
            |p| fs::remove_dir_all(p).unwrap(),
        )
        .unwrap();
        assert!(rows.is_empty());
    }
    #[test]
    fn previous_good_observation_never_authorizes_later_use() {
        let root = fixture();
        assert!(observe(root.path()).is_empty());
        let selected = root.path().join("selected");
        fs::create_dir(&selected).unwrap();
        let cwd = root.path().join("41/cwd");
        fs::remove_file(&cwd).unwrap();
        symlink(&selected, &cwd).unwrap();
        let rows = scan(
            root.path(),
            &[selected],
            &BTreeSet::new(),
            &mut Budget::new(),
            unsafe { libc::geteuid() },
            99,
        )
        .unwrap();
        assert_eq!(rows, ["live_process_references_selected_scope"]);
    }
    #[test]
    fn inaccessible_same_uid_and_individual_limits_are_never_positive() {
        let root = fixture();
        let path = root.path().join("41/environ");
        if unsafe { libc::geteuid() } != 0 {
            fs::set_permissions(&path, fs::Permissions::from_mode(0)).unwrap();
            assert_eq!(observe(root.path()), ["process_evidence_inaccessible"]);
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        fs::write(path, vec![b'x'; 1024 * 1024 + 1]).unwrap();
        assert!(!observe(root.path()).is_empty());
    }
}
