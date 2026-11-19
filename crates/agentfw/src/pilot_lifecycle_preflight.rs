// SPDX-License-Identifier: Apache-2.0
//! Current environment prerequisites, never active protection or removal consent.
//! All report strings are fixed codes/guidance. No raw process inventory escapes.
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Satisfied,
    Blocked,
    Unknown,
}
#[derive(Debug, Serialize)]
pub struct Check {
    pub id: &'static str,
    pub phase: &'static str,
    pub outcome: Outcome,
    pub reason_code: &'static str,
}
#[derive(Debug, Serialize)]
pub struct Report {
    pub format: &'static str,
    pub scope: &'static str,
    pub setup: Outcome,
    pub protected_run: Outcome,
    pub removal: Outcome,
    pub active_protection: &'static str,
    pub removal_authorized: bool,
    pub future_inactivity: &'static str,
    pub checks: Vec<Check>,
    pub guidance: Guidance,
    pub limits: Limits,
}
#[derive(Debug, Serialize)]
pub struct Guidance {
    setup: &'static str,
    protected_run: &'static str,
    removal: &'static str,
}
#[derive(Debug, Serialize)]
pub struct Limits {
    seconds: u64,
    total_bytes: usize,
    processes: usize,
    fds_per_process: usize,
    individual_bytes: usize,
}
impl Report {
    fn new() -> Self {
        Self {
            format: "sw-pilot-lifecycle-preflight/1",
            scope: "current_environment_prerequisites_only",
            setup: Outcome::Unknown,
            protected_run: Outcome::Unknown,
            removal: Outcome::Unknown,
            active_protection: "not_measured",
            removal_authorized: false,
            future_inactivity: "not_proven",
            checks: vec![],
            guidance: Guidance {
                setup: SETUP_GUIDANCE,
                protected_run: RUN_GUIDANCE,
                removal: REMOVAL_GUIDANCE,
            },
            limits: Limits {
                seconds: 10,
                total_bytes: 64 * 1024 * 1024,
                processes: 4096,
                fds_per_process: 1024,
                individual_bytes: 1024 * 1024,
            },
        }
    }
    fn add(
        &mut self,
        phase: &'static str,
        id: &'static str,
        outcome: Outcome,
        reason_code: &'static str,
    ) {
        self.checks.push(Check {
            phase,
            id,
            outcome,
            reason_code,
        });
    }
    fn finish(mut self) -> Self {
        for phase in ["setup", "protected_run", "removal"] {
            let values = self
                .checks
                .iter()
                .filter(|c| c.phase == phase)
                .map(|c| c.outcome)
                .collect::<Vec<_>>();
            let outcome = if values.contains(&Outcome::Blocked) {
                Outcome::Blocked
            } else if values.is_empty() || values.contains(&Outcome::Unknown) {
                Outcome::Unknown
            } else {
                Outcome::Satisfied
            };
            match phase {
                "setup" => self.setup = outcome,
                "protected_run" => self.protected_run = outcome,
                _ => self.removal = outcome,
            }
        }
        self
    }
}

pub const SETUP_GUIDANCE: &str = "Use an ordinary native Ubuntu 24.04 x86-64 session with readable kernel namespace controls. Diagnosis changes no settings.";
pub const RUN_GUIDANCE: &str = "The existing exact selected bubblewrap/runtime admission must still succeed before a protected host starts. Static controls do not prove admission or active protection.";
pub const REMOVAL_GUIDANCE: &str = "Use an operator-owned environment with complete same-user visibility in the host user namespace. Review owned services privately or choose a clean environment. Do not use sudo, ignore EACCES or relax ptrace/AppArmor. Preview removal again in its actual current state.";

pub fn inspect() -> Report {
    let mut report = Report::new();
    #[cfg(target_os = "linux")]
    native::inspect(&mut report);
    #[cfg(not(target_os = "linux"))]
    report.add(
        "setup",
        "native_platform",
        Outcome::Blocked,
        "native_linux_x86_64_required",
    );
    if !report.checks.iter().any(|c| c.phase == "protected_run") {
        report.add(
            "protected_run",
            "selected_namespace_admission",
            Outcome::Unknown,
            "selected_runtime_admission_unmeasured",
        );
    }
    if !report.checks.iter().any(|c| c.phase == "removal") {
        report.add(
            "removal",
            "native_process_evidence",
            Outcome::Unknown,
            "native_linux_evidence_unavailable",
        );
    }
    report.finish()
}

#[cfg(target_os = "linux")]
mod native {
    use super::*;
    use crate::pilot_component::removal::{environment_process_evidence, ProcessBudget};
    use std::{fs::OpenOptions, io::Read, os::unix::fs::OpenOptionsExt};

    fn read(path: &str, cap: u64, budget: &mut ProcessBudget) -> anyhow::Result<Vec<u8>> {
        let limit = budget.read_limit(cap)?;
        let mut raw = vec![];
        let selected = if path == "/etc/os-release" {
            let canonical = std::fs::canonicalize(path)?;
            anyhow::ensure!(
                canonical == std::path::Path::new("/etc/os-release")
                    || canonical == std::path::Path::new("/usr/lib/os-release"),
                "platform metadata"
            );
            canonical
        } else {
            std::path::PathBuf::from(path)
        };
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(selected)?;
        anyhow::ensure!(
            file.metadata()?.is_file(),
            "preflight regular metadata required"
        );
        file.take(limit).read_to_end(&mut raw)?;
        anyhow::ensure!(
            limit > cap || (raw.len() as u64) < limit,
            "preflight_read_budget"
        );
        budget.tick(raw.len())?;
        anyhow::ensure!(raw.len() as u64 <= cap, "preflight_read_bound");
        Ok(raw)
    }
    fn setup(report: &mut Report, budget: &mut ProcessBudget) -> anyhow::Result<()> {
        let distro = read("/etc/os-release", 16384, budget)?;
        let distro = std::str::from_utf8(&distro)?;
        let release = read("/proc/sys/kernel/osrelease", 4096, budget)?;
        let release = std::str::from_utf8(&release)?.to_ascii_lowercase();
        let value = |key: &str| {
            distro
                .lines()
                .find_map(|l| l.strip_prefix(key))
                .map(|v| v.trim_matches('"'))
        };
        let (outcome, reason) = if !cfg!(target_arch = "x86_64") {
            (Outcome::Blocked, "native_linux_x86_64_required")
        } else if release.contains("microsoft") {
            (Outcome::Unknown, "wsl_existing_qualification_boundary")
        } else if value("ID=") != Some("ubuntu") || value("VERSION_ID=") != Some("24.04") {
            (Outcome::Blocked, "native_ubuntu_24_04_required")
        } else {
            (Outcome::Satisfied, "native_ubuntu_24_04_x86_64")
        };
        report.add("setup", "native_platform", outcome, reason);
        let ordinary = unsafe { libc::geteuid() } != 0;
        report.add(
            "setup",
            "ordinary_operator",
            if ordinary {
                Outcome::Satisfied
            } else {
                Outcome::Blocked
            },
            if ordinary {
                "ordinary_operator"
            } else {
                "ordinary_operator_required"
            },
        );
        let namespace = std::fs::read_link("/proc/self/ns/user")?;
        let namespace = namespace
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("namespace"))?;
        let number = namespace
            .strip_prefix("user:[")
            .and_then(|v| v.strip_suffix(']'))
            .unwrap_or("");
        anyhow::ensure!(
            !number.is_empty() && number.bytes().all(|v| v.is_ascii_digit()),
            "namespace"
        );
        let max = read("/proc/sys/user/max_user_namespaces", 64, budget)?;
        let mut enabled = std::str::from_utf8(&max)?.trim().parse::<u64>()? > 0;
        match read("/proc/sys/kernel/unprivileged_userns_clone", 64, budget) {
            Ok(raw) => match raw.trim_ascii() {
                b"0" => enabled = false,
                b"1" => (),
                _ => anyhow::bail!("namespace"),
            },
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) => {}
            Err(e) => return Err(e),
        }
        report.add(
            "setup",
            "namespace_controls",
            if enabled {
                Outcome::Satisfied
            } else {
                Outcome::Blocked
            },
            if enabled {
                "namespace_controls_observed"
            } else {
                "user_namespaces_disabled"
            },
        );
        report.add(
            "protected_run",
            "selected_namespace_admission",
            if enabled {
                Outcome::Unknown
            } else {
                Outcome::Blocked
            },
            if enabled {
                "selected_runtime_admission_unmeasured"
            } else {
                "user_namespaces_disabled"
            },
        );
        Ok(())
    }
    fn proc_mount(budget: &mut ProcessBudget) -> anyhow::Result<()> {
        budget.tick(0)?;
        let proc = std::fs::File::open("/proc")?;
        use std::os::fd::AsRawFd;
        let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
        let ok = unsafe { libc::fstatfs(proc.as_raw_fd(), info.as_mut_ptr()) };
        anyhow::ensure!(
            ok == 0 && unsafe { info.assume_init() }.f_type == libc::PROC_SUPER_MAGIC,
            "procfs required"
        );
        let raw = read("/proc/self/mountinfo", 1024 * 1024, budget)?;
        let mut found = 0;
        for line in std::str::from_utf8(&raw)?.lines() {
            let (left, right) = line
                .split_once(" - ")
                .ok_or_else(|| anyhow::anyhow!("mount"))?;
            let fields = left.split_whitespace().collect::<Vec<_>>();
            let extra = right.split_whitespace().collect::<Vec<_>>();
            anyhow::ensure!(fields.len() >= 6 && extra.len() >= 3, "mount");
            if fields[4] != "/proc" {
                continue;
            }
            found += 1;
            anyhow::ensure!(fields[3] == "/" && extra[0] == "proc", "mount");
            for value in fields[5].split(',').chain(extra[2].split(',')) {
                anyhow::ensure!(
                    (!value.starts_with("hidepid=") || value == "hidepid=0")
                        && value != "subset=pid",
                    "mount"
                );
            }
        }
        anyhow::ensure!(found == 1, "mount");
        Ok(())
    }
    pub(super) fn inspect(report: &mut Report) {
        let mut budget = ProcessBudget::new();
        if setup(report, &mut budget).is_err() {
            report.add(
                "setup",
                "namespace_controls",
                Outcome::Unknown,
                "namespace_or_platform_evidence_unavailable",
            );
        }
        match read("/proc/self/uid_map", 4096, &mut budget) {
            Ok(raw) => {
                let fields = raw
                    .split(|v| v.is_ascii_whitespace())
                    .filter(|v| !v.is_empty())
                    .collect::<Vec<_>>();
                let (outcome, reason) = if fields == [b"0".as_slice(), b"0", b"4294967295"] {
                    (Outcome::Satisfied, "host_user_namespace_observed")
                } else if !fields.is_empty()
                    && fields.len().is_multiple_of(3)
                    && fields
                        .iter()
                        .all(|v| !v.is_empty() && v.iter().all(u8::is_ascii_digit))
                {
                    (Outcome::Blocked, "removal_host_user_namespace_required")
                } else {
                    (Outcome::Unknown, "namespace_identity_unknown")
                };
                report.add("removal", "host_user_namespace", outcome, reason);
            }
            Err(_) => report.add(
                "removal",
                "host_user_namespace",
                Outcome::Unknown,
                "namespace_identity_unknown",
            ),
        }
        if proc_mount(&mut budget).is_err() {
            report.add(
                "removal",
                "same_uid_process_evidence",
                Outcome::Unknown,
                "proc_inventory_hidden_or_unverified",
            );
            return;
        }
        match environment_process_evidence(&mut budget) {
            Ok(codes) if codes.is_empty() => report.add(
                "removal",
                "same_uid_process_evidence",
                Outcome::Satisfied,
                "visible_process_evidence_readable",
            ),
            Ok(codes) => {
                for code in codes {
                    report.add(
                        "removal",
                        "same_uid_process_evidence",
                        if code == "process_evidence_inaccessible" {
                            Outcome::Blocked
                        } else {
                            Outcome::Unknown
                        },
                        code,
                    );
                }
            }
            Err(code) => report.add(
                "removal",
                "same_uid_process_evidence",
                Outcome::Unknown,
                code,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    #[test]
    fn pilot_lifecycle_preflight_support_export_preserves_the_finite_contract() {
        use sha2::Digest;
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let report = crate::doctor::Report {
            schema: "sw-agent-doctor/1",
            observed_at_ms: 42,
            setup: crate::doctor::Outcome::Unknown,
            active_host_call_protection: "unknown",
            scope: "local_setup_and_authenticated_runtime_not_active_host_execution",
            checks: vec![],
            pilot: None,
            lifecycle: Some(inspect()),
        };
        let output = root.path().join("support");
        crate::support_bundle::export(&report, &output).unwrap();
        let raw = std::fs::read(output.join("report.json")).unwrap();
        let value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        let allowed = [
            "format",
            "scope",
            "setup",
            "protected_run",
            "removal",
            "active_protection",
            "removal_authorized",
            "future_inactivity",
            "checks",
            "guidance",
            "limits",
        ];
        let lifecycle = value["lifecycle"].as_object().unwrap();
        assert_eq!(lifecycle.len(), allowed.len());
        assert!(lifecycle.keys().all(|k| allowed.contains(&k.as_str())));
        assert_eq!(lifecycle["removal_authorized"], false);
        assert_eq!(lifecycle["active_protection"], "not_measured");
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(output.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(
            manifest["lifecycle_schema"],
            "sw-pilot-lifecycle-preflight/1"
        );
        assert_eq!(
            manifest["files"][0]["sha256"],
            format!("{:x}", sha2::Sha256::digest(&raw))
        );
        for key in [
            "pid",
            "argv",
            "environ",
            "maps",
            "workspace_path",
            "credentials",
        ] {
            assert!(!lifecycle.contains_key(key));
        }
    }

    #[test]
    fn removal_limitation_does_not_relabel_setup_or_protection() {
        let mut r = Report::new();
        r.add("setup", "static", Outcome::Satisfied, "observed");
        r.add("protected_run", "runtime", Outcome::Unknown, "unmeasured");
        r.add(
            "removal",
            "process",
            Outcome::Blocked,
            "process_evidence_inaccessible",
        );
        let r = r.finish();
        assert_eq!(r.setup, Outcome::Satisfied);
        assert_eq!(r.protected_run, Outcome::Unknown);
        assert_eq!(r.removal, Outcome::Blocked);
        assert!(!r.removal_authorized);
        assert_eq!(r.future_inactivity, "not_proven");
    }
}
