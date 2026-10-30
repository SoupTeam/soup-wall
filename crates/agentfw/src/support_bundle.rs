// SPDX-License-Identifier: Apache-2.0
//! Explicit local-only support export. This is not a raw-log archive.

use crate::doctor::Report;
use std::path::Path;

#[cfg(target_os = "linux")]
pub fn export(report: &Report, destination: &Path) -> anyhow::Result<()> {
    export_edit(report, None, destination)
}

#[cfg(target_os = "linux")]
pub(crate) fn export_edit(
    report: &Report,
    edit: Option<&crate::edit_session::diagnostic::Report>,
    destination: &Path,
) -> anyhow::Result<()> {
    use anyhow::ensure;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    let bytes = if let Some(edit) = edit {
        let mut value = serde_json::to_value(report)?;
        value["edit_session"] = serde_json::to_value(edit)?;
        serde_json::to_vec_pretty(&value)?
    } else {
        serde_json::to_vec_pretty(report)?
    };
    ensure!(bytes.len() <= 128 * 1024, "diagnostic report exceeds cap");
    // The exported schema contains fixed enums/codes/timestamps/hashes only.
    // Never serialize raw config, host settings, tokens, errors or environment.
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let mut manifest = json!({
        "schema": "sw-agent-doctor-support/1",
        "report_schema": "sw-agent-doctor/1",
        "created_at_ms": report.observed_at_ms,
        "privacy": "fixed_allowlist_no_raw_inputs_no_network",
        "files": [{"name":"report.json", "sha256":digest, "bytes":bytes.len()}],
        "active_host_call_protection": "unknown"
    });
    if let Some(pilot) = &report.pilot {
        manifest["pilot_schema"] = json!(pilot.schema);
    }
    if let Some(edit_session) = edit {
        manifest["edit_session_schema"] = json!(edit_session.schema);
    }
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    ensure!(manifest_bytes.len() < 8192, "support manifest exceeds cap");
    crate::private_export::publish(
        destination,
        &[("report.json", &bytes), ("manifest.json", &manifest_bytes)],
        || Ok(()),
    )
}

#[cfg(not(target_os = "linux"))]
pub fn export(_report: &Report, _destination: &Path) -> anyhow::Result<()> {
    anyhow::bail!("private support export requires Linux")
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn export_edit(
    _report: &Report,
    _edit: Option<&crate::edit_session::diagnostic::Report>,
    _destination: &Path,
) -> anyhow::Result<()> {
    anyhow::bail!("private support export requires Linux")
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::doctor::{Outcome, Report};
    use sha2::Digest;

    fn sample() -> Report {
        Report {
            schema: "sw-agent-doctor/1",
            observed_at_ms: 42,
            setup: Outcome::Unknown,
            active_host_call_protection: "unknown",
            scope: "local_setup_and_authenticated_runtime_not_active_host_execution",
            checks: vec![],
            pilot: None,
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn private_no_clobber_bundle_and_hash() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("support");
        export(&sample(), &path).unwrap();
        let bytes = std::fs::read(path.join("report.json")).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("secret-sentinel"));
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(
            value["files"][0]["sha256"].as_str().unwrap(),
            format!("{:x}", sha2::Sha256::digest(&bytes))
        );
        assert!(export(&sample(), &path).is_err());
        assert!(path.join("report.json").exists());
        let linked = dir.path().join("linked");
        std::os::unix::fs::symlink(&path, &linked).unwrap();
        assert!(export(&sample(), &linked).is_err());
        let remaining: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(remaining.len(), 2);
    }

    #[test]
    fn edit_diagnosis_uses_existing_allowlisted_private_export() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let report = sample();
        let edit =
            crate::edit_session::diagnostic::inspect(&crate::edit_session::diagnostic::Args {
                run: dir.path().join("secret-path-canary-unavailable"),
                json: true,
                check_output: false,
                support_bundle: None,
            });
        let out = dir.path().join("support");
        export_edit(&report, Some(&edit), &out).unwrap();
        for name in ["report.json", "manifest.json"] {
            let bytes = std::fs::read(out.join(name)).unwrap();
            assert!(!String::from_utf8_lossy(&bytes).contains("secret-path-canary"));
            assert!(bytes.len() <= 128 * 1024);
        }
        let manifest: serde_json::Value =
            serde_json::from_slice(&std::fs::read(out.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(
            manifest["edit_session_schema"],
            "sw-installed-edit-status/1"
        );
        assert!(export_edit(&report, Some(&edit), &out).is_err());
    }
}
