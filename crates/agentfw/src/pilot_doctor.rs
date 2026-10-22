// SPDX-License-Identifier: Apache-2.0
//! Additive Linux two-server diagnosis behind `doctor`. No process launch,
//! authority mutation, tool dispatch or raw-log export is permitted here.
mod incident;
mod io;

use crate::{
    doctor::{check, Check, DoctorArgs, Outcome},
    mcp::server_profile,
    protection_status::{self, Expectations, Mode},
    Config,
};
use clap::Args;
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Args, Clone, Debug, Default)]
pub struct PilotArgs {
    /// Diagnose the selected installed original Linux read-only filesystem/Git pair.
    #[arg(long = "pilot", requires_all = ["fs_profile", "git_profile", "workspace", "agent"])]
    pub enabled: bool,
    /// Installed profile JSON, as produced by the existing original-server installer.
    #[arg(long, requires = "enabled")]
    pub fs_profile: Option<PathBuf>,
    #[arg(long, requires = "enabled")]
    pub git_profile: Option<PathBuf>,
    #[arg(long, requires = "enabled")]
    pub workspace: Option<PathBuf>,
    /// One explicitly selected private JSONL file, never a history directory.
    #[arg(long, requires_all = ["enabled", "incident_source"])]
    pub incident_file: Option<PathBuf>,
    /// native-audit or collector-report. Unknown values are safely refused.
    #[arg(long, requires = "incident_file")]
    pub incident_source: Option<String>,
    /// Native call ID (not an MCP host ID); paired call/result records are retained.
    #[arg(long, requires = "incident_file", conflicts_with_all = ["incident_seq", "incident_host_id_json"])]
    pub incident_call_id: Option<String>,
    /// Exact native event sequence; requires the audited session epoch.
    #[arg(long, requires_all = ["incident_file", "incident_session"], conflicts_with = "incident_host_id_json")]
    pub incident_seq: Option<u64>,
    #[arg(long, requires = "incident_seq")]
    pub incident_session: Option<String>,
    /// Exact typed MCP host ID as JSON, for a collector report only.
    #[arg(long, requires_all = ["incident_file", "incident_server"])]
    pub incident_host_id_json: Option<String>,
    /// filesystem or git; prevents cross-server host-ID collisions.
    #[arg(long, requires = "incident_host_id_json")]
    pub incident_server: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct PilotReport {
    pub schema: &'static str,
    pub setup: Outcome,
    pub active_host_call_protection: &'static str,
    pub asset_trust: &'static str,
    pub checks: Vec<Check>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incident: Option<incident::Incident>,
}

pub(crate) fn combine(a: Outcome, b: Outcome) -> Outcome {
    for value in [Outcome::Failed, Outcome::Unsupported, Outcome::Unknown] {
        if a == value || b == value {
            return value;
        }
    }
    Outcome::Ready
}
fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn strict(bytes: &[u8]) -> anyhow::Result<Value> {
    let crate::mcp::admission::Strict(value) = serde_json::from_slice(bytes)?;
    Ok(value)
}
fn digest_check(
    id: &'static str,
    source: &'static str,
    code: &'static str,
    digest: String,
    explanation: &'static str,
) -> Check {
    let mut c = check(id, source, Outcome::Ready, code, explanation,
        "Keep the reviewed installation pins; setup identity alone does not prove a protected host call.");
    c.sha256 = Some(digest);
    c
}

fn registry_for(format: &str) -> anyhow::Result<Value> {
    let manifest = server_profile::original_manifest_for(format)?;
    let profiles = server_profile::classify_manifest_for(format, &manifest)?;
    let tools = manifest["tools"].as_array().expect("shipped tools").iter().map(|tool| {
        let name = tool["name"].as_str().expect("shipped name");
        let class = if format == server_profile::git::FORMAT {
            if profiles[name].unsupported_reason.is_none() {"read_only"} else {"destructive"}
        } else {
            match name {"write_file" | "edit_file" | "create_directory" => "side_effecting", "move_file" => "destructive", _ => "read_only"}
        };
        let mut value = json!({"name":name,"schema_sha256":crate::native::canonical_digest(&tool["inputSchema"]),
            "action_class":class,"result_provenance":"untrusted","egress":[]});
        if profiles[name].unsupported_reason.is_none() {value["mcp_result_profile"] = json!(format);}
        value
    }).collect::<Vec<_>>();
    Ok(
        json!({"contract_version":"sw-native/1","registry_id":if format == server_profile::FORMAT {"filesystem-readonly-v1"} else {"git-readonly-v1"},"tools":tools}),
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProfileFailure {
    Profile,
    Workspace,
    Receipt,
    Identity,
    Package,
    Runtime,
    Changed,
}
impl ProfileFailure {
    fn check(self, id: &'static str) -> Check {
        let (code, explanation, next) = match self {
            Self::Profile => ("pilot_profile_missing_unsafe_or_invalid", "Selected profile cannot be safely read or validated.", "Select the private original installer's profile.json; do not follow links or repair it in doctor."),
            Self::Workspace => ("pilot_profile_workspace_mismatch", "Selected profile format or workspace does not match this server selection.", "Select the filesystem/Git profile for the exact workspace; inspect the existing installer selection privately."),
            Self::Receipt => ("pilot_receipt_missing_or_invalid", "The existing installation receipt or adjacent registry/policy is absent, unsafe or invalid.", "Inspect installation.json, registry.json and policy.yaml in the selected private installation; use the reviewed installer workflow if incomplete."),
            Self::Identity => ("pilot_original_identity_mismatch", "Installed receipt, original schema/registry or profile policy differs from the accepted identities.", "Compare the selected installation with the reviewed original profile; do not replace a digest merely to accept drift."),
            Self::Package => ("pilot_package_changed_or_unsafe", "The selected package tree, original entrypoint or lock differs from its pin or cannot be safely hashed within bounds.", "Inspect the selected server package and installer receipt privately; do not launch it until the reviewed package pins agree."),
            Self::Runtime => ("pilot_runtime_asset_changed_or_unsafe", "A selected runtime, sandbox, Git executable or system library differs from its installed pin or is unsafe.", "Compare the selected runtime and library pins with installation.json; use the existing reviewed runtime preparation workflow before launch."),
            Self::Changed => ("pilot_profile_changed_during_inspection", "Selected profile or receipt changed while bounded inspection was running.", "Finish any operator installation change, then retry a read-only diagnostic of the stable selected profile."),
        };
        check(
            id,
            "private_installed_profile_and_receipt",
            Outcome::Failed,
            code,
            explanation,
            next,
        )
    }
}

fn profile(
    path: &Path,
    workspace: &Path,
    format: &str,
    budget: &mut io::Budget,
) -> Result<Vec<Check>, ProfileFailure> {
    use anyhow::{ensure, Context};
    let mut phase = ProfileFailure::Profile;
    let result = (|| -> anyhow::Result<Vec<Check>> {
        let bytes = crate::doctor::read_private(path, server_profile::MAX_PROFILE_BYTES as u64)?;
        let config = server_profile::ProfileConfig::read(&bytes)?;
        phase = ProfileFailure::Workspace;
        ensure!(
            config.format == format && config.workspace == workspace,
            "profile/workspace mismatch"
        );
        let parent = path.parent().context("profile parent")?;
        phase = ProfileFailure::Receipt;
        let receipt_bytes =
            crate::doctor::read_private(&parent.join("installation.json"), 1024 * 1024)?;
        let receipt = strict(&receipt_bytes)?;
        let registry_bytes =
            crate::doctor::read_private(&parent.join("registry.json"), 1024 * 1024)?;
        let policy_bytes = crate::doctor::read_private(&parent.join("policy.yaml"), 1024 * 1024)?;
        let (upstream, policy, receipt_format) = if format == server_profile::FORMAT {
            (
                include_str!("../../../profiles/mcp/filesystem-readonly-v1/upstream-identity.json"),
                include_str!("../../../profiles/mcp/filesystem-readonly-v1/policy.yaml"),
                "sou62-profile-installation/1",
            )
        } else {
            (
                include_str!("../../../profiles/mcp/git-readonly-v1/upstream-identity.json"),
                include_str!("../../../profiles/mcp/git-readonly-v1/policy.yaml"),
                "sou68-profile-installation/1",
            )
        };
        phase = ProfileFailure::Identity;
        ensure!(
            receipt["format"] == receipt_format
                && receipt["profile"] == strict(&bytes)?
                && receipt["upstream_identity"] == strict(upstream.as_bytes())?
                && receipt["profile_sha256"] == sha(&bytes)
                && receipt["registry_sha256"] == sha(&registry_bytes)
                && receipt["policy_sha256"] == sha(&policy_bytes)
                && policy_bytes == policy.as_bytes()
                && strict(&registry_bytes)? == registry_for(format)?,
            "installed receipt/schema/registry mismatch"
        );
        ensure!(
            config.package_root == parent.join("package"),
            "package selection mismatch"
        );
        phase = ProfileFailure::Package;
        ensure!(
            io::tree(&config.package_root, budget)? == config.package_tree_sha256,
            "package pin mismatch"
        );
        if format == server_profile::FORMAT {
            let identity = strict(upstream.as_bytes())?;
            ensure!(
                io::asset(
                    &config.package_root.join(server_profile::SERVER_ENTRYPOINT),
                    budget
                )? == identity["package"]["originalEntrypointSha256"],
                "original entrypoint mismatch"
            );
            ensure!(
                io::asset(&config.package_root.join("package-lock.json"), budget)?
                    == identity["packageLockSha256"],
                "original lock mismatch"
            );
        }
        phase = ProfileFailure::Runtime;
        for (path, expected) in [
            (&config.runtime_path, &config.runtime_sha256),
            (&config.bwrap_path, &config.bwrap_sha256),
        ]
        .into_iter()
        .chain(
            config
                .git
                .iter()
                .chain(config.git_launcher.iter())
                .map(|l| (&l.path, &l.sha256)),
        ) {
            ensure!(
                io::asset(path, budget)? == *expected,
                "runtime asset mismatch"
            );
        }
        for library in &config.libraries {
            ensure!(
                io::system_library(&library.path, budget)? == library.sha256,
                "system library pin mismatch"
            );
        }
        phase = ProfileFailure::Changed;
        // Re-read private descriptors to detect profile/receipt edits during the asset pass.
        ensure!(
            crate::doctor::read_private(path, server_profile::MAX_PROFILE_BYTES as u64)? == bytes
                && crate::doctor::read_private(&parent.join("installation.json"), 1024 * 1024)?
                    == receipt_bytes,
            "profile changed"
        );
        let id = if format == server_profile::FORMAT {
            "filesystem_profile"
        } else {
            "git_profile"
        };
        Ok(vec![
        digest_check(id, "private_installed_profile_and_receipt", "original_profile_pins_verified", sha(&bytes),
            "Installed profile, original schema/registry, policy, package tree and selected runtime assets match their pins."),
        digest_check(if id == "filesystem_profile" {"filesystem_schema"} else {"git_schema"}, "compiled_original_discovery", "original_schema_identity", crate::native::canonical_digest(&server_profile::original_manifest_for(format)?),
            "This schema identity is the accepted original discovery; doctor does not run discovery."),
        digest_check(if id == "filesystem_profile" {"filesystem_package"} else {"git_package"}, "descriptor_hashed_installed_package", "package_tree_identity", config.package_tree_sha256,
            "Installed package bytes matched the recorded installation tree pin; this is not package runtime attestation."),
    ])
    })();
    result.map_err(|_| phase)
}

pub(crate) async fn diagnose(
    args: &DoctorArgs,
    home: &Path,
    config: Option<&Config>,
) -> PilotReport {
    let mut report = PilotReport {
        schema: "sw-agent-doctor-pilot/1",
        setup: Outcome::Unknown,
        active_host_call_protection: "unknown",
        asset_trust: "operator_installed_pins_not_runtime_attestation",
        checks: vec![],
        incident: None,
    };
    if !cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        report.checks.push(check("pilot_platform", "compile_target", Outcome::Unsupported, "pilot_runtime_unsupported",
            "The selected original two-server pilot supports Linux x86-64 only.", "Diagnose the owned Linux x86-64 installation; no sandbox or platform fallback is used."));
        report.setup = Outcome::Unsupported;
        return report;
    }
    let mut budget = io::Budget::new();
    let workspace = args.pilot.workspace.as_deref();
    let workspace_valid = workspace.is_some_and(|p| io::directory(p).is_ok());
    report.checks.push(check(
        "pilot_workspace",
        "selected_directory_descriptors",
        if workspace_valid {
            Outcome::Ready
        } else {
            Outcome::Failed
        },
        if workspace_valid {
            "workspace_selected"
        } else {
            "workspace_missing_or_unsafe"
        },
        "Workspace is inspected as a directory only; no workspace content is exported.",
        "Select the absolute, link-free workspace used by both installed profiles.",
    ));
    for (path, format, id) in [
        (
            &args.pilot.fs_profile,
            server_profile::FORMAT,
            "filesystem_profile",
        ),
        (
            &args.pilot.git_profile,
            server_profile::git::FORMAT,
            "git_profile",
        ),
    ] {
        match path
            .as_deref()
            .zip(workspace)
            .filter(|_| workspace_valid)
            .map(|(p, w)| profile(p, w, format, &mut budget))
        {
            Some(Ok(checks)) => report.checks.extend(checks),
            Some(Err(failure)) => report.checks.push(failure.check(id)),
            None => report.checks.push(ProfileFailure::Profile.check(id)),
        }
    }
    if let (Some(path), Some(wanted)) = (&args.classifier_script, &args.classifier_sha256) {
        if let Ok(actual) = crate::doctor::hash_selected_file(path, 16 * 1024 * 1024) {
            if actual == *wanted {
                report.checks.push(digest_check("pilot_classifier", "selected_classifier_source", "selected_classifier_source_identity", actual,
                    "Reviewed classifier source matches the declared digest; daemon status does not attest classifier worker use."));
            }
        }
    }
    let mut expected_registry = None;
    if let Some(cfg) = config {
        report.checks.push(digest_check("pilot_config", "validated_disk_config", "selected_config_identity",
            protection_status::config_digest(cfg), "Validated disk configuration identity is compared with the authenticated startup identity."));
        if let Some(native) = &cfg.native {
            if let Ok(bytes) = crate::doctor::read_private(&native.registry_path, 1024 * 1024) {
                let valid = (|| -> anyhow::Result<()> {
                    anyhow::ensure!(sha(&bytes) == native.registry_sha256, "registry digest");
                    let value = strict(&bytes)?;
                    let parsed = crate::native::NativeState::from_bytes(
                        &bytes,
                        &native.registry_sha256,
                        "diagnostic-not-a-credential".into(),
                    )?;
                    let mut expected = std::collections::BTreeMap::new();
                    for format in [server_profile::FORMAT, server_profile::git::FORMAT] {
                        for tool in registry_for(format)?["tools"]
                            .as_array()
                            .expect("shipped registry")
                        {
                            anyhow::ensure!(
                                expected
                                    .insert(tool["name"].as_str().unwrap().to_owned(), tool.clone())
                                    .is_none(),
                                "registry collision"
                            );
                        }
                    }
                    let actual = value["tools"].as_array().context("registry tools")?;
                    anyhow::ensure!(
                        actual.len() == expected.len()
                            && parsed.registry.tools.len() == expected.len()
                            && actual
                                .iter()
                                .all(
                                    |v| v["name"].as_str().and_then(|n| expected.get(n)) == Some(v)
                                ),
                        "combined original registry mismatch"
                    );
                    Ok(())
                })();
                if valid.is_ok() {
                    expected_registry = Some(native.registry_sha256.clone());
                }
            }
        }
        let mut registry_check = check("pilot_registry", "private_config_and_original_schemas", if expected_registry.is_some(){Outcome::Ready}else{Outcome::Failed},
            if expected_registry.is_some(){"two_server_registry_verified"}else{"two_server_registry_mismatch"},
            "The selected native registry is compared with both accepted original tool/schema sets.", "Use the reviewed combined original filesystem/Git registry; retain exact tool and schema pins.");
        registry_check.sha256 = expected_registry.clone();
        report.checks.push(registry_check);
        let policy = (|| -> anyhow::Result<_> {
            let policy = if let Some(path) = &cfg.policy {
                let bytes = crate::doctor::read_private(path, 1024 * 1024)?;
                soup_wall_agent::AgentPolicySet::from_yaml(std::str::from_utf8(&bytes)?)?
            } else {
                soup_wall_agent::AgentPolicySet::from_yaml(include_str!(
                    "../../agent/policies/agent-default.yaml"
                ))?
            };
            Ok(sha(&serde_json::to_vec(&policy)?))
        })()
        .ok();
        if let Some(digest) = &policy {
            report.checks.push(digest_check("pilot_policy", "validated_selected_policy", "selected_policy_identity", digest.clone(),
                "Selected policy identity uses the same serialized format as authenticated status; managed policy changes can differ."));
        } else {
            report.checks.push(check(
                "pilot_policy",
                "private_selected_policy",
                Outcome::Failed,
                "pilot_policy_unverifiable",
                "Selected policy cannot be safely read or validated.",
                "Review the private policy selection; doctor does not repair or replace policy.",
            ));
        }
        let token = crate::doctor::read_private(&home.join("token"), 4096)
            .ok()
            .and_then(|b| String::from_utf8(b).ok());
        let binary = args
            .agent
            .as_deref()
            .and_then(|p| crate::doctor::hash_selected_file(p, 512 * 1024 * 1024).ok());
        let expected = Expectations {
            config_sha256: Some(protection_status::config_digest(cfg)),
            policy_sha256: policy,
            binary_sha256: binary,
            registry_sha256: expected_registry.clone(),
            ..Default::default()
        };
        let observed = if let Some(token) = token.filter(|t| !t.trim().is_empty()) {
            protection_status::query(cfg, token.trim(), &expected, Duration::from_secs(2)).await
        } else {
            Err("status_token_unavailable")
        };
        match observed {
            Ok(snapshot) => {
                let active = snapshot.mode == Mode::Enforcing && expected_registry.is_some()
                    && snapshot.paths.iter().any(|p| p.path=="native_admission" && p.configured==Some(true) && p.capability==protection_status::Evidence::Supported);
                let mut c = check("pilot_runtime","authenticated_status_nonce_and_bearer",if active{Outcome::Ready}else{Outcome::Failed},
                    if active{"current_instance_ready_not_execution"}else{"installed_pilot_not_active"},
                    if active{"Current authenticated instance matches selected binary/config/policy/registry and supports native admission; no host call was tested."}
                    else{"Authenticated daemon is present, but this installed pilot is not active for enforcing native admission."},
                    "Use the existing operator lifecycle workflow if activation is needed; doctor never starts or restarts the daemon.");
                c.sha256=Some(sha(snapshot.runtime.instance.as_bytes())); report.checks.push(c);
            }
            Err(code) => report.checks.push(check("pilot_runtime","authenticated_status_nonce_and_bearer",Outcome::Unknown,
                if code=="status_identity_mismatch" {"pilot_runtime_identity_mismatch"} else {"pilot_daemon_unavailable_or_unverifiable"},
                "No matching authenticated current-instance observation is available; an open port or a local record is insufficient.",
                "Run agentfw protection-status --query-only in the selected installation; inspect lifecycle status privately before operator recovery.")),
        }
    }
    if args.classifier_script.is_none() {
        report.checks.push(check("pilot_classifier","explicit_classifier_selection",Outcome::Unknown,"pilot_classifier_not_selected",
            "The launcher-selected classifier is not declared by daemon status; no classifier runtime use is inferred.",
            "Pass the reviewed --classifier-script and --classifier-sha256; selected source identity still does not prove a worker ran."));
    }
    if args.pilot.incident_file.is_some() {
        report.incident = Some(incident::lookup(
            &args.pilot,
            expected_registry.as_deref(),
            args.classifier_sha256.as_deref(),
        ));
    }
    report.setup = crate::doctor::setup(&report.checks.iter().collect::<Vec<_>>());
    report
}
use anyhow::Context;

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn profile_failure_identifies_the_failed_operator_check_without_paths_or_errors() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let file = root.join("profile.json");
        assert_eq!(
            profile(&file, &root, server_profile::FORMAT, &mut io::Budget::new()).unwrap_err(),
            ProfileFailure::Profile
        );
        std::fs::write(&file, b"PRIVATE-PROFILE-CANARY").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            profile(&file, &root, server_profile::FORMAT, &mut io::Budget::new()).unwrap_err(),
            ProfileFailure::Profile
        );
        let values = [
            ProfileFailure::Profile,
            ProfileFailure::Workspace,
            ProfileFailure::Receipt,
            ProfileFailure::Identity,
            ProfileFailure::Package,
            ProfileFailure::Runtime,
            ProfileFailure::Changed,
        ];
        let codes: std::collections::BTreeSet<_> = values
            .iter()
            .map(|v| v.check("filesystem_profile").reason_code)
            .collect();
        assert_eq!(codes.len(), values.len());
        let serialized = serde_json::to_string(
            &values
                .iter()
                .map(|v| v.check("filesystem_profile"))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(!serialized.contains("CANARY") && !serialized.contains(root.to_str().unwrap()));
    }
}
