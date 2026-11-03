// SPDX-License-Identifier: Apache-2.0
//! Authoritative, bounded configuration projection for private recovery.
//!
//! The installed helper supplies already descriptor-read bytes. This command
//! reads no paths and creates no daemon, policy authority, provider or child.
//! Unsupported declarations refuse instead of silently disappearing from a
//! purported complete backup. The private caller must separately verify and
//! rebind the returned policy, registry and audit directory references.

use crate::config::{Config, JudgeCfg};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Component, Path};

const VERSION: &str = "sw-pilot-configuration-projection/1";
const MAX_INPUT: u64 = 64 * 1024;
const MAX_PATH: usize = 4096;
const POLICY: &str =
    include_str!("../../../scripts/benchmarks/pilot-readiness-policies/baseline.yaml");

fn exact_keys(value: &Value, keys: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn path_reference(path: &Path) -> Result<Value, &'static str> {
    let text = path.to_str().ok_or("configuration_reference_unsupported")?;
    if !path.is_absolute()
        || text.is_empty()
        || text.len() > MAX_PATH
        || text.chars().any(char::is_control)
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err("configuration_reference_unsupported");
    }
    Ok(Value::String(text.to_owned()))
}

fn project_config(text: &str) -> Result<Value, &'static str> {
    let config = Config::from_yaml(text).map_err(|_| "configuration_invalid")?;
    if config.capture_unknown_raw {
        return Err("configuration_raw_capture_unsupported");
    }
    if config.judge != JudgeCfg::default() {
        return Err("configuration_judge_unsupported");
    }
    if config.audit.is_some() {
        return Err("configuration_legacy_audit_unsupported");
    }
    if config
        .native
        .as_ref()
        .is_some_and(|native| native.execution.is_some() || native.git_execution.is_some())
    {
        return Err("configuration_execution_unsupported");
    }

    let policy = path_reference(
        config
            .policy
            .as_deref()
            .ok_or("configuration_policy_reference_required")?,
    )?;
    let registry = config
        .native
        .as_ref()
        .map(|native| path_reference(&native.registry_path))
        .transpose()?
        .unwrap_or(Value::Null);
    let audit_directory = config
        .audit_retention
        .as_ref()
        .map(|retention| path_reference(&retention.directory))
        .transpose()?
        .unwrap_or(Value::Null);

    let mut normalized = serde_json::to_value(&config).map_err(|_| "configuration_invalid")?;
    // Check the complete authoritative serialization before removing references
    // and the verified default judge. New Config fields require explicit review.
    if !exact_keys(
        &normalized,
        &[
            "bind",
            "port",
            "enforce",
            "policy",
            "audit",
            "audit_retention",
            "capture_unknown_raw",
            "max_record_bytes",
            "provenance",
            "deterministic_timeout_ms",
            "max_body_bytes",
            "judge",
            "native",
        ],
    ) {
        return Err("configuration_schema_unsupported");
    }
    if !exact_keys(
        &normalized["provenance"],
        &[
            "per_session_bytes",
            "total_bytes",
            "max_sessions",
            "max_input_bytes",
            "max_source_bytes",
            "max_literal_bytes",
            "max_session_id_bytes",
        ],
    ) {
        return Err("configuration_provenance_schema_unsupported");
    }
    if let Some(native) = normalized.get_mut("native").and_then(Value::as_object_mut) {
        if native.keys().any(|key| {
            !matches!(
                key.as_str(),
                "registry_path" | "registry_sha256" | "approval" | "liveness"
            )
        }) || native.remove("registry_path").is_none()
        {
            return Err("configuration_native_schema_unsupported");
        }
        if native
            .get("approval")
            .is_some_and(|value| !exact_keys(value, &["ttl_seconds"]))
            || native.get("liveness").is_some_and(|value| {
                !exact_keys(
                    value,
                    &[
                        "default_lease_seconds",
                        "max_lease_seconds",
                        "maintenance_interval_ms",
                    ],
                )
            })
        {
            return Err("configuration_native_schema_unsupported");
        }
    }
    if let Some(retention) = normalized
        .get_mut("audit_retention")
        .filter(|value| !value.is_null())
    {
        if !exact_keys(
            retention,
            &[
                "version",
                "directory",
                "segment_size_bytes",
                "segment_count",
                "total_disk_bytes",
                "max_record_bytes",
            ],
        ) {
            return Err("configuration_audit_schema_unsupported");
        }
        retention
            .as_object_mut()
            .ok_or("configuration_audit_schema_unsupported")?
            .remove("directory");
    }
    let object = normalized
        .as_object_mut()
        .ok_or("configuration_schema_unsupported")?;
    object.remove("policy");
    // A nondefault disabled judge is refused above, including its URL/model.
    // Absent judge reconstructs exactly the accepted disabled default.
    object.remove("judge");
    Ok(json!({
        "version": VERSION,
        "kind": "config",
        "status": "projected",
        "config": normalized,
        "references": {"policy": policy, "registry": registry, "audit_directory": audit_directory}
    }))
}

fn project_policy(text: &str) -> Result<Value, &'static str> {
    let policy = soup_wall_agent::AgentPolicySet::from_yaml(text)
        .map_err(|_| "configuration_policy_invalid")?;
    let accepted = soup_wall_agent::AgentPolicySet::from_yaml(POLICY)
        .map_err(|_| "configuration_policy_baseline_unavailable")?;
    let normalized = serde_json::to_value(&policy).map_err(|_| "configuration_policy_invalid")?;
    let baseline =
        serde_json::to_value(&accepted).map_err(|_| "configuration_policy_baseline_unavailable")?;
    if normalized != baseline {
        return Err("configuration_policy_unsupported");
    }
    let bytes =
        serde_json::to_vec(&normalized).map_err(|_| "configuration_policy_baseline_unavailable")?;
    Ok(
        json!({"version": VERSION, "kind": "policy", "status": "projected",
        "policy_sha256": format!("{:x}", Sha256::digest(bytes))}),
    )
}

fn project(raw: &[u8], policy: bool) -> Result<Value, &'static str> {
    if raw.len() as u64 > MAX_INPUT {
        return Err("configuration_input_limit");
    }
    let text = std::str::from_utf8(raw).map_err(|_| "configuration_input_invalid")?;
    if policy {
        project_policy(text)
    } else {
        project_config(text)
    }
}

fn run(input: impl Read, mut output: impl Write, policy: bool) -> i32 {
    let kind = if policy { "policy" } else { "config" };
    let (value, code) = if !cfg!(target_os = "linux") {
        (
            json!({"version": VERSION, "kind": kind, "status": "unsupported",
                "reason": "configuration_projection_platform_unsupported"}),
            5,
        )
    } else {
        let mut raw = Vec::new();
        let projected = input
            .take(MAX_INPUT + 1)
            .read_to_end(&mut raw)
            .map_err(|_| "configuration_input_unreadable")
            .and_then(|_| project(&raw, policy));
        match projected {
            Ok(value) => (value, 0),
            Err(reason) => (
                json!({"version": VERSION, "kind": kind, "status": "refused", "reason": reason}),
                2,
            ),
        }
    };
    if serde_json::to_writer(&mut output, &value).is_err() || output.write_all(b"\n").is_err() {
        return 4;
    }
    code
}

/// Internal installed-helper adapter. No file discovery or persistent mutation.
pub fn run_cli(policy: bool) -> i32 {
    run(std::io::stdin().lock(), std::io::stdout().lock(), policy)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn config() -> Value {
        json!({
            "policy": "/owned/current/policy.yaml", "enforce": true, "port": 12345,
            "native": {
                "registry_path": "/owned/current/registry.json", "registry_sha256": "a".repeat(64),
                "approval": {"ttl_seconds": 45},
                "liveness": {"default_lease_seconds": 4, "max_lease_seconds": 8, "maintenance_interval_ms": 250}
            },
            "audit_retention": {"version": 1, "directory": "/owned/audit", "segment_size_bytes": 65536,
                "segment_count": 2, "total_disk_bytes": 512000, "max_record_bytes": 1024}
        })
    }

    fn projected(value: &Value) -> Result<Value, &'static str> {
        project(&serde_json::to_vec(value).unwrap(), false)
    }

    #[test]
    fn original_parser_normalizes_defaults_and_moves_only_verified_references() {
        let value = projected(&config()).unwrap();
        assert_eq!(value["status"], "projected");
        assert_eq!(value["references"]["policy"], "/owned/current/policy.yaml");
        assert_eq!(
            value["references"]["registry"],
            "/owned/current/registry.json"
        );
        assert_eq!(value["references"]["audit_directory"], "/owned/audit");
        assert_eq!(value["config"]["max_record_bytes"], 262_144);
        assert_eq!(value["config"]["native"]["approval"]["ttl_seconds"], 45);
        assert!(value["config"].get("judge").is_none());
        assert!(value["config"].get("policy").is_none());
        assert!(value["config"]["native"].get("registry_path").is_none());
        assert!(value["config"]["audit_retention"]
            .get("directory")
            .is_none());
    }

    #[test]
    fn reference_rebinding_roundtrips_complete_supported_config() {
        let original = config();
        let value = projected(&original).unwrap();
        let mut restored = value["config"].clone();
        restored["policy"] = value["references"]["policy"].clone();
        restored["native"]["registry_path"] = value["references"]["registry"].clone();
        restored["audit_retention"]["directory"] = value["references"]["audit_directory"].clone();
        assert_eq!(
            Config::from_yaml(&serde_json::to_string(&original).unwrap()).unwrap(),
            Config::from_yaml(&serde_json::to_string(&restored).unwrap()).unwrap()
        );
    }

    #[test]
    fn standalone_config_retains_explicit_native_absence() {
        let value = projected(&json!({"policy":"/owned/policy.yaml"})).unwrap();
        assert_eq!(value["config"]["native"], Value::Null);
        assert_eq!(value["references"]["registry"], Value::Null);
        assert_eq!(value["config"]["enforce"], false);
    }

    #[test]
    fn enabled_or_customized_disabled_judge_cannot_be_omitted() {
        for judge in [
            json!({"enabled": true}),
            json!({"enabled": false, "url": "http://secret-canary.invalid"}),
            json!({"enabled": false, "model": "private-canary"}),
            json!({"enabled": false, "timeout_ms": 9000}),
        ] {
            let mut value = config();
            value.as_object_mut().unwrap().remove("native");
            value["judge"] = judge;
            assert_eq!(projected(&value), Err("configuration_judge_unsupported"));
        }
    }

    #[test]
    fn sensitive_capture_legacy_audit_and_unknown_settings_refuse() {
        for (key, setting, reason) in [
            (
                "capture_unknown_raw",
                json!(true),
                "configuration_raw_capture_unsupported",
            ),
            ("audit", json!("/private/audit"), "configuration_invalid"),
            (
                "secret_canary",
                json!("never-export"),
                "configuration_invalid",
            ),
        ] {
            let mut value = config();
            value[key] = setting;
            assert_eq!(projected(&value), Err(reason));
        }
        let mut value = config();
        value.as_object_mut().unwrap().remove("audit_retention");
        value["audit"] = json!("/private/audit");
        assert_eq!(
            projected(&value),
            Err("configuration_legacy_audit_unsupported")
        );
    }

    #[test]
    fn unsupported_native_execution_and_invalid_ttls_refuse() {
        let mut value = config();
        value["native"]["git_execution"] = json!({"profile_path":"/private/git-profile.json",
            "profile_sha256":"b".repeat(64),"server_id":"original-git"});
        assert_eq!(
            projected(&value),
            Err("configuration_execution_unsupported")
        );
        value["native"]
            .as_object_mut()
            .unwrap()
            .remove("git_execution");
        value["native"]["approval"]["ttl_seconds"] = json!(301);
        assert_eq!(projected(&value), Err("configuration_invalid"));
    }

    #[test]
    fn unsafe_or_missing_policy_and_registry_references_refuse() {
        for policy in [
            Value::Null,
            json!("relative.yaml"),
            json!("/owned/../policy.yaml"),
            json!("/owned/\nprivate.yaml"),
        ] {
            let mut value = config();
            value["policy"] = policy;
            assert!(projected(&value).is_err());
        }
        let mut value = config();
        value["native"]["registry_path"] = json!("relative.json");
        assert_eq!(projected(&value), Err("configuration_invalid"));
    }

    #[test]
    fn authoritative_parser_refuses_duplicate_json_yaml_and_nested_unknown_fields() {
        for input in [
            r#"{"policy":"/owned/policy.yaml","port":1,"port":2}"#,
            "policy: /owned/policy.yaml\nport: 1\nport: 2\n",
            "policy: /owned/policy.yaml\nprovenance:\n  private_canary: never-export\n",
            "policy: /owned/policy.yaml\n---\npolicy: /second.yaml\n",
        ] {
            assert_eq!(
                project(input.as_bytes(), false),
                Err("configuration_invalid")
            );
        }
    }

    #[test]
    fn oversized_and_invalid_utf8_are_refused_before_config_parsing() {
        assert_eq!(
            project(&vec![b' '; MAX_INPUT as usize + 1], false),
            Err("configuration_input_limit")
        );
        assert_eq!(project(&[255], false), Err("configuration_input_invalid"));
    }

    #[test]
    fn baseline_policy_uses_authoritative_parser_and_semantic_equality() {
        let value = project(POLICY.as_bytes(), true).unwrap();
        assert_eq!(value["kind"], "policy");
        assert_eq!(value["policy_sha256"].as_str().unwrap().len(), 64);
        let parsed = soup_wall_agent::AgentPolicySet::from_yaml(POLICY).unwrap();
        let equivalent = serde_json::to_vec(&parsed).unwrap();
        assert_eq!(project(&equivalent, true).unwrap(), value);
        assert_eq!(
            project(b"agent_policies: []\ndefault: allow\n", true),
            Err("configuration_policy_unsupported")
        );
        assert_eq!(
            project(b"secret_canary: never-export\n", true),
            Err("configuration_policy_invalid")
        );
    }

    #[test]
    fn refused_cli_output_contains_only_finite_reason_and_never_parser_input() {
        let mut output = Vec::new();
        let code = run(
            &b"secret_canary: private-provider-key\n"[..],
            &mut output,
            false,
        );
        assert_eq!(code, 2);
        let value: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["reason"], "configuration_invalid");
        assert!(!String::from_utf8(output)
            .unwrap()
            .contains("private-provider-key"));
    }
}
