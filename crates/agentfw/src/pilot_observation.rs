// SPDX-License-Identifier: Apache-2.0
//! Offline projection of an already queried prepared-run diagnostic snapshot.
//!
//! The discovery reader supplies held/verified config and policy bytes and a
//! fresh nonce. This command reuses the authoritative diagnostic validator and
//! policy/config digest formats. It never reads a home, contacts a daemon,
//! creates authority, or upgrades unknown execution coverage into protection.
use crate::{protection_status as status, Config};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

const MAX_INPUT: u64 = 256 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    format: String,
    nonce: String,
    daemon_pid: u32,
    binary_sha256: String,
    registry_sha256: String,
    config: String,
    policy: String,
    snapshot: status::Snapshot,
}

fn project(input: Input, now: u64) -> Result<Value, &'static str> {
    if input.format != "sw-prepared-pilot-observation-input/1"
        || input.config.len() > 65536
        || input.policy.len() > 65536
        || input.daemon_pid < 2
        || [&input.binary_sha256, &input.registry_sha256]
            .iter()
            .any(|s| {
                s.len() != 64
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
    {
        return Err("observation_input_invalid");
    }
    let config = Config::from_yaml(&input.config).map_err(|_| "observation_config_invalid")?;
    let endpoint: std::net::SocketAddr = config
        .socket_address()
        .parse()
        .map_err(|_| "observation_endpoint_invalid")?;
    if !endpoint.ip().is_loopback() || input.snapshot.runtime.pid != input.daemon_pid {
        return Err("observation_identity_mismatch");
    }
    let policy = soup_wall_agent::AgentPolicySet::from_yaml(&input.policy)
        .map_err(|_| "observation_policy_invalid")?;
    let policy_bytes = serde_json::to_vec(&policy).map_err(|_| "observation_policy_invalid")?;
    let expected = status::Expectations {
        config_sha256: Some(status::config_digest(&config)),
        policy_sha256: Some(format!("{:x}", Sha256::digest(policy_bytes))),
        binary_sha256: Some(input.binary_sha256),
        registry_sha256: Some(input.registry_sha256),
        ..Default::default()
    };
    status::validate(&input.snapshot, &input.nonce, now, &expected)?;
    let s = input.snapshot;
    Ok(json!({"format":"sw-prepared-pilot-observation/1",
        "state":"authenticated_daemon_observed", "reason":"current_instance_ready_not_execution",
        "mode":s.mode, "policy_sha256":s.policy.sha256,
        "registry_sha256":s.registry.sha256, "config_sha256":s.runtime.loaded_config_sha256,
        "binary_sha256":s.runtime.binary_sha256, "protection":"unknown", "execution_coverage":"unknown",
        "paths":s.paths.into_iter().map(|p| json!({"path":p.path, "capability":p.capability,
            "configured":p.configured, "execution_coverage":p.execution_coverage, "reason":p.reason})).collect::<Vec<_>>() }))
}

pub fn run() -> i32 {
    let mut raw = Vec::new();
    let result = (|| {
        std::io::stdin()
            .take(MAX_INPUT + 1)
            .read_to_end(&mut raw)
            .map_err(|_| "observation_input_unavailable")?;
        if raw.len() as u64 > MAX_INPUT {
            return Err("observation_input_limit");
        }
        let input: Input = serde_json::from_slice(&raw).map_err(|_| "observation_input_invalid")?;
        project(input, status::now_ms())
    })();
    let (value, code) = match result {
        Ok(value) => (value, 0),
        Err(reason) => (
            json!({"format":"sw-prepared-pilot-observation/1", "state":"unavailable",
            "reason":reason, "protection":"unknown", "execution_coverage":"unknown"}),
            1,
        ),
    };
    let mut output = std::io::stdout().lock();
    if writeln!(output, "{value}").is_err() {
        return 1;
    }
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Input {
        let config = Config::from_yaml("bind: 127.0.0.1\nport: 9876\nenforce: true\n").unwrap();
        let policy = "agent_policies: []\ndefault: allow\n";
        let parsed = soup_wall_agent::AgentPolicySet::from_yaml(policy).unwrap();
        let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&parsed).unwrap()));
        let identities = [
            "legacy_http_hook",
            "mcp_manifest",
            "native_admission",
            "unbound_mcp_resource_executor",
            "arbitrary_server_containment",
            "model_consumption",
            "bound_resource_executor",
        ];
        let reasons = [
            "legacy_http_hook_fail_open",
            "manifest_check_only_not_execution",
            "trusted_collector_required",
            "resource_executor_unsupported",
            "no_arbitrary_server_containment",
            "model_consumption_unverified",
            "executor_runtime_unverified",
        ];
        let capabilities = [
            "supported",
            "supported",
            "supported",
            "unsupported",
            "unsupported",
            "unknown",
            "unknown",
        ];
        serde_json::from_value(json!({"format":"sw-prepared-pilot-observation-input/1", "nonce":"a".repeat(32),
            "daemon_pid":42, "binary_sha256":"b".repeat(64), "registry_sha256":"c".repeat(64),
            "config":"bind: 127.0.0.1\nport: 9876\nenforce: true\n", "policy":policy,
            "snapshot":{"contract_version":status::CONTRACT, "nonce":"a".repeat(32), "captured_at_ms":10000,
            "mode":"enforcing", "runtime":{"pid":42, "instance":"d".repeat(32), "started_at_ms":9000,
                "binary_sha256":"b".repeat(64), "loaded_config_sha256":status::config_digest(&config), "lifecycle":null},
            "policy":{"digest_format":"agent-policy-json/1", "sha256":digest, "rule_count":0,
                "managed_revision":null,"managed_sequence":null,"managed_source_sha256":null},
            "registry":{"state":"supported","id":"owned-registry","sha256":"c".repeat(64),"tool_count":2},
            "paths":identities.iter().enumerate().map(|(i,id)| json!({"path":id,"capability":capabilities[i],
                "configured":if i==2 {Some(true)} else {None}, "execution_coverage":"unknown", "reason":reasons[i],
                "activity":if i<3 {Some(json!({"authenticated_requests":0,"last_seen_ms":null}))} else {None}})).collect::<Vec<_>>()}})).unwrap()
    }

    #[test]
    fn accepted_validator_binds_policy_config_and_coverage_without_claiming_execution() {
        let value = project(input(), 10001).unwrap();
        assert_eq!(value["protection"], "unknown");
        assert_eq!(value["paths"].as_array().unwrap().len(), 7);
        assert!(value.get("nonce").is_none());
        assert!(value.get("runtime").is_none());
        for mutation in 0..7 {
            let mut i = input();
            match mutation {
                0 => i.snapshot.nonce = "wrong".into(),
                1 => i.snapshot.runtime.loaded_config_sha256 = "0".repeat(64),
                2 => i.snapshot.policy.sha256 = "0".repeat(64),
                3 => i.snapshot.paths[2].execution_coverage = status::Evidence::Supported,
                4 => i.snapshot.paths.pop().map(|_| ()).unwrap(),
                5 => i.snapshot.runtime.pid = 43,
                _ => i.snapshot.captured_at_ms = 0,
            }
            assert!(project(i, 10001).is_err(), "mutation {mutation}");
        }
    }
}
