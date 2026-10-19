// SPDX-License-Identifier: Apache-2.0
//! Operator opt-in aggregate Windows Job budgets. These are resource limits,
//! never filesystem/network confinement or authority to select a server profile.

#![cfg_attr(not(windows), allow(dead_code))]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const ENVIRONMENT: &str = "AGENTFW_MCP_WINDOWS_BUDGET";
pub(crate) const FORMAT: &str = "sw-mcp/windows-job-budget/1";
const MAX_CONFIG_BYTES: usize = 4096;

fn refusal() -> anyhow::Error {
    anyhow::anyhow!("windows_budget_config_invalid")
}

/// Separate from reviewed tool manifests. Both the hard memory ceiling and
/// the lower terminal pressure threshold are explicit operator choices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Config {
    pub format: String,
    pub memory_max_bytes: u64,
    pub memory_pressure_bytes: u64,
    pub active_process_max: u32,
    pub cpu_user_millis: u64,
    pub wall_millis: u64,
}

impl Config {
    pub(crate) fn read(bytes: &[u8]) -> anyhow::Result<Self> {
        anyhow::ensure!(
            bytes.len() <= MAX_CONFIG_BYTES,
            "windows_budget_config_invalid"
        );
        let super::admission::Strict(value) =
            serde_json::from_slice(bytes).map_err(|_| refusal())?;
        let config: Self = serde_json::from_value(value).map_err(|_| refusal())?;
        anyhow::ensure!(
            config.format == FORMAT
                && (64 * 1024 * 1024..=16 * 1024 * 1024 * 1024).contains(&config.memory_max_bytes)
                && config.memory_max_bytes.is_multiple_of(65_536)
                && (32 * 1024 * 1024..config.memory_max_bytes)
                    .contains(&config.memory_pressure_bytes)
                && config.memory_pressure_bytes.is_multiple_of(65_536)
                && (2..=256).contains(&config.active_process_max)
                && (100..=300_000).contains(&config.cpu_user_millis)
                && (1000..=3_600_000).contains(&config.wall_millis),
            "windows_budget_config_invalid"
        );
        Ok(config)
    }

    pub(crate) fn identity(&self) -> String {
        // Fixed struct field order, no file path or account identity.
        format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(self).expect("finite fields"))
        )
    }

    pub(crate) fn load_from_env() -> anyhow::Result<Option<Self>> {
        let Some(path) = std::env::var_os(ENVIRONMENT) else {
            return Ok(None);
        };
        #[cfg(not(windows))]
        {
            let _ = path;
            anyhow::bail!("windows_budget_platform_unsupported");
        }
        #[cfg(windows)]
        {
            use std::io::Read;
            use std::os::windows::{fs::OpenOptionsExt, io::AsRawHandle};
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_READ_DATA, READ_CONTROL,
            };
            // No shared writers/deleters; final component cannot resolve a link.
            // Validate the actual open object, without repairing its permissions.
            let mut file = std::fs::OpenOptions::new()
                .access_mode(FILE_READ_DATA | FILE_READ_ATTRIBUTES | READ_CONTROL)
                .share_mode(0)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)
                .map_err(|_| refusal())?;
            crate::private_file_windows::verify_retention_security(
                file.as_raw_handle().cast(),
                false,
            )
            .map_err(|_| refusal())?;
            anyhow::ensure!(
                file.metadata().map_err(|_| refusal())?.len() <= MAX_CONFIG_BYTES as u64,
                "windows_budget_config_invalid"
            );
            let mut bytes = Vec::new();
            file.by_ref()
                .take(MAX_CONFIG_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| refusal())?;
            Self::read(&bytes).map(Some)
        }
    }
}

#[cfg(windows)]
mod backend;
#[cfg(windows)]
pub(crate) use backend::{Budget, Guard};

#[cfg(not(windows))]
#[derive(Clone)]
pub(crate) struct Guard;
#[cfg(not(windows))]
impl Guard {
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn valid() -> serde_json::Value {
        json!({"format":FORMAT,"memoryMaxBytes":134217728,"memoryPressureBytes":100663296,
            "activeProcessMax":8,"cpuUserMillis":2000,"wallMillis":10000})
    }
    #[test]
    fn complete_bounded_operator_config_is_independent_of_json_order() {
        let config = Config::read(valid().to_string().as_bytes()).unwrap();
        let reordered = br#"{"wallMillis":10000,"cpuUserMillis":2000,"activeProcessMax":8,"memoryPressureBytes":100663296,"memoryMaxBytes":134217728,"format":"sw-mcp/windows-job-budget/1"}"#;
        assert_eq!(config, Config::read(reordered).unwrap());
        assert_eq!(
            config.identity(),
            Config::read(reordered).unwrap().identity()
        );
    }
    #[test]
    fn incomplete_unknown_nonfinite_and_out_of_range_configs_are_refused() {
        let bad = [
            ("format", json!("sw-mcp/linux-cgroup-budget/1")),
            ("memoryMaxBytes", json!(0)),
            ("memoryMaxBytes", json!(u64::MAX)),
            ("memoryPressureBytes", json!(134217728)),
            ("memoryPressureBytes", json!(1)),
            ("activeProcessMax", json!(0)),
            ("activeProcessMax", json!(257)),
            ("cpuUserMillis", json!(0)),
            ("cpuUserMillis", json!(300001)),
            ("wallMillis", json!(999)),
            ("wallMillis", json!(3600001)),
            ("cpuRate", json!(50)),
        ];
        for (key, value) in bad {
            let mut config = valid();
            config[key] = value;
            assert_eq!(
                Config::read(config.to_string().as_bytes())
                    .unwrap_err()
                    .to_string(),
                "windows_budget_config_invalid",
                "{key}"
            );
        }
        for key in valid().as_object().unwrap().keys() {
            let mut config = valid();
            config.as_object_mut().unwrap().remove(key);
            assert!(
                Config::read(config.to_string().as_bytes()).is_err(),
                "{key}"
            );
        }
        let valid = valid().to_string();
        let duplicate = format!(
            "{},\"wallMillis\":10000}}",
            valid.strip_suffix('}').unwrap()
        );
        assert!(
            Config::read(duplicate.as_bytes()).is_err(),
            "equal duplicate authority must be refused"
        );
        for bytes in [
            b"{\"format\":NaN}".as_slice(),
            b"{\"format\":1,\"format\":2}",
            &vec![b' '; MAX_CONFIG_BYTES + 1],
        ] {
            assert!(Config::read(bytes).is_err());
        }
    }
}
