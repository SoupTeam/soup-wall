// SPDX-License-Identifier: Apache-2.0
//! Experimental, operator-pinned complete-result semantic review.
//! Native/1 currently rejects configuration and ignores permits: runtime-to-Call
//! provenance is missing. This module is retained as an isolated prototype.
//!
//! This is not a wire permission. A private permit binds every original decoded
//! channel, including duplicate/empty channels and their order. It only enables
//! the agent's narrow structural-evidence alternative; current policy, authority,
//! signatures, provenance retention and all other detectors still decide release.
//! Unavailable, busy, uncertain or failed workers leave the original decision.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const MODEL_SHA256: &str = "5ae9f527897b1ffcb2b13440875769d0c28a25fb976b8b42465f0ad5b462b61b";
#[cfg(any(target_os = "linux", test))]
const PROTOCOL: &str = "soup-result-data/1";
const MAX_TEXT: usize = 1024 * 1024;
const MAX_CHANNELS: usize = 64;
#[cfg(target_os = "linux")]
const MAX_FRAME: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const DEADLINE: std::time::Duration = std::time::Duration::from_millis(1400);

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Owner-private Python venv, outside every tool-writable workspace.
    pub runtime_dir: PathBuf,
    /// SHA-256 of the canonical Python executable, not a symlink's text.
    pub interpreter_sha256: String,
    /// Hash of the complete runtime tree, using `runtime_digest` below.
    pub runtime_sha256: String,
    /// Owner-private pinned BASE assets; the embedded worker verifies all assets.
    pub assets_dir: PathBuf,
}

impl Config {
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            cfg!(target_os = "linux"),
            "result data review is Linux-only"
        );
        anyhow::ensure!(
            self.runtime_dir.is_absolute()
                && self.assets_dir.is_absolute()
                && crate::native::is_digest(&self.interpreter_sha256)
                && crate::native::is_digest(&self.runtime_sha256),
            "result data review requires absolute private paths and lowercase SHA-256 pins"
        );
        Ok(())
    }
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn input(channels: &[String]) -> Option<String> {
    if channels.is_empty()
        || channels.len() > MAX_CHANNELS
        || channels
            .iter()
            .try_fold(0usize, |size, s| size.checked_add(s.len()))?
            > MAX_TEXT
    {
        return None;
    }
    // No trim, normalization, truncation, deduplication or tool/record exceptions.
    serde_json::to_string(&serde_json::json!({ "channels": channels })).ok()
}

/// Construction is private to this module's validated owned-worker reply path.
pub(crate) struct DataPermit {
    input_sha256: String,
}

impl DataPermit {
    pub(crate) fn matches(&self, channels: &[String]) -> bool {
        input(channels).is_some_and(|value| sha(value.as_bytes()) == self.input_sha256)
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reply {
    v: String,
    #[serde(rename = "type")]
    kind: String,
    id: u64,
    input_sha256: String,
    model_sha256: String,
    assessment: String,
    coverage_complete: bool,
    view_count: usize,
    max_score: Option<f64>,
}

#[cfg(any(target_os = "linux", test))]
fn check_reply(bytes: &[u8], id: u64, digest: &str, channels: usize) -> anyhow::Result<bool> {
    let reply: Reply = serde_json::from_slice(bytes)?;
    anyhow::ensure!(
        reply.v == PROTOCOL
            && reply.kind == "review"
            && reply.id == id
            && reply.input_sha256 == digest
            && reply.model_sha256 == MODEL_SHA256,
        "result review reply binding mismatch"
    );
    anyhow::ensure!(
        matches!(
            reply.assessment.as_str(),
            "data" | "instruction" | "unknown"
        ),
        "unknown result assessment"
    );
    if let Some(score) = reply.max_score {
        anyhow::ensure!(
            score.is_finite() && (0.0..=1.0).contains(&score),
            "invalid score"
        );
    }
    if reply.assessment == "data" {
        anyhow::ensure!(
            reply.coverage_complete
                && reply.view_count == channels + 1
                && reply.max_score.is_some_and(|score| score <= 0.05),
            "incomplete or uncertain Data reply"
        );
        return Ok(true);
    }
    Ok(false)
}

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{installation_pin, runtime_digest, Reviewer};

#[cfg(not(target_os = "linux"))]
pub struct Reviewer;
#[cfg(not(target_os = "linux"))]
impl Reviewer {
    pub fn start(_: Config) -> anyhow::Result<Self> {
        anyhow::bail!("result data review is Linux-only")
    }

    pub(crate) async fn review(&self, _: Vec<String>) -> Option<DataPermit> {
        None
    }

    pub(crate) fn ready(&self) -> bool {
        false
    }
}

#[cfg(test)]
pub(crate) fn test_permit(channels: &[String]) -> DataPermit {
    DataPermit {
        input_sha256: sha(input(channels).expect("bounded test input").as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(id: u64, digest: &str) -> serde_json::Value {
        serde_json::json!({"v": PROTOCOL, "type": "review", "id": id,
            "input_sha256": digest, "model_sha256": MODEL_SHA256,
            "assessment": "data", "coverage_complete": true,
            "view_count": 4, "max_score": 0.02})
    }

    #[test]
    fn private_permit_binds_all_original_channels() {
        let channels = vec!["a\r\n".into(), "a\r\n".into(), "".into()];
        let digest = sha(input(&channels).unwrap().as_bytes());
        assert!(check_reply(
            &serde_json::to_vec(&frame(1, &digest)).unwrap(),
            1,
            &digest,
            3
        )
        .unwrap());
        let permit = DataPermit {
            input_sha256: digest,
        };
        assert!(permit.matches(&channels));
        assert!(!permit.matches(&["a\n".into(), "a\r\n".into(), "".into()]));
        assert!(!permit.matches(&["a\r\n".into(), "".into()]));
        assert!(!permit.matches(&["".into(), "a\r\n".into(), "a\r\n".into()]));
    }

    #[test]
    fn malformed_stale_partial_and_uncertain_data_are_not_permits() {
        let original = frame(7, &"a".repeat(64));
        for (key, value) in [
            ("id", serde_json::json!(8)),
            ("input_sha256", serde_json::json!("b".repeat(64))),
            ("model_sha256", serde_json::json!("b".repeat(64))),
            ("coverage_complete", serde_json::json!(false)),
            ("view_count", serde_json::json!(3)),
            ("max_score", serde_json::json!(0.05000001)),
            ("max_score", serde_json::Value::Null),
            ("extra", serde_json::json!(true)),
        ] {
            let mut changed = original.clone();
            changed[key] = value;
            assert!(
                check_reply(
                    &serde_json::to_vec(&changed).unwrap(),
                    7,
                    &"a".repeat(64),
                    3
                )
                .is_err(),
                "{key}"
            );
        }
        for assessment in ["unknown", "instruction"] {
            let mut changed = original.clone();
            changed["assessment"] = serde_json::json!(assessment);
            assert!(!check_reply(
                &serde_json::to_vec(&changed).unwrap(),
                7,
                &"a".repeat(64),
                3
            )
            .unwrap());
        }
    }

    #[test]
    fn capacity_does_not_silently_change_the_input() {
        assert!(input(&[]).is_none());
        assert!(input(&vec!["".into(); 65]).is_none());
        assert!(input(&["a".repeat(MAX_TEXT), "b".into()]).is_none());
        assert!(input(&["a".repeat(MAX_TEXT)]).is_some());
    }

    #[test]
    fn default_config_does_not_enable_or_serialize_review() {
        let legacy = crate::Config::default();
        assert!(legacy.result_data_review.is_none());
        assert!(serde_json::to_value(legacy)
            .unwrap()
            .get("result_data_review")
            .is_none());
        let config = serde_json::json!({"result_data_review": {
            "runtime_dir": "/private/runtime", "assets_dir": "/private/assets",
            "runtime_sha256": "a".repeat(64), "interpreter_sha256": "b".repeat(64),
        }});
        assert!(
            crate::Config::from_yaml(&config.to_string()).is_err(),
            "native enforce must be configured"
        );
    }
}
