// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Daemon configuration: `~/.agentfw/config.yaml` with safe defaults.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use soup_wall_agent::TaintLimits;

fn default_bind() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    #[cfg(test)]
    if let Some(port) = TEST_DEFAULT_PORT.with(std::cell::Cell::get) {
        return port;
    }
    8787
}

// Absent-config lifecycle tests need their own endpoint without creating the
// very config.yaml whose absence they are testing. This override is compiled
// only into unit tests; it is thread-local, scoped, and restored on panic.
#[cfg(test)]
thread_local! {
    static TEST_DEFAULT_PORT: std::cell::Cell<Option<u16>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn with_test_default_port<T>(port: u16, run: impl FnOnce() -> T) -> T {
    assert_ne!(port, 0, "test endpoint must have an allocated port");
    struct Restore(Option<u16>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_DEFAULT_PORT.with(|value| value.set(self.0));
        }
    }
    let _restore = Restore(TEST_DEFAULT_PORT.with(|value| value.replace(Some(port))));
    run()
}
fn default_max_record_bytes() -> usize {
    262_144
}
fn default_timeout_ms() -> u64 {
    100
}
fn default_max_body_bytes() -> usize {
    8 * 1024 * 1024
}
fn default_judge_url() -> String {
    "http://localhost:1234/v1/chat/completions".into()
}
fn default_judge_model() -> String {
    "local-model".into()
}
fn default_judge_timeout() -> u64 {
    3000
}
fn default_max_span() -> usize {
    4096
}

/// Optional local-model escalation tier. Off unless a model is actually available.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JudgeCfg {
    #[serde(default)]
    pub enabled: bool,
    /// Any OpenAI-compatible chat-completions endpoint. Must be loopback.
    #[serde(default = "default_judge_url")]
    pub url: String,
    #[serde(default = "default_judge_model")]
    pub model: String,
    #[serde(default = "default_judge_timeout")]
    pub timeout_ms: u64,
    /// Cap on the tainted span sent for judging. Prefill dominates latency on a
    /// local model, so this is the main lever on how long a judgement takes.
    #[serde(default = "default_max_span")]
    pub max_span_bytes: usize,
}

impl Default for JudgeCfg {
    fn default() -> Self {
        Self {
            enabled: false,
            url: default_judge_url(),
            model: default_judge_model(),
            timeout_ms: default_judge_timeout(),
            max_span_bytes: default_max_span(),
        }
    }
}

/// Extract the host component (no port, no brackets) from a `scheme://...` URL,
/// without pulling in a URL-parsing dependency for one check. Anchors on the
/// authority component rather than matching a raw string prefix: a prefix check
/// against `"http://localhost"` would also match `http://localhost.evil.com`,
/// where `localhost.evil.com` is an attacker-controlled DNS name that merely
/// starts with the string "localhost".
fn url_host(url: &str) -> Option<&str> {
    let after_scheme = url.split_once("://")?.1;
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    // Drop userinfo (`user:pass@host`) if present.
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: `[::1]` or `[::1]:1234`.
        return rest.split(']').next();
    }
    // Strip a trailing `:port` — only if what follows the last colon is all digits,
    // so a bare IPv6 literal without brackets (which we don't accept anyway) isn't
    // mistaken for host:port.
    match authority.rfind(':') {
        Some(idx)
            if !authority[idx + 1..].is_empty()
                && authority[idx + 1..].bytes().all(|b| b.is_ascii_digit()) =>
        {
            Some(&authority[..idx])
        }
        _ => Some(authority),
    }
}

/// Whether a `judge.url` points at this machine only. Exact match on the extracted
/// host — never a prefix check, which lookalike hostnames like
/// `localhost.evil.com` or `127.0.0.1.evil.com` would defeat.
fn is_loopback_url(url: &str) -> bool {
    match url_host(url) {
        Some(host) => matches!(
            host.to_ascii_lowercase().as_str(),
            "localhost" | "127.0.0.1" | "::1"
        ),
        None => false,
    }
}

/// Daemon configuration. Every field has a safe default, so an absent config file
/// is equivalent to an empty one.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Loopback only. A non-loopback value is rejected at parse time.
    #[serde(default = "default_bind")]
    pub bind: String,
    #[serde(default = "default_port")]
    pub port: u16,
    /// `false` = shadow mode: verdicts are computed and logged but never enforced.
    #[serde(default)]
    pub enforce: bool,
    #[serde(default)]
    pub policy: Option<PathBuf>,
    #[serde(default)]
    pub audit: Option<PathBuf>,
    /// Opt-in, owner-only Linux or Windows audit segments. Legacy `audit` remains unchanged
    /// when this is absent.
    #[serde(default)]
    pub audit_retention: Option<crate::audit::RetentionConfig>,
    /// Persist the complete body of hook events unknown to this build.
    /// Disabled by default because future event shapes may contain credentials,
    /// prompts, file contents, or other sensitive material.
    #[serde(default)]
    pub capture_unknown_raw: bool,
    /// Cap on content handed to the taint recorder. Bounds synchronous recording
    /// work instead of scaling with an arbitrary tool-result size.
    #[serde(default = "default_max_record_bytes")]
    pub max_record_bytes: usize,
    /// Retained provenance accounting; defaults preserve existing configuration files.
    #[serde(default)]
    pub provenance: TaintLimits,
    #[serde(default = "default_timeout_ms")]
    pub deterministic_timeout_ms: u64,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    /// Optional local-model escalation tier. Off by default.
    #[serde(default)]
    pub judge: JudgeCfg,
    /// Optional operator-installed native registry. Never provided by hook callers.
    #[serde(default)]
    pub native: Option<NativeCfg>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeCfg {
    /// Opt-in daemon-owned verified original runtime. No client profile/command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution: Option<crate::native::execution::Config>,
    pub registry_path: PathBuf,
    pub registry_sha256: String,
    /// Opt-in single-use operator approval for native Ask calls. Absent = refusal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval: Option<NativeApprovalCfg>,
    /// Opt-in authenticated session liveness and bounded maintenance (SOU-89).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liveness: Option<NativeLivenessCfg>,
}

/// Bounded pending-approval lifecycle for native MCP Ask calls (SOU-48).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeApprovalCfg {
    /// Lifetime of one pending approval, 1..=300 seconds.
    #[serde(default = "default_native_approval_ttl")]
    pub ttl_seconds: u64,
}

fn default_native_approval_ttl() -> u64 {
    120
}

/// Opt-in session liveness and bounded orphan reclamation (SOU-89).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeLivenessCfg {
    /// Default lease duration in seconds (clamped to 1..=60).
    #[serde(default = "default_liveness_lease_seconds")]
    pub default_lease_seconds: u64,
    /// Maximum lease duration in seconds (clamped to 1..=60).
    #[serde(default = "default_liveness_max_lease_seconds")]
    pub max_lease_seconds: u64,
    /// Maintenance sweep interval in milliseconds.
    #[serde(default = "default_liveness_maintenance_interval_ms")]
    pub maintenance_interval_ms: u64,
}

fn default_liveness_lease_seconds() -> u64 {
    10
}

fn default_liveness_max_lease_seconds() -> u64 {
    60
}

fn default_liveness_maintenance_interval_ms() -> u64 {
    500
}

impl Default for Config {
    fn default() -> Self {
        Self {
            bind: default_bind(),
            port: default_port(),
            enforce: false,
            policy: None,
            audit: None,
            audit_retention: None,
            capture_unknown_raw: false,
            max_record_bytes: default_max_record_bytes(),
            provenance: TaintLimits::default(),
            deterministic_timeout_ms: default_timeout_ms(),
            max_body_bytes: default_max_body_bytes(),
            judge: JudgeCfg::default(),
            native: None,
        }
    }
}

impl Config {
    pub fn from_yaml(s: &str) -> anyhow::Result<Self> {
        let c: Config = serde_yaml::from_str(s)?;
        c.validate()?;
        Ok(c)
    }

    /// Socket/URL authority for this validated loopback bind. IPv6 literals
    /// require brackets so their colons cannot be mistaken for the port.
    pub fn socket_address(&self) -> String {
        if self.bind == "::1" {
            format!("[{}]:{}", self.bind, self.port)
        } else {
            format!("{}:{}", self.bind, self.port)
        }
    }

    /// Daemon HTTP endpoint, shared by preflight, installation, and MCP.
    pub fn endpoint_url(&self, path: &str) -> String {
        format!("http://{}{path}", self.socket_address())
    }

    /// Reject anything that would expose the daemon beyond this machine.
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        self.provenance.validate()?;
        if let Some(retention) = &self.audit_retention {
            retention.validate()?;
            anyhow::ensure!(
                self.audit.is_none(),
                "audit and audit_retention cannot both be set"
            );
        }
        if let Some(native) = &self.native {
            anyhow::ensure!(
                self.enforce && !self.judge.enabled,
                "native admission requires enforce: true and the optional judge disabled"
            );
            anyhow::ensure!(
                native.registry_path.is_absolute()
                    && crate::native::is_digest(&native.registry_sha256),
                "native registry requires an absolute operator path and lowercase SHA-256"
            );
            if let Some(approval) = &native.approval {
                anyhow::ensure!(
                    (1..=300).contains(&approval.ttl_seconds),
                    "native approval ttl_seconds must be 1..=300"
                );
            }
            if let Some(liveness) = &native.liveness {
                anyhow::ensure!(
                    (1..=60).contains(&liveness.default_lease_seconds),
                    "native liveness default_lease_seconds must be 1..=60"
                );
                anyhow::ensure!(
                    (1..=60).contains(&liveness.max_lease_seconds),
                    "native liveness max_lease_seconds must be 1..=60"
                );
                anyhow::ensure!(
                    liveness.default_lease_seconds <= liveness.max_lease_seconds,
                    "native liveness default_lease_seconds cannot exceed max_lease_seconds"
                );
                anyhow::ensure!(
                    (50..=10_000).contains(&liveness.maintenance_interval_ms),
                    "native liveness maintenance_interval_ms must be 50..=10000"
                );
            }
        }
        let ok = self.bind == "127.0.0.1" || self.bind == "::1" || self.bind == "localhost";
        anyhow::ensure!(
            ok,
            "bind must be a loopback address (127.0.0.1, ::1, localhost); got {:?}. \
             The daemon holds session data and taint state and must never be reachable off-host.",
            self.bind
        );
        // Only enforced when the judge is actually enabled: a disabled judge with a
        // silly timeout or a non-loopback URL sitting in a config file must not
        // stop the daemon from booting. Most installs will never turn this on.
        if self.judge.enabled {
            anyhow::ensure!(
                self.judge.timeout_ms <= 4000,
                "judge.timeout_ms must be <= 4000: the Claude Code hook timeout is 5s, and a judge \
                 allowed to outlast it would make the hook itself time out. Got {}",
                self.judge.timeout_ms
            );
            anyhow::ensure!(
                is_loopback_url(&self.judge.url),
                "judge.url must be a loopback address; got {:?}. The judge prompt contains tool \
                 arguments and untrusted fetched content — sending that off-host would make this \
                 firewall an exfiltration channel.",
                self.judge.url
            );
        }
        Ok(())
    }

    /// Resolve the profile path without creating directories or changing permissions.
    pub fn home_path() -> anyhow::Result<PathBuf> {
        platform_home_dir()
            .map(|p| p.join(".agentfw"))
            .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))
    }

    /// `~/.agentfw`, created if absent.
    pub fn home() -> anyhow::Result<PathBuf> {
        let home = platform_home_dir()
            .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))?;
        let dir = home.join(".agentfw");
        #[cfg(windows)]
        crate::private_file_windows::ensure_private_directory(&dir)?;
        #[cfg(not(windows))]
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }
}

fn platform_home_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe() {
        let c = Config::default();
        assert_eq!(c.bind, "127.0.0.1", "must never bind a public interface");
        assert_eq!(c.port, 8787);
        assert!(
            !c.enforce,
            "shadow mode is the default; enforcement is opt-in"
        );
        assert_eq!(c.max_record_bytes, 262_144);
        assert_eq!(c.deterministic_timeout_ms, 100);
        assert!(
            !c.capture_unknown_raw,
            "raw unknown events may contain secrets and must be opt-in"
        );
    }

    #[test]
    fn parses_a_partial_file_and_keeps_defaults() {
        let c = Config::from_yaml("enforce: true\nport: 9001\n").unwrap();
        assert!(c.enforce);
        assert_eq!(c.port, 9001);
        assert_eq!(c.bind, "127.0.0.1");
        assert_eq!(c.max_record_bytes, 262_144);
        assert!(!c.capture_unknown_raw);
    }

    #[test]
    fn test_endpoint_is_thread_local_and_restored_after_nested_panic() {
        assert_eq!(Config::default().port, 8787);
        with_test_default_port(12345, || {
            assert_eq!(Config::default().port, 12345);
            assert_eq!(Config::from_yaml("{}").unwrap().port, 12345);
            assert_eq!(Config::from_yaml("port: 9001").unwrap().port, 9001);
            assert_eq!(
                std::thread::spawn(|| Config::default().port)
                    .join()
                    .unwrap(),
                8787
            );
            let result = std::panic::catch_unwind(|| {
                with_test_default_port(12346, || panic!("fixture unwind"));
            });
            assert!(result.is_err());
            assert_eq!(Config::default().port, 12345);
        });
        assert_eq!(Config::default().port, 8787);
    }

    #[test]
    fn raw_unknown_capture_requires_explicit_opt_in() {
        let c = Config::from_yaml("capture_unknown_raw: true\n").unwrap();
        assert!(c.capture_unknown_raw);
    }

    #[test]
    fn an_empty_file_is_all_defaults() {
        let c = Config::from_yaml("{}").unwrap();
        assert_eq!(c, Config::default());
    }

    #[test]
    fn a_non_loopback_bind_is_rejected() {
        // Binding a public interface would expose session data and let any host
        // poison taint state. This must be impossible via config.
        let err = Config::from_yaml("bind: 0.0.0.0\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("loopback"), "got: {err}");
    }

    #[test]
    fn each_supported_bind_formats_a_valid_socket_and_endpoint_authority() {
        for (bind, authority) in [
            ("127.0.0.1", "127.0.0.1:9001"),
            ("::1", "[::1]:9001"),
            ("localhost", "localhost:9001"),
        ] {
            let cfg = Config::from_yaml(&format!("bind: '{bind}'\nport: 9001\n")).unwrap();
            assert_eq!(cfg.socket_address(), authority);
            for path in ["/health", "/hook", "/mcp"] {
                let endpoint = cfg.endpoint_url(path);
                let url = reqwest::Url::parse(&endpoint).unwrap();
                assert_eq!(url.port(), Some(9001));
                assert_eq!(url.path(), path);
                assert_eq!(endpoint, format!("http://{authority}{path}"));
            }
            if bind != "localhost" {
                assert!(cfg
                    .socket_address()
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .ip()
                    .is_loopback());
            }
        }
    }

    #[test]
    fn ipv6_formatting_does_not_expand_the_allowed_bind_list() {
        for bind in ["::", "[::1]", "0.0.0.0", "localhost.example.invalid"] {
            assert!(Config::from_yaml(&format!("bind: '{bind}'\n")).is_err());
        }
    }

    // Optional judge configuration.

    #[test]
    fn the_judge_is_disabled_by_default() {
        let c = Config::default();
        assert!(
            !c.judge.enabled,
            "a local model is optional; the tool must work without one"
        );
        assert_eq!(c.judge.timeout_ms, 3000);
        assert_eq!(c.judge.max_span_bytes, 4096);
        assert!(c.judge.url.contains("/v1/chat/completions"));
    }

    #[test]
    fn a_config_without_a_judge_block_still_parses() {
        // Existing configurations without a judge block must keep working.
        let c = Config::from_yaml("enforce: true\n").unwrap();
        assert!(!c.judge.enabled);
    }

    #[test]
    fn an_empty_file_still_equals_default_with_judge_added() {
        let c = Config::from_yaml("{}").unwrap();
        assert_eq!(c, Config::default());
    }

    #[test]
    fn a_judge_timeout_that_would_outlast_the_hook_is_rejected() {
        // The Claude Code hook timeout is 5s. A judge allowed to run longer would
        // make the hook itself time out, which is a worse failure than no judge.
        let err = Config::from_yaml("judge:\n  enabled: true\n  timeout_ms: 9000\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("timeout"), "got: {err}");
    }

    #[test]
    fn a_disabled_judge_with_an_oversized_timeout_does_not_block_boot() {
        // Most installs have no local model. A silly timeout on a disabled judge
        // must not stop the daemon from starting.
        let c = Config::from_yaml("judge:\n  enabled: false\n  timeout_ms: 999999\n").unwrap();
        assert!(!c.judge.enabled);
        assert_eq!(c.judge.timeout_ms, 999_999);
    }

    #[test]
    fn a_judge_url_must_be_loopback_when_enabled() {
        // The prompt contains tainted content and tool arguments. Sending that to a
        // remote endpoint would be an exfiltration channel opened by the firewall.
        let err = Config::from_yaml(
            "judge:\n  enabled: true\n  url: https://api.example.com/v1/chat/completions\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("loopback"), "got: {err}");
    }

    #[test]
    fn a_lookalike_loopback_hostname_is_not_fooled_by_a_prefix_check() {
        // "http://localhost.evil.com" starts with "http://localhost" but resolves
        // to an attacker-controlled domain. A naive `starts_with` check would let
        // this through and turn the judge into an exfiltration channel.
        for url in [
            "http://localhost.evil.com/v1/chat/completions",
            "http://127.0.0.1.evil.com/v1/chat/completions",
        ] {
            let err = Config::from_yaml(&format!("judge:\n  enabled: true\n  url: {url}\n"))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("loopback"),
                "lookalike host {url:?} must be rejected, got: {err}"
            );
        }
    }

    #[test]
    fn loopback_urls_with_ports_and_ipv6_are_accepted() {
        for url in [
            "http://localhost:1234/v1/chat/completions",
            "http://127.0.0.1:1234/v1/chat/completions",
            "http://[::1]:1234/v1/chat/completions",
        ] {
            let c = Config::from_yaml(&format!("judge:\n  enabled: true\n  url: {url}\n"))
                .unwrap_or_else(|e| panic!("expected {url:?} to be accepted, got: {e}"));
            assert!(c.judge.enabled);
        }
    }

    #[test]
    fn an_unknown_key_inside_the_judge_block_is_rejected() {
        let err = Config::from_yaml("judge:\n  enabled: true\n  bogus: 1\n")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("bogus") || err.contains("unknown field"),
            "got: {err}"
        );
    }
    #[test]
    fn provenance_limits_are_additive_and_partial_configuration_keeps_defaults() {
        let defaults = Config::from_yaml("enforce: true\n").unwrap();
        assert_eq!(defaults.provenance, TaintLimits::default());
        let custom =
            Config::from_yaml("provenance:\n  per_session_bytes: 65536\n  max_sessions: 8\n")
                .unwrap();
        assert_eq!(custom.provenance.per_session_bytes, 65536);
        assert_eq!(custom.provenance.max_sessions, 8);
        assert_eq!(custom.provenance.total_bytes, 64 * 1024 * 1024);
        assert_eq!(custom.provenance.max_literal_bytes, 4096);
    }

    #[test]
    fn provenance_limits_reject_unknown_and_unreviewed_values() {
        for yaml in [
            "provenance:\n  unknown_budget: 1\n",
            "provenance:\n  max_sessions: 65537\n",
            "provenance:\n  max_input_bytes: 1048577\n",
            "provenance:\n  max_literal_bytes: -1\n",
        ] {
            assert!(Config::from_yaml(yaml).is_err(), "accepted {yaml}");
        }
    }

    #[test]
    fn zero_provenance_budgets_are_explicit_valid_configuration() {
        let config = Config::from_yaml(
            "provenance:\n  per_session_bytes: 0\n  total_bytes: 0\n  max_sessions: 0\n",
        )
        .unwrap();
        assert_eq!(config.provenance.per_session_bytes, 0);
        assert_eq!(config.provenance.total_bytes, 0);
        assert_eq!(config.provenance.max_sessions, 0);
    }
}
