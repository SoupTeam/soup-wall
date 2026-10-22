// SPDX-License-Identifier: Apache-2.0
//! `agentfw self-test`: one operator command that exercises an installed Agent
//! end to end in an owned, isolated workspace and writes a versioned report.
//!
//! The controlled path is a scripted stdio MCP client, the production
//! `agentfw mcp --native-admission` collector, the explicitly selected local
//! classifier, an owned `agentfw serve` daemon with the shipped default policy,
//! the bundled fixture MCP server and an owned numeric-loopback receiver. It is
//! not Claude Code, model-context or live-model evidence.

pub mod fixture;
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) mod windows_safety;

use std::path::PathBuf;

use serde::Serialize;
use serde_json::{json, Value};

pub use fixture::FixtureArgs;

pub const SCHEMA: &str = "sw-self-test/1";

#[cfg(target_os = "linux")]
pub const PROFILE: &str = "linux-stdio-mcp-admission-v1";
#[cfg(target_os = "macos")]
pub const PROFILE: &str = "macos-stdio-mcp-admission-v1";
#[cfg(windows)]
pub const PROFILE: &str = "windows-stdio-mcp-admission-v1";
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub const PROFILE: &str = "unsupported-stdio-mcp-admission-v1";

/// Stable exit codes. Clap reports usage errors with 2.
pub const EXIT_PASSED: i32 = 0;
pub const EXIT_FAILED: i32 = 3;
pub const EXIT_INCOMPLETE: i32 = 4;
pub const EXIT_UNSUPPORTED: i32 = 5;

pub const CONTROLLED_PATH: &str = "scripted stdio MCP client -> agentfw mcp --native-admission collector -> \
selected rule-baseline classifier -> owned agentfw serve daemon (/native/v1, shipped default policy, \
bundled registry) -> bundled fixture MCP server -> owned 127.0.0.1 receiver";

#[cfg(target_os = "linux")]
const PLATFORM_LIMITATION: &str =
    "Linux execution profile only; the collector is not an OS sandbox";
#[cfg(target_os = "macos")]
const PLATFORM_LIMITATION: &str =
    "macOS execution profile only; the collector is not an OS sandbox";
#[cfg(windows)]
const PLATFORM_LIMITATION: &str =
    "Native Windows standard-user execution profile; the collector is not an OS sandbox";
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
const PLATFORM_LIMITATION: &str =
    "Unsupported execution profile; the collector is not an OS sandbox";

pub const LIMITATIONS: [&str; 6] = [
    "Scripted MCP client frames: not Claude Code, not model context and not live-model effectiveness",
    "One bundled fixture server, two fixture tools and synthetic data; other servers need their own review",
    "Result release is to the MCP client; the client's later use of a released result is outside this test",
    "Unattended Ask is enforced as a refusal; there is no approval channel",
    PLATFORM_LIMITATION,
    "Configured and healthy daemon state is reported separately and is never counted as witnessed protection",
];

#[derive(clap::Args, Debug, Clone)]
pub struct Args {
    /// Installed Agent executable to exercise. It is never discovered from PATH.
    #[arg(long)]
    pub agent: PathBuf,
    /// Classifier kind. Only the locally installed Task 1 rule baseline is supported.
    #[arg(long, value_parser = ["rule-baseline"])]
    pub classifier: String,
    /// Locally installed classifier source (`rule_baseline.py`).
    #[arg(long)]
    pub classifier_script: PathBuf,
    /// Expected SHA-256 of the classifier source; any other revision is refused.
    #[arg(long)]
    pub classifier_sha256: String,
    /// Python 3 interpreter that runs the classifier.
    #[arg(long)]
    pub classifier_python: PathBuf,
    /// Fresh path for the JSON evidence report (an existing file is never replaced).
    #[arg(long)]
    pub report: PathBuf,
    /// Existing directory for the owned temporary workspace (default: the system temporary directory).
    #[arg(long)]
    pub work_parent: Option<PathBuf>,
    /// Preferred first loopback port for the owned daemon; a busy port is replaced by a free one.
    #[arg(long)]
    pub daemon_port: Option<u16>,
    /// Upper bound for the whole run.
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(10..=600))]
    pub timeout_seconds: u64,
    /// Keep the owned workspace (synthetic data only) for inspection.
    #[arg(long)]
    pub keep_workspace: bool,
    /// Linux acceptance option: exercise the production bounded audit sink.
    #[arg(long)]
    pub bounded_audit_retention: bool,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Passed,
    Failed,
    Unavailable,
    Unsupported,
    Incomplete,
}

impl Status {
    pub fn label(self) -> &'static str {
        match self {
            Status::Passed => "PASS",
            Status::Failed => "FAIL",
            Status::Unavailable => "UNAVAILABLE",
            Status::Unsupported => "UNSUPPORTED",
            Status::Incomplete => "INCOMPLETE",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Scenario {
    pub id: &'static str,
    pub status: Status,
    pub expected: &'static str,
    pub detail: String,
    pub observed: Value,
    pub receipts: Value,
}

pub const SCENARIOS: [(&str, &str); 5] = [
    ("allowed_read", "read_document executes once and the client receives the exact note bytes"),
    ("adversarial_result", "read_document executes but its injected result is withheld from the client"),
    ("protected_send_refused", "send_http with the synthetic key is refused; the MCP child and receiver see nothing"),
    ("useful_read_after_refusal", "a later read_document executes and returns the exact note bytes"),
    ("daemon_loss", "after the owned daemon is killed, a protected send never reaches the MCP child or receiver"),
];

pub fn pending_scenarios(status: Status, detail: &str) -> Vec<Scenario> {
    SCENARIOS
        .iter()
        .map(|(id, expected)| Scenario {
            id,
            status,
            expected,
            detail: detail.into(),
            observed: Value::Null,
            receipts: Value::Null,
        })
        .collect()
}

/// Overall result: unsupported, then any failure, then anything short of a pass.
pub fn overall(
    platform_supported: bool,
    scenarios: &[Scenario],
    cleanup_ok: bool,
) -> (Status, i32) {
    if !platform_supported {
        (Status::Unsupported, EXIT_UNSUPPORTED)
    } else if scenarios.iter().any(|s| s.status == Status::Failed) {
        (Status::Failed, EXIT_FAILED)
    } else if !cleanup_ok
        || scenarios.is_empty()
        || scenarios.iter().any(|s| s.status != Status::Passed)
    {
        (Status::Incomplete, EXIT_INCOMPLETE)
    } else {
        (Status::Passed, EXIT_PASSED)
    }
}

pub fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Base report shared by every outcome; never contains credentials, host
/// configuration, user paths or invocation arguments.
pub fn base_report(platform_supported: bool) -> serde_json::Map<String, Value> {
    let value = json!({
        "schema_version": SCHEMA,
        "agentfw_version": env!("CARGO_PKG_VERSION"),
        "profile": {"id": PROFILE, "os": std::env::consts::OS, "arch": std::env::consts::ARCH,
                    "supported": platform_supported},
        "started_at_unix_ms": now_unix_ms(),
        "controlled_path": CONTROLLED_PATH,
        "limitations": LIMITATIONS,
    });
    match value {
        Value::Object(map) => map,
        _ => unreachable!(),
    }
}

pub fn render_human(report: &Value) -> String {
    let mut out = format!(
        "Soup Wall Agent self-test ({})\n",
        report["profile"]["id"].as_str().unwrap_or(PROFILE)
    );
    if let Some(scenarios) = report["scenarios"].as_array() {
        for scenario in scenarios {
            let label = match scenario["status"].as_str() {
                Some("passed") => "PASS",
                Some("failed") => "FAIL",
                Some("unavailable") => "UNAVAILABLE",
                Some("unsupported") => "UNSUPPORTED",
                _ => "INCOMPLETE",
            };
            out.push_str(&format!(
                "  {label:<11} {:<26} {}\n",
                scenario["id"].as_str().unwrap_or("?"),
                scenario["detail"].as_str().unwrap_or("")
            ));
        }
    }
    if let Some(cleanup) = report.get("cleanup").filter(|c| !c.is_null()) {
        out.push_str(&format!(
            "  cleanup: {}\n",
            cleanup["summary"].as_str().unwrap_or("not recorded")
        ));
    }
    out.push_str(&format!(
        "Result: {} (exit {}). {}\n",
        report["result"]
            .as_str()
            .unwrap_or("incomplete")
            .to_uppercase(),
        report["exit_code"],
        report["explanation"].as_str().unwrap_or("")
    ));
    out.push_str("Scope: scripted MCP client and bundled fixture server; not Claude Code, model-context or live-model coverage.\n");
    out
}

/// Entry point. Returns the stable process exit code.
pub fn run(args: Args) -> i32 {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        unix::run(args)
    }
    #[cfg(windows)]
    {
        windows::run(args)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        unsupported(args)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn unsupported(args: Args) -> i32 {
    let mut report = base_report(false);
    let scenarios = pending_scenarios(
        Status::Unsupported,
        "this platform has no supported self-test profile",
    );
    let (status, code) = overall(false, &scenarios, true);
    report.insert("result".into(), json!(status));
    report.insert("exit_code".into(), json!(code));
    report.insert(
        "explanation".into(),
        json!(
            "Linux, macOS and native Windows are the supported self-test profiles; nothing ran and no protection is claimed."
        ),
    );
    report.insert("scenarios".into(), json!(scenarios));
    let report = Value::Object(report);
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.report)
    {
        use std::io::Write;
        let _ = file.write_all(&serde_json::to_vec_pretty(&report).unwrap_or_default());
    }
    print!("{}", render_human(&report));
    code
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario(status: Status) -> Scenario {
        Scenario {
            id: "x",
            status,
            expected: "",
            detail: String::new(),
            observed: Value::Null,
            receipts: Value::Null,
        }
    }

    #[test]
    fn overall_keeps_failed_incomplete_and_unsupported_distinct() {
        assert_eq!(
            overall(false, &[scenario(Status::Passed)], true),
            (Status::Unsupported, EXIT_UNSUPPORTED)
        );
        assert_eq!(
            overall(
                true,
                &[scenario(Status::Passed), scenario(Status::Failed)],
                true
            ),
            (Status::Failed, EXIT_FAILED)
        );
        assert_eq!(
            overall(
                true,
                &[scenario(Status::Passed), scenario(Status::Unavailable)],
                true
            ),
            (Status::Incomplete, EXIT_INCOMPLETE)
        );
        assert_eq!(
            overall(true, &[scenario(Status::Passed)], false),
            (Status::Incomplete, EXIT_INCOMPLETE)
        );
        assert_eq!(
            overall(true, &[], true),
            (Status::Incomplete, EXIT_INCOMPLETE)
        );
        assert_eq!(
            overall(true, &[scenario(Status::Passed)], true),
            (Status::Passed, EXIT_PASSED)
        );
    }

    #[test]
    fn human_summary_never_reports_pass_for_incomplete() {
        let mut report = base_report(true);
        report.insert("result".into(), json!("incomplete"));
        report.insert("exit_code".into(), json!(EXIT_INCOMPLETE));
        report.insert("explanation".into(), json!("classifier missing"));
        report.insert(
            "scenarios".into(),
            json!(pending_scenarios(Status::Unavailable, "not run")),
        );
        let text = render_human(&Value::Object(report));
        assert!(text.contains("Result: INCOMPLETE (exit 4)"));
        assert!(!text.contains("PASS "));
    }
}
