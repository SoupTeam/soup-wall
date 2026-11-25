// SPDX-License-Identifier: Apache-2.0
//! What the Unix and Windows execution profiles of `agentfw self-test` have in
//! common: limits, the reply and outcome model, and loopback HTTP helpers.
//!
//! Everything here is platform independent. Process ownership, the private
//! workspace and the daemon lifecycle stay in `unix.rs` and `windows.rs`.

use std::fs::File;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};

use super::fixture;
use super::Status;

pub(super) const WORKSPACE_PREFIX: &str = "agentfw-self-test-";
pub(super) const OWNER_MARKER: &str = ".agentfw-self-test-owner";
pub(super) const MAX_REPLY_LINE: usize = 512 * 1024;
pub(super) const MAX_LOG_READ: u64 = 8 * 1024 * 1024;
pub(super) const MAX_RECEIVER_BODY: usize = 64 * 1024;
pub(super) const MAX_RECEIVER_CONNECTIONS: usize = 32;
pub(super) const REPLY_TIMEOUT: Duration = Duration::from_secs(15);
/// Debug builds initialize detectors slowly; release builds are healthy far sooner.
pub(super) const DAEMON_START_TIMEOUT: Duration = Duration::from_secs(30);

/// Reason a run stopped before all scenarios were witnessed.
#[derive(Debug)]
pub(crate) struct Abort {
    pub(super) status: Status,
    pub(super) reason: String,
}

pub(super) fn abort(status: Status, reason: impl Into<String>) -> Abort {
    Abort {
        status,
        reason: reason.into(),
    }
}

pub(super) fn hash_file(path: &Path) -> std::io::Result<(String, u64)> {
    use sha2::{Digest, Sha256};
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut size = 0u64;
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size += read as u64;
        hasher.update(&buffer[..read]);
    }
    Ok((format!("{:x}", hasher.finalize()), size))
}

/// Owned numeric-loopback delivery witness. Counts connections and bodies only.
pub(super) struct LoopbackReceiver {
    pub(super) url: String,
    pub(super) bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    pub(super) connections: Arc<AtomicUsize>,
    pub(super) stop: Arc<AtomicBool>,
    pub(super) thread: Option<std::thread::JoinHandle<()>>,
}

pub(super) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

pub(super) fn http_get(port: u16, path: &str) -> Option<(u16, Vec<u8>)> {
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_millis(500)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .ok()?;
    let mut bytes = Vec::new();
    stream.take(64 * 1024).read_to_end(&mut bytes).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let status = text.split_whitespace().nth(1)?.parse().ok()?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.as_bytes().to_vec())
        .unwrap_or_default();
    Some((status, body))
}

pub(super) fn free_port() -> Option<u16> {
    TcpListener::bind(("127.0.0.1", 0))
        .ok()?
        .local_addr()
        .ok()
        .map(|a| a.port())
}

pub(super) struct Assets {
    pub(super) agent: PathBuf,
    pub(super) runner: PathBuf,
    pub(super) classifier_script: PathBuf,
    pub(super) classifier_python: PathBuf,
    pub(super) identities: Value,
}

pub(super) enum Reply {
    Line(Vec<u8>),
    Closed,
    Timeout,
    Malformed,
    Interrupted,
}

pub(super) fn frame(id: u64, method: &str, params: Value) -> Vec<u8> {
    let mut value = json!({"jsonrpc": "2.0", "id": id, "method": method});
    if !params.is_null() {
        value["params"] = params;
    }
    value.to_string().into_bytes()
}

pub(super) fn call_frame(id: u64, tool: &str, arguments: Value) -> Vec<u8> {
    frame(
        id,
        "tools/call",
        json!({"name": tool, "arguments": arguments,
        "_meta": {"claudecode/toolUseId": format!("toolu_selftest_{id}"), "progressToken": id}}),
    )
}

/// Host-visible outcome of one reply, from its exact bytes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Released(String),
    Refused(String),
    ResultWithheld(String),
    PolicyNotReached,
    Error,
    Malformed,
}

impl Outcome {
    pub(super) fn label(&self) -> &'static str {
        match self {
            Outcome::Released(_) => "released",
            Outcome::Refused(_) => "invocation_refused",
            Outcome::ResultWithheld(_) => "result_withheld",
            Outcome::PolicyNotReached => "policy_not_reached",
            Outcome::Error => "error",
            Outcome::Malformed => "malformed",
        }
    }
}

pub(crate) fn outcome(line: &[u8], expected_id: u64) -> Outcome {
    let Ok(value) = serde_json::from_slice::<Value>(line) else {
        return Outcome::Malformed;
    };
    if value["jsonrpc"] != "2.0" || value["id"] != json!(expected_id) {
        return Outcome::Malformed;
    }
    if let Some(error) = value.get("error") {
        let message = error["message"].as_str().unwrap_or_default();
        return if message.contains("policy not reached") {
            Outcome::PolicyNotReached
        } else {
            Outcome::Error
        };
    }
    let result = &value["result"];
    let Some(text) = result["content"]
        .as_array()
        .and_then(|c| c.first())
        .and_then(|b| b["text"].as_str())
    else {
        return Outcome::Malformed;
    };
    let reason = |prefix: &str| {
        text.strip_prefix(prefix)
            .and_then(|r| r.strip_suffix(')'))
            .map(str::to_owned)
    };
    if result["isError"] == true {
        if let Some(reason) = reason("Soup Wall withheld MCP invocation (") {
            return Outcome::Refused(reason);
        }
        if let Some(reason) = reason("Soup Wall withheld MCP result (") {
            return Outcome::ResultWithheld(reason);
        }
        return Outcome::Error;
    }
    Outcome::Released(text.to_owned())
}

pub(super) struct Observation {
    pub(super) reply: Option<Vec<u8>>,
    pub(super) outcome: Outcome,
    pub(super) transport: &'static str,
    pub(super) frame: Vec<u8>,
    pub(super) executed: Vec<Vec<u8>>,
    pub(super) responses_before: usize,
    pub(super) deliveries: usize,
    pub(super) connections: usize,
    pub(super) audit: Vec<Value>,
    pub(super) latency_ms: f64,
}

pub(super) fn observed_json(o: &Observation) -> Value {
    json!({"transport": o.transport, "outcome": o.outcome.label(),
           "reason": match &o.outcome { Outcome::Refused(r) | Outcome::ResultWithheld(r) => json!(r), _ => Value::Null },
           "mcp_child_executions": o.executed.len(), "receiver_deliveries": o.deliveries,
           "receiver_connections": o.connections, "latency_ms": o.latency_ms})
}

pub(super) fn not_completed(o: &Observation) -> Option<Status> {
    match o.transport {
        "reply" => None,
        _ => Some(Status::Incomplete),
    }
}

pub(super) fn receiver_address_control(url: &str) -> bool {
    fixture::receiver_address(url)
        .map(|address| fixture::post(address, fixture::RECEIVER_CONTROL_BODY).is_ok())
        .unwrap_or(false)
}
