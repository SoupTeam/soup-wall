// SPDX-License-Identifier: Apache-2.0
//! Bounded transport observations, including futures dropped on cancellation.
use super::{sha, Value};
use serde_json::json;
use std::io::Write;
use std::time::Instant;

pub(super) struct Transport {
    start: Instant,
    event: &'static str,
    session: String,
    call: Option<String>,
    content: Option<String>,
    pub outcome: &'static str,
}
impl Transport {
    pub fn new(body: &Value) -> Self {
        let event = match body["event"].as_str() {
            Some("call") => "call",
            Some("result") => "result",
            Some("context") => "context",
            Some("session_start") => "session_start",
            Some("session_end") => "session_end",
            Some("publish") => "publish",
            _ => "other",
        };
        Self {
            start: Instant::now(),
            event,
            session: sha(body["session_id"].as_str().unwrap_or("").as_bytes()),
            call: body["call_id"].as_str().map(|id| sha(id.as_bytes())),
            content: body["content"].as_str().map(|text| sha(text.as_bytes())),
            outcome: "cancelled_or_incomplete",
        }
    }
}
impl Drop for Transport {
    fn drop(&mut self) {
        let _ = writeln!(
            std::io::stderr().lock(),
            "{}",
            json!({
                "event":"mcp_native_transport_timing","version":1,"request_event":self.event,
                "session_sha256":self.session,"call_sha256":self.call,"content_sha256":self.content,
                "elapsed_us":self.start.elapsed().as_micros(),"outcome":self.outcome,
                "authority":false
            })
        );
    }
}
