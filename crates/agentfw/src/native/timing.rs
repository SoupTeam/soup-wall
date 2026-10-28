// SPDX-License-Identifier: Apache-2.0
//! One fixed-size, payload-free timing row per native admission. Durations use
//! a monotonic clock; no samples, sessions or input bytes are retained here.
use super::{hash, Request, Response};
use serde_json::json;
use std::io::Write;
use std::time::Instant;

pub(super) struct Timing {
    started: Instant,
    event: String,
    session: String,
    call: Option<String>,
    content: Option<String>,
    pub session_wait_us: u128,
    pub firewall_wait_us: u128,
    pub evidence_us: u128,
    pub detectors_us: u128,
    pub tracking_us: u128,
    pub audit_us: u128,
}

impl Timing {
    pub fn new(request: &Request) -> Self {
        Self {
            started: Instant::now(),
            event: request.event.clone(),
            session: hash(request.session_id.as_bytes()),
            call: request.call_id.as_deref().map(|id| hash(id.as_bytes())),
            content: request.content.as_deref().map(|text| hash(text.as_bytes())),
            session_wait_us: 0,
            firewall_wait_us: 0,
            evidence_us: 0,
            detectors_us: 0,
            tracking_us: 0,
            audit_us: 0,
        }
    }

    pub fn elapsed_us(&self) -> u128 {
        self.started.elapsed().as_micros()
    }

    pub(super) fn record(&self, result: &Result<Response, &'static str>) -> serde_json::Value {
        let (outcome, released) = match result {
            Ok(response) => (response.verdict, response.release),
            Err(code) => (*code, false),
        };
        // Static event/outcome codes and digests only. This is service completion,
        // not a claim that the peer received or accepted a late response.
        let total = self.started.elapsed().as_micros();
        json!({
            "event":"native_admission_timing", "version":1,
            "request_event":self.event, "session_sha256":self.session,
            "call_sha256": self.call.clone().or_else(|| result.as_ref().ok()
                .and_then(|r| r.call_id.as_deref()).map(|id| hash(id.as_bytes()))),
            "content_sha256":self.content, "outcome":outcome,
            "release_decision":released, "total_us":total,
        "state_and_decode_us":total.saturating_sub(self.session_wait_us + self.firewall_wait_us + self.evidence_us + self.detectors_us + self.tracking_us + self.audit_us),
            "session_wait_us":self.session_wait_us,"firewall_wait_us":self.firewall_wait_us,
            "evidence_us":self.evidence_us,"detectors_us":self.detectors_us,
            "tracking_us":self.tracking_us,"audit_us":self.audit_us
        })
    }

    pub fn finish(self, result: &Result<Response, &'static str>) {
        let _ = writeln!(std::io::stderr().lock(), "{}", self.record(result));
    }
}
