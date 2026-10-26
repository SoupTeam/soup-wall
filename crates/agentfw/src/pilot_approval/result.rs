use anyhow::Result;
use serde::Serialize;
use serde_json::{json, Value};
use std::{fmt, io::Write};

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Reason {
    UnsupportedPlatform,
    InvalidInput,
    RunUnavailable,
    UnsafeRunRecord,
    RunExpired,
    RunStopping,
    SelectionChanged,
    DaemonUnavailable,
    DaemonRefused,
    DaemonIdentityChanged,
    PendingUnavailable,
    PendingExpired,
    BindingChanged,
    InspectionRequired,
    DecisionConflict,
    StopOwnershipUnverified,
    StopUnconfirmed,
    OutputUnavailable,
    OutputLimit,
    Unknown,
}

impl Reason {
    pub(crate) fn exit_code(self) -> i32 {
        match self {
            Self::DaemonUnavailable | Self::RunUnavailable => 4,
            Self::StopUnconfirmed | Self::StopOwnershipUnverified | Self::Unknown => 5,
            Self::OutputUnavailable | Self::OutputLimit => 6,
            _ => 3,
        }
    }

    fn outcome(self) -> &'static str {
        match self.exit_code() {
            4 => "unavailable",
            5 | 6 => "unknown",
            _ => "refused",
        }
    }
}

#[derive(Debug)]
struct Failure {
    reason: Reason,
    source: anyhow::Error,
}

impl fmt::Display for Failure {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.source, out)
    }
}

impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

pub(crate) fn tag(error: anyhow::Error, reason: Reason) -> anyhow::Error {
    if error.chain().any(|cause| cause.is::<Failure>()) {
        error
    } else {
        Failure {
            reason,
            source: error,
        }
        .into()
    }
}

pub(crate) fn reason(error: &anyhow::Error) -> Reason {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<Failure>())
        .map(|failure| failure.reason)
        .unwrap_or(Reason::Unknown)
}

pub(super) struct Output {
    pub structured: bool,
    pub emitted: bool,
    pub identity: Value,
    pub stop_requested: bool,
    operation: &'static str,
}

impl Output {
    pub fn new(structured: bool, operation: &'static str) -> Self {
        Self {
            structured,
            operation,
            emitted: false,
            identity: Value::Null,
            stop_requested: false,
        }
    }

    pub fn render(&self, data: &Value, outcome: &str, reason: &str) -> Result<String> {
        let record = if self.structured {
            json!({"format":"sw-pilot-operator-result/1", "operation":self.operation,
                "outcome":outcome, "reason":reason, "identity":self.identity, "data":data})
        } else {
            data.clone()
        };
        let text = super::escaped(&record)?;
        anyhow::ensure!(
            text.len() < 16 * 1024 * 1024,
            "operator result exceeds output bound"
        );
        Ok(text)
    }

    pub fn emit(
        &mut self,
        data: &Value,
        outcome: &str,
        reason: &str,
        writer: &mut impl Write,
    ) -> Result<()> {
        let text = if !self.structured && self.operation != "list" {
            Ok(data.to_string())
        } else {
            self.render(data, outcome, reason)
        }
        .map_err(|error| tag(error, Reason::OutputLimit))?;
        self.emitted = true;
        writeln!(writer, "{text}")
            .and_then(|()| writer.flush())
            .map_err(|error| tag(error.into(), Reason::OutputUnavailable))
    }

    pub fn failure(&mut self, error: &anyhow::Error, writer: &mut impl Write) -> i32 {
        let code = reason(error);
        if !self.emitted {
            let outcome = if self.stop_requested {
                "stop_requested"
            } else {
                code.outcome()
            };
            let label = serde_json::to_value(code).expect("fixed reason");
            if self
                .emit(&Value::Null, outcome, label.as_str().unwrap(), writer)
                .is_err()
            {
                return 6;
            }
        }
        code.exit_code()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_errors_are_not_classified_by_their_text() {
        for text in [
            "pending call expired",
            "binding differs from exact pending call",
            "daemon unavailable",
        ] {
            let mut output = Output::new(true, "approve");
            let mut bytes = Vec::new();
            assert_eq!(output.failure(&anyhow::anyhow!(text), &mut bytes), 5);
            let record: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(record["outcome"], "unknown");
            assert_eq!(record["reason"], "unknown");
            assert!(!String::from_utf8(bytes).unwrap().contains(text));
        }
    }

    #[test]
    fn emitted_inspection_is_not_followed_by_a_second_record() {
        let mut output = Output::new(true, "inspect");
        let mut bytes = Vec::new();
        output
            .emit(
                &json!({"args":{"path":"/workspace/notes.txt"}}),
                "inspection_presented",
                "exact_pending_arguments",
                &mut bytes,
            )
            .unwrap();
        let first = bytes.clone();
        assert_eq!(
            output.failure(&anyhow::anyhow!("receipt write failed"), &mut bytes),
            5
        );
        assert_eq!(bytes, first);
    }

    #[test]
    fn requested_stop_never_becomes_confirmed_after_daemon_loss() {
        let mut output = Output::new(true, "stop");
        output.stop_requested = true;
        let mut bytes = Vec::new();
        let error = tag(
            anyhow::anyhow!("private token must not escape"),
            Reason::DaemonUnavailable,
        );
        assert_eq!(output.failure(&error, &mut bytes), 4);
        let record: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(record["outcome"], "stop_requested");
        assert_eq!(record["reason"], "daemon_unavailable");
        assert!(record["data"].is_null());
    }
}
