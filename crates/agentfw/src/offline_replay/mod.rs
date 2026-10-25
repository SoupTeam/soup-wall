// SPDX-License-Identifier: Apache-2.0
//! Bounded policy simulation over explicitly declared legacy event context.
//! This module never discovers an Agent home or accesses runtime authority.

mod input;
mod io;

use clap::{Args, ValueEnum};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use soup_wall_agent::{AgentFirewall, AgentPolicySet, SafetyFloor, Verdict, DEFAULT_TAINT_CAP};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

pub const MAX_INPUT_BYTES: usize = 1024 * 1024;
pub const MAX_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_OUTPUT_BYTES: usize = 1024 * 1024;
const SHIPPED: &str = include_str!("../../../agent/policies/agent-default.yaml");

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Format {
    Json,
    Text,
}

#[derive(Debug, Args)]
pub struct OfflineArgs {
    /// Simulate explicit event/policy files in a new private in-memory context.
    #[arg(long, requires_all = ["input", "policy"], conflicts_with = "log")]
    pub offline: bool,
    /// Versioned complete simulation input; never inferred from an audit log.
    #[arg(long, requires = "offline")]
    pub input: Option<PathBuf>,
    /// Explicit AgentPolicySet YAML; no installed/default policy is selected.
    #[arg(long, requires = "offline")]
    pub policy: Option<PathBuf>,
    /// Optional second explicit policy, evaluated with independent fresh state.
    #[arg(long, requires = "offline")]
    pub compare_policy: Option<PathBuf>,
    /// Redacted report representation (default: json).
    #[arg(long, value_enum, requires = "offline")]
    pub format: Option<Format>,
    /// Create a new private report file; existing paths are never overwritten.
    #[arg(long, requires = "offline")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure(pub &'static str);
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Failure {}
type Result<T> = std::result::Result<T, Failure>;

struct Limited {
    bytes: Vec<u8>,
    length: usize,
    limit: usize,
    retain: bool,
}
impl Limited {
    fn new(limit: usize, retain: bool) -> Self {
        Self {
            bytes: Vec::new(),
            length: 0,
            limit,
            retain,
        }
    }
}
impl Write for Limited {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        let next = self
            .length
            .checked_add(bytes.len())
            .filter(|n| *n <= self.limit)
            .ok_or_else(|| std::io::Error::other("offline_output_bounds"))?;
        if self.retain {
            if next > self.bytes.capacity() {
                self.bytes
                    .try_reserve_exact(next - self.bytes.len())
                    .map_err(|_| std::io::Error::other("offline_output_allocation"))?;
            }
            self.bytes.extend_from_slice(bytes);
        }
        self.length = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encoded_len(value: &impl Serialize, limit: usize) -> Result<usize> {
    let mut sink = Limited::new(limit, false);
    serde_json::to_writer(&mut sink, value).map_err(|_| Failure("offline_output_bounds"))?;
    Ok(sink.length)
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn identity(bytes: &[u8]) -> Value {
    json!({"sha256":hash(bytes),"bytes":bytes.len()})
}

fn policy(bytes: &[u8]) -> Result<AgentPolicySet> {
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(Failure("offline_policy_bounds"));
    }
    let yaml = std::str::from_utf8(bytes).map_err(|_| Failure("offline_policy_utf8"))?;
    // The bounded v1 YAML subset excludes aliases/anchors/tags before serde can
    // expand them. Quoted scalars and comments remain ordinary policy text.
    let (mut quote, mut escaped, mut comment) = (None, false, false);
    let mut boundary = true;
    for c in yaml.chars() {
        if c == '\n' {
            comment = false;
            boundary = true;
        }
        if comment {
            continue;
        }
        if let Some(q) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if q == '"' && c == '\\' {
                escaped = true;
                continue;
            }
            if c == q {
                quote = None;
            }
            continue;
        }
        if c == '#' {
            comment = true;
            continue;
        }
        if c == '\'' || c == '"' {
            quote = Some(c);
            continue;
        }
        if boundary && matches!(c, '&' | '*' | '!') {
            return Err(Failure("offline_policy_yaml_extension"));
        }
        boundary = c.is_whitespace() || matches!(c, ':' | ',' | '[' | '{');
    }
    let policy = AgentPolicySet::from_yaml(yaml).map_err(|_| Failure("offline_policy_invalid"))?;
    if policy.agent_policies.len() > 64
        || policy.egress_allowlist.len() > 128
        || policy.egress_allowlist.iter().any(|s| s.len() > 256)
        || policy.agent_policies.iter().any(|r| {
            r.name.len() > 128
                || r.message.as_ref().is_some_and(|s| s.len() > 2048)
                || r.when.detector.as_ref().is_some_and(|s| s.len() > 128)
        })
    {
        return Err(Failure("offline_policy_bounds"));
    }
    Ok(policy)
}

fn evaluate(input: &input::Input, policy: AgentPolicySet, bytes: &[u8], label: &str) -> Value {
    let mut firewall = AgentFirewall::new(policy.clone(), DEFAULT_TAINT_CAP);
    let mut incomplete = input.incomplete;
    let mut rows = Vec::new();
    for (index, prepared) in input.events.iter().enumerate() {
        let Some(event) = &prepared.event else {
            incomplete = true;
            rows.push(
                json!({"index":index,"seq":prepared.seq,"kind":prepared.kind,
                "status":prepared.status.unwrap_or("insufficient_context"),
                "reason_codes":prepared.reasons,"simulated_verdict":null,"trace":null}),
            );
            continue;
        };
        if incomplete {
            firewall.mark_provenance_incomplete(&event.session);
        }
        let (out, trace) = firewall.inspect_with_trace(event);
        let trace = trace.expect("validated tool calls/results always evaluate policy");
        incomplete |= out.provenance_incomplete;
        let operator = trace.policy.operator_rule.map(|n| {
            json!({
            "index":n,"name_sha256":hash(policy.agent_policies[n].name.as_bytes())})
        });
        let mut reasons = vec![if operator.is_some() {
            "operator_rule"
        } else {
            "operator_default"
        }];
        let floor = match trace.policy.applied_floor {
            Some(SafetyFloor::ShippedDeny { rule }) => {
                reasons.push("shipped_hard_deny");
                json!({"kind":"shipped_hard_deny","index":rule,
                    "name_sha256":out.rule.as_ref().map(|s| hash(s.as_bytes()))})
            }
            Some(SafetyFloor::IncompleteProvenance) => {
                reasons.push("incomplete_provenance_ask");
                json!({"kind":"incomplete_provenance_ask"})
            }
            None => Value::Null,
        };
        if out.verdict == Verdict::Escalate {
            reasons.push("judge_disabled_fallback");
        }
        reasons.push("no_judge_executed");
        if incomplete {
            reasons.push("incomplete_history_context");
        }
        let resolved = soup_wall_agent::resolution::resolve(out.verdict, out.fallback, false);
        // Incomplete context is never projected as a final simulated Allow.
        // The actual evaluator trace still explains its conservative floor.
        let verdict = (!incomplete).then_some(resolved);
        let mut findings = BTreeMap::new();
        for (_, finding) in &out.findings {
            *findings.entry(finding.detector.as_str()).or_insert(0usize) += 1;
        }
        rows.push(json!({"index":index,"seq":event.seq,"kind":prepared.kind,
            "status":if incomplete {"insufficient_context"} else {"simulated"},
            "reason_codes":reasons,"simulated_verdict":verdict,
            "trace":{"operator_rule":operator,"operator_verdict":trace.policy.operator_verdict,
                "operator_fallback":trace.policy.operator_fallback,"applied_floor":floor,
                "pre_resolution_verdict":out.verdict,"fallback":out.fallback,
                "resolution":"judge_disabled_no_judge_executed"},
            "signals":{"action_class":trace.action_class,"sensitive_path":trace.touches_sensitive_path,
                "risk_score":out.risk_score,"detector_counts":findings,"egress_count":out.egress_hosts.len(),
                "taint":out.taint.as_ref().map(|t| json!({"source_kind":t.source.kind(),"seq":t.seq})),
                "provenance_incomplete":out.provenance_incomplete,
                "retained_taint_entries":firewall.taint_len(&event.session)}}));
    }
    let complete = rows.iter().all(|r| r["status"] == "simulated");
    json!({"label":label,"format":"agent-policy-set-yaml/1","identity":identity(bytes),"complete":complete,"events":rows})
}

/// Evaluate only supplied bytes. No file, network, clock or authority lookup.
/// Report identities always hash the original supplied bytes, never JSON/YAML
/// reserialization. Unsupported raw input never reaches the production inspector.
pub fn simulate(input: &[u8], policy_a: &[u8], policy_b: Option<&[u8]>) -> Result<Value> {
    if input.len() > MAX_INPUT_BYTES {
        return Err(Failure("offline_input_bounds"));
    }
    let input_prepared = input::parse(input)?;
    let a = policy(policy_a)?;
    let b = policy_b.map(policy).transpose()?;
    let a = evaluate(&input_prepared, a, policy_a, "a");
    let mut policies = vec![a];
    let comparison = if let Some(b) = b {
        let b = evaluate(&input_prepared, b, policy_b.unwrap(), "b");
        let changed: Vec<_> = policies[0]["events"].as_array().unwrap().iter()
            .zip(b["events"].as_array().unwrap()).enumerate().map(|(index, (a, b))| json!({
                "index":index,"verdict_changed":a["simulated_verdict"] != b["simulated_verdict"],
                "status_changed":a["status"] != b["status"],
                "reasons_changed":a["reason_codes"] != b["reason_codes"] || a["trace"] != b["trace"]})).collect();
        policies.push(b);
        json!(changed)
    } else {
        Value::Null
    };
    let complete = policies.iter().all(|p| p["complete"] == true);
    Ok(
        json!({"format":"sw-policy-offline-report/1","simulated":true,"protection_claim":false,
        "status":if complete {"complete"} else {"incomplete"},"input":identity(input),
        "evaluator":{"scope":"legacy-agent-event-inspection/1","agent_version":"0.2.0",
            "shipped_floor_policy_sha256":hash(SHIPPED.as_bytes()),
            "context":"declared_simulation_data_not_authenticated_provenance","judge_execution":"none"},
        "policies":policies,"comparison":comparison}),
    )
}

fn render(report: &Value, format: Format) -> Result<Vec<u8>> {
    let mut output = Limited::new(MAX_OUTPUT_BYTES, true);
    match format {
        Format::Json => serde_json::to_writer_pretty(&mut output, report)
            .map_err(|_| Failure("offline_output_bounds"))?,
        Format::Text => {
            writeln!(
                output,
                "OFFLINE SIMULATION — no runtime admission or protection claim"
            )
            .map_err(|_| Failure("offline_output_bounds"))?;
            writeln!(
                output,
                "Input SHA-256: {}",
                report["input"]["sha256"].as_str().unwrap()
            )
            .map_err(|_| Failure("offline_output_bounds"))?;
            for policy in report["policies"].as_array().unwrap() {
                writeln!(
                    output,
                    "Policy {} SHA-256: {}",
                    policy["label"].as_str().unwrap(),
                    policy["identity"]["sha256"].as_str().unwrap()
                )
                .map_err(|_| Failure("offline_output_bounds"))?;
                for row in policy["events"].as_array().unwrap() {
                    writeln!(
                        output,
                        "  Event #{}: {} / simulated verdict: {}",
                        row["index"],
                        row["status"].as_str().unwrap(),
                        row["simulated_verdict"].as_str().unwrap_or("unavailable")
                    )
                    .map_err(|_| Failure("offline_output_bounds"))?;
                    if let Some(index) = row["trace"]["operator_rule"]["index"].as_u64() {
                        writeln!(
                            output,
                            "    Operator rule #{index} (zero-based); name SHA-256: {}",
                            row["trace"]["operator_rule"]["name_sha256"]
                                .as_str()
                                .unwrap()
                        )
                        .map_err(|_| Failure("offline_output_bounds"))?;
                    }
                    for reason in row["reason_codes"].as_array().unwrap() {
                        writeln!(output, "    {}", reason.as_str().unwrap())
                            .map_err(|_| Failure("offline_output_bounds"))?;
                    }
                    writeln!(
                        output,
                        "    Pre-resolution: {}; declared fallback: {}",
                        row["trace"]["pre_resolution_verdict"], row["trace"]["fallback"]
                    )
                    .map_err(|_| Failure("offline_output_bounds"))?;
                }
            }
            if !report["comparison"].is_null() {
                writeln!(
                    output,
                    "Comparison (event index; verdict/status/reason changes): {}",
                    report["comparison"]
                )
                .map_err(|_| Failure("offline_output_bounds"))?;
            }
            writeln!(output, "Review the declared context and the referenced rule in the exact supplied policy. No judge ran; no tool was executed.")
                .map_err(|_| Failure("offline_output_bounds"))?;
        }
    }
    output
        .write_all(b"\n")
        .map_err(|_| Failure("offline_output_bounds"))?;
    Ok(output.bytes)
}

fn run(args: &OfflineArgs) -> Result<bool> {
    let input = io::read(
        args.input
            .as_ref()
            .ok_or(Failure("offline_input_required"))?,
        MAX_INPUT_BYTES,
    )?;
    let a = io::read(
        args.policy
            .as_ref()
            .ok_or(Failure("offline_policy_required"))?,
        MAX_POLICY_BYTES,
    )?;
    let b = args
        .compare_policy
        .as_ref()
        .map(|p| io::read(p, MAX_POLICY_BYTES))
        .transpose()?;
    let report = simulate(&input, &a, b.as_deref())?;
    let rendered = render(&report, args.format.unwrap_or(Format::Json))?;
    if let Some(path) = &args.output {
        io::export(path, &rendered)?;
    } else {
        io::stdout(&rendered, &mut std::io::stdout().lock())?;
    }
    Ok(report["status"] == "complete")
}

pub fn run_cli(args: &OfflineArgs) -> i32 {
    match run(args) {
        Ok(true) => 0,
        Ok(false) => 2,
        Err(error) => {
            let _ = writeln!(std::io::stderr().lock(), "Offline replay failed: {error}");
            1
        }
    }
}

#[cfg(test)]
mod tests;
