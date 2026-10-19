// SPDX-License-Identifier: Apache-2.0
//! Explicit, bounded stdio MCP admission. This collector owns server forwarding;
//! `mcp_host` release is not attestation of the host's eventual model context.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{bail, ensure, Context};
use futures_util::StreamExt;
use serde::de::{MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::Command;

use super::input::InputSchema;
use crate::native::{NativeState, CONTRACT, MAX_CONTENT};
use soup_wall_adapter::runner::evaluate_baseline_policy;
use soup_wall_adapter::{ToolActionCategory, ToolClassification, Verdict as AdapterVerdict};
use soup_wall_agent::ActionClass;

mod real_server;

const MAX_REQUESTS: usize = 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(30);
const CLASSIFICATION_CONTRACT: &str = "sw-classification/candidate-1";
const CLASSIFIER_TIMEOUT: Duration = Duration::from_secs(2);
// Verify and execute one immutable byte snapshot in the child, not a path
// checked by the parent and reopened after another process can replace it.
const PYTHON_CLASSIFIER_BOOTSTRAP: &str = r#"import hashlib, sys
path, expected = sys.argv[1:]
with open(path, "rb") as handle:
    source = handle.read(1024 * 1024 + 1)
if len(source) > 1024 * 1024 or hashlib.sha256(source).hexdigest() != expected:
    raise SystemExit(78)
sys.argv = [path]
exec(compile(source, path, "exec"), {"__name__": "__main__", "__file__": path})
"#;

/// Internal classifier input. Discovery content is evidence; only the registry
/// and successful admission establish the trusted baseline.
#[derive(Clone)]
pub struct Invocation {
    pub server_id: String,
    pub host_call_id: Value,
    pub registry_sha256: String,
    pub snapshot_sha256: String,
    pub schema_sha256: String,
    pub tool: String,
    pub description: String,
    pub schema: Value,
    /// Original untrusted discovery definition, including supported annotations.
    pub definition: Value,
    /// Server-advertised identity; the operator-selected server_id is authoritative.
    pub server_info: Value,
    pub definition_sha256: String,
    /// Identity for semantic prediction reuse, never an execution grant.
    pub input_sha256: String,
    pub classifier_revision: Option<String>,
    pub args: Value,
    pub baseline: ActionClass,
}

impl Invocation {
    /// Semantic input for classifiers. Correlation and operator permissions
    /// stay on the orchestration side; server metadata is untrusted evidence.
    pub fn semantic_input(&self) -> Value {
        json!({"tool_name":self.tool,"raw_arguments":self.args,
            "tool_description":self.description,"tool_schema":self.schema,
            "server_id":self.server_id})
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct Classification {
    pub actions: Vec<String>,
    pub unknown: bool,
    pub confidence: f64,
    pub uncertainty: f64,
    pub reason: String,
}

pub trait InvocationClassifier: Send + Sync {
    fn source(&self) -> &'static str;
    fn revision(&self) -> Option<&str> {
        None
    }
    fn classify(&self, invocation: &Invocation) -> anyhow::Result<Classification>;
}

/// Explicit local Python adapter. Classification never grants authorization.
struct RuleBaseline {
    script: std::path::PathBuf,
    python: std::ffi::OsString,
    digest: String,
}

#[derive(Deserialize)]
struct BaselineReply {
    status: String,
    #[serde(flatten)]
    classification: Classification,
}

impl InvocationClassifier for RuleBaseline {
    fn source(&self) -> &'static str {
        "rule-baseline/python"
    }
    fn revision(&self) -> Option<&str> {
        Some(&self.digest)
    }
    fn classify(&self, invocation: &Invocation) -> anyhow::Result<Classification> {
        // Do not inherit the daemon's credentials or change original MCP frames.
        let mut bytes = serde_json::to_vec(&invocation.semantic_input())?;
        ensure!(bytes.len() <= 1024 * 1024, "classifier input exceeds limit");
        bytes.push(b'\n');
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let output = runtime.block_on(async {
            use tokio::io::AsyncReadExt;
            let mut command = Command::new(&self.python);
            command
                .arg("-I")
                .arg("-u")
                .arg("-c")
                .arg(PYTHON_CLASSIFIER_BOOTSTRAP)
                .arg(&self.script)
                .arg(&self.digest)
                .env_clear();
            // Windows Python needs its OS runtime directory; no application secrets.
            #[cfg(windows)]
            if let Some(root) = std::env::var_os("SystemRoot") {
                command.env("SystemRoot", root);
            }
            let mut child = command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
            let mut input = child.stdin.take().context("classifier stdin missing")?;
            let output = child.stdout.take().context("classifier stdout missing")?;
            let exchange = async {
                let write = async {
                    input.write_all(&bytes).await?;
                    input.shutdown().await?;
                    drop(input);
                    Ok::<_, anyhow::Error>(())
                };
                let read = async {
                    let mut bytes = Vec::new();
                    output.take(16 * 1024 + 1).read_to_end(&mut bytes).await?;
                    ensure!(bytes.len() <= 16 * 1024, "classifier output exceeds limit");
                    Ok::<_, anyhow::Error>(bytes)
                };
                let (_, bytes) = tokio::try_join!(write, read)?;
                ensure!(child.wait().await?.success(), "classifier process failed");
                Ok::<_, anyhow::Error>(bytes)
            };
            // Reclaim the subprocess before the outer two-second admission timeout.
            let result = tokio::time::timeout(Duration::from_millis(1500), exchange).await;
            match result {
                Ok(Ok(bytes)) => Ok(bytes),
                other => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                    match other {
                        Ok(Err(error)) => Err(error),
                        _ => Err(anyhow::anyhow!("classifier process timed out")),
                    }
                }
            }
        })?;
        parse_classifier_reply(&output)
    }
}

/// Shared by the single-shot adapter and the packaged worker so both accept exactly
/// the same classifier output.
pub(crate) fn parse_classifier_reply(bytes: &[u8]) -> anyhow::Result<Classification> {
    ensure!(bytes.len() <= 16 * 1024, "classifier output exceeds limit");
    let reply: BaselineReply =
        serde_json::from_slice(bytes).context("invalid classifier output")?;
    ensure!(
        matches!(reply.status.as_str(), "ok" | "unknown"),
        "classifier returned technical error"
    );
    ensure!(
        reply.status != "unknown" || reply.classification.unknown,
        "inconsistent unknown status"
    );
    Ok(reply.classification)
}

/// Select a real classifier explicitly; test doubles remain debug-only.
pub fn classifier_from_env() -> anyhow::Result<Option<Arc<dyn InvocationClassifier>>> {
    match std::env::var("AGENTFW_CLASSIFIER") {
        Err(std::env::VarError::NotPresent) => test_classifier_from_env(),
        Ok(value) if value == "rule-baseline" => {
            ensure!(
                std::env::var_os("AGENTFW_TEST_CLASSIFIER").is_none()
                    && std::env::var_os("AGENTFW_TEST_CLASSIFIER_READ").is_none(),
                "conflicting classifiers"
            );
            let script = std::env::var_os("AGENTFW_RULE_BASELINE")
                .context("AGENTFW_RULE_BASELINE must explicitly select a local script")?;
            let script = std::path::PathBuf::from(script).canonicalize()?;
            ensure!(script.is_file(), "classifier script missing");
            let mut source = Vec::new();
            use std::io::Read;
            std::fs::File::open(&script)?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut source)?;
            ensure!(
                source.len() <= 1024 * 1024,
                "classifier source exceeds limit"
            );
            let digest = sha(&source);
            let python = std::env::var_os("AGENTFW_CLASSIFIER_PYTHON").unwrap_or_else(|| {
                if cfg!(windows) {
                    "python".into()
                } else {
                    "python3".into()
                }
            });
            Ok(Some(Arc::new(RuleBaseline {
                script,
                python,
                digest,
            })))
        }
        Ok(value) if value == "rule-package" => {
            ensure!(
                std::env::var_os("AGENTFW_TEST_CLASSIFIER").is_none()
                    && std::env::var_os("AGENTFW_TEST_CLASSIFIER_READ").is_none()
                    && std::env::var_os("AGENTFW_RULE_BASELINE").is_none(),
                "conflicting classifiers"
            );
            // Only the verified installed package; no path, no PATH lookup, no fallback.
            let home = crate::config::Config::home()?;
            Ok(Some(Arc::new(
                crate::classifier_runtime::worker::PackagedClassifier::from_home(&home)?,
            )))
        }
        _ => bail!("unsupported classifier setting"),
    }
}

struct ReadTestDouble;

impl InvocationClassifier for ReadTestDouble {
    fn source(&self) -> &'static str {
        "test-double/read-v1"
    }
    fn classify(&self, invocation: &Invocation) -> anyhow::Result<Classification> {
        ensure!(
            !invocation.server_id.is_empty()
                && !invocation.registry_sha256.is_empty()
                && !invocation.snapshot_sha256.is_empty()
                && !invocation.schema_sha256.is_empty()
                && id(&invocation.host_call_id).is_ok()
                && invocation.args.is_object()
                && invocation.schema.is_object()
                && invocation.baseline == ActionClass::ReadOnly,
            "test classifier input missing"
        );
        Ok(Classification {
            actions: vec!["read".into()],
            unknown: false,
            confidence: 1.0,
            uncertainty: 0.0,
            reason: "fixed fixture output".into(),
        })
    }
}

/// Identified test double for the seam, never classifier acceptance. It infers
/// `send_data` from URL-valued arguments rather than tool names, otherwise
/// echoes the trusted baseline, and injects faults named in argument values.
struct FixtureTestDouble;

impl InvocationClassifier for FixtureTestDouble {
    fn source(&self) -> &'static str {
        "test-double/fixture-v1"
    }
    fn classify(&self, invocation: &Invocation) -> anyhow::Result<Classification> {
        let values: Vec<&str> = invocation
            .args
            .as_object()
            .into_iter()
            .flatten()
            .filter_map(|(_, value)| value.as_str())
            .collect();
        let fault = |name: &str| {
            let marker = format!("classifier-fault-{name}");
            values.iter().any(|value| value.contains(&marker))
        };
        if fault("timeout") {
            std::thread::sleep(CLASSIFIER_TIMEOUT * 2);
        }
        assert!(!fault("crash"), "fixture classifier crash");
        let actions = if fault("unknown") {
            vec![]
        } else if fault("mixed") {
            vec!["read".into(), "send_data".into()]
        } else if fault("duplicate") {
            vec!["read".into(), "read".into()]
        } else if fault("understate") {
            vec!["read".into()]
        } else if values
            .iter()
            .any(|value| value.starts_with("http://") || value.starts_with("https://"))
        {
            vec!["send_data".into()]
        } else {
            vec![baseline_action(invocation.baseline).into()]
        };
        Ok(Classification {
            actions,
            unknown: fault("unknown"),
            confidence: if fault("invalid") { 2.0 } else { 0.9 },
            uncertainty: 0.1,
            reason: "fixture test double".into(),
        })
    }
}

fn baseline_action(class: ActionClass) -> &'static str {
    match class {
        ActionClass::ReadOnly => "read",
        ActionClass::SideEffecting => "write",
        ActionClass::Network => "send_data",
        ActionClass::PrivilegeChanging => "change_permissions",
        ActionClass::Destructive => "delete",
    }
}

/// Single action mapping to ActionClass for backwards-compatible telemetry and baseline comparison.
/// Mixed actions, unknown, and no-actions return `Ok(None)`.
fn map_classification(result: &Classification) -> Result<Option<ActionClass>, &'static str> {
    let valid = result.confidence.is_finite()
        && (0.0..=1.0).contains(&result.confidence)
        && result.uncertainty.is_finite()
        && (0.0..=1.0).contains(&result.uncertainty)
        && !result.reason.is_empty()
        && result.reason.len() <= 1024
        && result.actions.iter().collect::<BTreeSet<_>>().len() == result.actions.len()
        && result.actions.iter().all(|action| {
            matches!(
                action.as_str(),
                "read" | "write" | "delete" | "send_data" | "change_permissions"
            )
        });
    if !valid {
        return Err("classifier_invalid");
    }
    match (result.unknown, result.actions.as_slice()) {
        (false, [action]) => Ok(Some(match action.as_str() {
            "read" => ActionClass::ReadOnly,
            "write" => ActionClass::SideEffecting,
            "delete" => ActionClass::Destructive,
            "send_data" => ActionClass::Network,
            _ => ActionClass::PrivilegeChanging,
        })),
        _ => Ok(None),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProductionVerdict {
    Allow,
    Ask,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClassifiedAssessment {
    pub verdict: ProductionVerdict,
    pub ambiguous_or_unknown: bool,
}

impl ClassifiedAssessment {
    pub fn allow() -> Self {
        Self {
            verdict: ProductionVerdict::Allow,
            ambiguous_or_unknown: false,
        }
    }
}

pub fn compose_production_policy(
    classification: &Classification,
    baseline: ActionClass,
    egress_declared: bool,
) -> Result<ProductionVerdict, &'static str> {
    compose_scoped_production_policy(classification, baseline, egress_declared, false)
}

fn compose_https_get_policy(
    classification: &Classification,
    baseline: ActionClass,
    egress_declared: bool,
) -> Result<ProductionVerdict, &'static str> {
    let verdict = compose_production_policy(classification, baseline, egress_declared)?;
    // The reviewed GET is classified as read by the existing rule baseline.
    // Its operator-owned Network baseline and native egress gate remain
    // authoritative. Empty, understated or mixed predictions add no authority.
    Ok(
        if verdict == ProductionVerdict::Allow
            && !(baseline == ActionClass::Network && classification.actions.as_slice() == ["read"])
        {
            ProductionVerdict::Ask
        } else {
            verdict
        },
    )
}

/// Only a validated installed constrained create profile supplies write authority.
/// A description, classifier result, or generic side-effecting baseline cannot.
fn compose_scoped_production_policy(
    classification: &Classification,
    baseline: ActionClass,
    egress_declared: bool,
    create_file_authority: bool,
) -> Result<ProductionVerdict, &'static str> {
    let valid = classification.confidence.is_finite()
        && (0.0..=1.0).contains(&classification.confidence)
        && classification.uncertainty.is_finite()
        && (0.0..=1.0).contains(&classification.uncertainty)
        && !classification.reason.is_empty()
        && classification.reason.len() <= 1024
        && classification.actions.iter().collect::<BTreeSet<_>>().len()
            == classification.actions.len()
        && classification.actions.iter().all(|action| {
            matches!(
                action.as_str(),
                "read" | "write" | "delete" | "send_data" | "change_permissions"
            )
        });
    if !valid {
        return Err("classifier_invalid");
    }

    if classification.actions.iter().any(|a| a == "delete") {
        return Ok(ProductionVerdict::Deny);
    }

    if classification.actions.iter().any(|a| a == "send_data")
        && !egress_declared
        && baseline != ActionClass::Network
    {
        return Ok(ProductionVerdict::Deny);
    }

    if classification
        .actions
        .iter()
        .any(|a| a == "change_permissions")
    {
        return Ok(ProductionVerdict::Deny);
    }

    if baseline == ActionClass::ReadOnly && classification.actions.iter().any(|a| a == "write") {
        return Ok(ProductionVerdict::Deny);
    }

    if classification.unknown || classification.uncertainty >= 0.8 {
        return Ok(ProductionVerdict::Ask);
    }

    if create_file_authority {
        return Ok(
            if baseline == ActionClass::SideEffecting
                && classification.actions.as_slice() == ["write"]
            {
                ProductionVerdict::Allow
            } else {
                // Understated, empty or mixed predictions cannot activate a write.
                ProductionVerdict::Ask
            },
        );
    }

    if classification.actions.iter().any(|a| a == "write") {
        return Ok(ProductionVerdict::Ask);
    }

    if classification.actions.iter().all(|a| {
        a == "read" || (a == "send_data" && (egress_declared || baseline == ActionClass::Network))
    }) {
        return Ok(ProductionVerdict::Allow);
    }

    Ok(ProductionVerdict::Ask)
}

fn validate_resource_receipt(admission: Option<&Value>, reply: &Value) -> anyhow::Result<()> {
    if let Some(admission) = admission {
        let admission: crate::native::resource::Admission =
            serde_json::from_value(admission.clone())?;
        admission.validate_shape().map_err(anyhow::Error::msg)?;
        ensure!(
            reply["resources_sha256"] == admission.resources_sha256(),
            "MCP admission resource receipt mismatch"
        );
    } else {
        ensure!(
            reply.get("resources_sha256").is_none(),
            "unexpected legacy resources receipt"
        );
    }
    Ok(())
}

struct AdmittedTool {
    description: String,
    schema: Value,
    schema_sha256: String,
    definition: Value,
    definition_sha256: String,
}
struct Snapshot {
    sha256: String,
    tools: BTreeMap<String, AdmittedTool>,
    server_info: Value,
}

fn prediction_identity(
    server: &str,
    snapshot: &Snapshot,
    tool: &AdmittedTool,
    name: &str,
    args: &Value,
    source: &str,
    revision: Option<&str>,
) -> String {
    // Trusted profiles, policy, native IDs and permissions are not prediction-cache
    // identity. No predictions are cached here: each invocation is recomputed.
    sha(
        canonical(&json!({"profile":"sou11-input-v1","server":server,
        "server_info":snapshot.server_info,"snapshot":snapshot.sha256,
        "tool":name,"schema":tool.schema_sha256,"definition":tool.definition_sha256,
        "arguments":args,"classifier":source,"revision":revision}))
        .to_string()
        .as_bytes(),
    )
}

pub fn classification_to_adapter(
    result: &Classification,
) -> Result<ToolClassification, &'static str> {
    let valid = result.confidence.is_finite()
        && (0.0..=1.0).contains(&result.confidence)
        && result.uncertainty.is_finite()
        && (0.0..=1.0).contains(&result.uncertainty)
        && !result.reason.is_empty()
        && result.reason.len() <= 1024
        && result.actions.iter().collect::<BTreeSet<_>>().len() == result.actions.len()
        && result.actions.iter().all(|action| {
            matches!(
                action.as_str(),
                "read" | "write" | "delete" | "send_data" | "change_permissions"
            )
        });
    if !valid {
        return Err("classifier_invalid");
    }
    let mut categories = Vec::new();
    for action in &result.actions {
        categories.push(match action.as_str() {
            "read" => ToolActionCategory::Read,
            "write" => ToolActionCategory::Write,
            "delete" => ToolActionCategory::Delete,
            "send_data" => ToolActionCategory::SendData,
            "change_permissions" => ToolActionCategory::ChangePermissions,
            _ => ToolActionCategory::Unknown,
        });
    }
    if result.unknown {
        categories.push(ToolActionCategory::Unknown);
    }
    Ok(ToolClassification {
        categories,
        confidence: result.confidence as f32,
        uncertainty: result.uncertainty as f32,
        reason: Some(result.reason.clone()),
    })
}

pub struct AdmissionCfg {
    pub host_session: Option<String>,
    pub child_authority: Option<String>,
    pub daemon_url: String,
    pub manifest_url: String,
    pub manifest_token: String,
    pub server_id: String,
    pub native: NativeState,
    pub command: String,
    pub args: Vec<String>,
    pub classifier: Option<Arc<dyn InvocationClassifier>>,
    pub resource_profiles: BTreeMap<String, super::resources::ResourceProfile>,
    /// Opt-in wait for a single-use operator approval of a native Ask call.
    /// `None` keeps the default correlated refusal.
    pub approval: Option<ApprovalWait>,
    pub liveness_url: Option<String>,
    pub liveness_lease_seconds: Option<u64>,
}

impl AdmissionCfg {
    pub fn liveness_endpoint(&self) -> String {
        if let Some(url) = &self.liveness_url {
            return url.clone();
        }
        if let Some(base) = self.daemon_url.strip_suffix("/native/v1") {
            format!("{base}/native/liveness/v1")
        } else if let Some(base) = self.daemon_url.strip_suffix("/native") {
            format!("{base}/native/liveness/v1")
        } else {
            format!(
                "{}/native/liveness/v1",
                self.daemon_url.trim_end_matches('/')
            )
        }
    }
}

pub struct ApprovalWait {
    pub url: String,
    pub wait: Duration,
}

// A generic spawned program has no enforced filesystem/destination capability.
// An environment Boolean or a lexical command check cannot establish one.
pub fn resource_profiles_from_env(
) -> anyhow::Result<BTreeMap<String, super::resources::ResourceProfile>> {
    match std::env::var_os("AGENTFW_RESOURCE_PROFILES") {
        None => Ok(BTreeMap::new()),
        Some(val) => {
            let path = std::path::PathBuf::from(&val);
            let content = if path.is_file() {
                std::fs::read_to_string(&path)?
            } else {
                val.to_str()
                    .context("invalid AGENTFW_RESOURCE_PROFILES")?
                    .to_owned()
            };
            let profiles: Vec<super::resources::ResourceProfile> =
                serde_json::from_str(&content).context("invalid resource profiles format")?;
            let mut map = BTreeMap::new();
            for profile in profiles {
                map.insert(profile.tool_name.clone(), profile);
            }
            Ok(map)
        }
    }
}

/// Debug fixtures only. The release build refuses both switches.
pub fn test_classifier_from_env() -> anyhow::Result<Option<Arc<dyn InvocationClassifier>>> {
    let read = std::env::var_os("AGENTFW_TEST_CLASSIFIER_READ");
    let fixture = std::env::var_os("AGENTFW_TEST_CLASSIFIER");
    match (read, fixture) {
        (None, None) => Ok(None),
        _ if !cfg!(debug_assertions) => bail!("test classifier is unavailable"),
        (Some(value), None) if value == "1" => Ok(Some(Arc::new(ReadTestDouble))),
        (None, Some(value)) if value == "fixture-v1" => Ok(Some(Arc::new(FixtureTestDouble))),
        _ => bail!("invalid test classifier setting"),
    }
}

fn sha(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn canonical(value: &Value) -> Value {
    match value {
        Value::Object(map) => serde_json::to_value(
            map.iter()
                .map(|(key, value)| (key, canonical(value)))
                .collect::<BTreeMap<_, _>>(),
        )
        .expect("JSON values serialize"),
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        other => other.clone(),
    }
}

// JSON-RPC ids and arguments cannot acquire different meanings in different parsers.
pub(crate) struct Strict(pub(crate) Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct JsonVisitor;
        impl<'de> Visitor<'de> for JsonVisitor {
            type Value = Strict;
            fn expecting(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                out.write_str("unambiguous JSON")
            }
            fn visit_bool<E>(self, value: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(value)))
            }
            fn visit_i64<E>(self, value: i64) -> Result<Strict, E> {
                Ok(Strict(value.into()))
            }
            fn visit_u64<E>(self, value: u64) -> Result<Strict, E> {
                Ok(Strict(value.into()))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Strict, E> {
                serde_json::Number::from_f64(value)
                    .map(|n| Strict(Value::Number(n)))
                    .ok_or_else(|| E::custom("non-finite JSON"))
            }
            fn visit_str<E>(self, value: &str) -> Result<Strict, E> {
                Ok(Strict(Value::String(value.into())))
            }
            fn visit_string<E>(self, value: String) -> Result<Strict, E> {
                Ok(Strict(Value::String(value)))
            }
            fn visit_none<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_unit<E>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(Strict(value)) = seq.next_element()? {
                    values.push(value);
                }
                Ok(Strict(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Strict, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some((key, Strict(value))) = map.next_entry::<String, Strict>()? {
                    if values.insert(key, value).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON member"));
                    }
                }
                Ok(Strict(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(JsonVisitor)
    }
}

fn parse(raw: &[u8]) -> anyhow::Result<Value> {
    let Strict(value) = serde_json::from_slice(raw).context("unsupported or malformed MCP JSON")?;
    ensure!(
        value.is_object() && value["jsonrpc"] == "2.0",
        "unsupported MCP envelope"
    );
    Ok(value)
}

fn keys(value: &Value, allowed: &[&str]) -> anyhow::Result<()> {
    ensure!(
        value
            .as_object()
            .is_some_and(|map| map.keys().all(|key| allowed.contains(&key.as_str()))),
        "unsupported MCP fields"
    );
    Ok(())
}

fn id(value: &Value) -> anyhow::Result<String> {
    ensure!(
        value
            .as_str()
            .is_some_and(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control))
            || value.as_i64().is_some(),
        "unsupported MCP request id"
    );
    Ok(value.to_string())
}

// The retained partial frame makes select cancellation safe: consumed bytes survive.
async fn line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    raw: &mut Vec<u8>,
) -> anyhow::Result<Option<Vec<u8>>> {
    loop {
        let buffer = reader.fill_buf().await?;
        if buffer.is_empty() {
            ensure!(raw.is_empty(), "unterminated MCP frame");
            return Ok(None);
        }
        let end = buffer
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buffer.len(), |index| index + 1);
        ensure!(
            raw.len() + end <= MAX_CONTENT,
            "MCP frame exceeds admission limit"
        );
        raw.extend_from_slice(&buffer[..end]);
        let complete = buffer[end - 1] == b'\n';
        reader.consume(end);
        if complete {
            return Ok(Some(std::mem::take(raw)));
        }
    }
}

async fn write<W: AsyncWrite + Unpin>(output: &mut W, raw: &[u8]) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(5), async {
        output.write_all(raw).await?;
        output.flush().await
    })
    .await
    .context("MCP stdio write timed out")??;
    Ok(())
}

// Brokered resource operations finish inside the client branch, without a
// Pending::Call. Monitor unread bytes while each execution/result gate is in
// progress so an unsupported pipelined request cannot become a serialized call.
// fill_buf does not consume bytes, including an incomplete next frame. Reply
// writes use the completion-first guard below so a client observing a finished
// response can immediately submit its next sequential request.
async fn without_resource_overlap<R, F, T>(
    client: &mut R,
    resource_bound: bool,
    operation: F,
) -> anyhow::Result<T>
where
    R: AsyncBufRead + Unpin,
    F: Future<Output = anyhow::Result<T>>,
{
    if !resource_bound {
        return operation.await;
    }
    tokio::pin!(operation);
    tokio::select! {
        biased;
        available = client.fill_buf() => {
            ensure!(available?.is_empty(), "concurrent MCP requests are not supported");
            // EOF cannot add another request. Preserve the existing single-call
            // resource behavior when a client closes stdin after its last frame.
            operation.await
        }
        result = &mut operation => result,
    }
}

// Unix admission uses direct nonblocking pipe writes: once the complete frame
// is visible, its write future completes in the same poll. A blocking stdout
// worker cannot provide that ordering because it may publish its completion
// after the client has already submitted a legitimate sequential request.
// Preserve one pinned write across EOF and give physical completion priority.
// Refusing overlap cannot retract already-exposed first-call bytes.
async fn write_resource_reply<R, W>(
    client: &mut R,
    host: &mut W,
    resource_bound: bool,
    raw: &[u8],
) -> anyhow::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    if !resource_bound {
        return write(host, raw).await;
    }
    ensure!(
        raw.ends_with(b"\n"),
        "resource MCP reply must end with a newline"
    );
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let outcome = {
        let writing = tokio::time::timeout_at(deadline, async {
            host.write_all(raw).await?;
            #[cfg(unix)]
            host.flush().await?;
            #[cfg(not(unix))]
            {
                // Preserve the existing non-Unix transport; the bounded
                // Windows uses the existing non-Unix stdout drain.
                let written = host.write(&[]).await?;
                ensure!(written == 0, "empty stdout drain wrote unexpected bytes");
            }
            Ok::<_, anyhow::Error>(())
        });
        tokio::pin!(writing);
        tokio::select! {
            biased;
            result = &mut writing => result,
            available = client.fill_buf() => {
                ensure!(available?.is_empty(), "concurrent MCP requests are not supported");
                writing.await
            }
        }
    };
    outcome.context("MCP stdio write timed out")??;
    #[cfg(not(unix))]
    tokio::time::timeout_at(deadline, host.flush())
        .await
        .context("MCP stdio write timed out")??;
    Ok(())
}

#[derive(Clone, Copy)]
struct ClassificationAuthority {
    egress_declared: bool,
    create_file_profile: Option<&'static str>,
    https_get: bool,
}

pub struct Collector<'a> {
    config: &'a AdmissionCfg,
    host_session: Option<String>,
    child_authority: Option<String>,
    client: reqwest::Client,
    session: String,
    pub liveness: Option<Arc<crate::native::liveness::CollectorLivenessClient>>,
}

impl<'a> Collector<'a> {
    async fn policy_boundary(&self) -> anyhow::Result<Option<crate::policy_transition::Boundary>> {
        match &self.config.native.policy_barrier {
            Some(barrier) => barrier.release_boundary().await.map(Some),
            None => Ok(None),
        }
    }

    fn new(config: &'a AdmissionCfg) -> anyhow::Result<Self> {
        if config.host_session.is_some() != config.child_authority.is_some() {
            anyhow::bail!(
                "both host_session and child_authority must be provided together for authenticated binding"
            );
        }
        Ok(Self {
            config,
            host_session: config.host_session.clone(),
            child_authority: config.child_authority.clone(),
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(5))
                .build()?,
            session: std::env::var("AGENTFW_MCP_SESSION")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| format!("mcp:{}", crate::token::generate())),
            liveness: None,
        })
    }

    pub fn is_uncertain(&self) -> bool {
        self.liveness.as_ref().is_some_and(|l| l.is_uncertain())
    }

    async fn fetch_daemon_instance_id(&self) -> anyhow::Result<String> {
        let instance_url = format!("{}/instance", self.config.daemon_url.trim_end_matches('/'));
        let response = self
            .client
            .get(&instance_url)
            .bearer_auth(&self.config.native.token)
            .send()
            .await
            .context("MCP daemon instance unavailable")?;
        ensure!(
            response.status().is_success(),
            "MCP daemon instance query rejected"
        );
        let info: serde_json::Value = response
            .json()
            .await
            .context("malformed MCP daemon instance reply")?;
        let instance_id = info["instance_id"]
            .as_str()
            .context("MCP daemon instance ID missing")?
            .to_string();
        ensure!(
            crate::native::identifier(&instance_id),
            "invalid daemon instance ID"
        );
        Ok(instance_id)
    }

    /// Classifies one validated call before the daemon sees it. The outer error is
    /// untrusted session state; the inner label is a call-local failure that must
    /// not execute and does not reach policy. A supported result is evidence only:
    /// the daemon still authorizes against the trusted registry baseline.
    async fn classify(
        &self,
        snapshot: &Snapshot,
        host_call_id: &Value,
        name: &str,
        args: &Value,
        baseline: ActionClass,
        authority: ClassificationAuthority,
    ) -> anyhow::Result<Result<ClassifiedAssessment, &'static str>> {
        let Some(classifier) = self.config.classifier.clone() else {
            return Ok(Ok(ClassifiedAssessment::allow()));
        };
        let tool = snapshot
            .tools
            .get(name)
            .context("classifier discovery state missing")?;
        let source = classifier.source();
        let revision = classifier.revision().map(str::to_owned);
        let input_sha256 = prediction_identity(
            &self.config.server_id,
            snapshot,
            tool,
            name,
            args,
            source,
            revision.as_deref(),
        );
        let input = Invocation {
            server_id: self.config.server_id.clone(),
            host_call_id: host_call_id.clone(),
            registry_sha256: self.config.native.registry_sha256.clone(),
            snapshot_sha256: snapshot.sha256.clone(),
            schema_sha256: tool.schema_sha256.clone(),
            tool: name.into(),
            description: tool.description.clone(),
            schema: tool.schema.clone(),
            definition: tool.definition.clone(),
            server_info: snapshot.server_info.clone(),
            definition_sha256: tool.definition_sha256.clone(),
            input_sha256: input_sha256.clone(),
            classifier_revision: revision.clone(),
            args: args.clone(),
            baseline,
        };
        let started = std::time::Instant::now();
        let task = tokio::task::spawn_blocking(move || classifier.classify(&input));
        // ponytail: a timed-out classifier thread is abandoned, not killed; an
        // out-of-process classifier would be needed to reclaim it.
        let (result, mapped) = match tokio::time::timeout(CLASSIFIER_TIMEOUT, task).await {
            Err(_) => (None, Err("classifier_timeout")),
            Ok(Err(_)) => (None, Err("classifier_crash")),
            Ok(Ok(Err(_))) => (None, Err("classifier_error")),
            Ok(Ok(Ok(result))) => {
                let mapped = map_classification(&result);
                (Some(result), mapped)
            }
        };
        let adapter_eval = if let Some(ref res) = result {
            if let Ok(tc) = classification_to_adapter(res) {
                Some(evaluate_baseline_policy(&tc))
            } else {
                None
            }
        } else {
            None
        };
        let prod_eval: Result<ClassifiedAssessment, &'static str> = if let Err(failure) = mapped {
            Err(failure) // Invalid classifier replies never reach policy.
        } else if let Some(ref res) = result {
            let ambiguous_or_unknown = res.unknown || res.uncertainty >= 0.8;
            let eval = if authority.https_get {
                compose_https_get_policy(res, baseline, authority.egress_declared)
            } else {
                compose_scoped_production_policy(
                    res,
                    baseline,
                    authority.egress_declared,
                    authority.create_file_profile.is_some(),
                )
            };
            eval.map(|verdict| ClassifiedAssessment {
                verdict,
                ambiguous_or_unknown,
            })
        } else {
            Err(mapped.err().unwrap_or("classifier_unavailable"))
        };
        let mapped_class = mapped.ok().flatten();
        let policy_reached = prod_eval.is_ok();
        let failure = if policy_reached {
            None
        } else {
            prod_eval.err()
        };
        eprintln!(
            "{}",
            json!({"event":"mcp_classification","contract_version":CLASSIFICATION_CONTRACT,
            "source":source,"classifier_sha256":revision,"host_call_id":host_call_id,"server_id":self.config.server_id,
            "tool":name,"snapshot_sha256":snapshot.sha256,
            "definition_sha256":tool.definition_sha256,"input_sha256":input_sha256,
            "schema_sha256":tool.schema_sha256,"args_sha256":sha(canonical(args).to_string().as_bytes()),
            "registry_sha256":self.config.native.registry_sha256,
            "classification":result.as_ref().map(|result| json!({"actions":result.actions,"unknown":result.unknown,
                "confidence":result.confidence,"uncertainty":result.uncertainty,
                "reason_sha256":sha(result.reason.as_bytes())})),
            "mapped_action_class":mapped_class,"trusted_baseline":baseline,
            "operator_execution_profile":authority.create_file_profile,
            "baseline_mismatch":mapped_class.map(|class| class != baseline),
            "adapter_verdict":adapter_eval.as_ref().map(|(v, _)| match v {
                AdapterVerdict::Allow => "allow",
                AdapterVerdict::Ask => "ask",
                AdapterVerdict::Deny => "deny",
            }),
            "authoritative_verdict":match &prod_eval {
                Ok(assessment) => match assessment.verdict {
                    ProductionVerdict::Allow => "allow",
                    ProductionVerdict::Ask => "ask",
                    ProductionVerdict::Deny => "deny",
                },
                Err(e) => *e,
            },
            "policy":if policy_reached { "reached" } else { "not_reached" },
            "failure":failure,"latency_us":started.elapsed().as_micros()})
        );
        match prod_eval {
            Ok(v) => Ok(Ok(v)),
            Err(failure) => Ok(Err(failure)),
        }
    }

    async fn post(&self, url: &str, token: &str, body: &Value) -> anyhow::Result<Value> {
        let mut request = self.client.post(url).bearer_auth(token).json(body);
        // Owner capabilities belong only to the native daemon, never the
        // separate manifest inspector or an MCP server.
        if url == self.config.daemon_url {
            request = self.bind_liveness_request(request).await?;
        }
        let response = request.send().await.context("MCP admission unavailable")?;
        ensure!(
            response.status().is_success(),
            "MCP admission request rejected"
        );
        let mut bytes = Vec::new();
        let mut chunks = response.bytes_stream();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk?;
            ensure!(
                bytes.len() + chunk.len() <= 16 * 1024,
                "MCP admission response exceeds limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        let Strict(reply) =
            serde_json::from_slice(&bytes).context("malformed MCP admission receipt")?;
        Ok(reply)
    }

    async fn bind_liveness_request(
        &self,
        request: reqwest::RequestBuilder,
    ) -> anyhow::Result<reqwest::RequestBuilder> {
        match &self.liveness {
            Some(liveness) => Ok(request.header(
                crate::native::liveness::COLLECTOR_IDENTITY_HEADER,
                liveness.admission_identity().await?,
            )),
            None => Ok(request),
        }
    }

    /// One call on the approval route. `Err(code)` is a daemon refusal code.
    async fn approval_post(&self, body: &Value) -> anyhow::Result<Result<Value, String>> {
        let approval = self.config.approval.as_ref().context("approval disabled")?;
        let request = self
            .client
            .post(&approval.url)
            .bearer_auth(&self.config.native.token)
            .json(body);
        let response = self
            .bind_liveness_request(request)
            .await?
            .send()
            .await
            .context("MCP approval unavailable")?;
        let ok = response.status().is_success();
        let mut bytes = Vec::new();
        let mut chunks = response.bytes_stream();
        while let Some(chunk) = chunks.next().await {
            let chunk = chunk?;
            ensure!(
                bytes.len() + chunk.len() <= 16 * 1024,
                "MCP approval response exceeds limit"
            );
            bytes.extend_from_slice(&chunk);
        }
        let Strict(reply) =
            serde_json::from_slice(&bytes).context("malformed MCP approval reply")?;
        if !ok {
            let code = reply["error_code"]
                .as_str()
                .filter(|c| {
                    c.len() <= 64 && c.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_')
                })
                .unwrap_or("native_approval_refused");
            return Ok(Err(code.to_owned()));
        }
        keys(
            &reply,
            &[
                "contract_version",
                "action",
                "pending_id",
                "state",
                "expires_in_ms",
                "binding_sha256",
            ],
        )?;
        ensure!(
            reply["contract_version"] == crate::native::approval::APPROVAL_CONTRACT
                && reply["pending_id"]
                    .as_str()
                    .is_some_and(|id| !id.is_empty() && id.len() <= 128)
                && reply["state"].as_str().is_some()
                && reply["expires_in_ms"].is_u64(),
            "MCP approval reply identity mismatch"
        );
        Ok(Ok(reply))
    }

    /// Hold ONE plain native call while an operator decides. The original frame is
    /// never replaced: on `Ok(Ok(id))` the caller re-presents the same call with the
    /// id. Any client byte or EOF while waiting cancels the pending approval and
    /// closes the session, so nothing can execute later.
    async fn obtain_approval<R>(
        &self,
        client: &mut R,
        source: &str,
        name: &str,
        args: &Value,
        schema_sha256: &str,
        resource_admission: Option<&Value>,
    ) -> anyhow::Result<Result<String, String>>
    where
        R: AsyncBufRead + Unpin,
    {
        let approval = self.config.approval.as_ref().context("approval disabled")?;
        let base = |action: &str| {
            json!({"contract_version":CONTRACT,"registry_sha256":self.config.native.registry_sha256,
                "session_id":self.session,"action":action})
        };
        let mut body = base("request");
        body.as_object_mut().expect("object").extend([
            ("source".to_owned(), json!(source)),
            ("tool".to_owned(), json!(name)),
            ("args".to_owned(), args.clone()),
            ("schema_sha256".to_owned(), json!(schema_sha256)),
        ]);
        if let Some(admission) = resource_admission {
            body["resource_admission"] = admission.clone();
        }
        let reply = match self.approval_post(&body).await? {
            Ok(reply) => reply,
            Err(code) => return Ok(Err(code)),
        };
        ensure!(
            reply["action"] == "request",
            "MCP approval reply action mismatch"
        );
        let id = reply["pending_id"]
            .as_str()
            .context("pending id")?
            .to_owned();
        let expires = reply["expires_in_ms"].as_u64().unwrap_or(0);
        eprintln!(
            "{}",
            json!({"event":"mcp_native_approval_pending","pending_id":id,"tool":name,
                "binding_sha256":reply["binding_sha256"],"expires_in_ms":expires,
                "source":source})
        );
        let limit = tokio::time::Instant::now() + approval.wait.min(Duration::from_millis(expires));
        let cancel = |id: &str| {
            let mut body = base("cancel");
            body["pending_id"] = json!(id);
            body
        };
        loop {
            tokio::select! {
                biased;
                available = client.fill_buf() => {
                    let closed = available.map(|b| b.is_empty()).unwrap_or(true);
                    let _ = self.approval_post(&cancel(&id)).await;
                    if closed {
                        bail!("MCP client closed with an outstanding approval");
                    }
                    bail!("concurrent MCP input during a pending approval");
                }
                _ = tokio::time::sleep(Duration::from_millis(250)) => {}
            }
            let mut status = base("status");
            status["pending_id"] = json!(id);
            let reply = match self.approval_post(&status).await {
                Ok(Ok(reply)) => reply,
                Ok(Err(code)) => return Ok(Err(code)),
                Err(error) => {
                    let _ = self.approval_post(&cancel(&id)).await;
                    return Err(error);
                }
            };
            ensure!(
                reply["pending_id"] == id.as_str() && reply["action"] == "status",
                "MCP approval status changed identity"
            );
            match reply["state"].as_str().unwrap_or("") {
                "approved" => return Ok(Ok(id)),
                "pending" => {
                    if tokio::time::Instant::now() >= limit {
                        let _ = self.approval_post(&cancel(&id)).await;
                        return Ok(Err("native_approval_timeout".to_owned()));
                    }
                }
                other => {
                    let code: String = other
                        .chars()
                        .filter(|c| c.is_ascii_lowercase())
                        .take(24)
                        .collect();
                    return Ok(Err(format!("native_approval_{code}")));
                }
            }
        }
    }

    async fn cancel_approval(&self, id: &str) -> anyhow::Result<()> {
        let body = json!({
            "contract_version": CONTRACT,
            "registry_sha256": self.config.native.registry_sha256,
            "session_id": self.session,
            "action": "cancel",
            "pending_id": id,
        });
        let _ = self.approval_post(&body).await;
        Ok(())
    }

    async fn inspect_manifest(&self, value: &Value) -> anyhow::Result<()> {
        let tools = value["tools"]
            .as_array()
            .context("MCP manifest absent")?
            .iter()
            .map(|tool| {
                // Preserve the original definition in the snapshot; inspect annotation
                // strings as untrusted metadata through the existing manifest boundary.
                let mut description = tool["description"].as_str().unwrap_or("").to_owned();
                if let Some(title) = tool
                    .get("annotations")
                    .and_then(|v| v.get("title"))
                    .and_then(Value::as_str)
                {
                    description.push('\n');
                    description.push_str(title);
                }
                json!({"name":tool["name"],"description":description,"schema":tool["inputSchema"]})
            })
            .collect::<Vec<_>>();
        let reply = self
            .post(
                &self.config.manifest_url,
                &self.config.manifest_token,
                &json!({"server":self.config.server_id,"tools":tools}),
            )
            .await?;
        keys(&reply, &["verdict", "enforce", "reason"])?;
        ensure!(
            reply.as_object().is_some_and(|map| map.len() == 3)
                && reply["verdict"] == "allow"
                && reply["enforce"] == true
                && (reply["reason"].is_null()
                    || reply["reason"].as_str().is_some_and(|s| s.len() <= 8192)),
            "MCP manifest was not admitted in enforcement mode"
        );
        Ok(())
    }

    async fn event(&self, event: &str, fields: Value) -> anyhow::Result<Value> {
        if event != "session_end" && self.is_uncertain() {
            anyhow::bail!("native_liveness_uncertain");
        }
        let expected_contract = if let Some(admission) = fields.get("resource_admission") {
            serde_json::from_value::<crate::native::resource::Admission>(admission.clone())?
                .contract()
        } else {
            fields
                .get("expected_contract_version")
                .and_then(Value::as_str)
                .unwrap_or(CONTRACT)
        };
        ensure!(
            matches!(
                expected_contract,
                CONTRACT
                    | crate::native::resource::CONTRACT
                    | crate::native::resource::CREATE_CONTRACT
                    | crate::native::resource::POST_CONTRACT
                    | crate::native::resource::NETWORK_CONTRACT
                    | crate::native::resource::WINDOWS_READ_CONTRACT
                    | crate::native::resource::WINDOWS_CREATE_CONTRACT
            ),
            "unsupported native receipt contract"
        );
        let mut body = json!({"contract_version":expected_contract,"registry_sha256":self.config.native.registry_sha256,"session_id":self.session,"event":event});
        if event == "session_start" && self.config.native.policy_barrier.is_some() {
            body["policy_transition"] = json!(crate::policy_transition::CONTRACT);
        }
        body.as_object_mut().expect("object").extend(
            fields
                .as_object()
                .context("invalid admission event")?
                .iter()
                .filter(|(key, _)| {
                    !matches!(
                        key.as_str(),
                        "expected_binding_sha256" | "expected_contract_version"
                    )
                })
                .map(|(key, value)| (key.clone(), value.clone())),
        );
        let reply = self
            .post(&self.config.daemon_url, &self.config.native.token, &body)
            .await?;
        let allowed = [
            "contract_version",
            "registry_sha256",
            "session_id",
            "event",
            "verdict",
            "enforced",
            "release",
            "call_id",
            "binding_sha256",
            "content_sha256",
            "reason_codes",
            "resources_sha256",
            "instance_id",
            "owner_token",
            "managed_policy",
        ];
        keys(&reply, &allowed)?;
        let required = [
            "contract_version",
            "registry_sha256",
            "session_id",
            "event",
            "verdict",
            "enforced",
            "release",
            "call_id",
            "binding_sha256",
            "content_sha256",
            "reason_codes",
        ];
        ensure!(
            reply.as_object().is_some_and(|map| {
                required.iter().all(|k| map.contains_key(*k))
                    && map.keys().all(|k| {
                        required.contains(&k.as_str())
                            || matches!(
                                k.as_str(),
                                "resources_sha256"
                                    | "instance_id"
                                    | "owner_token"
                                    | "managed_policy"
                            )
                    })
            }) && reply["contract_version"] == expected_contract
                && reply["registry_sha256"] == self.config.native.registry_sha256
                && reply["session_id"] == self.session
                && reply["event"] == event
                && reply["enforced"] == true,
            "MCP admission receipt identity mismatch"
        );
        if let Some(policy) = reply.get("managed_policy") {
            ensure!(
                self.config.native.policy_barrier.is_some(),
                "managed native boundary unavailable"
            );
            let policy: soup_wall_agent::engine::ManagedActivePolicy =
                serde_json::from_value(policy.clone())?;
            ensure!(
                policy.deployment_sequence > 0
                    && !policy.revision.is_empty()
                    && policy.revision.len() <= 128
                    && crate::native::is_digest(&policy.policy_sha256),
                "invalid managed policy receipt"
            );
        }
        let verdict = reply["verdict"]
            .as_str()
            .context("MCP admission verdict absent")?;
        ensure!(
            matches!(verdict, "allow" | "ask" | "deny")
                && reply["release"].as_bool() == Some(verdict == "allow"),
            "inconsistent MCP admission verdict"
        );
        ensure!(
            reply["reason_codes"]
                .as_array()
                .is_some_and(|codes| codes.len() <= 256
                    && codes
                        .iter()
                        .all(|v| v.as_str().is_some_and(|s| s.len() <= 256))),
            "malformed MCP admission reasons"
        );
        if event == "call" {
            if verdict == "allow" {
                ensure!(
                    reply["call_id"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty() && s.len() <= 128)
                        && reply["binding_sha256"]
                            .as_str()
                            .is_some_and(crate::native::is_digest),
                    "MCP admission invocation binding absent"
                );
                validate_resource_receipt(fields.get("resource_admission"), &reply)?;
            } else {
                ensure!(
                    reply["call_id"].is_null()
                        && reply["binding_sha256"].is_null()
                        && reply.get("resources_sha256").is_none(),
                    "withheld MCP call acquired binding"
                );
            }
            ensure!(
                reply["content_sha256"].is_null(),
                "unexpected MCP call content hash"
            );
        } else if event == "result" {
            ensure!(
                reply["call_id"] == fields["call_id"]
                    && reply["binding_sha256"] == fields["expected_binding_sha256"],
                "MCP result receipt changed invocation"
            );
            ensure!(
                reply["content_sha256"]
                    == sha(fields["content"]
                        .as_str()
                        .context("MCP result content missing")?
                        .as_bytes()),
                "MCP result receipt changed content"
            );
            ensure!(
                reply.get("resources_sha256").is_none(),
                "unexpected MCP result resources hash"
            );
        } else {
            ensure!(
                verdict == "allow"
                    && reply["call_id"].is_null()
                    && reply["binding_sha256"].is_null()
                    && reply["content_sha256"].is_null()
                    && reply.get("resources_sha256").is_none(),
                "MCP session receipt rejected"
            );
        }
        Ok(reply)
    }
}

enum Pending {
    Handshake(Value),
    Manifest(Value),
    Ping(Value),
    Call {
        id: Value,
        tool: String,
        args: Value,
        call_id: Value,
        binding: Value,
        contract_version: String,
    },
}

impl Pending {
    fn id(&self) -> &Value {
        match self {
            Self::Handshake(id) | Self::Manifest(id) | Self::Ping(id) | Self::Call { id, .. } => id,
        }
    }
}

fn manifest(
    value: &Value,
    native: &NativeState,
    server_info: &Value,
) -> anyhow::Result<(BTreeMap<String, InputSchema>, Snapshot)> {
    keys(value, &["tools"])?;
    let tools = value["tools"]
        .as_array()
        .context("MCP manifest tools absent")?;
    ensure!(
        tools.len() == native.registry.tools.len(),
        "MCP manifest coverage mismatch"
    );
    let mut seen = BTreeSet::new();
    let mut schemas: BTreeMap<String, InputSchema> = BTreeMap::new();
    let mut admitted = BTreeMap::new();
    for tool in tools {
        keys(tool, &["name", "description", "inputSchema", "annotations"])?;
        let name = tool["name"]
            .as_str()
            .context("MCP manifest tool name absent")?;
        ensure!(seen.insert(name), "duplicate MCP manifest tool");
        ensure!(
            !name.is_empty() && name.len() <= 128 && !name.chars().any(char::is_control),
            "invalid MCP tool name"
        );
        if let Some(annotations) = tool.get("annotations") {
            keys(
                annotations,
                &[
                    "title",
                    "readOnlyHint",
                    "destructiveHint",
                    "idempotentHint",
                    "openWorldHint",
                ],
            )?;
            for (key, value) in annotations.as_object().expect("checked object") {
                ensure!(
                    if key == "title" {
                        value.is_string()
                    } else {
                        value.is_boolean()
                    },
                    "invalid MCP tool annotation"
                );
            }
        }
        ensure!(
            tool.get("description").is_none_or(Value::is_string),
            "unsupported MCP tool description"
        );
        let installed = native
            .registry
            .tools
            .iter()
            .find(|t| t.name == name)
            .context("MCP tool is not installed by operator")?;
        let schema_sha256 = sha(canonical(&tool["inputSchema"]).to_string().as_bytes());
        ensure!(
            tool["inputSchema"].is_object() && schema_sha256 == installed.schema_sha256,
            "MCP tool schema differs from operator pin"
        );
        schemas.insert(name.into(), InputSchema::read(&tool["inputSchema"])?);
        admitted.insert(
            name.into(),
            AdmittedTool {
                description: tool["description"].as_str().unwrap_or("").into(),
                schema: tool["inputSchema"].clone(),
                schema_sha256,
                definition: tool.clone(),
                definition_sha256: sha(canonical(tool).to_string().as_bytes()),
            },
        );
    }
    Ok((
        schemas,
        Snapshot {
            sha256: sha(canonical(value).to_string().as_bytes()),
            tools: admitted,
            server_info: server_info.clone(),
        },
    ))
}

fn initialization(value: &Value) -> anyhow::Result<()> {
    keys(value, &["protocolVersion", "capabilities", "serverInfo"])?;
    ensure!(
        value["protocolVersion"]
            .as_str()
            .is_some_and(|s| !s.is_empty() && s.len() <= 64 && !s.chars().any(char::is_control)),
        "unsupported MCP protocol version"
    );
    keys(&value["capabilities"], &["tools"])?;
    if let Some(tools) = value["capabilities"].get("tools") {
        keys(tools, &["listChanged"])?;
        ensure!(
            tools.get("listChanged").is_none_or(Value::is_boolean),
            "invalid MCP manifest change capability"
        );
    }
    keys(&value["serverInfo"], &["name", "version"])?;
    for field in ["name", "version"] {
        ensure!(
            value["serverInfo"][field]
                .as_str()
                .is_some_and(|s| !s.is_empty()
                    && s.len() <= 128
                    && !s.chars().any(char::is_control)),
            "unsupported MCP server identity"
        );
    }
    Ok(())
}

fn correlation_id(value: &Value) -> bool {
    value.as_str().is_some_and(|id| {
        !id.is_empty()
            && id.len() <= 128
            && id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
    })
}

fn progress_token(value: &Value) -> bool {
    // Keep tokens integral and exactly representable across JSON consumers.
    value
        .as_u64()
        .is_some_and(|token| token <= 9_007_199_254_740_991)
}

fn discovery_params(value: &Value) -> anyhow::Result<()> {
    keys(value, &["_meta"])?;
    if let Some(metadata) = value.get("_meta") {
        keys(metadata, &["progressToken"])?;
        ensure!(
            progress_token(&metadata["progressToken"]),
            "unsupported MCP discovery correlation metadata"
        );
    }
    Ok(())
}

/// Observed Claude and Codex identifiers are transport correlation only. They
/// never supply native session identity, arguments, authority or provenance.
fn call_metadata(value: &Value) -> anyhow::Result<()> {
    keys(
        value,
        &["claudecode/toolUseId", "threadId", "progressToken"],
    )?;
    let host_id = match (value.get("claudecode/toolUseId"), value.get("threadId")) {
        (Some(id), None) | (None, Some(id)) => id,
        _ => bail!("unsupported MCP call correlation metadata"),
    };
    ensure!(
        value.as_object().is_some_and(|map| map.len() == 2)
            && correlation_id(host_id)
            && progress_token(&value["progressToken"]),
        "unsupported MCP call correlation metadata"
    );
    Ok(())
}

fn result_kind(value: &Value) -> anyhow::Result<&'static str> {
    if let Some(error) = value.get("error") {
        ensure!(
            value.get("result").is_none(),
            "ambiguous MCP result and error"
        );
        keys(error, &["code", "message"])?;
        ensure!(
            error["code"].as_i64().is_some() && error["message"].is_string(),
            "unsupported MCP error"
        );
        return Ok("error");
    }
    let result = value.get("result").context("MCP result absent")?;
    keys(result, &["content", "isError"])?;
    ensure!(
        result.get("isError").is_none_or(Value::is_boolean),
        "unsupported MCP isError"
    );
    let blocks = result["content"].as_array().context("MCP content absent")?;
    ensure!(blocks.len() <= 256, "MCP content block limit");
    for block in blocks {
        keys(block, &["type", "text"])?;
        ensure!(
            block["type"] == "text" && block["text"].is_string(),
            "unsupported non-text MCP content"
        );
    }
    Ok(if result["isError"] == true {
        "error"
    } else {
        "value"
    })
}

fn withheld(id: &Value, phase: &str, reasons: &Value) -> Vec<u8> {
    let reason = reasons
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    let message = format!("Soup Wall withheld MCP {phase} ({reason})");
    let mut raw = json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":message}],"isError":true}}).to_string().into_bytes();
    raw.push(b'\n');
    raw
}

/// A JSON-RPC error, not a policy refusal: the call did not execute and policy was not reached.
fn not_classified(id: &Value, failure: &str) -> Vec<u8> {
    let message =
        format!("Soup Wall could not classify the MCP invocation ({failure}); policy not reached");
    let mut raw = json!({"jsonrpc":"2.0","id":id,"error":{"code":-32603,"message":message}})
        .to_string()
        .into_bytes();
    raw.push(b'\n');
    raw
}

fn unsupported_resource_inventory(id: &Value) -> Vec<u8> {
    let mut raw = json!({"jsonrpc":"2.0","id":id,"error":{
        "code":-32601,"message":"Native MCP admission does not support resource inventory"
    }})
    .to_string()
    .into_bytes();
    raw.push(b'\n');
    raw
}

async fn relay<R, W, S, T>(
    collector: &Collector<'_>,
    client: &mut R,
    host: &mut W,
    server: &mut S,
    child: &mut T,
) -> anyhow::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    S: AsyncBufRead + Unpin,
    T: AsyncWrite + Unpin,
{
    let mut pending: Option<Pending> = None;
    let mut initialized = false;
    let mut notified = false;
    let mut ready = false;
    let mut schemas: BTreeMap<String, InputSchema> = BTreeMap::new();
    let mut admitted_snapshot: Option<Snapshot> = None;
    let mut server_info = Value::Null;
    let mut list_changed_supported = false;
    let mut used = BTreeSet::new();
    let mut client_partial = Vec::new();
    let mut server_partial = Vec::new();
    let mut deadline = tokio::time::Instant::now() + IO_TIMEOUT;
    loop {
        tokio::select! {
            raw = line(client, &mut client_partial) => {
                let Some(raw) = raw? else { ensure!(pending.is_none(), "MCP client closed with an outstanding request"); return Ok(()); };
                let value = parse(&raw)?;
                keys(&value, &["jsonrpc","id","method","params"])?;
                let method = value["method"].as_str().context("unsupported MCP client message")?;
                if method == "notifications/initialized" {
                    ensure!(initialized && !notified && pending.is_none() && value.get("id").is_none(), "unsupported initialized notification");
                    if let Some(params) = value.get("params") { keys(params, &[])?; }
                    notified = true;
                    write(child, &raw).await?;
                    continue;
                }
                ensure!(pending.is_none(), "concurrent MCP requests are not supported");
                let request_id = value.get("id").context("unsupported MCP notification")?;
                ensure!(used.len() < MAX_REQUESTS && used.insert(id(request_id)?), "replayed MCP request or session request limit");
                let params = value.get("params").cloned().unwrap_or_else(|| json!({}));
                ensure!(params.is_object(), "unsupported MCP parameters");
                let mut policy_boundary = None;
                let next = match method {
                    "initialize" => { ensure!(!initialized, "MCP session already initialized"); Pending::Handshake(request_id.clone()) }
                    "tools/list" => {
                        ensure!(initialized, "MCP manifest before initialization");
                        discovery_params(&params)?;
                        // A refresh is a new admission, never fallback to old definitions.
                        ready = false;
                        schemas.clear();
                        admitted_snapshot = None;
                        Pending::Manifest(request_id.clone())
                    }
                    "resources/list" | "resources/templates/list" => {
                        ensure!(ready, "MCP resource inventory before operator-pinned manifest");
                        discovery_params(&params)?;
                        // Hosts may probe inventory even though initialization advertises
                        // tools only. No request or resource content reaches the server.
                        write(host, &unsupported_resource_inventory(request_id)).await?;
                        continue;
                    }
                    "ping" => { keys(&params, &[])?; Pending::Ping(request_id.clone()) }
                    "tools/call" => {
                        ensure!(ready, "MCP call before operator-pinned manifest");
                        keys(&params, &["name","arguments","_meta"])?;
                        if let Some(metadata) = params.get("_meta") { call_metadata(metadata)?; }
                        let name = params["name"].as_str().context("MCP call tool absent")?;
                        let installed = collector.config.native.registry.tools.iter().find(|tool| tool.name == name).context("MCP call tool is not installed")?;
                        let resource_reply = installed.resource_policy.is_some()
                            || collector.config.resource_profiles.contains_key(name)
                            || name == "create_file" || name == "https_get" || name == "https_post";
                        if name == "https_post"
                            && !installed.resource_policy.as_ref().is_some_and(|policy| policy.is_https_post())
                        {
                            write_resource_reply(client, host, true,
                                &withheld(request_id, "invocation", &json!(["resource_https_profile_required"]))).await?;
                            continue;
                        }
                        if name == "https_get"
                            && !installed.resource_policy.as_ref().is_some_and(|policy| policy.is_https_get())
                        {
                            write_resource_reply(client, host, true,
                                &withheld(request_id, "invocation", &json!(["resource_https_profile_required"]))).await?;
                            continue;
                        }
                        if name == "create_file"
                            && !installed.resource_policy.as_ref().is_some_and(|policy| policy.is_create_file())
                        {
                            write_resource_reply(client, host, true,
                                &withheld(request_id, "invocation", &json!(["resource_create_profile_required"]))).await?;
                            continue;
                        }
                        let args = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
                        ensure!(args.is_object(), "MCP call arguments must be an object");
                        schemas.get(name).context("MCP tool schema not installed")?.validate(&args)?;
                        #[cfg(windows)]
                        let mut prepared_windows_read = None;
                        #[cfg(any(target_os = "linux", windows))]
                        let mut prepared_create = None;
                        let resource_admission = if let Some(policy) = &installed.resource_policy {
                            #[cfg(windows)]
                            if policy.is_windows_handles() {
                                // Refuse different roots and raw path aliases before
                                // generic extraction can follow an untrusted junction
                                // or mapped drive even for filesystem metadata.
                                let actual = std::env::var_os("AGENTFW_WORKSPACE")
                                    .map(std::path::PathBuf::from)
                                    .or_else(|| std::env::current_dir().ok());
                                let normal = |path: &std::path::Path| path.to_str()
                                    .map(|text| text.strip_prefix("\\\\?\\").unwrap_or(text).to_owned());
                                if actual.as_deref().and_then(normal).is_none()
                                    || actual.as_deref().and_then(normal) != normal(&policy.workspace) {
                                    write_resource_reply(client, host, true,
                                        &withheld(request_id, "invocation", &json!(["resource_workspace_mismatch"]))).await?;
                                    continue;
                                }
                                let [super::resources::Resource::Path { canonical }] = policy.allowed_resources.as_slice() else {
                                    bail!("validated Windows handle authority missing");
                                };
                                let path_ptr = policy.path_selector();
                                let original = crate::mcp::resources::selected(&args, path_ptr)
                                    .ok()
                                    .flatten()
                                    .and_then(|v| v.as_str())
                                    .context("validated Windows path missing")?;
                                if policy.is_windows_create() {
                                    let content_ptr = policy.content_selector();
                                    let content = crate::mcp::resources::selected(&args, content_ptr)
                                        .ok()
                                        .flatten()
                                        .and_then(|v| v.as_str())
                                        .context("validated create content missing")?;
                                    let prepared = match crate::windows_create::PreparedCreate::prepare(
                                        &policy.workspace, &policy.cwd, original, canonical, content) {
                                        Ok(prepared) => prepared,
                                        Err(error) => {
                                            write_resource_reply(client, host, true,
                                                &withheld(request_id, "invocation", &json!([error.code]))).await?;
                                            continue;
                                        }
                                    };
                                    prepared_create = Some(prepared);
                                } else {
                                    let prepared = match crate::windows_read::PreparedRead::prepare(
                                        &policy.workspace, &policy.cwd, original, canonical) {
                                        Ok(prepared) => prepared,
                                        Err(_) => {
                                            write_resource_reply(client, host, true,
                                                &withheld(request_id, "invocation", &json!(["resource_windows_read_prepare_failed"]))).await?;
                                            continue;
                                        }
                                    };
                                    prepared_windows_read = Some(prepared);
                                }
                            }
                            if (policy.is_create_file()
                                || policy.is_https_get()
                                || policy.is_https_post()
                                || policy.is_windows_handles()
                                || policy.binding.is_some())
                                && collector.config.server_id != policy.profile.server_id
                            {
                                write_resource_reply(client, host, true,
                                    &withheld(request_id, "invocation", &json!(["resource_server_identity_mismatch"]))).await?;
                                continue;
                            }
                            if policy.is_create_file() || policy.is_https_get() || policy.is_https_post() || policy.is_windows_handles() {
                                if !policy.is_windows_handles() {
                                    // Match run()'s actual operator-selected session root,
                                    // including its cwd fallback when no override exists.
                                    // Handle profiles checked exact spelling without DOS I/O.
                                    let actual_workspace = std::env::var_os("AGENTFW_WORKSPACE")
                                        .map(std::path::PathBuf::from)
                                        .or_else(|| std::env::current_dir().ok())
                                        .and_then(|path| path.canonicalize().ok());
                                    let configured_workspace = policy.workspace.canonicalize().ok();
                                    if !matches!((&configured_workspace, &actual_workspace),
                                        (Some(configured), Some(actual)) if configured == actual)
                                    {
                                        write_resource_reply(client, host, true,
                                            &withheld(request_id, "invocation", &json!(["resource_workspace_mismatch"]))).await?;
                                        continue;
                                    }
                                }
                            } else if let Some(agentfw_ws) = std::env::var_os("AGENTFW_WORKSPACE") {
                                let policy_ws_canon = policy.workspace.canonicalize().ok();
                                let agentfw_ws_canon =
                                    std::path::PathBuf::from(agentfw_ws).canonicalize().ok();
                                let same_workspace = matches!((&policy_ws_canon, &agentfw_ws_canon),
                                    (Some(policy), Some(actual)) if policy == actual);
                                let known_mismatch = policy_ws_canon.is_some()
                                    && agentfw_ws_canon.is_some() && !same_workspace;
                                if known_mismatch {
                                    let reasons = json!(["resource_workspace_mismatch"]);
                                    write_resource_reply(client, host, resource_reply,
                                        &withheld(request_id, "invocation", &reasons)).await?;
                                    continue;
                                }
                            }
                            if (policy.is_create_file() || policy.is_https_get() || policy.is_https_post() || policy.is_windows_handles())
                                && collector.config.classifier.as_ref()
                                    .and_then(|classifier| classifier.revision())
                                    != Some(policy.classifier_sha256.as_str())
                            {
                                write_resource_reply(client, host, true,
                                    &withheld(request_id, "invocation", &json!(["resource_classifier_revision_mismatch"]))).await?;
                                continue;
                            }
                            let snapshot = admitted_snapshot
                                .as_ref()
                                .context("classifier discovery state missing")?;
                            let admitted_tool = snapshot
                                .tools
                                .get(name)
                                .context("admitted tool snapshot missing")?;
                            let source = collector
                                .config
                                .classifier
                                .as_ref()
                                .map(|c| c.source())
                                .unwrap_or("unconfigured");
                            let revision = collector
                                .config
                                .classifier
                                .as_ref()
                                .and_then(|c| c.revision())
                                .map(str::to_owned);
                            let input_sha256 = prediction_identity(
                                &collector.config.server_id,
                                snapshot,
                                admitted_tool,
                                name,
                                &args,
                                source,
                                revision.as_deref(),
                            );
                            let input = Invocation {
                                server_id: policy.profile.server_id.clone(),
                                host_call_id: request_id.clone(),
                                registry_sha256: collector.config.native.registry_sha256.clone(),
                                snapshot_sha256: snapshot.sha256.clone(),
                                schema_sha256: installed.schema_sha256.clone(),
                                tool: name.into(),
                                description: admitted_tool.description.clone(),
                                schema: admitted_tool.schema.clone(),
                                definition: admitted_tool.definition.clone(),
                                server_info: snapshot.server_info.clone(),
                                definition_sha256: admitted_tool.definition_sha256.clone(),
                                input_sha256: input_sha256.clone(),
                                classifier_revision: revision.clone(),
                                args: args.clone(),
                                baseline: installed.action_class,
                            };
                            let context = super::resources::ExecutorContext {
                                os: std::env::consts::OS,
                                workspace: &policy.workspace,
                                cwd: &policy.cwd,
                                fixed_destinations: true,
                            };
                            #[cfg(windows)]
                            let derived = if policy.is_windows_handles() {
                                // Fixed Windows selectors are proven by retained native
                                // handles. Device mappings can change independently;
                                // generic DOS extraction must not reopen these paths.
                                let resources = if policy.is_windows_create() {
                                    let prepared = prepared_create.as_ref()
                                        .context("Windows create parent not pinned before extraction")?;
                                    crate::native::resource::windows_create_evidence(
                                        policy, &args, prepared.identity()).map_err(anyhow::Error::msg)?
                                } else {
                                    let prepared = prepared_windows_read.as_ref()
                                        .context("Windows read metadata not pinned before extraction")?;
                                    crate::native::resource::windows_read_evidence(
                                        policy, &args, prepared.identity()).map_err(anyhow::Error::msg)?
                                };
                                super::resources::Extraction {
                                    server_id: input.server_id.clone(),
                                    tool_name: input.tool.clone(),
                                    schema_sha256: input.schema_sha256.clone(),
                                    args_sha256: crate::native::canonical_digest(&args),
                                    profile_sha256: crate::native::canonical_digest(
                                        &serde_json::to_value(&policy.profile).context("profile serializes")?),
                                    snapshot_sha256: input.snapshot_sha256.clone(),
                                    executor_sha256: policy.executor_sha256.clone(),
                                    resources,
                                    issues: vec![],
                                    omitted_optional: vec![],
                                }
                            } else {
                                super::resources::extract(&input, &policy.profile, &context)
                            };
                            #[cfg(not(windows))]
                            let derived = super::resources::extract(&input, &policy.profile, &context);
                            if !derived.complete() {
                                let reasons = if !derived.issues.is_empty() {
                                    json!(derived
                                        .issues
                                        .iter()
                                        .map(|i| i.reason)
                                        .collect::<Vec<_>>())
                                } else {
                                    json!(["resource_extraction_incomplete"])
                                };
                                write_resource_reply(client, host, resource_reply, &withheld(request_id, "invocation", &reasons)).await?;
                                continue;
                            }
                            let profile_sha256 = crate::native::canonical_digest(
                                &serde_json::to_value(&policy.profile)
                                    .context("profile serializes")?,
                            );
                            let execution = if policy.is_create_file() {
                                #[cfg(windows)]
                                let create_binding = if policy.is_windows_create() {
                                    let prepared = prepared_create.as_ref()
                                        .context("Windows create parent not pinned before binding")?;
                                    crate::native::resource::windows_create_binding_with_identity(
                                        policy, &args, prepared.identity())
                                } else {
                                    crate::native::resource::create_file_binding(policy, &args)
                                };
                                #[cfg(not(windows))]
                                let create_binding = crate::native::resource::create_file_binding(policy, &args);
                                match create_binding {
                                    Ok(binding) => Some(binding),
                                    Err(reason) => {
                                        write_resource_reply(client, host, resource_reply,
                                            &withheld(request_id, "invocation", &json!([reason]))).await?;
                                        continue;
                                    }
                                }
                            } else {
                                None
                            };
                            let admission = crate::native::resource::Admission {
                                server_id: policy.profile.server_id.clone(),
                                host_call_id: request_id.clone(),
                                profile_sha256,
                                executor_sha256: policy.executor_sha256.clone(),
                                classifier_sha256: policy.classifier_sha256.clone(),
                                snapshot_sha256: snapshot.sha256.clone(),
                                definition_sha256: admitted_tool.definition_sha256.clone(),
                                input_sha256,
                                resources: derived.resources.clone(),
                                execution,
                                windows_read: None,
                                network: if policy.is_https_get() {
                                    match crate::native::resource::https_get_binding(policy, &args) {
                                        Ok(binding) => Some(binding),
                                        Err(reason) => {
                                            write_resource_reply(client, host, true,
                                                &withheld(request_id, "invocation", &json!([reason]))).await?;
                                            continue;
                                        }
                                    }
                                } else { None },
                                post: if policy.is_https_post() {
                                    match crate::native::resource::https_post_binding(policy, &args) {
                                        Ok(binding) => Some(binding),
                                        Err(reason) => {
                                            write_resource_reply(client, host, true,
                                                &withheld(request_id, "invocation", &json!([reason]))).await?;
                                            continue;
                                        }
                                    }
                                } else { None },
                            };
                            Some((admission, derived))
                        } else if collector.config.resource_profiles.contains_key(name) {
                            let reasons = json!(["resource_executor_unsupported"]);
                            write_resource_reply(client, host, resource_reply, &withheld(request_id, "invocation", &reasons)).await?;
                            continue;
                        } else {
                            None
                        };
                        let mut prod_assessment: Option<ClassifiedAssessment> = None;
                        let mut approval_id: Option<String> = None;
                        let egress_declared = installed.action_class == ActionClass::Network
                            || !installed.egress.is_empty();
                        let authority = ClassificationAuthority {
                            egress_declared,
                            create_file_profile: installed.resource_policy.as_ref()
                                .filter(|policy| policy.is_create_file()
                                    && resource_admission.as_ref().is_some_and(|(admission, _)| admission.execution.is_some()))
                                .map(|policy| if policy.is_windows_create() {
                                    crate::native::resource::WINDOWS_CREATE_EXECUTOR_PROFILE
                                } else {
                                    crate::native::resource::CREATE_FILE_EXECUTOR_PROFILE
                                }),
                            https_get: installed.resource_policy.as_ref()
                                .is_some_and(|policy| policy.is_https_get()),
                        };
                        if collector.config.classifier.is_some() {
                            let snapshot = admitted_snapshot
                                .as_ref()
                                .context("classifier discovery state missing")?;
                            match without_resource_overlap(
                                client,
                                resource_admission.is_some(),
                                collector.classify(
                                    snapshot,
                                    request_id,
                                    name,
                                    &args,
                                    installed.action_class,
                                    authority,
                                ),
                            )
                            .await?
                            {
                                Err(failure) => {
                                    write_resource_reply(client, host, resource_reply, &not_classified(request_id, failure)).await?;
                                    continue;
                                }
                                Ok(assessment) => {
                                    prod_assessment = Some(assessment);
                                }
                            }
                        }
                        if let Some(assessment) = prod_assessment {
                            match assessment.verdict {
                                ProductionVerdict::Allow => {}
                                ProductionVerdict::Ask => {
                                    let mut reasons = json!(["policy_unconfirmed_ask"]);
                                    let is_resource = resource_reply
                                        || installed.resource_policy.is_some();
                                    // SOU-88: Resource classifier-Ask continuation explicitly excludes
                                    // unknown or ambiguous classification (unknown=true or uncertainty >= 0.8).
                                    if is_resource && assessment.ambiguous_or_unknown {
                                        write_resource_reply(
                                            client,
                                            host,
                                            resource_reply,
                                            &withheld(request_id, "invocation", &json!(["policy_unconfirmed_ask", "classifier_unknown_or_ambiguous"])),
                                        )
                                        .await?;
                                        continue;
                                    }
                                    let can_approve = collector.config.approval.is_some()
                                        && (!resource_reply
                                            || crate::native::resource_approval::is_supported_linux_resource_tool(installed));
                                    if can_approve {
                                        let adm_val = resource_admission
                                            .as_ref()
                                            .and_then(|(adm, _)| serde_json::to_value(adm).ok());
                                        match collector
                                            .obtain_approval(
                                                client,
                                                "classifier",
                                                name,
                                                &args,
                                                &installed.schema_sha256,
                                                adm_val.as_ref(),
                                            )
                                            .await?
                                        {
                                            Err(code) => reasons = json!(["policy_unconfirmed_ask", code]),
                                            Ok(id) => {
                                                // Re-evaluate the classifier using the identical authority context.
                                                let snapshot = admitted_snapshot.as_ref().context("classifier discovery state missing")?;
                                                let again = collector.classify(snapshot, request_id, name, &args, installed.action_class, authority).await?;
                                                match again {
                                                    Ok(again_assessment) => {
                                                        if (is_resource && again_assessment.ambiguous_or_unknown)
                                                            || again_assessment.verdict == ProductionVerdict::Deny
                                                        {
                                                            let _ = collector.cancel_approval(&id).await;
                                                            reasons = json!(["policy_unconfirmed_ask", "native_approval_reclassify_refused"]);
                                                        } else {
                                                            approval_id = Some(id);
                                                        }
                                                    }
                                                    Err(_) => {
                                                        let _ = collector.cancel_approval(&id).await;
                                                        reasons = json!(["policy_unconfirmed_ask", "native_approval_reclassify_refused"]);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    if approval_id.is_none() {
                                        write_resource_reply(client, host, resource_reply, &withheld(request_id, "invocation", &reasons))
                                            .await?;
                                        continue;
                                    }
                                }
                                ProductionVerdict::Deny => {
                                    let reasons = json!(["policy_denied"]);
                                    write_resource_reply(client, host, resource_reply, &withheld(request_id, "invocation", &reasons))
                                        .await?;
                                    continue;
                                }
                            }
                        }
                        #[cfg(windows)]
                        let mut resource_admission = resource_admission;
                        let https_get = installed.resource_policy.as_ref().is_some_and(|policy| policy.is_https_get());
                        let https_post = installed.resource_policy.as_ref().is_some_and(|policy| policy.is_https_post());
                        if (https_get || https_post) && !cfg!(target_os = "linux") {
                            write_resource_reply(client, host, true,
                                &withheld(request_id, "invocation", &json!(["resource_https_platform_unsupported"]))).await?;
                            continue;
                        }
                        #[cfg(unix)]
                        let mut pinned_resource_ws: Option<(
                            crate::sandbox::PinnedWorkspace,
                            std::path::PathBuf,
                        )> = None;
                        #[cfg(not(any(unix, windows)))]
                        if resource_admission.is_some() {
                            let reasons = json!(["resource_executor_unsupported"]);
                            write_resource_reply(client, host, resource_reply, &withheld(request_id, "invocation", &reasons)).await?;
                            continue;
                        }
                        #[cfg(unix)]
                        if let Some((_, ref derived)) = resource_admission.as_ref()
                            .filter(|_| !https_get && !https_post) {
                            let policy = installed.resource_policy.as_ref().unwrap();
                            if policy.is_windows_handles() {
                                let reason = if policy.is_windows_create() {
                                    "resource_windows_create_platform_unsupported"
                                } else {
                                    "resource_windows_read_platform_unsupported"
                                };
                                write_resource_reply(client, host, resource_reply,
                                    &withheld(request_id, "invocation", &json!([reason]))).await?;
                                continue;
                            }
                            let creating = policy.is_create_bound_or_named(name);
                            if creating && !cfg!(target_os = "linux") {
                                let reasons = json!(["resource_create_platform_unsupported"]);
                                write_resource_reply(client, host, resource_reply,
                                    &withheld(request_id, "invocation", &reasons)).await?;
                                continue;
                            }
                            if !((installed.action_class == ActionClass::ReadOnly
                                && policy.is_read_bound_or_named(name))
                                || (installed.action_class == ActionClass::SideEffecting
                                    && creating))
                            {
                                let reasons = json!(["resource_executor_unsupported"]);
                                write_resource_reply(client, host, resource_reply, &withheld(request_id, "invocation", &reasons)).await?;
                                continue;
                            }
                            let first_res = derived.resources.first().map(|r| &r.resource);
                                let Some(super::resources::Resource::Path { canonical }) = first_res
                                else {
                                    let reasons = json!(["resource_destination_invalid"]);
                                    write_resource_reply(client, host, resource_reply, &withheld(request_id, "invocation", &reasons)).await?;
                                    continue;
                                };
                                let pinned = match crate::sandbox::PinnedWorkspace::open(
                                    &policy.workspace,
                                ) {
                                    Ok(ws) => ws,
                                    Err(_) => {
                                        let reasons = json!(["resource_workspace_invalid"]);
                                        write_resource_reply(client, host, resource_reply, &withheld(request_id, "invocation", &reasons))
                                            .await?;
                                        continue;
                                    }
                                };
                                let target_path = std::path::Path::new(canonical);
                                if pinned.relative_path(target_path).is_err() {
                                    let reasons = json!(["resource_target_outside_workspace"]);
                                    write_resource_reply(client, host, resource_reply, &withheld(request_id, "invocation", &reasons)).await?;
                                    continue;
                                }
                                if creating {
                                    #[cfg(target_os = "linux")]
                                    {
                                        let content_ptr = policy.content_selector();
                                        let content = crate::mcp::resources::selected(&args, content_ptr)
                                            .ok()
                                            .flatten()
                                            .and_then(|v| v.as_str())
                                            .context("validated create content missing")?;
                                        match super::create_file::PreparedCreate::prepare(&pinned, target_path, content) {
                                            Ok(prepared) => prepared_create = Some(prepared),
                                            Err(error) => {
                                                write_resource_reply(client, host, resource_reply,
                                                    &withheld(request_id, "invocation", &json!([error.code]))).await?;
                                                continue;
                                            }
                                        }
                                    }
                                } else {
                                    pinned_resource_ws = Some((pinned, target_path.to_path_buf()));
                                }
                            }
                        #[cfg(windows)]
                        if let Some((ref mut admission, ref derived)) = resource_admission.as_mut() {
                            let policy = installed.resource_policy.as_ref().expect("resource policy installed");
                            if !policy.is_windows_handles() {
                                write_resource_reply(client, host, true,
                                    &withheld(request_id, "invocation", &json!(["resource_executor_unsupported"]))).await?;
                                continue;
                            }
                            let Some(super::resources::Resource::Path { .. }) = derived.resources.first().map(|r| &r.resource) else {
                                write_resource_reply(client, host, true,
                                    &withheld(request_id, "invocation", &json!(["resource_destination_invalid"]))).await?;
                                continue;
                            };
                            if policy.is_windows_create() {
                                ensure!(installed.action_class == ActionClass::SideEffecting && policy.profile.tool_name == name,
                                    "Windows create tool semantics changed");
                                let prepared = prepared_create.as_ref().context("Windows create parent not pinned before admission")?;
                                let bound = crate::native::resource::windows_create_binding_with_identity(
                                    policy, &args, prepared.identity()).map_err(anyhow::Error::msg)?;
                                ensure!(admission.execution.as_ref() == Some(&bound), "Windows create binding changed");
                            } else {
                                // Sharing locks pin every ancestor and the leaf without
                                // FILE_READ_DATA; the data open follows native Allow.
                                let prepared = prepared_windows_read.as_ref().context("Windows metadata not pinned before extraction")?;
                                admission.windows_read = Some(crate::native::resource::windows_read_binding_with_identity(
                                    policy, &args, prepared.identity()).map_err(anyhow::Error::msg)?);
                            }
                        }
                        // A composed refusal must not reserve native capacity.
                        // Native trusted restrictions still gate every permitted call.
                        let mut call_fields = json!({
                            "tool": name,
                            "args": args,
                            "schema_sha256": installed.schema_sha256,
                        });
                        let contract_version = if let Some((ref admission, _)) = resource_admission
                        {
                            call_fields["resource_admission"] = serde_json::to_value(admission)?;
                            admission.contract().to_string()
                        } else {
                            CONTRACT.to_string()
                        };
                        if let Some(id) = &approval_id {
                            call_fields["approval_id"] = json!(id);
                        }
                        policy_boundary = collector.policy_boundary().await?;
                        let mut receipt = without_resource_overlap(
                            client,
                            resource_admission.is_some(),
                            collector.event("call", call_fields.clone()),
                        )
                        .await?;
                        let is_resource = resource_reply
                            || installed.resource_policy.is_some();
                        let can_approve_daemon = receipt["release"] != true
                            && receipt["verdict"] == "ask"
                            && approval_id.is_none()
                            && collector.config.approval.is_some()
                            && (!is_resource
                                || (!prod_assessment.as_ref().is_some_and(|a| a.ambiguous_or_unknown)
                                    && crate::native::resource_approval::is_supported_linux_resource_tool(installed)));
                        if can_approve_daemon {
                            drop(policy_boundary.take());
                            let adm_val = resource_admission
                                .as_ref()
                                .and_then(|(adm, _)| serde_json::to_value(adm).ok());
                            match collector
                                .obtain_approval(
                                    client,
                                    "daemon",
                                    name,
                                    &args,
                                    &installed.schema_sha256,
                                    adm_val.as_ref(),
                                )
                                .await?
                            {
                                Err(code) => {
                                    let mut reasons = receipt["reason_codes"].as_array().cloned().unwrap_or_default();
                                    reasons.push(json!(code));
                                    receipt["reason_codes"] = json!(reasons);
                                }
                                Ok(id) => {
                                    // If a classifier is configured, re-evaluate with the same authority context
                                    let mut ok_to_proceed = true;
                                    if collector.config.classifier.is_some() {
                                        let snapshot = admitted_snapshot.as_ref().context("classifier discovery state missing")?;
                                        let again = collector.classify(snapshot, request_id, name, &args, installed.action_class, authority).await?;
                                        match again {
                                            Ok(again_assessment) => {
                                                if (is_resource && again_assessment.ambiguous_or_unknown)
                                                    || again_assessment.verdict == ProductionVerdict::Deny
                                                {
                                                    let _ = collector.cancel_approval(&id).await;
                                                    ok_to_proceed = false;
                                                }
                                            }
                                            Err(_) => {
                                                let _ = collector.cancel_approval(&id).await;
                                                ok_to_proceed = false;
                                            }
                                        }
                                    }
                                    if ok_to_proceed {
                                        call_fields["approval_id"] = json!(id);
                                        policy_boundary = collector.policy_boundary().await?;
                                        receipt = collector.event("call", call_fields.clone()).await?;
                                    } else {
                                        let mut reasons = receipt["reason_codes"].as_array().cloned().unwrap_or_default();
                                        reasons.push(json!("native_approval_reclassify_refused"));
                                        receipt["reason_codes"] = json!(reasons);
                                    }
                                }
                            }
                        }
                        if receipt["release"] != true {
                            write_resource_reply(client, host, resource_reply,
                                &withheld(request_id, "invocation", &receipt["reason_codes"]),
                            )
                            .await?;
                            continue;
                        }
                        if https_get {
                            let policy = installed.resource_policy.as_ref().expect("network policy selected");
                            let bound = resource_admission.as_ref().and_then(|(admission, _)| admission.network.as_ref())
                                .context("network authority missing")?;
                            // Recompute the complete immutable policy/arguments authority
                            // after actual native Allow, immediately before dispatch.
                            ensure!(&crate::native::resource::https_get_binding(policy, &args)
                                .map_err(anyhow::Error::msg)? == bound, "network authority changed before dispatch");
                            let authority = policy.network.as_ref().expect("network profile selected");
                            let original_url = args["url"].as_str().context("validated URL missing")?;
                            let fetched = without_resource_overlap(client, true, async {
                                // Even DNS preparation starts only after real native
                                // Allow. Every preparation failure completes the spent
                                // reservation with an ordinary correlated error result.
                                Ok(match super::https_get::PreparedHttpsGet::prepare(authority, original_url).await {
                                    Ok(prepared) => prepared.execute().await,
                                    Err(error) => Err(error),
                                })
                            }).await?;
                            let (payload, fetched_text, result_kind, request_issued) = match fetched {
                                Ok(result) => (json!({"success":true,"status":result.status,
                                    "content_type":result.content_type,
                                    "received_bytes":result.received_bytes,
                                    "received_http_bytes":result.received_http_bytes,
                                    "received_encrypted_bytes":result.received_encrypted_bytes,
                                    "request_issued":result.request_issued}),
                                    Some(result.text), "value", result.request_issued),
                                Err(error) => (json!({"success":false,"error":error.code,
                                    "request_issued":error.request_issued}),None,"error",error.request_issued),
                            };
                            eprintln!("{}", json!({"event":"mcp_https_get_execution",
                                "host_call_id":request_id,"request_issued":request_issued,
                                "result_kind":result_kind,"received_bytes":payload.get("received_bytes"),
                                "received_http_bytes":payload.get("received_http_bytes"),
                                "received_encrypted_bytes":payload.get("received_encrypted_bytes"),
                                "error":payload.get("error")}));
                            let mut content = vec![json!({"type":"text","text":payload.to_string()})];
                            // Keep untrusted document text as an actual MCP text
                            // block. Nesting it inside a JSON string would escape
                            // line breaks before the native content inspector.
                            if let Some(text) = fetched_text { content.push(json!({"type":"text","text":text})); }
                            let response = json!({"jsonrpc":"2.0","id":request_id,
                                "result":{"isError":result_kind == "error",
                                    "content":content}});
                            let mut raw_response = response.to_string().into_bytes();
                            raw_response.push(b'\n');
                            let result_content = std::str::from_utf8(&raw_response).context("HTTPS result is UTF-8")?;
                            let result_receipt = without_resource_overlap(client, true,
                                collector.event("result", json!({
                                    "expected_contract_version":contract_version,
                                    "tool":name,"args":args,"call_id":receipt["call_id"],
                                    "result_kind":result_kind,"delivery":"mcp_host","content":result_content,
                                    "expected_binding_sha256":receipt["binding_sha256"]
                                }))).await?;
                            if result_receipt["release"] != true {
                                let mut reasons = result_receipt["reason_codes"].as_array().cloned().unwrap_or_default();
                                if request_issued { reasons.push(json!("resource_https_request_may_have_been_issued")); }
                                write_resource_reply(client, host, true,
                                    &withheld(request_id,"result",&json!(reasons))).await?;
                            } else {
                                write_resource_reply(client, host, true, &raw_response).await?;
                            }
                            continue;
                        }
                        if https_post {
                            let policy = installed.resource_policy.as_ref().expect("network policy selected");
                            let bound = resource_admission.as_ref().and_then(|(admission, _)| admission.post.as_ref())
                                .context("network authority missing")?;
                            // Recompute the complete immutable policy/arguments authority
                            // after actual native Allow, immediately before dispatch.
                            ensure!(&crate::native::resource::https_post_binding(policy, &args)
                                .map_err(anyhow::Error::msg)? == bound, "network authority changed before dispatch");
                            let authority = policy.post.as_ref().expect("network profile selected");
                            let original_url = args["url"].as_str().context("validated URL missing")?;
                            let body = args["body"].as_str().context("validated POST body missing")?;
                            let progress = super::https_post::PostProgress::default();
                            let fetched = without_resource_overlap(client, true, async {
                                // Even DNS preparation starts only after real native
                                // Allow. Every preparation failure completes the spent
                                // reservation with an ordinary correlated error result.
                                Ok(match super::https_post::PreparedHttpsPost::prepare(authority, original_url, body).await {
                                    Ok(prepared) => prepared.execute(&progress).await,
                                    Err(error) => Err(error),
                                })
                            }).await;
                            // Always record conservative progress, including cancellation.
                            // A killed process can leave only receiver-side evidence.
                            eprintln!("{}", json!({"event":"mcp_https_post_progress", "host_call_id":request_id,
                                "progress":progress.snapshot(), "execution_interrupted":fetched.is_err()}));
                            let fetched = fetched?;
                            let (payload, fetched_text, result_kind, request_issued) = match fetched {
                                Ok(result) => (json!({"success":true,"status":result.status,
                                    "content_type":result.content_type,
                                    "received_bytes":result.received_bytes,
                                    "received_http_bytes":result.received_http_bytes,
                                    "received_encrypted_bytes":result.received_encrypted_bytes,
                                    "request_issued":result.request_issued}),
                                    Some(result.text), "value", result.request_issued),
                                Err(error) => (json!({"success":false,"error":error.code,
                                    "request_issued":error.request_issued}),None,"error",error.request_issued),
                            };
                            eprintln!("{}", json!({"event":"mcp_https_post_execution",
                                "host_call_id":request_id,"request_issued":request_issued,
                                "result_kind":result_kind,"received_bytes":payload.get("received_bytes"),
                                "received_http_bytes":payload.get("received_http_bytes"),
                                "received_encrypted_bytes":payload.get("received_encrypted_bytes"),
                                "error":payload.get("error")}));
                            let mut content = vec![json!({"type":"text","text":payload.to_string()})];
                            // Keep untrusted document text as an actual MCP text
                            // block. Nesting it inside a JSON string would escape
                            // line breaks before the native content inspector.
                            if let Some(text) = fetched_text { content.push(json!({"type":"text","text":text})); }
                            let response = json!({"jsonrpc":"2.0","id":request_id,
                                "result":{"isError":result_kind == "error",
                                    "content":content}});
                            let mut raw_response = response.to_string().into_bytes();
                            raw_response.push(b'\n');
                            let result_content = std::str::from_utf8(&raw_response).context("HTTPS result is UTF-8")?;
                            let result_receipt = without_resource_overlap(client, true,
                                collector.event("result", json!({
                                    "expected_contract_version":contract_version,
                                    "tool":name,"args":args,"call_id":receipt["call_id"],
                                    "result_kind":result_kind,"delivery":"mcp_host","content":result_content,
                                    "expected_binding_sha256":receipt["binding_sha256"]
                                }))).await?;
                            eprintln!("{}", json!({"event":"mcp_https_post_result_gate", "host_call_id":request_id,
                                "release_authorized":result_receipt["release"], "progress":progress.snapshot()}));
                            if result_receipt["release"] != true {
                                let mut reasons = result_receipt["reason_codes"].as_array().cloned().unwrap_or_default();
                                if request_issued { reasons.push(json!("resource_https_request_may_have_been_issued")); }
                                write_resource_reply(client, host, true,
                                    &withheld(request_id,"result",&json!(reasons))).await?;
                            } else {
                                write_resource_reply(client, host, true, &raw_response).await?;
                            }
                            continue;
                        }
                        #[cfg(any(target_os = "linux", windows))]
                        if let Some(prepared) = prepared_create {
                            let policy = installed.resource_policy.as_ref().expect("create policy selected");
                            #[cfg(windows)]
                            {
                                let bound = resource_admission.as_ref().and_then(|(admission, _)| admission.execution.as_ref())
                                    .context("Windows create authority missing")?;
                                ensure!(&crate::native::resource::windows_create_binding_with_identity(
                                    policy, &args, prepared.identity()).map_err(anyhow::Error::msg)? == bound,
                                    "Windows create authority changed before staging");
                            }
                            let path_ptr = policy.path_selector();
                            let content_ptr = policy.content_selector();
                            let path_str = crate::mcp::resources::selected(&args, path_ptr)
                                .ok()
                                .flatten()
                                .and_then(|v| v.as_str())
                                .or_else(|| args["path"].as_str());
                            let content_str = crate::mcp::resources::selected(&args, content_ptr)
                                .ok()
                                .flatten()
                                .and_then(|v| v.as_str())
                                .or_else(|| args["content"].as_str())
                                .unwrap_or("");
                            // Only staging runs on the blocking worker. If unsupported
                            // cancellation/overlap wins, a detached worker cannot publish:
                            // dropping its returned owner cleans only its own stage.
                            let staging = tokio::task::spawn_blocking(move || prepared.stage());
                            let staged = without_resource_overlap(client, true, async {
                                staging.await.context("create staging worker failed")
                            }).await?;
                            let creation = match staged {
                                Ok(staged) => without_resource_overlap(client, true, async {
                                    // The syscall can complete immediately before process
                                    // interruption. Record intent first; absent a completion,
                                    // publication is indeterminate, never evidence of no write.
                                    eprintln!("{}", json!({"event":"mcp_create_file_publication_intent",
                                        "host_call_id":request_id,"publication_attempted":true,
                                        "staged_bytes":content_str.len(),
                                        "outcome":"indeterminate_until_completion"}));
                                    Ok(staged.publish())
                                }).await?,
                                Err(error) => Err(error),
                            };
                            let (payload, committed, result_kind) = match creation {
                                Ok(commit) => (json!({
                                    "success": true, "created": true, "committed": commit.committed,
                                    "path": path_str.map(Value::from).unwrap_or_else(|| args["path"].clone()),
                                    "bytes_written": commit.bytes_written,
                                    "content_sha256": sha(content_str.as_bytes()),
                                    "file_synced": commit.file_synced,
                                    "directory_synced": commit.directory_synced
                                }), commit.committed, "value"),
                                Err(error) => (json!({
                                    "success": false, "created": error.committed, "committed": error.committed,
                                    "error": error.code, "staged_bytes": error.staged_bytes,
                                    "committed_bytes": error.committed_bytes
                                }), error.committed, "error"),
                            };
                            // A failed fsync or denied result cannot roll back a published file.
                            eprintln!("{}", json!({"event":"mcp_create_file_execution",
                                "host_call_id":request_id,"committed":committed,
                                "result_kind":result_kind,
                                "committed_bytes":payload.get("bytes_written").or_else(|| payload.get("committed_bytes")),
                                "staged_bytes":payload.get("staged_bytes"),
                                "error":payload.get("error")}));
                            let response = json!({"jsonrpc":"2.0","id":request_id,
                                "result":{"isError":result_kind == "error",
                                    "content":[{"type":"text","text":payload.to_string()}]}});
                            let mut raw_response = response.to_string().into_bytes();
                            raw_response.push(b'\n');
                            let result_content = std::str::from_utf8(&raw_response)
                                .context("create receipt is UTF-8")?;
                            let res_receipt = without_resource_overlap(client, true,
                                collector.event("result", json!({
                                    "expected_contract_version":contract_version,
                                    "tool":name,"args":args,"call_id":receipt["call_id"],
                                    "result_kind":result_kind,"delivery":"mcp_host",
                                    "content":result_content,
                                    "expected_binding_sha256":receipt["binding_sha256"]
                                }))).await?;
                            if res_receipt["release"] != true {
                                let mut reasons = res_receipt["reason_codes"].as_array()
                                    .cloned().unwrap_or_default();
                                if committed { reasons.push(json!("resource_creation_committed")); }
                                write_resource_reply(client, host, true,
                                    &withheld(request_id,"result",&json!(reasons))).await?;
                            } else {
                                write_resource_reply(client, host, true, &raw_response).await?;
                            }
                            continue;
                        }
                        if resource_admission.is_some() {
                            #[cfg(any(unix, windows))]
                            {
                                #[cfg(unix)]
                                let (pinned, target_path) = pinned_resource_ws
                                    .expect("pinned workspace initialized on unix");
                                #[cfg(unix)]
                                let read = without_resource_overlap(client, true, async {
                                    Ok(pinned.read_file(&target_path))
                                })
                                .await?;
                                #[cfg(windows)]
                                let read = {
                                    let prepared = prepared_windows_read.take().expect("Windows read prepared before admission");
                                    let policy = installed.resource_policy.as_ref().expect("Windows read policy installed");
                                    let bound = resource_admission.as_ref().and_then(|(admission, _)| admission.windows_read.as_ref())
                                        .context("Windows read authority missing")?;
                                    let same = crate::native::resource::windows_read_binding_with_identity(policy, &args, prepared.identity())
                                        .map_err(anyhow::Error::msg)? == *bound;
                                    without_resource_overlap(client, true, async {
                                        if !same { return Ok(Err(anyhow::anyhow!("Windows read authority changed"))); }
                                        Ok(prepared.read_bounded(crate::native::resource::WINDOWS_READ_MAX_CONTENT).await)
                                    }).await?
                                };
                                let content = match read {
                                    Ok(c) => c,
                                    Err(err) => {
                                        let err_msg = err.to_string();
                                        let reasons = if err_msg.contains("outside the workspace")
                                            || err_msg.contains("path traversal")
                                        {
                                            json!(["resource_target_outside_workspace"])
                                        } else {
                                            json!(["resource_read_failed"])
                                        };
                                        let withheld_bytes =
                                            withheld(request_id, "invocation", &reasons);
                                        let withheld_content = std::str::from_utf8(&withheld_bytes)
                                            .context("withheld is UTF-8")?;
                                        without_resource_overlap(client, true, async {
                                            let _ = collector
                                                .event(
                                                    "result",
                                                    json!({
                                                        "expected_contract_version": contract_version,
                                                        "tool": name,
                                                        "args": args,
                                                        "call_id": receipt["call_id"],
                                                        "result_kind": "error",
                                                        "delivery": "mcp_host",
                                                        "content": withheld_content,
                                                        "expected_binding_sha256": receipt["binding_sha256"]
                                                    }),
                                                )
                                                .await;
                                            Ok(())
                                        })
                                        .await?;
                                        write_resource_reply(client, host, resource_reply, &withheld_bytes).await?;
                                        continue;
                                    }
                                };
                                let result_envelope = json!({
                                    "content": [{
                                        "type": "text",
                                        "text": content
                                    }]
                                });
                                let response = json!({
                                    "jsonrpc": "2.0",
                                    "id": request_id,
                                    "result": result_envelope
                                });
                                let mut raw_response = response.to_string().into_bytes();
                                raw_response.push(b'\n');
                                let result_content = std::str::from_utf8(&raw_response)
                                    .context("result is UTF-8")?;
                                let res_receipt = without_resource_overlap(
                                    client,
                                    true,
                                    collector.event(
                                        "result",
                                        json!({
                                            "expected_contract_version": contract_version,
                                            "tool": name,
                                            "args": args,
                                            "call_id": receipt["call_id"],
                                            "result_kind": "value",
                                            "delivery": "mcp_host",
                                            "content": result_content,
                                            "expected_binding_sha256": receipt["binding_sha256"]
                                        }),
                                    ),
                                )
                                .await?;
                                if res_receipt["release"] != true {
                                    write_resource_reply(client, host, resource_reply,
                                        &withheld(
                                            request_id,
                                            "result",
                                            &res_receipt["reason_codes"],
                                        ),
                                    )
                                    .await?;
                                    continue;
                                }
                                write_resource_reply(client, host, resource_reply, &raw_response).await?;
                                continue;
                            }
                            #[cfg(not(any(unix, windows)))]
                            {
                                unreachable!("unsupported platforms are refused before reserving call");
                            }
                        }
                        Pending::Call {
                            id: request_id.clone(),
                            tool: name.into(),
                            args,
                            call_id: receipt["call_id"].clone(),
                            binding: receipt["binding_sha256"].clone(),
                            contract_version,
                        }
                    }
                    _ => bail!("unsupported MCP method"),
                };
                pending = Some(next);
                deadline = tokio::time::Instant::now() + IO_TIMEOUT;
                write(child, &raw).await?;
                drop(policy_boundary);
            }
            raw = line(server, &mut server_partial) => {
                let raw = raw?.context("MCP server closed before client completion")?;
                let value = parse(&raw)?;
                if value["method"] == "notifications/tools/list_changed" {
                    keys(&value, &["jsonrpc", "method", "params"])?;
                    ensure!(initialized && list_changed_supported && pending.is_none(), "unsupported MCP definition change timing");
                    if let Some(params) = value.get("params") { keys(params, &[])?; }
                    ready = false;
                    schemas.clear();
                    admitted_snapshot = None;
                    write(host, &raw).await?;
                    continue;
                }
                keys(&value, &["jsonrpc","id","result","error"])?;
                let request = pending.take().context("unbound or replayed MCP server response")?;
                ensure!(value.get("id") == Some(request.id()), "MCP response id mismatch");
                let mut policy_boundary = None;
                match request {
                    Pending::Handshake(_) => {
                        ensure!(value.get("error").is_none() && value["result"].is_object(), "MCP initialization failed");
                        initialization(&value["result"])?;
                        server_info = value["result"]["serverInfo"].clone();
                        list_changed_supported = value["result"]["capabilities"]["tools"]["listChanged"] == true;
                        initialized = true;
                    }
                    Pending::Manifest(_) => {
                        ensure!(value.get("error").is_none(), "MCP tools/list failed");
                        let (validated_schemas, snapshot) = manifest(&value["result"], &collector.config.native, &server_info)?;
                        collector.inspect_manifest(&value["result"]).await?;
                        schemas = validated_schemas;
                        admitted_snapshot = Some(snapshot);
                        ready = true;
                    }
                    Pending::Ping(_) => { ensure!(value.get("error").is_none(), "MCP ping failed"); keys(&value["result"], &[])?; }
                    Pending::Call { id, tool, args, call_id, binding, contract_version } => {
                        policy_boundary = collector.policy_boundary().await?;
                        let kind = result_kind(&value)?;
                        let content = std::str::from_utf8(&raw).context("MCP result is not UTF-8")?;
                        let receipt = collector.event("result", json!({"expected_contract_version":contract_version,"tool":tool,"args":args,"call_id":call_id,"result_kind":kind,"delivery":"mcp_host","content":content,"expected_binding_sha256":binding})).await?;
                        if receipt["release"] != true {
                            write(host, &withheld(&id, "result", &receipt["reason_codes"])).await?;
                            continue;
                        }
                    }
                }
                write(host, &raw).await?;
                drop(policy_boundary);
            }
            _ = tokio::time::sleep_until(deadline), if pending.is_some() => bail!("MCP server response timed out"),
        }
    }
}

/// Stop host output on diagnostic failure or collector lease uncertainty.
/// Check at each write/flush poll, including when a blocked host becomes writable
/// before the outer monitor's next tick. Earlier committed bytes cannot be retracted.
struct DiagnosticOutput<W> {
    inner: W,
    failed: Arc<AtomicBool>,
    budget: Option<super::windows_budget::Guard>,
    liveness: Option<Arc<crate::native::liveness::CollectorLivenessClient>>,
}

impl<W> DiagnosticOutput<W> {
    fn boundary_error(&self) -> Option<std::io::Error> {
        let code = if self.failed.load(Ordering::Acquire) {
            "native MCP diagnostics boundary closed"
        } else if self
            .liveness
            .as_ref()
            .is_some_and(|lease| lease.is_uncertain())
        {
            "native_liveness_uncertain"
        } else {
            return None;
        };
        Some(std::io::Error::new(std::io::ErrorKind::BrokenPipe, code))
    }

    fn guarded_io<T>(
        &mut self,
        output: impl FnOnce(&mut W) -> Poll<std::io::Result<T>>,
    ) -> Poll<std::io::Result<T>> {
        if let Some(error) = self.boundary_error() {
            return Poll::Ready(Err(error));
        }
        if let Some(guard) = &self.budget {
            match guard.with_output(|| output(&mut self.inner)) {
                Ok(result) => result,
                Err(reason) => Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    reason,
                ))),
            }
        } else {
            output(&mut self.inner)
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for DiagnosticOutput<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.get_mut()
            .guarded_io(|inner| Pin::new(inner).poll_write(cx, bytes))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        self.get_mut()
            .guarded_io(|inner| Pin::new(inner).poll_flush(cx))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        self.get_mut()
            .guarded_io(|inner| Pin::new(inner).poll_shutdown(cx))
    }
}

pub async fn run(config: AdmissionCfg) -> anyhow::Result<()> {
    let mut collector = Collector::new(&config)?;
    let env_liveness_flag = std::env::var("AGENTFW_NATIVE_LIVENESS").ok().map(|v| {
        let v = v.trim().to_ascii_lowercase();
        v != "0" && v != "false" && v != "no" && v != "off"
    });
    let env_lease_seconds = std::env::var("AGENTFW_NATIVE_LIVENESS_LEASE_SECONDS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok());
    let liveness_opt_in = config.liveness_url.is_some()
        && (env_liveness_flag.unwrap_or(false)
            || config.liveness_lease_seconds.is_some()
            || env_lease_seconds.is_some());

    let mut start_fields = json!({});
    if let (Some(host_session), Some(child_authority)) =
        (&collector.host_session, &collector.child_authority)
    {
        start_fields["host_session"] = json!(host_session);
        start_fields["child_authority"] = json!(child_authority);
        start_fields["server_id"] = json!(collector.config.server_id);
    }
    if liveness_opt_in {
        start_fields["liveness"] = json!(crate::native::liveness::LIVENESS_CONTRACT);
    }
    let start_reply = collector.event("session_start", start_fields).await?;

    let (renewal_stop_tx, liveness_task) = if liveness_opt_in {
        let daemon_instance_id =
            if let Some(id) = start_reply.get("instance_id").and_then(|v| v.as_str()) {
                id.to_string()
            } else {
                collector.fetch_daemon_instance_id().await?
            };
        let owner_token = start_reply
            .get("owner_token")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let client = Arc::new(crate::native::liveness::CollectorLivenessClient::new(
            collector.client.clone(),
            config.liveness_endpoint(),
            collector.config.native.token.clone(),
            collector.config.native.registry_sha256.clone(),
            collector.session.clone(),
            daemon_instance_id,
            owner_token,
        ));
        let requested_lease = config.liveness_lease_seconds.or(env_lease_seconds);
        if let Err(enroll_err) = client.enroll(requested_lease).await {
            // Never close by physical ID alone: a failed old enrollment may
            // already have been replaced by a fresh collector owner.
            let _ = client.retire().await;
            return Err(enroll_err);
        }
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let task = client.clone().spawn_renewal_task(stop_rx);
        collector.liveness = Some(client);
        (Some(stop_tx), Some(task))
    } else {
        (None, None)
    };
    // Fail closed before spawning the server if the native daemon cannot admit a session.
    let operation = async {
        let cwd = std::env::current_dir()?;
        let workspace = std::env::var_os("AGENTFW_WORKSPACE")
            .map(std::path::PathBuf::from)
            .unwrap_or(cwd);
        if let Some(profile) = super::server_profile::ProfileConfig::load_from_env()? {
            ensure!(std::env::var_os(super::windows_budget::ENVIRONMENT).is_none(),
                "Windows MCP resource budgets do not enable original-server sandbox profiles");
            return real_server::run(&collector, &profile, &workspace).await;
        }
        ensure!(
            std::env::var_os(super::linux_budget::ENVIRONMENT).is_none(),
            "Linux MCP resource budgets require a selected filesystem or Git server profile"
        );
        #[cfg(windows)]
        let windows_spawn_pins = {
            let normal = |path: &std::path::Path| {
                path.to_str()
                    .map(|text| text.strip_prefix("\\\\?\\").unwrap_or(text).to_owned())
            };
            let mut read_pins = Vec::new();
            let mut create_pins = Vec::new();
            for policy in config.native.registry.tools.iter().filter_map(|tool| {
                tool.resource_policy
                    .as_ref()
                    .filter(|policy| policy.is_windows_handles())
            }) {
                // Compare names before any ordinary path API can resolve a
                // distinct environment-selected junction or mapped drive.
                ensure!(
                    normal(&workspace).is_some() && normal(&workspace) == normal(&policy.workspace),
                    "MCP Windows startup workspace mismatch"
                );
                if policy.is_windows_create() {
                    create_pins.push(
                        crate::windows_read::CreateParent::prepare_workspace(
                            &policy.workspace,
                            &policy.cwd,
                        )
                        .map_err(|_| {
                            anyhow::anyhow!("MCP Windows create startup metadata refused")
                        })?,
                    );
                    continue;
                }
                let [super::resources::Resource::Path { canonical }] =
                    policy.allowed_resources.as_slice()
                else {
                    bail!("MCP Windows read startup authority invalid");
                };
                let original = canonical.strip_prefix("\\\\?\\").unwrap_or(canonical);
                read_pins.push(
                    crate::windows_read::PreparedRead::prepare(
                        &policy.workspace,
                        &policy.cwd,
                        original,
                        canonical,
                    )
                    .map_err(|_| anyhow::anyhow!("MCP Windows read startup metadata refused"))?,
                );
            }
            (read_pins, create_pins)
        };
        #[cfg(unix)]
        let mut client =
            BufReader::new(super::stdio::Pipe::stdin().context("unsupported MCP stdin")?);
        #[cfg(unix)]
        let host = super::stdio::Pipe::stdout().context("unsupported MCP stdout")?;
        #[cfg(not(unix))]
        let mut client = BufReader::new(tokio::io::stdin());
        #[cfg(not(unix))]
        let host = tokio::io::stdout();
        // A working directory is operational context, never a sandbox assertion.
        // The child owns only piped diagnostics. Raw server stderr is never a
        // host stream, an audit field or a temporary log.
        let mut command = Command::new(&config.command);
        command
            .args(&config.args)
            .current_dir(&workspace)
            .env_remove("AGENTFW_TOKEN")
            .env_remove("AGENTFW_NATIVE_TOKEN")
            .env_remove("AGENTFW_CHILD_AUTHORITY")
            .env_remove("AGENTFW_HOST_SESSION")
            .env_remove("AGENTFW_TEST_CLASSIFIER_READ")
            .env_remove("AGENTFW_TEST_CLASSIFIER")
            .env_remove(super::windows_budget::ENVIRONMENT)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut process = super::native_child::OwnedChild::spawn(&mut command).await?;
        // The startup pins protect current_dir resolution only. Per-call
        // metadata pins are acquired independently before resource extraction.
        #[cfg(windows)]
        drop(windows_spawn_pins);
        let server_pid = process.child_mut().id();
        let ownership = process.ownership();
        let budget = process.budget_guard();
        let mut stderr_drain = None;
        // Every pipe extraction and relay error still reaches owned cleanup.
        let operation = async {
            let stderr = process
                .child_mut()
                .stderr
                .take()
                .context("native_mcp_stderr_missing")?;
            let drain = super::native_child::Drain::start(stderr);
            let failed = drain.failure_flag();
            stderr_drain = Some(drain);
            eprintln!(
                "{}",
                json!({"event":"mcp_native_server_start","diagnostics":"sw-mcp/native-stderr/1",
                    "server_pid":server_pid,"ownership":ownership,
                    "stderr_chunk_bytes":super::native_child::STDERR_CHUNK_BYTES,
                    "stderr_byte_limit":super::native_child::STDERR_BYTE_LIMIT,
                    "stderr_read_limit":super::native_child::STDERR_READ_LIMIT,
                    "stderr_lifetime_ms":super::native_child::STDERR_LIFETIME.as_millis(),
                    "shutdown_grace_ms":super::native_child::CHILD_GRACE.as_millis(),
                    "shutdown_reap_ms":super::native_child::CHILD_REAP.as_millis(),
                    "shutdown_drain_ms":super::native_child::DRAIN_SHUTDOWN.as_millis()})
            );
            let mut child = process
                .child_mut()
                .stdin
                .take()
                .context("MCP server stdin unavailable")?;
            let mut server = BufReader::new(
                process
                    .child_mut()
                    .stdout
                    .take()
                    .context("MCP server stdout unavailable")?,
            );
            let mut host = DiagnosticOutput {
                inner: host,
                failed,
                budget: budget.clone(),
                liveness: collector.liveness.clone(),
            };
            let result = {
                let exchange = relay(&collector, &mut client, &mut host, &mut server, &mut child);
                tokio::pin!(exchange);
                let mut diagnostics_eof = false;
                loop {
                    tokio::select! {
                        // Once diagnostic uncertainty is observed, a pending
                        // relay cannot win over that failure on the next poll.
                        biased;
                        _ = async {
                            if let Some(guard) = &budget {
                                loop {
                                    if guard.check().is_err() { return; }
                                    tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                                }
                            } else { std::future::pending::<()>().await; }
                        } => break Err(anyhow::anyhow!("windows_budget_terminal")),
                        _ = async {
                            if let Some(liveness) = &collector.liveness {
                                loop {
                                    if liveness.is_uncertain() {
                                        return;
                                    }
                                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                                }
                            } else {
                                std::future::pending::<()>().await;
                            }
                        } => break Err(anyhow::anyhow!("native_liveness_uncertain")),
                        report = stderr_drain.as_mut().expect("owned stderr reader").wait(), if !diagnostics_eof => {
                            if report.is_failure() {
                                break Err(anyhow::anyhow!(report.code()));
                            }
                            // EOF is normal; closing stderr does not disable
                            // useful protocol work or recreate a drain task.
                            diagnostics_eof = true;
                        }
                        _ = tokio::signal::ctrl_c() => {
                            break Err(anyhow::anyhow!("native_mcp_interrupted"));
                        }
                        result = &mut exchange => break result,
                    }
                }
            };
            drop(child);
            drop(server);
            result
        }.await;
        // Capture terminal pressure even when normal relay EOF wins the race.
        let operation = operation.and_then(|()| {
            if let Some(guard) = &budget { guard.check().map_err(anyhow::Error::msg)?; }
            Ok(())
        });
        let clean_exit_required = config.native.registry.tools.iter().any(|tool| {
            tool.resource_policy.as_ref().is_some_and(|policy| {
                policy.is_create_file() || policy.is_https_get() || policy.is_https_post() || policy.is_windows_handles()
            })
        });
        // Windows handle profiles finalize their independent refusal ledgers
        // after EOF even when the relay refused an operation. Preserve that
        // accepted bounded grace; no result forwarding resumes during cleanup.
        let windows_handles_profile = config.native.registry.tools.iter().any(|tool| {
            tool.resource_policy.as_ref().is_some_and(|policy| policy.is_windows_handles())
        });
        let cleanup = process.cleanup(operation.is_ok() || windows_handles_profile).await;
        let operation = operation.and_then(|()| {
            if let Some(guard) = &budget { guard.check().map_err(anyhow::Error::msg)?; }
            Ok(())
        });
        if let Some(report) = process.budget_report() {
            eprintln!("{}",json!({"event":"mcp_windows_budget_end","budget":report,
                "cleanup_verified":cleanup.cleaned&&cleanup.reaped,"effects_rolled_back":false}));
        }
        let stderr_report = match stderr_drain {
            Some(drain) => Some(drain.finish().await),
            None => None,
        };
        let stderr_cleanup_verified = stderr_report
            .as_ref()
            .is_some_and(|report| report.cleanup_verified());
        let stderr_failed = stderr_report.as_ref().is_none_or(|report| report.is_failure());
        if let Some(report) = &stderr_report {
            eprintln!(
                "{}",
                json!({"event":"mcp_native_stderr","outcome":report.code(),
                    "received_bytes":report.received_bytes,"read_chunks":report.read_chunks,
                    "released":false})
            );
        }
        let clean_exit = !clean_exit_required || cleanup.exit_success;
        let reason = if stderr_failed {
            stderr_report.as_ref().map_or("native_mcp_stderr_missing", |report| report.code())
        } else if !cleanup.cleaned || !cleanup.reaped {
            cleanup.failure.unwrap_or("native_mcp_child_cleanup_unverified")
        } else if !clean_exit {
            "native_mcp_profile_exit_failed"
        } else if operation.is_err() {
            "native_mcp_transport_failed"
        } else {
            "native_mcp_transport_complete"
        };
        eprintln!(
            "{}",
            json!({"event":"mcp_native_server_end","server_pid":server_pid,"ownership":cleanup.ownership,
                "process_cleanup_verified":cleanup.cleaned&&cleanup.reaped,
                "stderr_cleanup_verified":stderr_cleanup_verified,
                "graceful_observed":cleanup.graceful_observed,"child_exit_success":cleanup.exit_success,
                "transport_complete":operation.is_ok()&&!stderr_failed&&cleanup.cleaned&&cleanup.reaped&&clean_exit,
                "reason":reason})
        );
        operation?;
        if stderr_failed {
            bail!("{reason}");
        }
        ensure!(cleanup.cleaned && cleanup.reaped, "native_mcp_child_cleanup_unverified");
        ensure!(stderr_cleanup_verified, "native_mcp_stderr_cleanup_unverified");
        ensure!(clean_exit, "MCP create-profile server did not close cleanly");
        Ok(())
    }
    .await;
    if let Some(stop_tx) = renewal_stop_tx {
        let _ = stop_tx.send(true);
        if let Some(liveness) = &collector.liveness {
            let _ = liveness.retire().await;
        }
        if let Some(task) = liveness_task {
            let _ = task.await;
        }
    } else {
        let ended = collector.event("session_end", json!({})).await;
        ended?;
    }
    operation?;
    Ok(())
}

#[cfg(test)]
mod input_identity_tests {
    use super::*;

    fn discovered(description: &str) -> (NativeState, Value, Value) {
        let schema: Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/mcp_inputs/nested_schema.json"
        ))
        .unwrap();
        let registry = json!({"contract_version":CONTRACT,"registry_id":"sou11-fixture","tools":[
            {"name":"inventory_lookup","schema_sha256":sha(canonical(&schema).to_string().as_bytes()),
                "action_class":"read_only","result_provenance":"untrusted","egress":[]}]});
        let bytes = registry.to_string().into_bytes();
        let native =
            NativeState::from_bytes(&bytes, &sha(&bytes), "fixture-token-1234567890".into())
                .unwrap();
        let result = json!({"tools":[{"name":"inventory_lookup","description":description,
            "inputSchema":schema,"annotations":{"title":"Synthetic","readOnlyHint":true}}]});
        (native, result, json!({"name":"fixture","version":"1"}))
    }

    #[test]
    fn original_discovery_schema_and_annotations_are_retained() {
        let (native, result, info) = discovered("fixture description");
        let (_, snapshot) = manifest(&result, &native, &info).unwrap();
        let tool = &snapshot.tools["inventory_lookup"];
        assert_eq!(tool.definition, result["tools"][0]);
        assert_eq!(tool.schema, result["tools"][0]["inputSchema"]);
        assert_eq!(snapshot.server_info, info);
        assert_eq!(tool.description, "fixture description");
        let mut invocation = Invocation {
            server_id: "selected-local-server".into(),
            host_call_id: json!("original-id"),
            registry_sha256: "trusted-registry".into(),
            snapshot_sha256: snapshot.sha256.clone(),
            schema_sha256: tool.schema_sha256.clone(),
            tool: "inventory_lookup".into(),
            description: tool.description.clone(),
            schema: tool.schema.clone(),
            definition: tool.definition.clone(),
            server_info: info,
            definition_sha256: tool.definition_sha256.clone(),
            input_sha256: "input".into(),
            classifier_revision: Some("revision".into()),
            args: json!({"query":{"names":[],"limit":1}}),
            baseline: ActionClass::ReadOnly,
        };
        let semantic = invocation.semantic_input();
        assert_eq!(semantic["raw_arguments"], invocation.args);
        assert_eq!(
            semantic,
            json!({"tool_name":"inventory_lookup","raw_arguments":invocation.args,
            "tool_description":tool.description,"tool_schema":tool.schema,"server_id":"selected-local-server"})
        );
        invocation.host_call_id = json!("different-id");
        invocation.registry_sha256 = "different-registry".into();
        invocation.baseline = ActionClass::Destructive;
        assert_eq!(
            semantic,
            invocation.semantic_input(),
            "correlation and permissions are not semantic inputs"
        );
        assert_eq!(
            tool.definition_sha256,
            sha(canonical(&result["tools"][0]).to_string().as_bytes())
        );
    }

    #[test]
    fn prediction_identity_binds_server_arguments_metadata_and_classifier_revision() {
        let (native, result, info) = discovered("first");
        let (_, snapshot) = manifest(&result, &native, &info).unwrap();
        let args = json!({"query":{"names":["alpha"],"limit":1}});
        let identity =
            |server: &str, snap: &Snapshot, args: &Value, source: &str, rev: Option<&str>| {
                prediction_identity(
                    server,
                    snap,
                    &snap.tools["inventory_lookup"],
                    "inventory_lookup",
                    args,
                    source,
                    rev,
                )
            };
        let original = identity(
            "operator-selected",
            &snapshot,
            &args,
            "classifier",
            Some("rev1"),
        );
        assert_eq!(
            original,
            identity(
                "operator-selected",
                &snapshot,
                &args,
                "classifier",
                Some("rev1")
            )
        );
        for changed in [
            identity(
                "different-server",
                &snapshot,
                &args,
                "classifier",
                Some("rev1"),
            ),
            identity(
                "operator-selected",
                &snapshot,
                &json!({}),
                "classifier",
                Some("rev1"),
            ),
            identity(
                "operator-selected",
                &snapshot,
                &args,
                "classifier",
                Some("rev2"),
            ),
            identity(
                "operator-selected",
                &snapshot,
                &args,
                "other-classifier",
                Some("rev1"),
            ),
            identity("operator-selected", &snapshot, &args, "classifier", None),
        ] {
            assert_ne!(original, changed);
        }
        let mut updated = result.clone();
        updated["tools"][0]["annotations"]["readOnlyHint"] = json!(false);
        let (_, metadata_changed) = manifest(&updated, &native, &info).unwrap();
        assert_ne!(
            original,
            identity(
                "operator-selected",
                &metadata_changed,
                &args,
                "classifier",
                Some("rev1")
            )
        );
        let (_, server_changed) =
            manifest(&result, &native, &json!({"name":"fixture","version":"2"})).unwrap();
        assert_ne!(
            original,
            identity(
                "operator-selected",
                &server_changed,
                &args,
                "classifier",
                Some("rev1")
            )
        );
    }

    #[test]
    fn changed_schema_tool_list_and_unsupported_annotations_require_readmission() {
        let (native, result, info) = discovered("first");
        let mut changed = result.clone();
        changed["tools"][0]["inputSchema"]["properties"]["new"] = json!({"type":"string"});
        assert!(manifest(&changed, &native, &info).is_err());
        changed = result.clone();
        changed["tools"] = json!([]);
        assert!(manifest(&changed, &native, &info).is_err());
        changed = result;
        changed["tools"][0]["annotations"]["customPermission"] = json!("allow");
        assert!(manifest(&changed, &native, &info).is_err());
    }

    #[test]
    fn sou56_https_profile_requires_exact_read_prediction_and_retains_hard_denials() {
        let prediction = |actions: &[&str], unknown, uncertainty| Classification {
            actions: actions.iter().map(|action| (*action).to_owned()).collect(),
            unknown,
            confidence: 0.95,
            uncertainty,
            reason: "bounded HTTPS scope regression".into(),
        };
        assert_eq!(
            compose_https_get_policy(
                &prediction(&["read"], false, 0.1),
                ActionClass::Network,
                true
            ),
            Ok(ProductionVerdict::Allow)
        );
        for actions in [&[][..], &["send_data"], &["read", "send_data"], &["write"]] {
            assert_eq!(
                compose_https_get_policy(
                    &prediction(actions, false, 0.1),
                    ActionClass::Network,
                    true
                ),
                Ok(ProductionVerdict::Ask)
            );
        }
        for actions in [&["delete"][..], &["read", "change_permissions"]] {
            assert_eq!(
                compose_https_get_policy(
                    &prediction(actions, false, 0.1),
                    ActionClass::Network,
                    true
                ),
                Ok(ProductionVerdict::Deny)
            );
        }
        assert_eq!(
            compose_https_get_policy(
                &prediction(&["read"], true, 0.1),
                ActionClass::Network,
                true
            ),
            Ok(ProductionVerdict::Ask)
        );
        assert_eq!(
            compose_https_get_policy(
                &prediction(&["read"], false, 0.9),
                ActionClass::Network,
                true
            ),
            Ok(ProductionVerdict::Ask)
        );
        assert_eq!(
            compose_https_get_policy(
                &prediction(&["read"], false, 0.1),
                ActionClass::ReadOnly,
                true
            ),
            Ok(ProductionVerdict::Ask)
        );
        assert_eq!(
            compose_https_get_policy(
                &prediction(&["read"], false, f64::NAN),
                ActionClass::Network,
                true
            ),
            Err("classifier_invalid")
        );
    }

    #[test]
    fn sou54_write_authority_preserves_hard_denials_and_unknown_refusal() {
        let prediction = |actions: &[&str], unknown, uncertainty| Classification {
            actions: actions.iter().map(|value| (*value).to_owned()).collect(),
            unknown,
            confidence: 0.95,
            uncertainty,
            reason: "bounded policy regression".into(),
        };
        assert_eq!(
            compose_production_policy(
                &prediction(&["write"], false, 0.1),
                ActionClass::SideEffecting,
                false
            )
            .unwrap(),
            ProductionVerdict::Ask
        );
        assert_eq!(
            compose_scoped_production_policy(
                &prediction(&["write"], false, 0.1),
                ActionClass::SideEffecting,
                false,
                true
            )
            .unwrap(),
            ProductionVerdict::Allow
        );
        for actions in [
            &["delete"][..],
            &["write", "delete"],
            &["write", "change_permissions"],
            &["write", "send_data"],
        ] {
            assert_eq!(
                compose_scoped_production_policy(
                    &prediction(actions, false, 0.95),
                    ActionClass::SideEffecting,
                    false,
                    true
                )
                .unwrap(),
                ProductionVerdict::Deny
            );
        }
        for (actions, unknown, uncertainty) in [
            (&["write"][..], true, 0.1),
            (&["write"][..], false, 0.8),
            (&["read", "write"][..], false, 0.1),
            (&["read"][..], false, 0.1),
            (&[][..], false, 0.1),
        ] {
            assert_eq!(
                compose_scoped_production_policy(
                    &prediction(actions, unknown, uncertainty),
                    ActionClass::SideEffecting,
                    false,
                    true
                )
                .unwrap(),
                ProductionVerdict::Ask
            );
        }
        assert_eq!(
            compose_scoped_production_policy(
                &prediction(&["write"], false, 0.9),
                ActionClass::ReadOnly,
                false,
                true
            )
            .unwrap(),
            ProductionVerdict::Deny
        );
        for invalid in [f64::NAN, f64::INFINITY, -0.1, 1.1] {
            assert_eq!(
                compose_scoped_production_policy(
                    &prediction(&["write"], false, invalid),
                    ActionClass::SideEffecting,
                    false,
                    true
                ),
                Err("classifier_invalid")
            );
        }
    }

    #[test]
    fn compose_production_policy_rules() {
        let make_cl = |actions: Vec<&str>, unknown: bool, uncertainty: f64| Classification {
            actions: actions.into_iter().map(String::from).collect(),
            unknown,
            confidence: 0.95,
            uncertainty,
            reason: "synthetic reason".into(),
        };

        // delete -> Deny
        let cl = make_cl(vec!["delete"], false, 0.05);
        assert_eq!(
            compose_production_policy(&cl, ActionClass::Destructive, false).unwrap(),
            ProductionVerdict::Deny
        );

        // write on read_only baseline -> Deny
        let cl = make_cl(vec!["write"], false, 0.05);
        assert_eq!(
            compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
            ProductionVerdict::Deny
        );

        // write on read_only baseline with high uncertainty -> hard Deny (SOU-24)
        let cl = make_cl(vec!["write"], false, 0.9);
        assert_eq!(
            compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
            ProductionVerdict::Deny
        );

        // write on other baseline -> Ask
        let cl = make_cl(vec!["write"], false, 0.05);
        assert_eq!(
            compose_production_policy(&cl, ActionClass::SideEffecting, false).unwrap(),
            ProductionVerdict::Ask
        );

        // send_data with declared egress -> Allow
        let cl = make_cl(vec!["send_data"], false, 0.05);
        assert_eq!(
            compose_production_policy(&cl, ActionClass::Network, true).unwrap(),
            ProductionVerdict::Allow
        );

        // send_data without declared egress and not network baseline -> Deny
        let cl = make_cl(vec!["send_data"], false, 0.05);
        assert_eq!(
            compose_production_policy(&cl, ActionClass::SideEffecting, false).unwrap(),
            ProductionVerdict::Deny
        );

        // high uncertainty -> Ask
        let cl = make_cl(vec!["read"], false, 0.85);
        assert_eq!(
            compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
            ProductionVerdict::Ask
        );

        // unknown -> Ask
        let cl = make_cl(vec![], true, 0.05);
        assert_eq!(
            compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
            ProductionVerdict::Ask
        );

        // read -> Allow
        let cl = make_cl(vec!["read"], false, 0.05);
        assert_eq!(
            compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
            ProductionVerdict::Allow
        );

        // mixed: read + delete -> hard Deny
        let cl = make_cl(vec!["read", "delete"], false, 0.05);
        assert_eq!(
            compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
            ProductionVerdict::Deny
        );

        // mixed: read + change_permissions -> hard Deny
        let cl = make_cl(vec!["read", "change_permissions"], false, 0.05);
        assert_eq!(
            compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
            ProductionVerdict::Deny
        );

        // mixed: read + authorized send_data -> Allow
        let cl = make_cl(vec!["read", "send_data"], false, 0.05);
        assert_eq!(
            compose_production_policy(&cl, ActionClass::Network, true).unwrap(),
            ProductionVerdict::Allow
        );

        // mixed: read + unauthorized send_data -> Deny
        let cl = make_cl(vec!["read", "send_data"], false, 0.05);
        assert_eq!(
            compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
            ProductionVerdict::Deny
        );

        // actions plus unknown: read + unknown -> Ask
        let cl = make_cl(vec!["read"], true, 0.05);
        assert_eq!(
            compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
            ProductionVerdict::Ask
        );

        // hard-deny takes precedence over unknown: delete + unknown -> hard Deny
        let cl = make_cl(vec!["delete"], true, 0.05);
        assert_eq!(
            compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
            ProductionVerdict::Deny
        );

        // Duplicate actions violate the core contract and never reach policy.
        let cl = make_cl(vec!["read", "read"], false, 0.05);
        assert_eq!(map_classification(&cl), Err("classifier_invalid"));
        assert_eq!(
            compose_production_policy(&cl, ActionClass::Network, true),
            Err("classifier_invalid")
        );

        // proven no-op (D07): empty actions, unknown=false -> Allow
        let cl = make_cl(vec![], false, 0.05);
        assert_eq!(
            compose_production_policy(&cl, ActionClass::ReadOnly, false).unwrap(),
            ProductionVerdict::Allow
        );
    }
}

#[cfg(all(test, unix))]
mod classifier_revision_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn quote(value: &str) -> String {
        format!("'{}'", value.replace('\'', "'\\''"))
    }

    #[test]
    fn classifier_changed_between_parent_check_and_launch_never_executes() {
        let temporary = tempfile::tempdir().unwrap();
        let root = temporary.path().canonicalize().unwrap();
        let script = root.join("classifier.py");
        let marker = root.join("unexpected-classifier-execution");
        let wrapper = root.join("python-wrapper");
        let reply = r#"{"status":"ok","actions":["read"],"unknown":false,"confidence":1.0,"uncertainty":0.0,"reason":"synthetic"}"#;
        let original = format!("print({reply:?})\n");
        std::fs::write(&script, &original).unwrap();
        let digest = sha(original.as_bytes());
        let actual_python = std::process::Command::new("python3")
            .args(["-c", "import sys; print(sys.executable)"])
            .output()
            .unwrap();
        assert!(actual_python.status.success());
        let python = String::from_utf8(actual_python.stdout).unwrap();
        let python = python.trim();
        let replacement = format!(
            "import pathlib\npathlib.Path({:?}).touch()\nprint({reply:?})\n",
            marker.to_str().unwrap()
        );
        // The interpreter wrapper mutates the file only after the parent has
        // selected the revision and begun launching the classification process.
        let launcher = format!(
            "#!/bin/sh\n{} -c {} {} {}\nexec {} \"$@\"\n",
            quote(python),
            quote("import pathlib,sys; pathlib.Path(sys.argv[1]).write_text(sys.argv[2])"),
            quote(script.to_str().unwrap()),
            quote(&replacement),
            quote(python)
        );
        std::fs::write(&wrapper, launcher).unwrap();
        std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700)).unwrap();
        let classifier = RuleBaseline {
            script,
            python: wrapper.into_os_string(),
            digest,
        };
        let invocation = Invocation {
            server_id: "synthetic".into(),
            host_call_id: json!(1),
            registry_sha256: "registry".into(),
            snapshot_sha256: "snapshot".into(),
            schema_sha256: "schema".into(),
            tool: "read_file".into(),
            description: "synthetic read".into(),
            schema: json!({"type":"object"}),
            definition: json!({"name":"read_file","inputSchema":{"type":"object"}}),
            server_info: json!({"name":"fixture","version":"1"}),
            definition_sha256: "definition".into(),
            input_sha256: "input".into(),
            classifier_revision: None,
            args: json!({"path":"fixture.txt"}),
            baseline: ActionClass::ReadOnly,
        };
        assert!(classifier.classify(&invocation).is_err());
        assert!(!marker.exists(), "changed classifier source executed");
    }
}

#[cfg(test)]
mod resource_receipt_tests {
    use super::*;
    use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

    fn admission() -> Value {
        json!({"server_id":"resource-fixture","host_call_id":"original-host-id",
            "profile_sha256":"a".repeat(64),"executor_sha256":"e".repeat(64),
            "classifier_sha256":"c".repeat(64),"snapshot_sha256":"d".repeat(64),
            "definition_sha256":"f".repeat(64),"input_sha256":"a".repeat(64),
            "resources":[{"pointer":"/url","source":"argument","resource":{
                "kind":"url","canonical":"http://127.0.0.1:8000/allowed",
                "host":"127.0.0.1","port":8000}}]})
    }

    #[tokio::test]
    async fn missing_or_changed_resource_hash_and_old_contract_are_refused_over_http() {
        let context = admission();
        let expected = crate::native::canonical_digest(&context["resources"]);
        for (contract, hash, accepted) in [
            (crate::native::resource::CONTRACT, None, false),
            (
                crate::native::resource::CONTRACT,
                Some("0".repeat(64)),
                false,
            ),
            (CONTRACT, Some(expected.clone()), false),
            (
                crate::native::resource::CONTRACT,
                Some(expected.clone()),
                true,
            ),
        ] {
            let server = MockServer::start().await;
            let registry=json!({"contract_version":CONTRACT,"registry_id":"receipt-tests","tools":[{
                "name":"retrieve_page","schema_sha256":"1".repeat(64),"action_class":"read_only",
                "result_provenance":"untrusted","egress":[]
            }]}).to_string();
            let native = NativeState::from_bytes(
                registry.as_bytes(),
                &sha(registry.as_bytes()),
                "synthetic-native-key".into(),
            )
            .unwrap();
            let config = AdmissionCfg {
                host_session: None,
                child_authority: None,
                server_id: "resource-fixture".into(),
                daemon_url: format!("{}/native/v1", server.uri()),
                manifest_url: format!("{}/mcp/manifest", server.uri()),
                manifest_token: "synthetic-manifest-key".into(),
                native,
                command: "not-started".into(),
                args: vec![],
                classifier: None,
                resource_profiles: BTreeMap::new(),
                approval: None,
                liveness_url: None,
                liveness_lease_seconds: None,
            };
            let collector = Collector::new(&config).unwrap();
            let mut response = json!({"contract_version":contract,"registry_sha256":config.native.registry_sha256,
                "session_id":collector.session,"event":"call","verdict":"allow","enforced":true,"release":true,
                "call_id":"synthetic-call","binding_sha256":"b".repeat(64),"content_sha256":null,"reason_codes":[]});
            if let Some(hash) = hash {
                response["resources_sha256"] = json!(hash);
            }
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(200).set_body_json(response))
                .expect(1)
                .mount(&server)
                .await;
            let result = collector
                .event(
                    "call",
                    json!({"tool":"retrieve_page","args":{"url":"http://127.0.0.1:8000/allowed"},
                "schema_sha256":"1".repeat(64),"resource_admission":context}),
                )
                .await;
            assert_eq!(
                result.is_ok(),
                accepted,
                "contract={contract}, accepted={accepted}"
            );
        }
    }

    #[test]
    fn canonical_resource_digest_is_independent_of_property_order_and_legacy_stays_closed() {
        let context = admission();
        let reordered:Value=serde_json::from_str(r#"[{"source":"argument","resource":{"port":8000,"kind":"url","host":"127.0.0.1","canonical":"http://127.0.0.1:8000/allowed"},"pointer":"/url"}]"#).unwrap();
        assert_eq!(
            crate::native::canonical_digest(&context["resources"]),
            crate::native::canonical_digest(&reordered)
        );
        let reply = json!({"resources_sha256":crate::native::canonical_digest(&reordered)});
        assert!(validate_resource_receipt(Some(&context), &reply).is_ok());
        assert!(validate_resource_receipt(None, &reply).is_err());
        assert!(validate_resource_receipt(None, &json!({})).is_ok());
    }
}

#[cfg(test)]
mod diagnostic_output_tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn leased_output<W>(
        inner: W,
    ) -> (
        DiagnosticOutput<W>,
        Arc<crate::native::liveness::CollectorLivenessClient>,
    ) {
        let liveness = Arc::new(crate::native::liveness::CollectorLivenessClient::new(
            reqwest::Client::new(),
            "http://127.0.0.1/unused".into(),
            "unused-token".into(),
            "registry".into(),
            "collector".into(),
            "instance".into(),
            None,
        ));
        (
            DiagnosticOutput {
                inner,
                failed: Arc::new(AtomicBool::new(false)),
                budget: None,
                liveness: Some(liveness.clone()),
            },
            liveness,
        )
    }

    #[tokio::test]
    async fn liveness_failure_withholds_output_without_waiting_for_monitor_tick() {
        let (mut observer, output) = tokio::io::duplex(64);
        let (mut guarded, liveness) = leased_output(output);
        guarded.write_all(b"useful\n").await.unwrap();
        liveness.mark_failed();
        // No outer select or 50ms monitor tick runs between failure and output.
        assert_eq!(
            guarded.write_all(b"withheld\n").await.unwrap_err().kind(),
            std::io::ErrorKind::BrokenPipe
        );
        assert!(guarded.flush().await.is_err());
        assert!(guarded.shutdown().await.is_err());
        drop(guarded);
        let mut received = Vec::new();
        observer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"useful\n");
    }

    #[tokio::test]
    async fn liveness_failure_stops_pending_output_when_host_becomes_writable() {
        let (mut observer, output) = tokio::io::duplex(1);
        let (mut guarded, liveness) = leased_output(output);
        {
            let writing = guarded.write_all(b"xy");
            tokio::pin!(writing);
            assert!(futures_util::poll!(writing.as_mut()).is_pending());
            liveness.mark_failed();
            let mut committed = [0u8; 1];
            observer.read_exact(&mut committed).await.unwrap();
            assert_eq!(&committed, b"x");
            assert!(
                matches!(futures_util::poll!(writing.as_mut()), Poll::Ready(Err(_))),
                "a writable host must not extend output after lease uncertainty"
            );
        }
        drop(guarded);
        let mut received = Vec::new();
        observer.read_to_end(&mut received).await.unwrap();
        assert!(received.is_empty());
    }

    #[tokio::test]
    async fn observed_diagnostic_failure_refuses_future_output_and_flush() {
        let (mut observer, output) = tokio::io::duplex(64);
        let failed = Arc::new(AtomicBool::new(false));
        let mut guarded = DiagnosticOutput {
            inner: output,
            failed: failed.clone(),
            budget: None,
            liveness: None,
        };
        guarded.write_all(b"useful\n").await.unwrap();
        failed.store(true, Ordering::Release);
        let error = guarded.write_all(b"withheld\n").await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        assert!(guarded.flush().await.is_err());
        assert!(guarded.shutdown().await.is_err());
        drop(guarded);
        let mut received = Vec::new();
        observer.read_to_end(&mut received).await.unwrap();
        assert!(
            received == b"useful\n",
            "only the earlier committed frame may be present"
        );
    }

    #[tokio::test]
    async fn diagnostic_failure_stops_a_pending_partial_write() {
        let (mut observer, output) = tokio::io::duplex(1);
        let failed = Arc::new(AtomicBool::new(false));
        let mut guarded = DiagnosticOutput {
            inner: output,
            failed: failed.clone(),
            budget: None,
            liveness: None,
        };
        {
            let writing = guarded.write_all(b"xy");
            tokio::pin!(writing);
            assert!(futures_util::poll!(writing.as_mut()).is_pending());
            failed.store(true, Ordering::Release);
            assert!(writing.await.is_err());
        }
        drop(guarded);
        let mut received = Vec::new();
        observer.read_to_end(&mut received).await.unwrap();
        assert!(
            received == b"x",
            "bytes committed before failure are not retracted or extended"
        );
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_budget_stops_a_pending_partial_host_write() {
        use std::os::windows::io::{FromRawHandle, OwnedHandle};
        let raw = unsafe {
            windows_sys::Win32::System::JobObjects::CreateJobObjectW(
                std::ptr::null(),
                std::ptr::null(),
            )
        };
        assert!(!raw.is_null());
        let job = Arc::new(unsafe { OwnedHandle::from_raw_handle(raw.cast()) });
        let config = super::super::windows_budget::Config::read(br#"{"format":"sw-mcp/windows-job-budget/1","memoryMaxBytes":134217728,"memoryPressureBytes":100663296,"activeProcessMax":8,"cpuUserMillis":2000,"wallMillis":1000}"#).unwrap();
        let mut budget = super::super::windows_budget::Budget::install(job, config).unwrap();
        let (mut observer, output) = tokio::io::duplex(1);
        let mut guarded = DiagnosticOutput {
            inner: output,
            failed: Arc::new(AtomicBool::new(false)),
            budget: Some(budget.guard()),
            liveness: None,
        };
        {
            let writing = guarded.write_all(b"xy");
            tokio::pin!(writing);
            assert!(futures_util::poll!(writing.as_mut()).is_pending());
            tokio::time::sleep(tokio::time::Duration::from_millis(1100)).await;
            assert!(writing.await.is_err());
        }
        drop(guarded);
        let mut received = Vec::new();
        observer.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, b"x");
        budget.finish(true);
        assert_eq!(
            budget.guard().report()["observed"]["reason"],
            "windows_budget_wall_deadline"
        );
    }
}
