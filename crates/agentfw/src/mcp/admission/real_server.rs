// SPDX-License-Identifier: Apache-2.0
//! Explicit selected-server transport. Legacy brokered executors retain their loop.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};

use anyhow::{bail, ensure, Context};
use futures_util::stream::{FuturesUnordered, StreamExt};
use futures_util::FutureExt;
use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time::Instant;

use super::DaemonSizeLimit;
use super::{canonical, id, keys, line, not_classified, parse, sha, withheld, write};
use super::{AdmittedTool, ClassificationAuthority, Collector, ProductionVerdict, Snapshot};
#[cfg(target_os = "linux")]
use crate::mcp::original_create::{run_original_upstream, VerifiedOutput};
use crate::mcp::{server_profile, server_sandbox};
use crate::native::CONTRACT;

pub(super) const ACTIVE_LIMIT: usize = 8;
pub(super) const QUEUE_LIMIT: usize = 8;
const MAX_MESSAGES: usize = 8192;
const MAX_PROGRESS: usize = 128;
const MAX_JSON_DEPTH: usize = 20;
const MAX_JSON_NODES: usize = 16_384;

// Fixed, bounded, correlated refusals. Each names the specific limit; none
// copies server bytes. A withheld result may already have been executed.
const TEXT_BUDGET_MESSAGE: &str = "MCP result withheld: a result text exceeds the 262144-byte per-result budget; the original call may have executed";
const FRAME_BUDGET_MESSAGE: &str = "MCP result withheld: the response frame exceeds the 1048576-byte envelope budget; the original call may have executed";
const OVERSIZED_CONTROL_ERROR: &str = "oversized MCP control response";
const PATH_OUTSIDE_MESSAGE: &str =
    "MCP path refused before execution: it is outside the selected workspace /workspace";
const PATH_SPELLING_MESSAGE: &str = "MCP path refused before execution: unsupported spelling (empty, '.', '..' or '//' segment, backslash, '~', control character, relative ':' or over 4096 bytes)";

mod frames;
mod outcomes;

// Host-owned diagnostic pipes may close before the namespace owners finish.
// Reporting must not panic past cleanup or its authenticated acknowledgement;
// failures of the actual transport, drain and owner boundaries remain errors.
macro_rules! diagnostic {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr().lock(), $($arg)*);
    }};
}

struct Grant {
    source: Option<Box<crate::native::execution::Dispatch>>,
    original_result: Option<Box<crate::native::execution::OriginalResult>>,
    call_id: Value,
    binding: Value,
    boundary: Option<crate::policy_transition::Boundary>,
    continuation: Option<ContinuationTiming>,
}

/// Observations only: never used for authority, deadlines, retries or admission.
struct ContinuationTiming {
    observed: Instant,
    previous: Instant,
}

impl ContinuationTiming {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            observed: now,
            previous: now,
        }
    }

    fn record(&mut self, call: &Call, stage: &'static str, success: bool) {
        let now = Instant::now();
        diagnostic!(
            "{}",
            json!({
                "event": "mcp_real_approval_timing", "profile": call.profile,
                "host_call_id": call.id, "stage": stage, "success": success,
                "stage_ms": now.duration_since(self.previous).as_secs_f64() * 1000.0,
                "post_observed_ms": now.duration_since(self.observed).as_secs_f64() * 1000.0,
                "clock": "collector_monotonic", "authority": false
            })
        );
        self.previous = now;
    }
}

struct Release {
    raw: Vec<u8>,
    #[cfg(target_os = "linux")]
    authorized: bool,
    _boundary: Option<crate::policy_transition::Boundary>,
}

enum Phase {
    Queued,
    Admitting,
    Running(Grant),
    #[cfg(target_os = "linux")]
    Creating(Grant),
    #[cfg(target_os = "linux")]
    Staging,
    Inspecting,
    Reclaiming,
}

struct Call {
    profile: String,
    id: Value,
    tool: String,
    args: Value,
    raw: Vec<u8>,
    request_sha256: String,
    phase: Phase,
    cancelled: bool,
    cancel: tokio::sync::watch::Sender<bool>,
    dispatched: bool,
    deadline: Instant,
    progress: Option<Value>,
    progress_count: usize,
    last_progress: f64,
    // Cancellation spends native authority before the producer necessarily
    // finishes cleanup. Workers retain this lease independently of the call.
    create_lease: Option<Arc<()>>,
    // Pin the exact operator workspace *before* native admission.
    // Never reopen a substituted root after native result Allow.
    #[cfg(target_os = "linux")]
    pinned_workspace: Option<Arc<crate::sandbox::PinnedWorkspace>>,
}

#[derive(Default)]
struct CreateSlot(Weak<()>);

impl CreateSlot {
    fn reserve(&mut self) -> Option<Arc<()>> {
        if self.0.upgrade().is_some() {
            return None;
        }
        let lease = Arc::new(());
        self.0 = Arc::downgrade(&lease);
        Some(lease)
    }
}

#[cfg(any(test, target_os = "linux"))]
async fn retain_create_slot<T>(lease: Option<Arc<()>>, work: impl Future<Output = T>) -> T {
    let _lease = lease;
    work.await
}

#[cfg(target_os = "linux")]
async fn produce_original_create(
    profile: &server_profile::ProfileConfig,
    args: &Value,
) -> anyhow::Result<(Vec<u8>, Option<VerifiedOutput>)> {
    #[cfg(test)]
    if let Some(result) = fault_tests::controlled_create_output(args) {
        return result;
    }
    run_original_upstream(profile, args).await
}

enum Decision {
    Refused(Vec<u8>),
    Allowed(Grant),
}

enum WorkEvent {
    Admitted(String, anyhow::Result<Decision>),
    Inspected(String, anyhow::Result<Option<Release>>),
    #[cfg(target_os = "linux")]
    Created(String, anyhow::Result<(Vec<u8>, Option<VerifiedOutput>)>),
    #[cfg(target_os = "linux")]
    CreateInspected(String, anyhow::Result<Option<Release>>, VerifiedOutput),
    #[cfg(target_os = "linux")]
    CreateStaged(
        String,
        anyhow::Result<crate::mcp::create_file::StagedCreate>,
        Release,
    ),
    Reclaimed(String, anyhow::Result<()>),
}

type Work<'a> = Pin<Box<dyn Future<Output = WorkEvent> + Send + 'a>>;

struct Control {
    id: Value,
    method: String,
    deadline: Instant,
    host_id: Value,
    tools: Vec<Value>,
    cursors: BTreeSet<String>,
    pages: usize,
}

fn rpc_key(value: &Value) -> anyhow::Result<String> {
    let key = id(value)?;
    if let Some(number) = value.as_i64() {
        ensure!(
            number.unsigned_abs() <= 9_007_199_254_740_991,
            "MCP ID is not a safe JSON integer"
        );
    }
    Ok(key)
}

fn bounded(value: &Value, depth: usize, nodes: &mut usize) -> anyhow::Result<()> {
    *nodes += 1;
    ensure!(
        depth <= MAX_JSON_DEPTH && *nodes <= MAX_JSON_NODES,
        "selected MCP JSON exceeds limits"
    );
    match value {
        Value::Array(values) => {
            for value in values {
                bounded(value, depth + 1, nodes)?;
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                bounded(value, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn frame(value: &Value) -> Vec<u8> {
    let mut raw = value.to_string().into_bytes();
    raw.push(b'\n');
    raw
}

fn error(id: &Value, code: i64, message: &'static str) -> Vec<u8> {
    frame(&json!({"jsonrpc":"2.0", "id":id, "error":{"code":code,"message":message}}))
}

fn audit(call: &Call, state: &str, active: usize, queued: usize) {
    diagnostic!(
        "{}",
        json!({"event":"mcp_real_call","profile":call.profile,
        "host_call_id":call.id,"id_type":if call.id.is_string(){"string"}else{"integer"},
        "state":state,"active":active,"queued":queued,"execution_dispatched":call.dispatched,
        "enqueue_to_stage_us":Instant::now().saturating_duration_since(call.deadline - super::IO_TIMEOUT).as_micros(),
        "arguments_sha256":sha(canonical(&call.args).to_string().as_bytes())})
    );
}

fn counts(calls: &BTreeMap<String, Call>) -> (usize, usize) {
    let queued = calls
        .values()
        .filter(|call| matches!(call.phase, Phase::Queued))
        .count();
    (calls.len() - queued, queued)
}

fn metadata(params: &Value) -> anyhow::Result<Option<Value>> {
    let Some(meta) = params.get("_meta") else {
        return Ok(None);
    };
    keys(meta, &["claudecode/toolUseId", "threadId", "progressToken"])?;
    for key in ["claudecode/toolUseId", "threadId"] {
        if let Some(value) = meta.get(key) {
            ensure!(
                super::correlation_id(value),
                "unsupported host correlation metadata"
            );
        }
    }
    ensure!(
        !(meta.get("claudecode/toolUseId").is_some() && meta.get("threadId").is_some()),
        "ambiguous host correlation metadata"
    );
    if let Some(token) = meta.get("progressToken") {
        rpc_key(token)?;
    }
    Ok(meta.get("progressToken").cloned())
}

async fn admit(
    collector: &Collector<'_>,
    snapshot: Arc<Snapshot>,
    call: &Call,
    profile: &server_profile::ProfileConfig,
) -> anyhow::Result<Decision> {
    let creating =
        call.profile == server_profile::filesystem_create::FORMAT && call.tool == "write_file";
    if creating && (!cfg!(target_os = "linux") || collector.config.classifier.is_none()) {
        return Ok(Decision::Refused(withheld(
            &call.id,
            "invocation",
            &json!(["original_create_classifier_or_platform_unavailable"]),
        )));
    }
    let installed = collector
        .config
        .native
        .registry
        .tools
        .iter()
        .find(|tool| tool.name == call.tool)
        .context("selected MCP registry tool missing")?;
    let assessment = match collector
        .classify(
            &snapshot,
            &call.id,
            &call.tool,
            &call.args,
            installed.action_class,
            ClassificationAuthority {
                replacement: false,
                egress_declared: false,
                create_file_profile: creating.then_some(server_profile::filesystem_create::FORMAT),
                https_get: false,
            },
        )
        .await?
    {
        Err(code) => return Ok(Decision::Refused(not_classified(&call.id, code))),
        Ok(assessment) => assessment,
    };
    let refusal = |code: &str| Decision::Refused(withheld(&call.id, "invocation", &json!([code])));
    if *call.cancel.borrow() || Instant::now() >= call.deadline {
        return Ok(refusal("native_approval_cancelled"));
    }
    if assessment.verdict == ProductionVerdict::Deny {
        return Ok(refusal("classifier_deny"));
    }
    // Only the exact installed create-only profile may continue a classified
    // mutation. Unknown read-only semantics remain unsupported for approvals.
    if !(if creating {
        assessment.known_create
    } else {
        assessment.known_read_only
    }) {
        return Ok(refusal(if collector.config.approval.is_some() {
            "classifier_unknown_approval_unsupported"
        } else {
            "classifier_ask"
        }));
    }
    let mut boundary = collector.policy_boundary().await?;
    let mut fields = json!({"tool":call.tool,"args":call.args,
        "schema_sha256":installed.schema_sha256,"mcp_host_call_id":call.id});
    let create_context = if creating {
        #[cfg(target_os = "linux")]
        {
            let Some(workspace) = call.pinned_workspace.as_deref() else {
                return Ok(refusal("native_approval_create_resource_unavailable"));
            };
            let resource = match server_profile::filesystem_create::CreateResource::capture(
                workspace, &call.args,
            ) {
                Ok(resource) => resource,
                Err(_) => return Ok(refusal("native_approval_create_resource_changed")),
            };
            Some(selected_invocation(
                collector,
                &snapshot,
                call,
                profile,
                Some(resource),
            )?)
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    } else {
        None
    };
    if let Some(context) = &create_context {
        fields["selected_invocation"] = json!(context);
    }
    let mut receipt = if assessment.verdict == ProductionVerdict::Ask {
        None
    } else {
        Some(collector.event("call", fields.clone()).await?)
    };
    let source = if assessment.verdict == ProductionVerdict::Ask {
        Some("classifier")
    } else if receipt
        .as_ref()
        .is_some_and(|reply| reply["verdict"] == "ask")
    {
        Some("daemon")
    } else {
        None
    };
    let mut continuation = None;
    if let Some(source) = source {
        // No transition gate is held across a human wait. Acquire a fresh
        // boundary, rerun classification and redeem under the current policy.
        drop(boundary.take());
        if collector.config.approval.is_none() {
            return Ok(if let Some(reply) = receipt {
                Decision::Refused(withheld(&call.id, "invocation", &reply["reason_codes"]))
            } else {
                refusal("classifier_ask")
            });
        }
        // This increment requires the accepted host/agent capability and live
        // collector owner. Plain legacy sessions keep their correlated refusal.
        if collector.host_session.is_none() || collector.liveness.is_none() {
            return Ok(refusal("native_approval_bound_owner_required"));
        }
        let context = match create_context {
            Some(context) => context,
            None => selected_invocation(collector, &snapshot, call, profile, None)?,
        };
        // Bind same-FD verified input observations before publishing a pending
        // request. Only kernel-enforced immutable bytes may be reused later.
        // This state belongs to this exact Ask, never a global authority cache.
        let verified_assets = if let Some(runtime) = collector.runtime() {
            ensure!(
                runtime.matches(profile),
                "verified_execution_profile_changed"
            );
            None
        } else {
            let frozen = profile.clone();
            Some(tokio::task::spawn_blocking(move || frozen.capture_verified_assets()).await??)
        };
        let approval_id =
            match wait_approval(collector, call, source, &installed.schema_sha256, &context).await?
            {
                Ok(id) => id,
                Err(code) => return Ok(refusal(&code)),
            };
        let mut timing = ContinuationTiming::new();
        let resumed = async {
            let verified = if let Some(verified_assets) = verified_assets {
                let frozen = profile.clone();
                tokio::task::spawn_blocking(move || frozen.revalidate_assets(&verified_assets))
                    .await?
            } else {
                match collector.runtime() {
                    Some(runtime) if runtime.matches(profile) => {
                        if let Some(context) = &collector.execution {
                            context.check()
                        } else {
                            Ok(())
                        }
                    }
                    _ => Err(anyhow::anyhow!("verified_execution_profile_changed")),
                }
            };
            timing.record(call, "profile_and_assets", verified.is_ok());
            verified?;
            #[cfg(target_os = "linux")]
            if let Some(expected) = &context.original_create {
                let workspace = call
                    .pinned_workspace
                    .as_deref()
                    .context("selected create root missing")?;
                ensure!(
                    &server_profile::filesystem_create::CreateResource::capture(
                        workspace, &call.args
                    )? == expected,
                    "selected create resource changed during approval"
                );
            }
            boundary = collector.policy_boundary().await?;
            timing.record(call, "policy_boundary", true);
            let reassessed = collector
                .classify(
                    &snapshot,
                    &call.id,
                    &call.tool,
                    &call.args,
                    installed.action_class,
                    ClassificationAuthority {
                        replacement: false,
                        egress_declared: false,
                        create_file_profile: creating
                            .then_some(server_profile::filesystem_create::FORMAT),
                        https_get: false,
                    },
                )
                .await;
            timing.record(call, "classifier", matches!(&reassessed, Ok(Ok(_))));
            let reassessed = reassessed?;
            ensure!(
                reassessed.is_ok_and(|value| (if creating {
                    value.known_create
                } else {
                    value.known_read_only
                }) && value.verdict != ProductionVerdict::Deny),
                "selected approval reclassification refused"
            );
            ensure!(
                !*call.cancel.borrow() && Instant::now() < call.deadline,
                "selected approval cancelled before dispatch"
            );
            Ok::<_, anyhow::Error>(())
        }
        .await;
        if resumed.is_err() {
            collector.cancel_approval(&approval_id).await?;
            return Ok(refusal("native_approval_revalidation_refused"));
        }
        fields["approval_id"] = json!(approval_id);
        fields["selected_invocation"] = json!(context);
        let admitted = collector.event("call", fields).await;
        timing.record(
            call,
            "daemon_redemption",
            admitted.as_ref().is_ok_and(|r| r["release"] == true),
        );
        // Idempotent cancellation removes approved but unused state. A lost or
        // malformed native receipt is session-fatal, as on the ordinary path:
        // retire the session rather than orphaning an unseen reserved call.
        collector.cancel_approval(&approval_id).await?;
        receipt = Some(admitted?);
        continuation = Some(timing);
    }
    let receipt = receipt.context("selected admission receipt absent")?;
    if receipt["release"] != true {
        return Ok(Decision::Refused(withheld(
            &call.id,
            "invocation",
            &receipt["reason_codes"],
        )));
    }
    Ok(Decision::Allowed(Grant {
        source: None,
        original_result: None,
        call_id: receipt["call_id"].clone(),
        binding: receipt["binding_sha256"].clone(),
        boundary,
        continuation,
    }))
}

/// Freeze observations for the existing signed grant and call binding. Runtime,
/// package, schema and classifier revisions remain part of this same identity.
fn selected_invocation(
    collector: &Collector<'_>,
    snapshot: &Snapshot,
    call: &Call,
    profile: &server_profile::ProfileConfig,
    original_create: Option<server_profile::filesystem_create::CreateResource>,
) -> anyhow::Result<crate::native::approval::SelectedInvocation> {
    let classifier = collector
        .config
        .classifier
        .as_ref()
        .context("selected classifier missing")?;
    let classifier_digest = classifier
        .revision()
        .filter(|digest| crate::native::is_digest(digest))
        .context("selected classifier revision missing")?;
    let definition = snapshot
        .tools
        .get(&call.tool)
        .context("selected definition missing")?;
    Ok(crate::native::approval::SelectedInvocation {
        host_call_id: call.id.clone(),
        request_sha256: call.request_sha256.clone(),
        server_id: collector.config.server_id.clone(),
        profile: call.profile.clone(),
        profile_sha256: sha(canonical(&serde_json::to_value(profile)?)
            .to_string()
            .as_bytes()),
        classifier_sha256: classifier_digest.to_owned(),
        snapshot_sha256: snapshot.sha256.clone(),
        definition_sha256: definition.definition_sha256.clone(),
        input_sha256: super::prediction_identity(
            &collector.config.server_id,
            snapshot,
            definition,
            &call.tool,
            &call.args,
            classifier.source(),
            classifier.revision(),
        ),
        original_create,
    })
}

/// One bounded admission worker, independent of host input and useful peers.
/// Always finish opening before observing cancellation so the returned pending
/// id can be cancelled. Fatal relay exit closes the entire native session.
async fn wait_approval(
    collector: &Collector<'_>,
    call: &Call,
    source: &str,
    schema: &str,
    context: &crate::native::approval::SelectedInvocation,
) -> anyhow::Result<Result<String, String>> {
    let base = |action| {
        json!({"contract_version":CONTRACT,
        "registry_sha256":collector.config.native.registry_sha256,
        "session_id":collector.session,"action":action})
    };
    if *call.cancel.borrow() {
        return Ok(Err("native_approval_cancelled".into()));
    }
    let mut body = base("request");
    body["source"] = json!(source);
    body["tool"] = json!(call.tool);
    body["args"] = call.args.clone();
    body["schema_sha256"] = json!(schema);
    body["selected_invocation"] = json!(context);
    let reply = match collector.approval_post(&body).await? {
        Ok(reply) => reply,
        Err(code) => return Ok(Err(code)),
    };
    ensure!(
        reply["action"] == "request",
        "selected approval action mismatch"
    );
    let id = reply["pending_id"]
        .as_str()
        .context("pending id")?
        .to_owned();
    diagnostic!(
        "{}",
        json!({"event":"mcp_native_approval_pending","pending_id":id,
        "tool":call.tool,"host_call_id":call.id,"binding_sha256":reply["binding_sha256"],
        "expires_in_ms":reply["expires_in_ms"],"source":source})
    );
    let limit = call.deadline.min(
        Instant::now()
            + collector.config.approval.as_ref().unwrap().wait.min(
                std::time::Duration::from_millis(reply["expires_in_ms"].as_u64().unwrap_or(0)),
            ),
    );
    let mut cancel = call.cancel.subscribe();
    let outcome = async {
        loop {
            if *cancel.borrow() { return Ok(Err("native_approval_cancelled".into())); }
            tokio::select! {
                biased;
                _ = cancel.changed() => return Ok(Err("native_approval_cancelled".into())),
                _ = tokio::time::sleep_until(limit) => return Ok(Err("native_approval_timeout".into())),
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
            }
            let mut status = base("status"); status["pending_id"] = json!(id);
            let reply = match collector.approval_post(&status).await? {
                Ok(reply) => reply, Err(code) => return Ok(Err(code)),
            };
            ensure!(reply["action"] == "status" && reply["pending_id"] == id,
                "selected approval status identity mismatch");
            match reply["state"].as_str() {
                Some("approved") => return Ok(Ok(id.clone())),
                Some("pending") => {},
                Some("rejected") => return Ok(Err("native_approval_rejected".into())),
                Some("expired") => return Ok(Err("native_approval_expired".into())),
                _ => return Ok(Err("native_approval_closed".into())),
            }
        }
    }.await;
    if !matches!(&outcome, Ok(Ok(_))) {
        collector.cancel_approval(&id).await?;
    }
    outcome
}

async fn inspect(
    collector: &Collector<'_>,
    call: &Call,
    mut grant: Grant,
    raw: Vec<u8>,
    kind: &str,
) -> anyhow::Result<Option<Release>> {
    let boundary = collector.policy_boundary().await?;
    let fields = |kind: &str, content: &str| {
        json!({"tool":call.tool,"args":call.args,
        "call_id":grant.call_id,"expected_binding_sha256":grant.binding,
        "expected_contract_version":CONTRACT,"result_kind":kind,"delivery":"mcp_host","content":content})
    };
    let content = std::str::from_utf8(&raw).context("selected MCP result is not UTF-8")?;
    let (raw, receipt, _original_inspected) = match collector
        .event_inner(
            "result",
            fields(kind, content),
            grant.original_result.take().map(|result| *result),
        )
        .await
    {
        Ok(receipt) => (raw, receipt, true),
        Err(failure) => {
            // A size refusal leaves the grant unspent at the daemon. Spend it
            // with a small correlated error instead of ending the session.
            let limit = failure
                .downcast_ref::<DaemonSizeLimit>()
                .copied()
                .ok_or(failure)?;
            diagnostic!(
                "{}",
                json!({"event":"mcp_real_result_withheld","host_call_id":call.id,
                    "limit":limit.code(),"observed_bytes":raw.len(),"released":false})
            );
            let replacement = error(&call.id, -32603, limit.message());
            let content = std::str::from_utf8(&replacement).expect("fixed UTF-8 error");
            let receipt = collector.event("result", fields("error", content)).await?;
            // Allowing this correlated error to reach the host does not
            // authorize publication of an uninspected original create result.
            (replacement, receipt, false)
        }
    };
    if let Some(timing) = &mut grant.continuation {
        timing.record(call, "result_inspection", receipt["release"] == true);
    }
    let authorized = receipt["release"] == true;
    diagnostic!("{}", json!({"event":"mcp_call_outcome","version":1,
        "stage":"result_inspection", "request_sha256":call.request_sha256,
        "host_call_sha256":sha(canonical(&call.id).to_string().as_bytes()),
        "released":authorized,"response_sha256":sha(&raw),
        "response":parse(&raw).ok().as_ref().map(outcomes::response),"authority":false}));
    let raw = if authorized {
        raw
    } else {
        withheld(&call.id, "result", &receipt["reason_codes"])
    };
    Ok(Some(Release {
        raw,
        #[cfg(target_os = "linux")]
        authorized: authorized && _original_inspected,
        _boundary: boundary,
    }))
}

async fn execute_in_daemon(
    collector: &Collector<'_>,
    call: &Call,
    mut grant: Grant,
    profile: &server_profile::ProfileConfig,
) -> anyhow::Result<Option<Release>> {
    let reply = collector
        .execute_original_git(&grant.call_id, &grant.binding, profile)
        .await?;
    ensure!(
        reply["completed"] == true,
        "original daemon execution incomplete"
    );
    let receipt = &reply["receipt"];
    let authorized = receipt["release"] == true;
    let raw = if authorized {
        let raw = reply["frame"]
            .as_str()
            .context("original daemon frame missing")?;
        let decoded = parse(raw.as_bytes())?;
        ensure!(decoded["id"] == call.id, "original daemon host ID mismatch");
        let profiles = server_profile::classify_manifest_for(
            &profile.format,
            &server_profile::original_manifest_for(&profile.format)?,
        )?;
        profiles
            .get(&call.tool)
            .context("original daemon tool missing")?
            .validate_result(&decoded)?;
        raw.as_bytes().to_vec()
    } else {
        withheld(&call.id, "result", &receipt["reason_codes"])
    };
    if let Some(timing) = &mut grant.continuation {
        timing.record(call, "daemon_original_result", authorized);
    }
    Ok(Some(Release {
        raw,
        #[cfg(target_os = "linux")]
        authorized,
        _boundary: grant.boundary.take(),
    }))
}

async fn reclaim(collector: &Collector<'_>, call: &Call, mut grant: Grant) -> anyhow::Result<()> {
    drop(grant.boundary.take());
    // A local transport error spends exactly this grant. It makes no claim that
    // a dispatched server request was rolled back or never executed.
    let raw = error(
        &call.id,
        -32800,
        "MCP request cancelled or incomplete; dispatched execution may have occurred",
    );
    let _ = inspect(collector, call, grant, raw, "error").await?;
    Ok(())
}

fn detached(call: &Call) -> Call {
    Call {
        profile: call.profile.clone(),
        id: call.id.clone(),
        tool: call.tool.clone(),
        args: call.args.clone(),
        raw: Vec::new(),
        request_sha256: call.request_sha256.clone(),
        phase: Phase::Admitting,
        cancelled: call.cancelled,
        cancel: call.cancel.clone(),
        dispatched: call.dispatched,
        deadline: call.deadline,
        progress: call.progress.clone(),
        progress_count: 0,
        last_progress: 0.0,
        create_lease: call.create_lease.clone(),
        #[cfg(target_os = "linux")]
        pinned_workspace: call.pinned_workspace.clone(),
    }
}

fn validate_registry(
    collector: &Collector<'_>,
    profiles: &BTreeMap<String, server_profile::ToolProfile>,
    tools: &[Value],
    format: &str,
) -> anyhow::Result<()> {
    ensure!(
        collector.config.resource_profiles.is_empty(),
        "selected server cannot mix brokered resource profiles"
    );
    // One daemon may explicitly install both accepted original server families.
    // Validate peer entries against their own pinned manifest without adding
    // them to this relay's callable profiles or advertised discovery result.
    // Arbitrary unadvertised registry entries remain a startup refusal.
    let peer_format = match format {
        server_profile::FORMAT => collector
            .config
            .native
            .registry
            .tools
            .iter()
            .filter_map(|tool| tool.mcp_result_profile.as_deref())
            .find(|format| server_profile::git_selected(format))
            .unwrap_or(server_profile::git::FORMAT),
        server_profile::git::FORMAT
        | server_profile::git::LOCAL_REFS_FORMAT
        | server_profile::git::FILE_READS_FORMAT
        | server_profile::git::SHALLOW_FORMAT
        | server_profile::git_local_clone::FORMAT
        | server_profile::git_tracked_symlinks::FORMAT => server_profile::FORMAT,
        server_profile::filesystem_create::FORMAT => server_profile::git::FORMAT,
        _ => bail!("unsupported selected registry profile"),
    };
    let peer_manifest = server_profile::original_manifest_for(peer_format)?;
    let peer_profiles = server_profile::classify_manifest_for(peer_format, &peer_manifest)?;
    let peer_tools = peer_manifest["tools"]
        .as_array()
        .context("peer selected manifest tools missing")?;
    for tool in &collector.config.native.registry.tools {
        let (definition, profile, expected_format) = tools
            .iter()
            .find(|value| value["name"] == tool.name)
            .map(|definition| (definition, &profiles[&tool.name], format))
            .or_else(|| {
                // The separately installed create-only profile does not acquire
                // the readonly pilot's union-registry authority.
                if format == server_profile::filesystem_create::FORMAT {
                    return None;
                }
                peer_tools
                    .iter()
                    .find(|value| value["name"] == tool.name)
                    .map(|definition| (definition, &peer_profiles[&tool.name], peer_format))
            })
            .context("selected registry contains an unadvertised tool")?;
        ensure!(
            tool.schema_sha256 == sha(canonical(&definition["inputSchema"]).to_string().as_bytes()),
            "selected registry schema pin changed"
        );
        ensure!(
            tool.resource_policy.is_none(),
            "selected server cannot acquire built-in resource authority"
        );
        if profile.unsupported_reason.is_none() {
            let required_action = if expected_format == server_profile::filesystem_create::FORMAT
                && tool.name == "write_file"
            {
                soup_wall_agent::ActionClass::SideEffecting
            } else {
                soup_wall_agent::ActionClass::ReadOnly
            };
            ensure!(
                tool.action_class == required_action
                    && tool.egress.is_empty()
                    && matches!(
                        tool.result_provenance,
                        crate::native::ResultProvenance::Untrusted
                    )
                    && tool.mcp_result_profile.as_deref() == Some(expected_format),
                "selected per-tool authority is not explicitly installed"
            );
        }
    }
    for (name, profile) in profiles {
        if profile.unsupported_reason.is_none() {
            ensure!(
                collector
                    .config
                    .native
                    .registry
                    .tools
                    .iter()
                    .any(|tool| tool.name == *name),
                "selected supported tool is not installed"
            );
        }
    }
    Ok(())
}

/// At most eight abandoned wire requests can survive a best-effort server
/// cancellation. Later cancellations withdraw delivery without forwarding an
/// abort that could suppress the only completion witness. Physical outstanding
/// requests remain bounded by sixteen, including those abandoned requests.
const WIRE_LIMIT: usize = ACTIVE_LIMIT * 2;
const FORWARDED_CANCELLATIONS: usize = ACTIVE_LIMIT;

fn forwarded_cancellation_limit(format: &str) -> usize {
    // The pinned Git SDK drops CancelScope::__exit__'s suppression result.
    // A wire abort during response backpressure kills its sibling tasks/stdio.
    // Withdraw locally and drain instead: keep the physical slot and deadline
    // until the original response arrives, without modifying the upstream server.
    if server_profile::git_selected(format) {
        0
    } else {
        FORWARDED_CANCELLATIONS
    }
}

async fn relay<R, W, S, T>(
    collector: &Collector<'_>,
    client: &mut R,
    host: &mut W,
    server: &mut S,
    child: &mut T,
    profile: &server_profile::ProfileConfig,
    git_view: Option<&server_profile::git::SelectedView>,
) -> anyhow::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    S: AsyncBufRead + Unpin,
    T: AsyncWrite + Unpin,
{
    let format = profile.format.as_str();
    let daemon_git = collector
        .config
        .native
        .git_execution_selected(&collector.config.server_id, profile)?;
    ensure!(
        !daemon_git
            || (server_profile::git_selected(format)
                && collector.prepared_budget.is_none()
                && collector.liveness.is_some()),
        "daemon Git execution requires selected Git, liveness and an independent execution budget"
    );
    let mut initialized = false;
    let mut notified = false;
    let mut ready = false;
    let mut control: Option<Control> = None;
    let mut calls: BTreeMap<String, Call> = BTreeMap::new();
    let mut create_slot = CreateSlot::default();
    let mut queue = VecDeque::new();
    let mut used = BTreeSet::new();
    let mut wire: BTreeMap<String, (Instant, bool)> = BTreeMap::new();
    let mut forwarded_cancellations = 0;
    let cancellation_limit = forwarded_cancellation_limit(format);
    let mut grants = BTreeSet::new();
    let mut workers: FuturesUnordered<Work<'_>> = FuturesUnordered::new();
    let mut profiles: BTreeMap<String, server_profile::ToolProfile> = BTreeMap::new();
    let mut snapshot: Option<Arc<Snapshot>> = None;
    let mut server_info = Value::Null;
    let mut client_partial = Vec::new();
    let mut server_frames = frames::ServerFrames::default();
    let mut messages = 0usize;
    let mut client_closed = false;
    loop {
        while counts(&calls).0 < ACTIVE_LIMIT {
            let Some(key) = queue.pop_front() else {
                break;
            };
            let Some(call) = calls.get_mut(&key) else {
                continue;
            };
            if !matches!(call.phase, Phase::Queued) {
                continue;
            }
            call.phase = Phase::Admitting;
            let input = detached(call);
            let current = snapshot
                .clone()
                .context("selected discovery snapshot unavailable")?;
            workers.push(Box::pin(async move {
                WorkEvent::Admitted(key, admit(collector, current, &input, profile).await)
            }));
        }
        if client_closed && calls.is_empty() && control.is_none() && workers.is_empty() {
            return Ok(());
        }
        let deadline = calls
            .values()
            .filter(|call| !call.cancelled)
            .map(|call| call.deadline)
            .chain(control.iter().map(|item| item.deadline))
            .chain(
                wire.iter()
                    .filter(|(key, (_, abandoned))| !*abandoned && !calls.contains_key(*key))
                    .map(|(_, (deadline, _))| *deadline),
            )
            .min()
            .unwrap_or_else(|| Instant::now() + super::IO_TIMEOUT);
        tokio::select! {
            biased;
            raw=line(client,&mut client_partial),if !client_closed=>{
                let Some(raw) = raw? else {
                    client_closed = true;
                    for call in calls.values_mut() {
                        if matches!(call.phase, Phase::Admitting | Phase::Queued) {
                            call.cancel.send_replace(true);
                            call.cancelled = true;
                        }
                    }
                    calls.retain(|_, call| !matches!(call.phase, Phase::Queued));
                    queue.clear();
                    continue;
                };
                let value = parse(&raw)?;
                bounded(&value, 0, &mut 0)?;
                keys(&value, &["jsonrpc", "id", "method", "params"])?;
                messages += 1;
                ensure!(messages <= MAX_MESSAGES, "selected MCP message count limit");
                let method = value["method"]
                    .as_str()
                    .context("selected MCP client method missing")?;
                let params = value.get("params").cloned().unwrap_or_else(|| json!({}));
                if method == "notifications/initialized" {
                    ensure!(
                        initialized && !notified && control.is_none() && value.get("id").is_none(),
                        "invalid initialized notification"
                    );
                    keys(&params, &[])?;
                    notified = true;
                    write(child, &raw).await?;
                    continue;
                }
                if method == "notifications/cancelled" {
                    ensure!(
                        value.get("id").is_none(),
                        "cancellation must be a notification"
                    );
                    keys(&params, &["requestId", "reason"])?;
                    let key = rpc_key(params.get("requestId").context("cancellation ID missing")?)?;
                    ensure!(
                        params
                            .get("reason")
                            .is_none_or(|reason| reason.as_str().is_some_and(|text| text.len() <= 1024)),
                        "invalid cancellation reason"
                    );
                    if let Some(call) = calls.get_mut(&key) {
                        if call.cancelled {
                            continue;
                        }
                        call.cancelled = true;
                        call.cancel.send_replace(true);
                        write(
                            host,
                            &error(
                                &call.id,
                                -32800,
                                "MCP request cancelled; dispatched execution may have occurred",
                            ),
                        )
                        .await?;
                        let phase = std::mem::replace(&mut call.phase, Phase::Reclaiming);
                        match phase {
                            Phase::Queued => {
                                calls.remove(&key);
                            }
                            Phase::Running(grant) => {
                                if forwarded_cancellations < cancellation_limit {
                                    forwarded_cancellations += 1;
                                    if let Some(item) = wire.get_mut(&key) {
                                        item.1 = true;
                                    }
                                    write(child,&frame(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":call.id}}))).await?;
                                }
                                let input = detached(call);
                                let worker_key = key.clone();
                                workers.push(Box::pin(async move {
                                    WorkEvent::Reclaimed(worker_key, reclaim(collector, &input, grant).await)
                                }));
                            }
                            #[cfg(target_os = "linux")]
                            Phase::Creating(grant) => {
                                let input = detached(call);
                                let worker_key = key.clone();
                                workers.push(Box::pin(async move {
                                    WorkEvent::Reclaimed(worker_key,
                                        reclaim(collector, &input, grant).await)
                                }));
                            }
                            #[cfg(target_os = "linux")]
                            Phase::Staging => { calls.remove(&key); }
                            Phase::Admitting => call.phase = Phase::Admitting,
                            Phase::Inspecting => call.phase = Phase::Inspecting,
                            Phase::Reclaiming => {}
                        }
                        if let Some(call) = calls.get(&key) {
                            let (active, queued) = counts(&calls);
                            audit(call, "cancelled", active, queued);
                        }
                    } else {
                        diagnostic!(
                            "{}",
                            json!({"event":"mcp_real_cancel","state":if used.contains(&key){"late"}else{"unknown"}})
                        );
                    }
                    continue;
                }
                if value.get("id").is_none() {
                    bail!("unsupported selected MCP client notification");
                }
                let request_id = &value["id"];
                let key = rpc_key(request_id)?;
                ensure!(used.len() < super::MAX_REQUESTS, "MCP request-count limit");
                if !used.insert(key.clone()) {
                    // A replayed/previously spent host ID must never reach
                    // another native admission. Preserve useful read/write
                    // peers instead of terminating the entire session.
                    write(host, &error(request_id, -32600,
                        "Replayed or spent MCP request ID refused")).await?;
                    continue;
                }
                if !params.is_object() {
                    write(
                        host,
                        &error(request_id, -32602, "MCP params must be an object"),
                    )
                    .await?;
                    continue;
                }
                match method {
                    "initialize" => {
                        ensure!(
                            !initialized && control.is_none(),
                            "MCP session already initialized"
                        );
                        keys(&params, &["protocolVersion", "capabilities", "clientInfo"])?;
                        ensure!(
                            params["protocolVersion"].is_string()
                                && params["capabilities"].is_object()
                                && params["clientInfo"].is_object(),
                            "invalid client initialization"
                        );
                        control = Some(Control {
                            id: request_id.clone(),
                            method: method.into(),
                            deadline: Instant::now() + super::IO_TIMEOUT,
                            host_id: request_id.clone(),
                            tools: Vec::new(),
                            cursors: BTreeSet::new(),
                            pages: 0,
                        });
                        write(child, &raw).await?;
                    }
                    "tools/list" | "ping" => {
                        if !initialized || !notified || control.is_some() || !calls.is_empty() {
                            write(
                                host,
                                &error(
                                    request_id,
                                    -32002,
                                    "MCP control request is busy or not initialized",
                                ),
                            )
                            .await?;
                            continue;
                        }
                        let valid = if method == "tools/list" {
                            keys(&params, &["_meta"]).and_then(|_| metadata(&params).map(|_| ()))
                        } else {
                            keys(&params, &[])
                        };
                        if valid.is_err() {
                            write(
                                host,
                                &error(request_id, -32602, "Unsupported MCP discovery parameters"),
                            )
                            .await?;
                            continue;
                        }
                        if method == "tools/list" {
                            ready = false;
                        }
                        control = Some(Control {
                            id: request_id.clone(),
                            method: method.into(),
                            deadline: Instant::now() + super::IO_TIMEOUT,
                            host_id: request_id.clone(),
                            tools: Vec::new(),
                            cursors: BTreeSet::new(),
                            pages: 0,
                        });
                        write(child, &raw).await?;
                    }
                    "tools/call" => {
                        if !ready || control.is_some() {
                            write(
                                host,
                                &error(
                                    request_id,
                                    -32002,
                                    "Operator-pinned MCP discovery is required",
                                ),
                            )
                            .await?;
                            continue;
                        }
                        if keys(&params, &["name", "arguments", "_meta"]).is_err() {
                            write(
                                host,
                                &error(request_id, -32602, "Unsupported MCP call parameters"),
                            )
                            .await?;
                            continue;
                        }
                        let Some(name) = params["name"].as_str() else {
                            write(
                                host,
                                &error(request_id, -32602, "MCP tool name is required"),
                            )
                            .await?;
                            continue;
                        };
                        let Some(tool_profile) = profiles.get(name) else {
                            write(
                                host,
                                &error(
                                    request_id,
                                    -32601,
                                    "MCP tool is not installed in this profile",
                                ),
                            )
                            .await?;
                            continue;
                        };
                        if tool_profile.unsupported_reason.is_some() {
                            write(
                                host,
                                &error(
                                    request_id,
                                    -32601,
                                    "MCP tool is explicitly unsupported in the read-only profile",
                                ),
                            )
                            .await?;
                            continue;
                        }
                        let args = params
                            .get("arguments")
                            .cloned()
                            .unwrap_or_else(|| json!({}));
                        let progress = match metadata(&params).and_then(|progress| {
                            tool_profile.validate_arguments(&args)?;
                            if format == server_profile::filesystem_create::FORMAT
                                && name == "write_file"
                            {
                                server_profile::filesystem_create::validate_request(&args)?;
                            }
                            Ok(progress)
                        }) {
                            Ok(progress) => progress,
                            Err(failure) => {
                                // Not dispatched. Fixed text names the boundary
                                // and never echoes the refused argument.
                                let message = match failure.downcast_ref::<server_profile::PathRefusal>() {
                                    Some(server_profile::PathRefusal::Outside) => PATH_OUTSIDE_MESSAGE,
                                    Some(server_profile::PathRefusal::Spelling) => PATH_SPELLING_MESSAGE,
                                    None => "MCP arguments violate the selected input profile",
                                };
                                write(host, &error(request_id, -32602, message)).await?;
                                continue;
                            }
                        };
                        if git_view.is_some_and(|view| view.validate_call(name, &args).is_err()) {
                            write(host, &error(request_id, -32602,
                                "Git local reference or file revision unavailable, unsupported, or its source changed")).await?;
                            continue;
                        }
                        // One original mutator at a time. Each selected
                        // create receives a new heavy isolated Node/owner
                        // process; native read-only calls stay concurrent.
                        let create_lease = if format == server_profile::filesystem_create::FORMAT
                            && name == "write_file" {
                            match create_slot.reserve() {
                                Some(lease) => Some(lease),
                                None => {
                                    write(host, &error(request_id, -32003,
                                        "An original create operation is already active")).await?;
                                    continue;
                                }
                            }
                        } else { None };
                        let (active, queued) = counts(&calls);
                        if active >= ACTIVE_LIMIT && queued >= QUEUE_LIMIT {
                            write(
                                host,
                                &error(request_id, -32003, "MCP pending-call limit reached"),
                            )
                            .await?;
                            continue;
                        }
                        #[cfg(target_os = "linux")]
                        let pinned_workspace = if format == server_profile::filesystem_create::FORMAT
                            && name == "write_file"
                        {
                            match crate::sandbox::PinnedWorkspace::open(&profile.workspace) {
                                Ok(workspace) => Some(Arc::new(workspace)),
                                Err(_) => {
                                    write(host, &error(request_id, -32603,
                                        "Original create workspace identity unavailable")).await?;
                                    continue;
                                }
                            }
                        } else {
                            None
                        };
                        let call = Call {
                            profile: format.to_owned(),
                            id: request_id.clone(),
                            tool: name.into(),
                            args,
                            request_sha256: sha(&raw),
                            raw,
                            create_lease,
                            phase: Phase::Queued,
                            cancelled: false,
                            cancel: tokio::sync::watch::channel(false).0,
                            dispatched: false,
                            deadline: Instant::now() + super::IO_TIMEOUT,
                            progress,
                            progress_count: 0,
                            last_progress: 0.0,
                            #[cfg(target_os = "linux")]
                            pinned_workspace,
                        };
                        audit(&call, "queued", active, queued + 1);
                        calls.insert(key.clone(), call);
                        queue.push_back(key);
                    }
                    _ => {
                        write(
                            host,
                            &error(
                                request_id,
                                -32601,
                                "MCP method is unsupported by the selected profile",
                            ),
                        )
                        .await?
                    }
                }
            },
            event=workers.next(),if !workers.is_empty()=>{
                match event.context("selected MCP worker stream ended")? {
                    WorkEvent::Admitted(key, result) => {
                        let Some(call) = calls.get_mut(&key) else {
                            bail!("unbound native admission completion");
                        };
                        // A disconnected host cannot authorize new execution.
                        // Reclaim any late native Allow rather than launching
                        // an ephemeral writer after the client has disappeared.
                        if client_closed {
                            call.cancelled = true;
                        }
                        match result? {
                            Decision::Refused(raw) => {
                                if !call.cancelled {
                                    write(host, &raw).await?;
                                }
                                calls.remove(&key);
                            }
                            Decision::Allowed(mut grant) => {
                                ensure!(
                                    grants.insert(id(&grant.call_id)?),
                                    "native receipt call ID was reused"
                                );
                                if !call.cancelled && git_view.is_some_and(|view| view.validate_call(&call.tool, &call.args).is_err()) {
                                    write(host, &error(&call.id, -32602, "Git local-reference view changed or target unsupported")).await?;
                                    call.cancelled = true;
                                }
                                if call.cancelled || wire.len() >= WIRE_LIMIT {
                                    if !call.cancelled {
                                        write(
                                            host,
                                            &error(&call.id, -32003, "MCP physical pending-call limit reached"),
                                        )
                                        .await?;
                                        call.cancelled = true;
                                    }
                                    call.phase = Phase::Reclaiming;
                                    let input = detached(call);
                                    let worker_key = key.clone();
                                    workers.push(Box::pin(async move {
                                        WorkEvent::Reclaimed(
                                            worker_key,
                                            reclaim(collector, &input, grant).await,
                                        )
                                    }));
                                } else {
                                    #[cfg(target_os = "linux")]
                                    if format == server_profile::filesystem_create::FORMAT
                                        && call.tool == "write_file"
                                    {
                                        // The installed server stays read-only.
                                        // Only an isolated fresh ORIGINAL server
                                        // can run the mutating upstream tool.
                                        let worker_key = key.clone();
                                        let args = call.args.clone();
                                        let runner = profile.clone();
                                        let lease = call.create_lease.clone();
                                        call.phase = Phase::Creating(grant);
                                        call.dispatched = true;
                                        // The external Linux acceptance can
                                        // observe actual post-admission creation
                                        // without exposing content or credentials.
                                        diagnostic!("{}", json!({
                                            "event":"mcp_original_create_state",
                                            "host_call_id":call.id,
                                            "state":"creating"
                                        }));
                                        workers.push(Box::pin(async move {
                                            WorkEvent::Created(worker_key,
                                                retain_create_slot(lease,
                                                    produce_original_create(&runner, &args)).await)
                                        }));
                                        continue;
                                    }
                                    if daemon_git && matches!(call.tool.as_str(), "git_show" | "git_diff") {
                                        // Do NOT also dispatch the tools/call to the collector's server.
                                        // The daemon consumes the admission and owns the one actual result pipe.
                                        let input = detached(call);
                                        let worker_key = key.clone();
                                        call.dispatched = true;
                                        call.phase = Phase::Inspecting;
                                        workers.push(Box::pin(async move {
                                            WorkEvent::Inspected(worker_key,
                                                execute_in_daemon(collector, &input, grant, profile).await)
                                        }));
                                        continue;
                                    }
                                    if let Some(context)=&collector.execution {
                                        grant.source=Some(Box::new(context.dispatched(&collector.session,
                                            grant.call_id.as_str().context("private native call")?,
                                            grant.binding.as_str().context("private native binding")?,&call.raw)?));
                                    }
                                    write(child, &call.raw).await?;
                                    call.dispatched = true;
                                    if let Some(timing) = &mut grant.continuation {
                                        timing.record(call, "original_dispatch", true);
                                    }
                                    drop(grant.boundary.take());
                                    call.phase = Phase::Running(grant);
                                    wire.insert(key.clone(), (call.deadline, false));
                                    let (active, queued) = counts(&calls);
                                    audit(&calls[&key], "inflight", active, queued);
                                }
                            }
                        }
                    }
                    #[cfg(target_os = "linux")]
                    WorkEvent::Created(key, produced) => {
                        let Some(call) = calls.get_mut(&key) else { continue; };
                        if call.cancelled { continue; }
                        if client_closed {
                            // A host EOF before native result release must
                            // spend the admission grant and drop the isolated
                            // output. No publication occurs and relay can exit.
                            let phase = std::mem::replace(&mut call.phase, Phase::Reclaiming);
                            let Phase::Creating(grant) = phase else {
                                bail!("orphaned original create without native grant");
                            };
                            let input = detached(call);
                            workers.push(Box::pin(async move {
                                WorkEvent::Reclaimed(key,
                                    reclaim(collector, &input, grant).await)
                            }));
                            continue;
                        }
                        let phase = std::mem::replace(&mut call.phase, Phase::Inspecting);
                        let Phase::Creating(grant) = phase else {
                            bail!("original create returned without its bound native grant");
                        };
                        let input = detached(call);
                        let worker_key = key.clone();
                        match produced {
                            Ok((raw, verified)) => {
                                // Internal original-server RPC always uses id=3.
                                // The host must receive its own opaque request ID.
                                // Only the JSON-RPC transport ID is changed;
                                // original result/error fields are untouched.
                                let mut decoded = parse(&raw)?;
                                ensure!(decoded["id"] == 3,
                                    "unexpected original-server response correlation");
                                decoded["id"] = call.id.clone();
                                let raw = frame(&decoded);
                                if let Some(verified) = verified {
                                    workers.push(Box::pin(async move {
                                        let receipt = inspect(collector, &input, grant, raw, "value").await;
                                        #[cfg(test)]
                                        fault_tests::pause_create_completion("inspected").await;
                                        WorkEvent::CreateInspected(worker_key,
                                            receipt, verified)
                                    }));
                                } else {
                                    // Preserve the valid ORIGINAL error. It
                                    // has no output/publication capability.
                                    workers.push(Box::pin(async move {
                                        WorkEvent::Inspected(worker_key,
                                            inspect(collector, &input, grant, raw, "error").await)
                                    }));
                                }
                            }
                            Err(_) => {
                                let failure = error(&call.id, -32603,
                                    "Original isolated MCP create failed; workspace unchanged");
                                workers.push(Box::pin(async move {
                                    WorkEvent::Inspected(worker_key,
                                        inspect(collector, &input, grant, failure, "error").await)
                                }));
                            }
                        }
                    }
                    #[cfg(target_os = "linux")]
                    WorkEvent::CreateInspected(key, receipt, output) => {
                        let Some(call) = calls.get_mut(&key) else { continue; };
                        if call.cancelled || client_closed {
                            calls.remove(&key);
                            continue;
                        }
                        if call.deadline <= Instant::now() {
                            write(host, &error(&call.id, -32001,
                                "Original create timed out before publication; no file committed")).await?;
                            calls.remove(&key);
                            continue;
                        }
                        let release = receipt?.context("native original-create result missing")?;
                        if !release.authorized {
                            write(host, &release.raw).await?;
                            calls.remove(&key);
                            continue;
                        }
                        if collector.is_uncertain() {
                            write(host, &error(&call.id, -32603,
                                "Native collector became uncertain before publication")).await?;
                            calls.remove(&key);
                            continue;
                        }
                        let prepared = call.pinned_workspace.as_deref()
                            .context("original create workspace pin not held")
                            .and_then(|workspace| output.prepare_atomic_publication(workspace));
                        let prepared = match prepared {
                            Ok(value) => value,
                            Err(_) => {
                                write(host, &error(&call.id, -32603,
                                    "Unsafe or existing original-create destination; no publication")).await?;
                                calls.remove(&key);
                                continue;
                            }
                        };
                        call.phase = Phase::Staging;
                        let lease = call.create_lease.clone();
                        workers.push(Box::pin(async move {
                            let stage = tokio::task::spawn_blocking(move || {
                                let _lease = lease;
                                prepared.stage()
                            })
                                .await.map_err(anyhow::Error::from)
                                .and_then(|value| value.map_err(anyhow::Error::from));
                            #[cfg(test)]
                            fault_tests::pause_create_completion("staged").await;
                            WorkEvent::CreateStaged(key, stage, release)
                        }));
                    }
                    #[cfg(target_os = "linux")]
                    WorkEvent::CreateStaged(key, stage, release) => {
                        let Some(call) = calls.get_mut(&key) else { continue; };
                        // Cancellation after native result Allow, but before
                        // linkat, closes only an anonymous stage.
                        if call.cancelled || client_closed {
                            calls.remove(&key);
                            continue;
                        }
                        if collector.is_uncertain() || call.deadline <= Instant::now() {
                            write(host, &error(&call.id,
                                if collector.is_uncertain() { -32603 } else { -32001 },
                                "Original create authority expired or became uncertain; no file committed")).await?;
                            calls.remove(&key);
                            continue;
                        }
                        // release owns the native result policy boundary until
                        // this synchronous publication point is finished.
                        match stage {
                            Ok(stage) => match stage.publish() {
                                Ok(result) if result.committed && result.file_synced
                                    && result.directory_synced => {
                                    diagnostic!("{}", json!({
                                        "event":"mcp_original_create_commit",
                                        "committed":true,
                                        "bytes":result.bytes_written,
                                        "content_disclosed":false
                                    }));
                                    write(host, &release.raw).await?;
                                }
                                Ok(_) => bail!("incomplete original-create publication"),
                                Err(publish_error) => {
                                    diagnostic!("{}", json!({
                                        "event":"mcp_original_create_commit",
                                        "committed":publish_error.committed,
                                        "bytes":publish_error.committed_bytes,
                                        "reason":publish_error.code,
                                        "content_disclosed":false
                                    }));
                                    write(host, &error(&call.id, -32603,
                                        if publish_error.committed {
                                            "Create failed after commit; file effect may remain"
                                        } else {
                                            "Create publication refused; no file committed"
                                        })).await?;
                                }
                            },
                            Err(_) => {
                                write(host, &error(&call.id, -32603,
                                    "Original create staging failed; no file committed")).await?;
                            }
                        }
                        calls.remove(&key);
                    }
                    WorkEvent::Inspected(key, result) => {
                        let call = calls
                            .remove(&key)
                            .context("unbound native result completion")?;
                        // A fresh daemon worker must not turn withdrawal of
                        // the original collector-held view into an uncorrelated
                        // transport failure. Keep the same sticky refusal even
                        // when that worker also refused its source snapshot.
                        let source_withdrawn = git_view.is_some_and(|view| view.validate_call(&call.tool, &call.args).is_err());
                        if source_withdrawn && !call.cancelled {
                            write(host, &error(&call.id, -32602, "Git local-reference view changed during execution")).await?;
                        }
                        // Preserve fatal retirement on transport/auth/audit or
                        // cleanup uncertainty, even after the correlated refusal.
                        let result = result?;
                        if !call.cancelled && !source_withdrawn {
                            if let Some(release) = result {
                                if git_view.is_some_and(|view| view.validate_call(&call.tool, &call.args).is_err()) {
                                    write(host, &error(&call.id, -32602, "Git local-reference view changed during execution")).await?;
                                } else {
                                    let delivery_started = Instant::now();
                                    let delivered = write(host, &release.raw).await;
                                    diagnostic!("{}", json!({"event":"mcp_original_result_delivery_timing","version":1,
                                        "host_call_sha256":sha(canonical(&call.id).to_string().as_bytes()),
                                        "request_sha256":call.request_sha256,"response_sha256":sha(&release.raw),
                                        "elapsed_us":delivery_started.elapsed().as_micros(),
                                        "written":delivered.is_ok(),"authority":false}));
                                    delivered?;
                                }
                            }
                        }
                        let (active, queued) = counts(&calls);
                        audit(&call, "finished", active, queued);
                    }
                    WorkEvent::Reclaimed(key, result) => {
                        result?;
                        calls
                            .remove(&key)
                            .context("unbound native cleanup completion")?;
                    }
                }
            },
            next=server_frames.next(server)=>{
                let raw = match next?.context("selected MCP server closed with incomplete state")? {
                    frames::Frame::Line(raw) => raw,
                    frames::Frame::Oversized(oversized) => {
                        // Complete and well-formed, but over the envelope
                        // budget: never buffered, parsed or released. The
                        // validated top-level ID binds it to one admitted call.
                        messages += 1;
                        ensure!(messages <= MAX_MESSAGES, "selected MCP message count limit");
                        let key = rpc_key(&oversized.id)?;
                        ensure!(
                            control.as_ref().is_none_or(|item| item.id != oversized.id),
                            OVERSIZED_CONTROL_ERROR
                        );
                        ensure!(
                            wire.remove(&key).is_some(),
                            "unknown or duplicate MCP response ID"
                        );
                        let Some(call) = calls.get_mut(&key) else {
                            continue;
                        };
                        let phase = std::mem::replace(&mut call.phase, Phase::Inspecting);
                        let Phase::Running(grant) = phase else {
                            ensure!(
                                call.cancelled,
                                "MCP response arrived in an invalid call phase"
                            );
                            continue;
                        };
                        diagnostic!(
                            "{}",
                            json!({"event":"mcp_real_result_withheld","host_call_id":call.id,
                                "limit":"result_frame_bytes","budget_bytes":server_profile::RESULT_FRAME_BYTES,
                                "observed_bytes":oversized.bytes,"released":false})
                        );
                        let input = detached(call);
                        let replacement = error(&call.id, -32603, FRAME_BUDGET_MESSAGE);
                        workers.push(Box::pin(async move {
                            WorkEvent::Inspected(
                                key,
                                inspect(collector, &input, grant, replacement, "error").await,
                            )
                        }));
                        continue;
                    }
                };
                let value = parse(&raw)?;
                bounded(&value, 0, &mut 0)?;
                messages += 1;
                ensure!(messages <= MAX_MESSAGES, "selected MCP message count limit");
                if let Some(method) = value.get("method").and_then(Value::as_str) {
                    keys(&value, &["jsonrpc", "id", "method", "params"])?;
                    if let Some(request_id) = value.get("id") {
                        rpc_key(request_id)?;
                        write(
                            child,
                            &error(
                                request_id,
                                -32601,
                                "Server callbacks are unsupported by this operator profile",
                            ),
                        )
                        .await?;
                    } else if method == "notifications/tools/list_changed" {
                        if let Some(params) = value.get("params") {
                            keys(params, &[])?;
                        }
                        ready = false;
                        write(host, &raw).await?;
                    } else if method == "notifications/progress" {
                        let params = &value["params"];
                        keys(params, &["progressToken", "progress", "total", "message"])?;
                        rpc_key(&params["progressToken"])?;
                        let progress = params["progress"]
                            .as_f64()
                            .filter(|p| p.is_finite() && *p >= 0.0)
                            .context("invalid MCP progress")?;
                        ensure!(
                            params.get("total").is_none_or(|total| total
                                .as_f64()
                                .is_some_and(|t| t.is_finite() && t >= progress)),
                            "invalid MCP progress total"
                        );
                        ensure!(
                            params
                                .get("message")
                                .is_none_or(|message| message.as_str().is_some_and(|m| m.len() <= 4096)),
                            "invalid MCP progress message"
                        );
                        let matching = calls
                            .values_mut()
                            .filter(|call| {
                                call.progress.as_ref() == Some(&params["progressToken"]) && !call.cancelled
                            })
                            .collect::<Vec<_>>();
                        if matching.len() == 1 {
                            for call in matching {
                                call.progress_count += 1;
                                ensure!(
                                    call.progress_count <= MAX_PROGRESS && progress >= call.last_progress,
                                    "MCP progress limit/order"
                                );
                                call.last_progress = progress;
                            }
                        }
                        // Progress/logging text has no independently admitted data
                        // channel. Consume it; never forward even a message field.
                        diagnostic!(
                            "{}",
                            json!({"event":"mcp_real_notification","kind":"progress","released":false})
                        );
                    } else {
                        diagnostic!(
                            "{}",
                            json!({"event":"mcp_real_notification","kind":"unsupported_or_logging","released":false})
                        );
                    }
                    continue;
                }
                keys(&value, &["jsonrpc", "id", "result", "error"])?;
                ensure!(
                    value.get("result").is_some() ^ value.get("error").is_some(),
                    "MCP response must contain exactly one result or error"
                );
                let key = rpc_key(value.get("id").context("server response ID missing")?)?;
                if control.as_ref().is_some_and(|item| item.id == value["id"]) {
                    let mut current = control.take().expect("checked control");
                    match current.method.as_str() {
                        "initialize" => {
                            ensure!(
                                value.get("error").is_none(),
                                "selected server initialization failed"
                            );
                            server_profile::validate_initialization_for(format, &value["result"])?;
                            server_info = value["result"]["serverInfo"].clone();
                            initialized = true;
                            write(host, &raw).await?;
                        }
                        "ping" => {
                            ensure!(value.get("error").is_none(), "selected server ping failed");
                            keys(&value["result"], &[])?;
                            write(host, &raw).await?;
                        }
                        "tools/list" => {
                            let result = &value["result"];
                            keys(result, &["tools", "nextCursor"])?;
                            let page = result["tools"]
                                .as_array()
                                .context("selected manifest tools absent")?;
                            current.pages += 1;
                            current.tools.extend(page.iter().cloned());
                            ensure!(
                                serde_json::to_vec(&current.tools)?.len()
                                    <= server_profile::MAX_DISCOVERY_BYTES,
                                "selected manifest aggregate byte limit"
                            );
                            ensure!(
                                current.pages <= server_profile::MAX_PAGES
                                    && current.tools.len() <= server_profile::MAX_TOOLS,
                                "selected manifest page/count limit"
                            );
                            if let Some(cursor) = result.get("nextCursor") {
                                let cursor = cursor
                                    .as_str()
                                    .filter(|s| !s.is_empty() && s.len() <= 1024)
                                    .context("invalid MCP manifest cursor")?;
                                ensure!(
                                    current.pages < server_profile::MAX_PAGES
                                        && current.cursors.insert(cursor.into()),
                                    "MCP manifest pagination repeated or over limit"
                                );
                                current.id = json!(format!("sw-page:{}", crate::token::generate()));
                                write(child,&frame(&json!({"jsonrpc":"2.0","id":current.id,"method":"tools/list","params":{"cursor":cursor}}))).await?;
                                control = Some(current);
                                continue;
                            }
                            let aggregate = json!({"tools":current.tools});
                            let validated = server_profile::classify_manifest_for(format, &aggregate);
                            match validated.and_then(|profiles| {
                                validate_registry(
                                    collector,
                                    &profiles,
                                    aggregate["tools"].as_array().expect("tools"),
                                    format,
                                )?;
                                Ok(profiles)
                            }) {
                                Err(_) => {
                                    write(
                                        host,
                                        &error(
                                            &current.host_id,
                                            -32603,
                                            "MCP manifest differs from the installed selected-server profile",
                                        ),
                                    )
                                    .await?;
                                }
                                Ok(validated) => {
                                    collector.inspect_manifest(&aggregate).await?;
                                    let mut admitted = BTreeMap::new();
                                    for tool in aggregate["tools"].as_array().expect("tools") {
                                        let name = tool["name"]
                                            .as_str()
                                            .context("manifest tool name missing")?;
                                        admitted.insert(
                                            name.into(),
                                            AdmittedTool {
                                                description: tool["description"].as_str().unwrap_or("").into(),
                                                schema: tool["inputSchema"].clone(),
                                                schema_sha256: sha(canonical(&tool["inputSchema"])
                                                    .to_string()
                                                    .as_bytes()),
                                                definition: tool.clone(),
                                                definition_sha256: sha(canonical(tool).to_string().as_bytes()),
                                            },
                                        );
                                    }
                                    snapshot = Some(Arc::new(Snapshot {
                                        sha256: sha(canonical(&aggregate).to_string().as_bytes()),
                                        tools: admitted,
                                        server_info: server_info.clone(),
                                    }));
                                    profiles = validated;
                                    ready = true;
                                    if current.pages == 1 {
                                        write(host, &raw).await?;
                                    } else {
                                        write(host,&frame(&json!({"jsonrpc":"2.0","id":current.host_id,"result":aggregate}))).await?;
                                    }
                                }
                            }
                        }
                        _ => unreachable!(),
                    }
                    continue;
                }
                ensure!(
                    wire.remove(&key).is_some(),
                    "unknown or duplicate MCP response ID"
                );
                let Some(call) = calls.get_mut(&key) else {
                    continue;
                };
                let phase = std::mem::replace(&mut call.phase, Phase::Inspecting);
                let Phase::Running(mut grant) = phase else {
                    ensure!(
                        call.cancelled,
                        "MCP response arrived in an invalid call phase"
                    );
                    continue;
                };
                if let Some(timing) = &mut grant.continuation {
                    timing.record(call, "original_response", value.get("result").is_some());
                }
                diagnostic!("{}", json!({"event":"mcp_call_outcome","version":1,
                    "stage":"original_response","request_sha256":call.request_sha256,
                    "host_call_sha256":sha(canonical(&call.id).to_string().as_bytes()),
                    "response_sha256":sha(&raw),"response":outcomes::response(&value),
                    "authority":false}));
                let input = detached(call);
                let worker_key = key.clone();
                let validated = profiles[&call.tool]
                    .validate_result(&value)
                    .map(str::to_owned);
                match validated {
                    Ok(kind) => {
                        if let Some(source)=grant.source.take() {
                            grant.original_result=Some(Box::new((*source).response(&raw)?));
                        }
                        workers.push(Box::pin(async move {
                            WorkEvent::Inspected(worker_key,
                                inspect(collector,&input,grant,raw,&kind).await)
                        }));
                    },
                    Err(failure) => {
                        // Unsupported output is never partially released. A local
                        // error completes this reservation and leaves other calls usable.
                        let budget = failure
                            .downcast_ref::<crate::mcp::input::ResultBudgetExceeded>()
                            .is_some();
                        if budget {
                            diagnostic!(
                                "{}",
                                json!({"event":"mcp_real_result_withheld","host_call_id":call.id,
                                    "limit":"result_text_bytes","budget_bytes":server_profile::RESULT_TEXT_BYTES,
                                    "observed_bytes":raw.len(),"released":false})
                            );
                        }
                        let replacement = error(
                            &call.id,
                            -32603,
                            if budget {
                                TEXT_BUDGET_MESSAGE
                            } else {
                                "Unsupported MCP result withheld by the selected output profile"
                            },
                        );
                        workers.push(Box::pin(async move {
                            WorkEvent::Inspected(
                                worker_key,
                                inspect(collector, &input, grant, replacement, "error").await,
                            )
                        }));
                    }
                }
            },
            _=tokio::time::sleep_until(deadline),if control.is_some()||!calls.is_empty()||wire.values().any(|(_,abandoned)|!*abandoned)=>{
                ensure!(
                    control
                        .as_ref()
                        .is_none_or(|item| item.deadline > Instant::now()),
                    "MCP control request timed out"
                );
                let expired = calls
                    .iter()
                    .filter(|(_, call)| !call.cancelled && call.deadline <= Instant::now())
                    .map(|(key, _)| key.clone())
                    .collect::<Vec<_>>();
                for key in expired {
                    let call = calls.get_mut(&key).expect("expired call");
                    call.cancelled = true;
                    call.cancel.send_replace(true);
                    write(
                        host,
                        &error(
                            &call.id,
                            -32001,
                            "MCP call timed out; dispatched execution may have occurred",
                        ),
                    )
                    .await?;
                    let phase = std::mem::replace(&mut call.phase, Phase::Reclaiming);
                    match phase {
                        Phase::Queued => {
                            calls.remove(&key);
                        }
                        Phase::Running(grant) => {
                            if forwarded_cancellations < cancellation_limit {
                                forwarded_cancellations += 1;
                                if let Some(item) = wire.get_mut(&key) {
                                    item.1 = true;
                                }
                                write(child,&frame(&json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":call.id}}))).await?;
                            }
                            let input = detached(call);
                            let worker_key = key.clone();
                            workers.push(Box::pin(async move {
                                WorkEvent::Reclaimed(worker_key, reclaim(collector, &input, grant).await)
                            }));
                        }
                        #[cfg(target_os = "linux")]
                        Phase::Creating(grant) => {
                            let input = detached(call);
                            let worker_key = key.clone();
                            workers.push(Box::pin(async move {
                                WorkEvent::Reclaimed(worker_key,
                                    reclaim(collector, &input, grant).await)
                            }));
                        }
                        #[cfg(target_os = "linux")]
                        Phase::Staging => { calls.remove(&key); }
                        Phase::Admitting => call.phase = Phase::Admitting,
                        Phase::Inspecting => call.phase = Phase::Inspecting,
                        Phase::Reclaiming => {}
                    }
                }
                ensure!(
                    wire.iter().all(|(key, (deadline, abandoned))| *abandoned
                        || *deadline > Instant::now()
                        || calls.contains_key(key)),
                    "MCP server did not finish a withdrawn request within its bound"
                );
            }
        }
    }
}

// Untrusted stderr remains withheld. These fixed markers and a streaming digest
// are operator diagnostics only, never authority or a reason to release output.
const STDERR_MARKERS: &[(&[u8], &str)] = &[
    (
        b"AssertionError: Request already responded to",
        "request_already_responded",
    ),
    (
        b"RuntimeError: RequestResponder must be used as a context manager",
        "responder_context_missing",
    ),
    (b"anyio.BrokenResourceError", "broken_resource"),
    (b"anyio.ClosedResourceError", "closed_resource"),
    (b"ExceptionGroup:", "exception_group"),
    (b"KeyError:", "key_error"),
    (b"PermissionError:", "permission_error"),
    (b"RuntimeError:", "runtime_error"),
    (b"FileNotFoundError:", "file_not_found"),
    (b"OSError:", "os_error"),
    (b"AssertionError:", "assertion_error"),
    (b"ValueError:", "value_error"),
    (b"TypeError:", "type_error"),
    (b"BrokenPipeError:", "broken_pipe"),
    (b"BlockingIOError:", "blocking_io"),
    (b"anyio.EndOfStream", "end_of_stream"),
];

#[derive(Default)]
struct StderrWitness {
    received: usize,
    digest: sha2::Sha256,
    tail: Vec<u8>,
    markers: BTreeSet<&'static str>,
}

fn relay_failure_code(error: &anyhow::Error) -> &'static str {
    // Match complete fixed strings only. Never copy arbitrary error details,
    // which may contain untrusted protocol data or operational paths/URLs.
    for cause in error.chain() {
        match cause.to_string().as_str() {
            "unknown or duplicate MCP response ID" => return "response_id_unbound",
            "MCP response arrived in an invalid call phase" => return "response_phase_invalid",
            "selected MCP server closed with incomplete state" => {
                return "server_closed_incomplete"
            }
            "MCP server did not finish a withdrawn request within its bound" => {
                return "withdrawn_request_incomplete"
            }
            "MCP control request timed out" => return "control_timeout",
            "MCP stdio write timed out" => return "stdio_write_timeout",
            "MCP admission unavailable" => return "admission_unavailable",
            "MCP admission request rejected" => return "admission_rejected",
            "MCP response must contain exactly one result or error" => {
                return "response_shape_invalid"
            }
            "server response ID missing" => return "response_id_missing",
            OVERSIZED_CONTROL_ERROR => return "control_frame_oversized",
            frames::DRAIN_BYTES_ERROR => return "result_drain_bytes",
            frames::DRAIN_TIME_ERROR => return "result_drain_time",
            frames::MALFORMED_ERROR => return "result_frame_malformed",
            frames::UNCORRELATED_ERROR => return "result_frame_uncorrelated",
            frames::UNTERMINATED_ERROR => return "server_frame_unterminated",
            _ => {}
        }
    }
    "unknown_transport_failure"
}

impl StderrWitness {
    fn observe(&mut self, bytes: &[u8]) {
        use sha2::Digest;
        self.received = self.received.saturating_add(bytes.len());
        self.digest.update(bytes);
        self.tail.extend_from_slice(bytes);
        for (needle, marker) in STDERR_MARKERS {
            if self
                .tail
                .windows(needle.len())
                .any(|window| window == *needle)
            {
                self.markers.insert(marker);
            }
        }
        // Preserve only enough overlap to recognize a marker split across reads.
        let keep = STDERR_MARKERS
            .iter()
            .map(|(value, _)| value.len())
            .max()
            .unwrap_or(1)
            - 1;
        if self.tail.len() > keep {
            self.tail.drain(..self.tail.len() - keep);
        }
    }

    fn metadata(&self, complete: bool) -> Value {
        use sha2::Digest;
        json!({"event":"mcp_real_stderr", "received_bytes":self.received,
            "sha256":format!("{:x}",self.digest.clone().finalize()),
            "markers":self.markers,"complete":complete,"released":false,
            "origin":"untrusted_server_stderr"})
    }
}

async fn drain_stderr(mut stream: tokio::process::ChildStderr) -> anyhow::Result<()> {
    use tokio::io::AsyncReadExt;
    let mut buffer = [0u8; 8192];
    let mut witness = StderrWitness::default();
    let result = async {
        loop {
            let count = stream.read(&mut buffer).await?;
            if count == 0 {
                return Ok(());
            }
            witness.observe(&buffer[..count]);
            ensure!(
                witness.received <= 1024 * 1024,
                "selected MCP server stderr quota exceeded"
            );
        }
    }
    .await;
    diagnostic!("{}", witness.metadata(result.is_ok()));
    result
}

pub(super) async fn run(
    collector: &Collector<'_>,
    profile: &server_profile::ProfileConfig,
    workspace: &std::path::Path,
) -> anyhow::Result<()> {
    #[cfg(unix)]
    let client = BufReader::new(crate::mcp::stdio::Pipe::stdin()?);
    #[cfg(unix)]
    let host = crate::mcp::stdio::Pipe::stdout()?;
    #[cfg(not(unix))]
    let client = BufReader::new(tokio::io::stdin());
    #[cfg(not(unix))]
    let host = tokio::io::stdout();
    // Legacy stdio owns the process-level termination handlers. An embedded
    // daemon session must use its own connection lifetime instead.
    #[cfg(unix)]
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("install selected collector termination handler")?;
    let shutdown = async {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => "native_mcp_interrupted",
            _ = async {
                #[cfg(unix)]
                sigterm.recv().await;
                #[cfg(not(unix))]
                std::future::pending::<()>().await;
            } => "native_mcp_terminated",
        }
    };
    run_streams(collector, profile, workspace, client, host, shutdown, true).await
}

/// One selected-server transport with explicitly owned host streams. This is
/// transport plumbing only: it does not authenticate a launch or mint evidence.
/// Shutdown still reaches the same owner, budget, process and stderr cleanup.
pub(super) async fn run_streams<R, W, F>(
    collector: &Collector<'_>,
    profile: &server_profile::ProfileConfig,
    workspace: &std::path::Path,
    mut client: R,
    host: W,
    shutdown: F,
    inherit_environment: bool,
) -> anyhow::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    F: Future<Output = &'static str>,
{
    tokio::pin!(shutdown);
    if let Some(reason) = shutdown.as_mut().now_or_never() {
        bail!(reason);
    }
    profile.validate_command(&collector.config.command, &collector.config.args, workspace)?;
    let selected_budget = collector.prepared_budget.as_ref();
    if collector
        .config
        .native
        .git_execution_selected(&collector.config.server_id, profile)?
    {
        ensure!(
            server_profile::git_selected(&profile.format)
                && selected_budget.is_none()
                && collector.liveness.is_some(),
            "daemon Git execution does not support prepared budget selection"
        );
    }
    ensure!(
        selected_budget.is_none() || profile.format != server_profile::filesystem_create::FORMAT,
        "prepared budgets do not support the original-create profile"
    );
    ensure!(
        !inherit_environment
            || selected_budget.is_some()
            || std::env::var_os(crate::pilot_budget::BINDING_ENV).is_none(),
        "pilot_budget_binding_required"
    );
    let mut budget_record = selected_budget
        .map(|selection| selection.reserve(&collector.config.server_id))
        .transpose()?;
    // Register before even preparing/starting the selected owner's namespace.
    // Stop spends grants under the same native lock, so a late registration
    // cannot start a server after an unenrolled grant was revoked.
    let cleanup_owner = if collector.host_session.is_some()
        && matches!(collector.config.server_id.as_str(), "filesystem" | "git")
    {
        collector.liveness.as_ref()
    } else {
        None
    };
    if let Some(owner) = cleanup_owner {
        owner.pilot_cleanup("begin").await?;
    }
    let bound = selected_budget.map(crate::pilot_budget::VerifiedSelection::bound);
    let prepared = match if let Some(reason) = shutdown.as_mut().now_or_never() {
        Err(anyhow::anyhow!(reason))
    } else if let Some(runtime) = collector.runtime() {
        server_sandbox::prepare_verified(profile, bound, runtime)
    } else if inherit_environment {
        server_sandbox::prepare_with_budget(profile, bound)
    } else {
        server_sandbox::prepare_explicit(profile, bound)
    } {
        Ok(prepared) => prepared,
        Err(error) => {
            if let Some(owner) = cleanup_owner {
                owner.pilot_cleanup("finish").await?;
            }
            return Err(error);
        }
    };
    ensure!(
        prepared.workspace() == workspace,
        "selected sandbox workspace changed"
    );
    if let Some(reason) = shutdown.as_mut().now_or_never() {
        if let Some(owner) = cleanup_owner {
            owner.pilot_cleanup("finish").await?;
        }
        bail!(reason);
    }
    let git_view = prepared.git_view();
    if let Some(context) = &collector.execution {
        context.preparing();
    }
    let (mut process, mut budget, mut owner, sandbox_pid) = prepared.spawn().await?;
    let context_bound = collector
        .execution
        .as_ref()
        .map(|context| context.bind(&owner))
        .unwrap_or(Ok(()));
    let attached = if let Some(budget) = budget.as_mut() {
        budget.verify_attached(sandbox_pid)
    } else {
        Ok(())
    };
    let boundary_failed = budget
        .as_ref()
        .map(super::super::linux_budget::OwnedBudget::failed)
        .unwrap_or_else(|| Arc::new(std::sync::atomic::AtomicBool::new(false)));
    let owner_failed = owner.failed();
    let budget_requested = budget.is_some();
    let budget_mode = if budget_requested {
        "enforced"
    } else {
        "unbudgeted"
    };
    let mut stderr_task = None;
    diagnostic!(
        "{}",
        json!({"event":"mcp_real_owner_start","owner":owner.metadata()})
    );
    diagnostic!(
        "{}",
        json!({"event":"mcp_real_budget_start","mode":budget_mode,
        "budget":budget.as_ref().map(super::super::linux_budget::OwnedBudget::metadata)})
    );
    diagnostic!(
        "{}",
        json!({"event":"mcp_real_server_start","profile":profile.format,
        "sandbox":server_sandbox::profile_name(&profile.format),"sandbox_workspace":server_sandbox::SANDBOX_WORKSPACE,
        "sandbox_pid":sandbox_pid,"owner":owner.metadata(),"resource_budget":budget_mode,
        "active_limit":ACTIVE_LIMIT,"queued_limit":QUEUE_LIMIT,"wire_limit":WIRE_LIMIT,
        "forwarded_cancellation_limit":forwarded_cancellation_limit(&profile.format)})
    );
    let operation = {
        let transport = async {
            attached?;
            context_bound?;
            owner.check()?;
            if let Some(context) = &collector.execution {
                context.check()?;
            }
            if let (Some(record), Some(budget)) = (&mut budget_record, &budget) {
                record.record(budget.metadata(), false)?;
            }
            let stderr = process
                .stderr
                .take()
                .context("selected server stderr missing")?;
            stderr_task = Some(tokio::spawn(drain_stderr(stderr)));
            let mut child = process
                .stdin
                .take()
                .context("selected server stdin missing")?;
            let mut server = BufReader::new(
                process
                    .stdout
                    .take()
                    .context("selected server stdout missing")?,
            );
            // The monitor publishes failure before waking its select arm. An
            // already pending host write must observe the same withdrawal;
            // cancelling the relay alone does not provide that ordering.
            let host = super::DiagnosticOutput {
                budget: None,
                inner: host,
                failed: Arc::clone(&boundary_failed),
                liveness: None,
            };
            let host = super::DiagnosticOutput {
                budget: None,
                inner: host,
                failed: Arc::clone(&owner_failed),
                liveness: collector.liveness.clone(),
            };
            let mut host = super::DiagnosticOutput {
                budget: None,
                inner: host,
                liveness: None,
                failed: collector
                    .execution
                    .as_ref()
                    .map(|context| context.withdrawn.clone())
                    .unwrap_or_else(|| Arc::new(std::sync::atomic::AtomicBool::new(false))),
            };
            let result = {
                let exchange = relay(
                    collector,
                    &mut client,
                    &mut host,
                    &mut server,
                    &mut child,
                    profile,
                    git_view.as_deref(),
                );
                tokio::pin!(exchange);
                tokio::select! {
                    result = &mut exchange => result,
                    drained = stderr_task.as_mut().expect("stderr task") => {
                        stderr_task = None;
                        drained.context("selected server stderr worker failed")??;
                        exchange.await
                    }
                }
            };
            if let Err(error) = &result {
                // Record the relay's actual first failure before stdin shutdown
                // can provoke a secondary wrapper/server exit. The owner select
                // arm can otherwise win while this shutdown is still pending.
                diagnostic!(
                    "{}",
                    json!({"event":"mcp_real_transport_failure",
                    "failure_code":relay_failure_code(error),"released":false})
                );
            }
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), child.shutdown()).await;
            drop(child);
            result
        };
        tokio::pin!(transport);
        let budget_monitor = async {
            if let Some(budget) = budget.as_ref() {
                budget.wait_failure().await
            } else {
                std::future::pending::<anyhow::Result<()>>().await
            }
        };
        // Both owners surround stderr EOF and stdin shutdown. Their failure
        // flags also guard the actual host write, including a pending write.
        tokio::select! {
            biased;
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
            } => Err(anyhow::anyhow!("native_liveness_uncertain")),
            failure = owner.wait_failure() => match failure {
                Err(error) => Err(error),
                Ok(()) => Err(anyhow::anyhow!("mcp_owner_monitor_stopped")),
            },
            failure = budget_monitor => match failure {
                Err(error) => Err(error),
                Ok(()) => Err(anyhow::anyhow!("mcp_budget_monitor_stopped")),
            },
            reason = shutdown => Err(anyhow::anyhow!(reason)),
            result = &mut transport => result,
        }
    };
    // Check once more when useful transport and a controller event become ready
    // together. This reports observed uncertainty; it cannot retract a result
    // or effect committed before that observation.
    let budget_check = budget
        .as_ref()
        .map(super::super::linux_budget::OwnedBudget::check)
        .unwrap_or(Ok(()));
    let budget_failed =
        boundary_failed.load(std::sync::atomic::Ordering::Acquire) || budget_check.is_err();
    let owner_check = owner.check();
    // Record expected shutdown before the independent quota owner kills its
    // leaf. The guardian acknowledges only after observing any earlier fault.
    let owner_quiesce = owner.quiesce().await;
    // Always attempt all independent cleanup boundaries. In particular a
    // cgroup failure cannot skip group termination/reaping or the stderr join.
    let budget_cleanup = if let Some(budget) = budget.as_mut() {
        budget.finish().await
    } else {
        Ok(())
    };
    let owner_cleanup = owner.finish().await;
    let cleanup = server_sandbox::terminate(&mut process).await;
    let stderr_cleanup = if let Some(mut task) = stderr_task {
        match tokio::time::timeout(std::time::Duration::from_secs(1), &mut task).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) => Err(error),
            Ok(Err(error)) => Err(anyhow::anyhow!(
                "selected server stderr worker failed: {error}"
            )),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(anyhow::anyhow!("selected server stderr did not close"))
            }
        }
    } else {
        Ok(())
    };
    let budget_failed = budget_failed || boundary_failed.load(std::sync::atomic::Ordering::Acquire);
    let owner_failed = owner_failed.load(std::sync::atomic::Ordering::Acquire)
        || owner_check.is_err()
        || owner_quiesce.is_err();
    diagnostic!(
        "{}",
        json!({"event":"mcp_real_owner_end","owner":owner.metadata(),
        "cleanup_verified":owner_cleanup.is_ok(),"observed_failure":owner_failed})
    );
    diagnostic!(
        "{}",
        json!({"event":"mcp_real_budget_end","mode":budget_mode,
        "budget":budget.as_ref().map(super::super::linux_budget::OwnedBudget::metadata),
        "cleanup_verified":budget_cleanup.is_ok(),"observed_failure":budget_failed})
    );
    diagnostic!(
        "{}",
        json!({"event":"mcp_real_server_end","profile":profile.format,
        "budget_requested":budget_requested,"budget_cleanup_verified":budget_cleanup.is_ok(),
        "budget_failure_observed":budget_failed,
        "owner":owner.metadata(),"owner_cleanup_verified":owner_cleanup.is_ok(),
        "owner_failure_observed":owner_failed,
        "cleanup_verified":cleanup.is_ok()&&stderr_cleanup.is_ok()&&budget_cleanup.is_ok()&&owner_cleanup.is_ok(),
        "transport_complete":operation.is_ok()&&budget_check.is_ok()&&!budget_failed&&!owner_failed
            &&cleanup.is_ok()&&stderr_cleanup.is_ok()&&budget_cleanup.is_ok()&&owner_cleanup.is_ok()})
    );
    // Only the existing independent owner/budget/reap/stderr boundaries can
    // discharge this obligation. A transport error (including revoked lease)
    // does not prevent cleanup confirmation, and a failed boundary never does.
    let record_result = if let (Some(record), Some(budget)) = (&mut budget_record, &budget) {
        record.record(budget.metadata(), true)
    } else {
        Ok(())
    };
    let cleanup_confirmation = if cleanup.is_ok()
        && stderr_cleanup.is_ok()
        && budget_cleanup.is_ok()
        && owner_cleanup.is_ok()
    {
        if let Some(owner) = cleanup_owner {
            owner.pilot_cleanup("finish").await
        } else {
            Ok(())
        }
    } else {
        Err(anyhow::anyhow!("pilot_cleanup_unconfirmed"))
    };
    if cleanup_confirmation.is_ok() {
        if let Some(context) = &collector.execution {
            context.cleaned();
        }
    }
    cleanup_confirmation?;
    record_result?;
    operation?;
    budget_check?;
    owner_check?;
    owner_quiesce?;
    ensure!(!budget_failed, "mcp_budget_boundary_failed");
    ensure!(!owner_failed, "mcp_owner_boundary_failed");
    budget_cleanup?;
    owner_cleanup?;
    cleanup?;
    stderr_cleanup?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn original_create_cancelled_call_keeps_slot_until_producer_cleanup() {
        let mut slot = CreateSlot::default();
        let call = slot.reserve().unwrap();
        let reclaim = call.clone();
        let (finish, cleanup) = tokio::sync::oneshot::channel::<()>();
        let worker = tokio::spawn(retain_create_slot(Some(call.clone()), async move {
            cleanup.await.unwrap();
        }));
        // Native reclamation and logical removal do not stop the isolated
        // producer. A fresh writer must wait for its real cleanup completion.
        drop(call);
        drop(reclaim);
        assert!(slot.reserve().is_none());
        finish.send(()).unwrap();
        worker.await.unwrap();
        assert!(slot.reserve().is_some());
    }

    #[tokio::test]
    async fn original_create_blocking_stage_keeps_slot_after_waiter_is_aborted() {
        let mut slot = CreateSlot::default();
        let call = slot.reserve().unwrap();
        let stage_lease = call.clone();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (finish, cleanup) = std::sync::mpsc::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let _lease = stage_lease;
            started.send(()).unwrap();
            cleanup.recv().unwrap();
        });
        let waiter = tokio::spawn(async move { worker.await.unwrap() });
        ready.await.unwrap();
        waiter.abort();
        let _ = waiter.await;
        drop(call);
        assert!(slot.reserve().is_none());
        finish.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while slot.reserve().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn closed_diagnostic_pipe_cannot_abort_stderr_cleanup() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        const PROBE: &str = "AGENTFW_OWNED_CLOSED_DIAGNOSTIC_PROBE";
        if std::env::var_os(PROBE).is_some() {
            // The parent closes the stderr reader before releasing this child.
            let mut ready = [0u8; 1];
            std::io::Read::read_exact(&mut std::io::stdin(), &mut ready).unwrap();
            assert_eq!(ready, [1]);
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                for (script, expect_quota) in [
                    ("printf owned-stderr >&2", false),
                    ("/usr/bin/head -c 1048577 /dev/zero >&2", true),
                ] {
                    let mut child = tokio::process::Command::new("/bin/sh")
                        .args(["-c", script])
                        .stderr(Stdio::piped())
                        .kill_on_drop(true)
                        .spawn()
                        .unwrap();
                    let result = drain_stderr(child.stderr.take().unwrap()).await;
                    child.wait().await.unwrap();
                    if expect_quota {
                        assert!(result
                            .unwrap_err()
                            .to_string()
                            .contains("selected MCP server stderr quota exceeded"));
                    } else {
                        result.unwrap();
                    }
                }
            });
            println!("owned-stderr-drain-and-quota-preserved");
            return;
        }
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "mcp::admission::real_server::tests::closed_diagnostic_pipe_cannot_abort_stderr_cleanup",
                "--nocapture",
            ])
            .env(PROBE, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        drop(child.stderr.take());
        child.stdin.take().unwrap().write_all(&[1]).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("owned closed-diagnostic subprocess did not finish");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success(), "closed stderr aborted cleanup");
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .contains("owned-stderr-drain-and-quota-preserved"));
    }

    #[test]
    fn relay_failure_metadata_does_not_echo_untrusted_context_or_suffixes() {
        let error = anyhow::anyhow!("unknown or duplicate MCP response ID")
            .context("private URL and payload");
        assert_eq!(relay_failure_code(&error), "response_id_unbound");
        let error = anyhow::anyhow!("unknown or duplicate MCP response ID: private payload");
        assert_eq!(relay_failure_code(&error), "unknown_transport_failure");
        assert_eq!(
            relay_failure_code(&anyhow::anyhow!("arbitrary private payload")),
            "unknown_transport_failure"
        );
    }
    #[test]
    fn stderr_witness_matches_split_markers_but_never_serializes_untrusted_bytes() {
        for (needle, marker) in STDERR_MARKERS {
            for split in 0..=needle.len() {
                let mut witness = StderrWitness::default();
                witness.observe(b"private arbitrary path and MCP payload ");
                witness.observe(&needle[..split]);
                witness.observe(&needle[split..]);
                witness.observe(b" secret tail");
                let value = witness.metadata(true);
                assert!(value["markers"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|value| value == marker));
                let output = value.to_string();
                assert!(!output.contains("private arbitrary"));
                assert!(!output.contains("secret tail"));
                assert_eq!(value["released"], false);
                assert_eq!(value["origin"], "untrusted_server_stderr");
            }
        }
        let mut witness = StderrWitness::default();
        for _ in 0..128 {
            witness.observe(&[b'x'; 8192]);
        }
        assert_eq!(witness.received, 1024 * 1024);
        assert!(witness.tail.len() < 128);
        assert!(witness.metadata(false)["markers"]
            .as_array()
            .unwrap()
            .is_empty());
        assert_eq!(
            witness.metadata(false)["sha256"],
            sha(&vec![b'x'; 1024 * 1024])
        );
    }
    #[test]
    fn ids_keep_json_type_and_refuse_unsafe_numbers() {
        assert_ne!(rpc_key(&json!(1)).unwrap(), rpc_key(&json!("1")).unwrap());
        for invalid in [
            Value::Null,
            json!(1.5),
            json!(9_007_199_254_740_992u64),
            json!(""),
            json!("x".repeat(129)),
        ] {
            assert!(rpc_key(&invalid).is_err());
        }
    }
    #[test]
    fn metadata_does_not_supply_authority_and_accepts_optional_progress() {
        assert_eq!(metadata(&json!({})).unwrap(), None);
        assert_eq!(
            metadata(&json!({"_meta":{"progressToken":"call1"}})).unwrap(),
            Some(json!("call1"))
        );
        assert!(metadata(&json!({"_meta":{"nativeAllow":true}})).is_err());
        assert!(
            metadata(&json!({"_meta":{"threadId":"one","claudecode/toolUseId":"two"}})).is_err()
        );
    }
    #[test]
    fn json_limits_and_cancellation_errors_are_explicit() {
        let mut value = json!(0);
        for _ in 0..=MAX_JSON_DEPTH {
            value = json!([value]);
        }
        assert!(bounded(&value, 0, &mut 0).is_err());
        let value = parse(&error(&json!(17), -32800, "Execution may have occurred")).unwrap();
        assert_eq!(value["id"], 17);
        assert_eq!(value["error"]["code"], -32800);
    }
}

#[cfg(test)]
mod fault_tests;
