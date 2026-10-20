// SPDX-License-Identifier: Apache-2.0
//! Explicit selected-server transport. Legacy brokered executors retain their loop.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{bail, ensure, Context};
use futures_util::stream::{FuturesUnordered, StreamExt};
use serde_json::{json, Value};
use tokio::io::{AsyncBufRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::time::Instant;

use super::{canonical, id, keys, line, not_classified, parse, sha, withheld, write};
use super::{AdmittedTool, ClassificationAuthority, Collector, ProductionVerdict, Snapshot};
use crate::mcp::{server_profile, server_sandbox};
use crate::native::CONTRACT;

pub(super) const ACTIVE_LIMIT: usize = 8;
pub(super) const QUEUE_LIMIT: usize = 8;
const MAX_MESSAGES: usize = 8192;
const MAX_PROGRESS: usize = 128;
const MAX_JSON_DEPTH: usize = 20;
const MAX_JSON_NODES: usize = 16_384;

struct Grant {
    call_id: Value,
    binding: Value,
    boundary: Option<crate::policy_transition::Boundary>,
}

struct Release {
    raw: Vec<u8>,
    _boundary: Option<crate::policy_transition::Boundary>,
}

enum Phase {
    Queued,
    Admitting,
    Running(Grant),
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
}

enum Decision {
    Refused(Vec<u8>),
    Allowed(Grant),
}

enum WorkEvent {
    Admitted(String, anyhow::Result<Decision>),
    Inspected(String, anyhow::Result<Option<Release>>),
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
    eprintln!(
        "{}",
        json!({"event":"mcp_real_call","profile":call.profile,
        "host_call_id":call.id,"id_type":if call.id.is_string(){"string"}else{"integer"},
        "state":state,"active":active,"queued":queued,"execution_dispatched":call.dispatched,
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
                egress_declared: false,
                create_file_profile: None,
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
    if !assessment.known_read_only {
        return Ok(refusal("classifier_unknown_approval_unsupported"));
    }
    let mut boundary = collector.policy_boundary().await?;
    let mut fields = json!({"tool":call.tool,"args":call.args,
        "schema_sha256":installed.schema_sha256,"mcp_host_call_id":call.id});
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
        let Some(classifier) = &collector.config.classifier else {
            return Ok(refusal("native_approval_classifier_identity_required"));
        };
        let Some(classifier_digest) = classifier
            .revision()
            .filter(|digest| crate::native::is_digest(digest))
        else {
            return Ok(refusal("native_approval_classifier_identity_required"));
        };
        // This increment requires the accepted host/agent capability and live
        // collector owner. Plain legacy sessions keep their correlated refusal.
        if collector.host_session.is_none() || collector.liveness.is_none() {
            return Ok(refusal("native_approval_bound_owner_required"));
        }
        let definition = snapshot
            .tools
            .get(&call.tool)
            .context("selected definition missing")?;
        let context = crate::native::approval::SelectedInvocation {
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
                &snapshot,
                definition,
                &call.tool,
                &call.args,
                classifier.source(),
                classifier.revision(),
            ),
        };
        let approval_id =
            match wait_approval(collector, call, source, &installed.schema_sha256, &context).await?
            {
                Ok(id) => id,
                Err(code) => return Ok(refusal(&code)),
            };
        let resumed = async {
            let frozen = profile.clone();
            tokio::task::spawn_blocking(move || frozen.revalidate_assets()).await??;
            boundary = collector.policy_boundary().await?;
            let reassessed = collector
                .classify(
                    &snapshot,
                    &call.id,
                    &call.tool,
                    &call.args,
                    installed.action_class,
                    ClassificationAuthority {
                        egress_declared: false,
                        create_file_profile: None,
                        https_get: false,
                    },
                )
                .await?;
            ensure!(
                reassessed.is_ok_and(
                    |value| value.known_read_only && value.verdict != ProductionVerdict::Deny
                ),
                "selected approval reclassification refused"
            );
            ensure!(
                !*call.cancel.borrow() && Instant::now() < call.deadline,
                "selected approval cancelled before dispatch"
            );
            fields["approval_id"] = json!(approval_id);
            fields["selected_invocation"] = json!(context);
            collector.event("call", fields).await
        }
        .await;
        // Idempotent cancellation also removes an approved but unused grant.
        // Successful redemption is already terminal; this cannot undo effects.
        collector.cancel_approval(&approval_id).await?;
        receipt = Some(match resumed {
            Ok(receipt) => receipt,
            Err(_) => return Ok(refusal("native_approval_revalidation_refused")),
        });
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
        call_id: receipt["call_id"].clone(),
        binding: receipt["binding_sha256"].clone(),
        boundary,
    }))
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
    eprintln!(
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
    grant: Grant,
    raw: Vec<u8>,
    kind: &str,
) -> anyhow::Result<Option<Release>> {
    let boundary = collector.policy_boundary().await?;
    let content = std::str::from_utf8(&raw).context("selected MCP result is not UTF-8")?;
    let receipt = collector.event("result",json!({"tool":call.tool,"args":call.args,
        "call_id":grant.call_id,"expected_binding_sha256":grant.binding,
        "expected_contract_version":CONTRACT,"result_kind":kind,"delivery":"mcp_host","content":content})).await?;
    let raw = if receipt["release"] == true {
        raw
    } else {
        withheld(&call.id, "result", &receipt["reason_codes"])
    };
    Ok(Some(Release {
        raw,
        _boundary: boundary,
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
        server_profile::FORMAT => server_profile::git::FORMAT,
        server_profile::git::FORMAT => server_profile::FORMAT,
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
            ensure!(
                tool.action_class == soup_wall_agent::ActionClass::ReadOnly
                    && tool.egress.is_empty()
                    && matches!(
                        tool.result_provenance,
                        crate::native::ResultProvenance::Untrusted
                    )
                    && tool.mcp_result_profile.as_deref() == Some(expected_format),
                "selected read authority is not explicitly installed"
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
                "selected read tool is not installed"
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
    if format == server_profile::git::FORMAT {
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
) -> anyhow::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    S: AsyncBufRead + Unpin,
    T: AsyncWrite + Unpin,
{
    let format = profile.format.as_str();
    let mut initialized = false;
    let mut notified = false;
    let mut ready = false;
    let mut control: Option<Control> = None;
    let mut calls: BTreeMap<String, Call> = BTreeMap::new();
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
    let mut server_partial = Vec::new();
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
                            Phase::Admitting => call.phase = Phase::Admitting,
                            Phase::Inspecting => call.phase = Phase::Inspecting,
                            Phase::Reclaiming => {}
                        }
                        if let Some(call) = calls.get(&key) {
                            let (active, queued) = counts(&calls);
                            audit(call, "cancelled", active, queued);
                        }
                    } else {
                        eprintln!(
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
                ensure!(
                    used.len() < super::MAX_REQUESTS && used.insert(key.clone()),
                    "duplicate MCP ID or request-count limit"
                );
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
                        let Some(profile) = profiles.get(name) else {
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
                        if profile.unsupported_reason.is_some() {
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
                            profile.validate_arguments(&args)?;
                            Ok(progress)
                        }) {
                            Ok(progress) => progress,
                            Err(_) => {
                                write(
                                    host,
                                    &error(
                                        request_id,
                                        -32602,
                                        "MCP arguments violate the selected input profile",
                                    ),
                                )
                                .await?;
                                continue;
                            }
                        };
                        let (active, queued) = counts(&calls);
                        if active >= ACTIVE_LIMIT && queued >= QUEUE_LIMIT {
                            write(
                                host,
                                &error(request_id, -32003, "MCP pending-call limit reached"),
                            )
                            .await?;
                            continue;
                        }
                        let call = Call {
                            profile: format.to_owned(),
                            id: request_id.clone(),
                            tool: name.into(),
                            args,
                            request_sha256: sha(&raw),
                            raw,
                            phase: Phase::Queued,
                            cancelled: false,
                            cancel: tokio::sync::watch::channel(false).0,
                            dispatched: false,
                            deadline: Instant::now() + super::IO_TIMEOUT,
                            progress,
                            progress_count: 0,
                            last_progress: 0.0,
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
                                    write(child, &call.raw).await?;
                                    call.dispatched = true;
                                    drop(grant.boundary.take());
                                    call.phase = Phase::Running(grant);
                                    wire.insert(key.clone(), (call.deadline, false));
                                    let (active, queued) = counts(&calls);
                                    audit(&calls[&key], "inflight", active, queued);
                                }
                            }
                        }
                    }
                    WorkEvent::Inspected(key, result) => {
                        let call = calls
                            .remove(&key)
                            .context("unbound native result completion")?;
                        let result = result?;
                        if !call.cancelled {
                            if let Some(release) = result {
                                write(host, &release.raw).await?;
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
            raw=line(server,&mut server_partial)=>{
                let raw = raw?.context("selected MCP server closed with incomplete state")?;
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
                        eprintln!(
                            "{}",
                            json!({"event":"mcp_real_notification","kind":"progress","released":false})
                        );
                    } else {
                        eprintln!(
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
                let Phase::Running(grant) = phase else {
                    ensure!(
                        call.cancelled,
                        "MCP response arrived in an invalid call phase"
                    );
                    continue;
                };
                let input = detached(call);
                let worker_key = key.clone();
                let validated = profiles[&call.tool]
                    .validate_result(&value)
                    .map(str::to_owned);
                match validated {
                    Ok(kind) => workers.push(Box::pin(async move {
                        WorkEvent::Inspected(
                            worker_key,
                            inspect(collector, &input, grant, raw, &kind).await,
                        )
                    })),
                    Err(_) => {
                        // Unsupported output is never partially released. A local
                        // error completes this reservation and leaves other calls usable.
                        let replacement = error(
                            &call.id,
                            -32603,
                            "Unsupported MCP result withheld by the selected output profile",
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
    eprintln!("{}", witness.metadata(result.is_ok()));
    result
}

pub(super) async fn run(
    collector: &Collector<'_>,
    profile: &server_profile::ProfileConfig,
    workspace: &std::path::Path,
) -> anyhow::Result<()> {
    profile.validate_command(&collector.config.command, &collector.config.args, workspace)?;
    let prepared = server_sandbox::prepare(profile)?;
    ensure!(
        prepared.workspace() == workspace,
        "selected sandbox workspace changed"
    );
    let (mut process, mut budget, mut owner, sandbox_pid) = prepared.spawn().await?;
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
    eprintln!(
        "{}",
        json!({"event":"mcp_real_owner_start","owner":owner.metadata()})
    );
    eprintln!(
        "{}",
        json!({"event":"mcp_real_budget_start","mode":budget_mode,
        "budget":budget.as_ref().map(super::super::linux_budget::OwnedBudget::metadata)})
    );
    eprintln!(
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
            owner.check()?;
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
            #[cfg(unix)]
            let mut client = BufReader::new(crate::mcp::stdio::Pipe::stdin()?);
            #[cfg(unix)]
            let host = crate::mcp::stdio::Pipe::stdout()?;
            #[cfg(not(unix))]
            let mut client = BufReader::new(tokio::io::stdin());
            #[cfg(not(unix))]
            let host = tokio::io::stdout();
            // The monitor publishes failure before waking its select arm. An
            // already pending host write must observe the same withdrawal;
            // cancelling the relay alone does not provide that ordering.
            let host = super::DiagnosticOutput {
                budget: None,
                inner: host,
                failed: Arc::clone(&boundary_failed),
                liveness: None,
            };
            let mut host = super::DiagnosticOutput {
                budget: None,
                inner: host,
                failed: Arc::clone(&owner_failed),
                liveness: collector.liveness.clone(),
            };
            let result = {
                let exchange = relay(
                    collector,
                    &mut client,
                    &mut host,
                    &mut server,
                    &mut child,
                    profile,
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
                eprintln!(
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
            _ = tokio::signal::ctrl_c() => Err(anyhow::anyhow!("native_mcp_interrupted")),
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
    eprintln!(
        "{}",
        json!({"event":"mcp_real_owner_end","owner":owner.metadata(),
        "cleanup_verified":owner_cleanup.is_ok(),"observed_failure":owner_failed})
    );
    eprintln!(
        "{}",
        json!({"event":"mcp_real_budget_end","mode":budget_mode,
        "budget":budget.as_ref().map(super::super::linux_budget::OwnedBudget::metadata),
        "cleanup_verified":budget_cleanup.is_ok(),"observed_failure":budget_failed})
    );
    eprintln!(
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
