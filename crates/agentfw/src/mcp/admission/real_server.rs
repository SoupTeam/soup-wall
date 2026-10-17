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

#[derive(Clone)]
struct Grant {
    call_id: Value,
    binding: Value,
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
    phase: Phase,
    cancelled: bool,
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
    Inspected(String, anyhow::Result<Option<Vec<u8>>>),
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
) -> anyhow::Result<Decision> {
    let installed = collector
        .config
        .native
        .registry
        .tools
        .iter()
        .find(|tool| tool.name == call.tool)
        .context("selected MCP registry tool missing")?;
    match collector
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
        Ok(ProductionVerdict::Ask) => {
            return Ok(Decision::Refused(withheld(
                &call.id,
                "invocation",
                &json!(["classifier_ask"]),
            )))
        }
        Ok(ProductionVerdict::Deny) => {
            return Ok(Decision::Refused(withheld(
                &call.id,
                "invocation",
                &json!(["classifier_deny"]),
            )))
        }
        Ok(ProductionVerdict::Allow) => {}
    }
    let receipt = collector
        .event(
            "call",
            json!({"tool":call.tool,"args":call.args,
        "schema_sha256":installed.schema_sha256,"mcp_host_call_id":call.id}),
        )
        .await?;
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
    }))
}

async fn inspect(
    collector: &Collector<'_>,
    call: &Call,
    grant: Grant,
    raw: Vec<u8>,
    kind: &str,
) -> anyhow::Result<Option<Vec<u8>>> {
    let content = std::str::from_utf8(&raw).context("selected MCP result is not UTF-8")?;
    let receipt = collector.event("result",json!({"tool":call.tool,"args":call.args,
        "call_id":grant.call_id,"expected_binding_sha256":grant.binding,
        "expected_contract_version":CONTRACT,"result_kind":kind,"delivery":"mcp_host","content":content})).await?;
    Ok(Some(if receipt["release"] == true {
        raw
    } else {
        withheld(&call.id, "result", &receipt["reason_codes"])
    }))
}

async fn reclaim(collector: &Collector<'_>, call: &Call, grant: Grant) -> anyhow::Result<()> {
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
        phase: Phase::Admitting,
        cancelled: call.cancelled,
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
    for tool in &collector.config.native.registry.tools {
        let definition = tools
            .iter()
            .find(|value| value["name"] == tool.name)
            .context("selected registry contains an unadvertised tool")?;
        ensure!(
            tool.schema_sha256 == sha(canonical(&definition["inputSchema"]).to_string().as_bytes()),
            "selected registry schema pin changed"
        );
        ensure!(
            tool.resource_policy.is_none(),
            "selected server cannot acquire built-in resource authority"
        );
        if profiles[&tool.name].unsupported_reason.is_none() {
            ensure!(
                tool.action_class == soup_wall_agent::ActionClass::ReadOnly
                    && tool.egress.is_empty()
                    && matches!(
                        tool.result_provenance,
                        crate::native::ResultProvenance::Untrusted
                    )
                    && tool.mcp_result_profile.as_deref() == Some(format),
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

async fn relay<R, W, S, T>(
    collector: &Collector<'_>,
    client: &mut R,
    host: &mut W,
    server: &mut S,
    child: &mut T,
    format: &str,
) -> anyhow::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    S: AsyncBufRead + Unpin,
    T: AsyncWrite + Unpin,
{
    let mut initialized = false;
    let mut notified = false;
    let mut ready = false;
    let mut control: Option<Control> = None;
    let mut calls: BTreeMap<String, Call> = BTreeMap::new();
    let mut queue = VecDeque::new();
    let mut used = BTreeSet::new();
    let mut wire: BTreeMap<String, (Instant, bool)> = BTreeMap::new();
    let mut forwarded_cancellations = 0;
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
                WorkEvent::Admitted(key, admit(collector, current, &input).await)
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
                                if forwarded_cancellations < FORWARDED_CANCELLATIONS {
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
                            raw,
                            phase: Phase::Queued,
                            cancelled: false,
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
                            Decision::Allowed(grant) => {
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
                            if let Some(raw) = result {
                                write(host, &raw).await?;
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
                            if forwarded_cancellations < FORWARDED_CANCELLATIONS {
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

async fn drain_stderr(mut stream: tokio::process::ChildStderr) -> anyhow::Result<usize> {
    use tokio::io::AsyncReadExt;
    let mut buffer = [0u8; 8192];
    let mut received = 0usize;
    loop {
        let count = stream.read(&mut buffer).await?;
        if count == 0 {
            return Ok(received);
        }
        received = received.saturating_add(count);
        ensure!(
            received <= 1024 * 1024,
            "selected MCP server stderr quota exceeded"
        );
    }
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
    let mut process = prepared.spawn()?;
    let mut stderr_task = None;
    eprintln!(
        "{}",
        json!({"event":"mcp_real_server_start","profile":profile.format,
        "sandbox":server_sandbox::profile_name(&profile.format),"sandbox_workspace":server_sandbox::SANDBOX_WORKSPACE,
        "sandbox_pid":process.id(),
        "active_limit":ACTIVE_LIMIT,"queued_limit":QUEUE_LIMIT,"wire_limit":WIRE_LIMIT,
        "forwarded_cancellation_limit":FORWARDED_CANCELLATIONS})
    );
    let operation = async {
        let stderr = process.stderr.take().context("selected server stderr missing")?;
        stderr_task = Some(tokio::spawn(drain_stderr(stderr)));
        let mut child = process.stdin.take().context("selected server stdin missing")?;
        let mut server = BufReader::new(process.stdout.take().context("selected server stdout missing")?);
        #[cfg(unix)]
        let mut client = BufReader::new(crate::mcp::stdio::Pipe::stdin()?);
        #[cfg(unix)]
        let mut host = crate::mcp::stdio::Pipe::stdout()?;
        #[cfg(not(unix))]
        let mut client = BufReader::new(tokio::io::stdin());
        #[cfg(not(unix))]
        let mut host = tokio::io::stdout();
        let result = {
            let exchange = relay(collector, &mut client, &mut host, &mut server, &mut child, &profile.format);
            tokio::pin!(exchange);
            tokio::select! {
                result = &mut exchange => result,
                drained = stderr_task.as_mut().expect("stderr task") => {
                    stderr_task = None;
                    let received = drained.context("selected server stderr worker failed")??;
                    eprintln!("{}",json!({"event":"mcp_real_stderr","received_bytes":received,"released":false}));
                    exchange.await
                }
            }
        };
        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), child.shutdown()).await;
        drop(child);
        result
    }.await;
    let cleanup = server_sandbox::terminate(&mut process).await;
    let stderr_cleanup = if let Some(mut task) = stderr_task {
        match tokio::time::timeout(std::time::Duration::from_secs(1), &mut task).await {
            Ok(Ok(Ok(received))) => {
                eprintln!(
                    "{}",
                    json!({"event":"mcp_real_stderr","received_bytes":received,"released":false})
                );
                Ok(())
            }
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
    eprintln!(
        "{}",
        json!({"event":"mcp_real_server_end","profile":profile.format,
        "cleanup_verified":cleanup.is_ok()&&stderr_cleanup.is_ok(),"transport_complete":operation.is_ok()})
    );
    operation?;
    cleanup?;
    stderr_cleanup?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
