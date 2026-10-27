// SPDX-License-Identifier: Apache-2.0
//! Daemon-owned original Git execution, not a native admission or release grant.
//! No wire import/constructor for Completion exists. Native must still consume
//! its admitted Call, bind this operation, inspect raw bytes, and audit release.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]
use super::server_profile::ProfileConfig;
#[cfg(target_os = "linux")]
use anyhow::{ensure, Context};
use std::ops::Range;

/// Only separately qualified execution routes; selection remains operator opt-in.
pub(crate) fn supports_profile(format: &str) -> bool {
    matches!(
        format,
        super::server_profile::git::FORMAT
            | super::server_profile::git::FILE_READS_FORMAT
            | super::server_profile::git_tracked_symlinks::FORMAT
    )
}

pub(crate) struct Completion {
    raw: Vec<u8>,
    text: Option<String>,
    span: Option<Range<usize>>,
    #[cfg(target_os = "linux")]
    snapshot: std::sync::Arc<super::server_profile::git::object_witness::Snapshot>,
}
impl Completion {
    pub(crate) fn raw(&self) -> &[u8] {
        &self.raw
    }
    /// Exact complete original content[0].text only. A token copied into a body,
    /// another channel, or another result cannot select this header range.
    pub(crate) fn formatter_span(&self, text: &str) -> Option<Range<usize>> {
        self.validate().ok()?;
        (self.text.as_deref() == Some(text))
            .then(|| self.span.clone())
            .flatten()
    }
    pub(crate) fn validate(&self) -> anyhow::Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.snapshot.validate()
        }
        #[cfg(not(target_os = "linux"))]
        {
            anyhow::bail!("verified Git execution requires Linux");
        }
    }
}

pub(crate) async fn run(
    profile: &ProfileConfig,
    original_request: &[u8],
) -> anyhow::Result<Completion> {
    #[cfg(target_os = "linux")]
    {
        linux::run(profile, original_request).await
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (profile, original_request);
        anyhow::bail!("verified Git execution requires Linux");
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::super::{server_profile, server_sandbox};
    use super::*;
    use serde_json::{json, Value};
    use server_profile::git::{
        self,
        object_witness::{ObjectKind, Snapshot},
    };
    use std::sync::{Arc, LazyLock};
    use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
    use tokio::sync::{oneshot, Semaphore};
    use tokio::time::{Duration, Instant};

    const REQUEST_LIMIT: usize = 65_536;
    const RESULT_LIMIT: usize = server_profile::RESULT_FRAME_BYTES;
    const STDERR_LIMIT: usize = 1_048_576;
    // Same five-second exchange deadline as the native collector. Starts before
    // preparation/spawn, never reset between handshake/discovery/tool response.
    const EXCHANGE: Duration = Duration::from_secs(5);
    static ACTIVE: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(8)));

    #[cfg(test)]
    struct DispatchBarrier {
        key: String,
        original: Vec<u8>,
        workspace: std::path::PathBuf,
        format: String,
        written: oneshot::Sender<()>,
        resume: oneshot::Receiver<()>,
    }
    #[cfg(test)]
    static AFTER_TOOLS_WRITE: std::sync::Mutex<Option<DispatchBarrier>> =
        std::sync::Mutex::new(None);

    fn request(profile: &ProfileConfig, raw: &[u8]) -> anyhow::Result<Value> {
        ensure!(
            supports_profile(&profile.format),
            "verified Git profile unsupported"
        );
        ensure!(
            !raw.is_empty()
                && raw.len() <= REQUEST_LIMIT
                && raw.ends_with(b"\n")
                && !raw[..raw.len() - 1].contains(&b'\n'),
            "verified Git request framing/bound"
        );
        let super::super::admission::Strict(value) = serde_json::from_slice(raw)?;
        keys(&value, &["jsonrpc", "id", "method", "params"])?;
        keys(&value["params"], &["name", "arguments"])?;
        ensure!(
            value["jsonrpc"] == "2.0" && value["method"] == "tools/call",
            "verified Git request method"
        );
        ensure!(valid_id(&value["id"]), "verified Git request id");
        let tool = value["params"]["name"]
            .as_str()
            .context("verified Git tool missing")?;
        ensure!(
            matches!(tool, "git_show" | "git_diff"),
            "verified Git tool unsupported"
        );
        git::validate_arguments_with_extension(
            tool,
            &value["params"]["arguments"],
            if profile.format == git::FILE_READS_FORMAT {
                git::ReadExtension::FileRevisions
            } else {
                git::ReadExtension::None
            },
        )?;
        Ok(value)
    }
    fn keys(value: &Value, allowed: &[&str]) -> anyhow::Result<()> {
        let object = value.as_object().context("verified Git object expected")?;
        ensure!(
            object.keys().all(|key| allowed.contains(&key.as_str())),
            "verified Git unexpected fields"
        );
        Ok(())
    }
    fn valid_id(id: &Value) -> bool {
        id.as_i64()
            .is_some_and(|n| n.unsigned_abs() <= 9_007_199_254_740_991)
            || id.as_u64().is_some_and(|n| n <= 9_007_199_254_740_991)
            || id.as_str().is_some_and(|s| {
                !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control)
            })
    }
    async fn receive<R: AsyncBufRead + Unpin>(
        reader: &mut R,
        id: &Value,
        limit: usize,
    ) -> anyhow::Result<(Value, Vec<u8>)> {
        let mut frame = Vec::new();
        loop {
            let buf = reader.fill_buf().await?;
            ensure!(!buf.is_empty(), "verified Git ended before response");
            let end = buf.iter().position(|b| *b == b'\n');
            let take = end.map_or(buf.len(), |i| i + 1);
            ensure!(
                frame.len() + take <= limit,
                "verified Git response frame over bound"
            );
            frame.extend_from_slice(&buf[..take]);
            reader.consume(take);
            if end.is_some() {
                break;
            }
        }
        let super::super::admission::Strict(value) = serde_json::from_slice(&frame)?;
        keys(&value, &["jsonrpc", "id", "result", "error"])?;
        ensure!(
            value["jsonrpc"] == "2.0"
                && value.get("id") == Some(id)
                && (value.get("result").is_some() ^ value.get("error").is_some()),
            "verified Git unexpected response correlation/shape"
        );
        Ok((value, frame))
    }
    async fn send<W: AsyncWrite + Unpin>(writer: &mut W, value: &Value) -> anyhow::Result<()> {
        let mut bytes = serde_json::to_vec(value)?;
        ensure!(
            bytes.len() < REQUEST_LIMIT,
            "verified Git handshake request bound"
        );
        bytes.push(b'\n');
        writer.write_all(&bytes).await?;
        writer.flush().await?;
        Ok(())
    }
    async fn exchange<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
        profile: &ProfileConfig,
        original: &[u8],
        call: &Value,
        snapshot: &Snapshot,
        reader: &mut R,
        writer: &mut W,
    ) -> anyhow::Result<(Value, Vec<u8>)> {
        let init = json!(format!("sw-verified-init:{}", crate::token::generate()));
        let discovery = json!(format!("sw-verified-tools:{}", crate::token::generate()));
        ensure!(
            init != call["id"] && discovery != call["id"],
            "verified Git handshake id collision"
        );
        send(writer,&json!({"jsonrpc":"2.0","id":init,"method":"initialize","params":{"protocolVersion":server_profile::PROTOCOL_VERSION,"capabilities":{},"clientInfo":{"name":"soup-wall","version":"0.3.0"}}})).await?;
        let (hello, _) = receive(reader, &init, server_profile::MAX_FRAME_BYTES).await?;
        ensure!(
            hello.get("error").is_none(),
            "verified Git initialization error"
        );
        server_profile::validate_initialization_for(&profile.format, &hello["result"])?;
        send(
            writer,
            &json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )
        .await?;
        send(
            writer,
            &json!({"jsonrpc":"2.0","id":discovery,"method":"tools/list","params":{}}),
        )
        .await?;
        let (manifest, _) = receive(reader, &discovery, server_profile::MAX_FRAME_BYTES).await?;
        ensure!(
            manifest.get("error").is_none() && manifest["result"].get("nextCursor").is_none(),
            "verified Git discovery error/pagination unsupported"
        );
        let available =
            server_profile::classify_manifest_for(&profile.format, &manifest["result"])?;
        let tool = call["params"]["name"]
            .as_str()
            .context("verified Git tool missing")?;
        let selected = available
            .get(tool)
            .context("verified Git tool unavailable")?;
        selected.validate_arguments(&call["params"]["arguments"])?;
        snapshot.validate_call(tool, &call["params"]["arguments"])?;
        // Exactly one original tools/call. Never reserialize or rerender it.
        writer.write_all(original).await?;
        writer.flush().await?;
        #[cfg(test)]
        {
            // Private libtest barrier only. Production has no hook or IPC.
            let barrier = {
                let mut slot = AFTER_TOOLS_WRITE.lock().unwrap();
                if slot.as_ref().is_some_and(|barrier| {
                    barrier.original == original
                        && barrier.workspace == profile.workspace
                        && barrier.format == profile.format
                }) {
                    slot.take()
                } else {
                    None
                }
            };
            if let Some(barrier) = barrier {
                let _ = barrier.written.send(());
                barrier.resume.await.context("test dispatch barrier lost")?;
            }
        }
        let (reply, raw) = receive(reader, &call["id"], RESULT_LIMIT).await?;
        selected.validate_result(&reply)?;
        writer.shutdown().await?;
        Ok((reply, raw))
    }
    fn header_span(
        tool: &str,
        args: &Value,
        target: Option<&git::object_witness::ShowTarget>,
        text: &str,
    ) -> Option<Range<usize>> {
        let (prefix, id) = match tool {
            "git_show" => {
                // A file payload receives full baseline inspection even if it
                // happens to begin with a commit-looking line.
                if args["revision"]
                    .as_str()
                    .is_some_and(|revision| revision.contains(':'))
                {
                    return None;
                }
                let target = target?;
                if target.requested.kind != ObjectKind::Commit
                    || target.effective.kind != ObjectKind::Commit
                {
                    return None;
                }
                ("commit ", target.effective.oid.as_str())
            }
            "git_diff" => ("Diff with ", args["target"].as_str()?),
            _ => return None,
        };
        if id.len() != 40 || !id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let end = prefix.len() + id.len();
        let suffix = if tool == "git_diff" { ":\n" } else { "\n" };
        text.starts_with(&format!("{prefix}{id}{suffix}"))
            .then_some(prefix.len()..end)
    }
    fn completed_owned_output(
        profile: &ProfileConfig,
        call: &Value,
        reply: Value,
        raw: Vec<u8>,
        snapshot: Arc<Snapshot>,
    ) -> anyhow::Result<Completion> {
        snapshot.validate()?;
        let available =
            server_profile::classify_manifest_for(&profile.format, &git::original_manifest())?;
        let tool = call["params"]["name"]
            .as_str()
            .context("verified Git tool missing")?;
        let kind = available[tool].validate_result(&reply)?;
        let text = if kind == "value"
            && reply["result"]["content"]
                .as_array()
                .is_some_and(|b| b.len() == 1)
            && reply["result"].get("structuredContent").is_none()
        {
            reply["result"]["content"][0]["text"]
                .as_str()
                .map(str::to_owned)
        } else {
            None
        };
        let args = &call["params"]["arguments"];
        snapshot.validate_call(tool, args)?;
        let target = if tool == "git_show" {
            snapshot
                .show_target(args["revision"].as_str().unwrap_or(""))
                .ok()
        } else {
            None
        };
        let span = text
            .as_deref()
            .and_then(|text| header_span(tool, args, target.as_ref(), text));
        snapshot.validate()?;
        Ok(Completion {
            raw,
            text,
            span,
            snapshot,
        })
    }
    pub(super) async fn run(profile: &ProfileConfig, raw: &[u8]) -> anyhow::Result<Completion> {
        let call = request(profile, raw)?;
        let permit = ACTIVE
            .clone()
            .try_acquire_owned()
            .context("verified Git active worker bound")?;
        let deadline = Instant::now() + EXCHANGE;
        let profile = profile.clone();
        let original = raw.to_vec();
        let (mut tx, rx) = oneshot::channel();
        // The owned task retains its slot/owner until cleanup even if the native
        // caller is cancelled. Receiver loss cancels the exchange, not cleanup.
        tokio::spawn(async move {
            let _permit = permit;
            let result = owned(&profile, &original, &call, deadline, &mut tx).await;
            let _ = tx.send(result);
        });
        rx.await.context("verified Git owner task stopped")?
    }
    async fn owned(
        profile: &ProfileConfig,
        original: &[u8],
        call: &Value,
        deadline: Instant,
        tx: &mut oneshot::Sender<anyhow::Result<Completion>>,
    ) -> anyhow::Result<Completion> {
        ensure!(!tx.is_closed(), "verified Git native caller cancelled");
        let prepared = server_sandbox::prepare_verified_git(profile)?;
        let snapshot = prepared
            .verified_git_snapshot()
            .context("verified Git same snapshot missing")?;
        snapshot.validate()?;
        snapshot.validate_call(
            call["params"]["name"]
                .as_str()
                .context("verified Git tool missing")?,
            &call["params"]["arguments"],
        )?;
        ensure!(
            Instant::now() < deadline,
            "verified Git preparation exceeded exchange deadline"
        );
        ensure!(!tx.is_closed(), "verified Git native caller cancelled");
        let (mut process, mut budget, mut owner, pid) = prepared.spawn().await?;
        let mut stderr_task = None;
        let operation = async {
            if let Some(budget) = budget.as_mut() {
                budget.verify_attached(pid)?;
            }
            owner.check()?;
            snapshot.validate()?;
            let mut writer = process.stdin.take().context("verified Git stdin missing")?;
            let mut reader = BufReader::new(
                process
                    .stdout
                    .take()
                    .context("verified Git stdout missing")?,
            );
            let stderr = process
                .stderr
                .take()
                .context("verified Git stderr missing")?;
            stderr_task = Some(tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut stderr = stderr;
                let mut buffer = [0; 8192];
                let mut total = 0usize;
                loop {
                    let n = stderr.read(&mut buffer).await?;
                    if n == 0 {
                        break;
                    }
                    total = total
                        .checked_add(n)
                        .context("verified Git stderr count overflow")?;
                    ensure!(total <= STDERR_LIMIT, "verified Git stderr over bound");
                }
                Ok::<_, anyhow::Error>(())
            }));
            exchange(profile, original, call, &snapshot, &mut reader, &mut writer).await
        };
        let result = tokio::select! {
            biased;
            _=tx.closed()=>Err(anyhow::anyhow!("verified Git native caller cancelled")),
            result=tokio::time::timeout_at(deadline,operation)=>result.context("verified Git five-second exchange expired").and_then(|r|r),
        };
        // All cleanup attempts happen before propagating any RPC error, and no
        // Completion exists until the owned process tree is conclusively stopped.
        let quiesce = owner.quiesce().await;
        let budget_check = budget.as_ref().map(|b| b.check()).unwrap_or(Ok(()));
        let budget_cleanup = if let Some(b) = budget.as_mut() {
            b.finish().await
        } else {
            Ok(())
        };
        let owner_cleanup = owner.finish().await;
        let child_cleanup = server_sandbox::terminate(&mut process).await;
        let stderr_cleanup = if let Some(mut task) = stderr_task {
            match tokio::time::timeout(Duration::from_secs(2), &mut task).await {
                Ok(Ok(result)) => result,
                Ok(Err(_)) => Err(anyhow::anyhow!("verified Git stderr task failed")),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    Err(anyhow::anyhow!("verified Git stderr cleanup timed out"))
                }
            }
        } else {
            Err(anyhow::anyhow!("verified Git stderr drain missing"))
        };
        let (reply, raw) = result?;
        quiesce?;
        budget_check?;
        budget_cleanup?;
        owner_cleanup?;
        child_cleanup?;
        stderr_cleanup?;
        ensure!(
            Instant::now() <= deadline,
            "verified Git completed after exchange deadline"
        );
        completed_owned_output(profile, call, reply, raw, snapshot)
    }
    #[cfg(test)]
    mod tests {
        include!("verified_git_tests.rs");
    }
}
