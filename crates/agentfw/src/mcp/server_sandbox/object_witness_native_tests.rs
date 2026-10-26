// SPDX-License-Identifier: Apache-2.0
//! Owned component evidence only. This does not exercise SOU-155 authority.
#![cfg_attr(
    not(all(target_os = "linux", target_arch = "x86_64")),
    allow(dead_code)
)]
use super::*;
use anyhow::{ensure, Context};
use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

use super::super::server_profile::git::{self, object_witness as witness};

const FRAME_BYTES: usize = 1_048_576;
const SESSION_BYTES: usize = 8 * FRAME_BYTES;
const RESPONSE_TIME: Duration = Duration::from_secs(15);

fn save(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    ensure!(bytes.len() <= FRAME_BYTES, "owned evidence file bound");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}

fn wire(value: Value) -> anyhow::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(&value)?;
    bytes.push(b'\n');
    ensure!(bytes.len() <= 65_536, "owned request bound");
    Ok(bytes)
}

fn show(id: u64, revision: &str) -> anyhow::Result<Vec<u8>> {
    wire(json!({"jsonrpc":"2.0","id":id,"method":"tools/call",
        "params":{"name":"git_show","arguments":{
            "repo_path":SANDBOX_WORKSPACE,"revision":revision}}}))
}

fn error(value: &Value) -> bool {
    value.get("error").is_some() || value["result"]["isError"] == true
}

fn context(profile: &ProfileConfig) -> anyhow::Result<witness::ExecutionContext> {
    // Actual asset identities plus random LOCAL correlation, never an imported
    // execution capability or a daemon-authenticated process identity.
    let profile_bytes = serde_json::to_vec(profile)?;
    let closure = serde_json::to_vec(&json!({"runtime":profile.runtime_sha256,
        "package":profile.package_tree_sha256,"git":profile.git,
        "launcher":profile.git_launcher,"libraries":profile.libraries,
        "bwrap":profile.bwrap_sha256}))?;
    Ok(witness::ExecutionContext {
        profile_format: profile.format.clone(),
        profile_sha256: Sha256::digest(profile_bytes).into(),
        runtime_closure_sha256: Sha256::digest(closure).into(),
        daemon_generation: rand::random(),
        session_generation: rand::random(),
        process_generation: rand::random(),
    })
}

struct Original {
    child: Child,
    input: Option<tokio::process::ChildStdin>,
    output: BufReader<tokio::process::ChildStdout>,
    errors: tokio::task::JoinHandle<anyhow::Result<Vec<u8>>>,
    budget: Option<super::super::linux_budget::OwnedBudget>,
    owner: super::super::linux_owner::OwnerGuard,
    snapshot: Arc<witness::Snapshot>,
    producer: witness::Producer,
    context: witness::ExecutionContext,
    evidence: PathBuf,
    sent: usize,
    received: usize,
    bytes: usize,
}

impl Original {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    async fn start(profile: &ProfileConfig, evidence: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir(evidence)?;
        let prepared = prepare_linux_command_view(
            profile,
            &[
                "-I",
                "-B",
                "-m",
                "mcp_server_git",
                "--repository",
                SANDBOX_WORKSPACE,
            ]
            .map(str::to_owned),
            None,
            false,
            GitViewChoice::ObjectWitness,
        )?;
        let snapshot = prepared
            .object_witness
            .as_ref()
            .context("held test view missing")?
            .0
            .clone();
        let context = context(profile)?;
        let producer = witness::Producer::new(context.clone())?;
        let (mut child, budget, owner, _) = prepared.spawn().await?;
        let input = child.stdin.take().context("original stdin missing")?;
        let output = BufReader::new(child.stdout.take().context("original stdout missing")?);
        let stderr = child.stderr.take().context("original stderr missing")?;
        let errors = tokio::spawn(async move {
            let mut bytes = Vec::new();
            stderr
                .take(FRAME_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .await?;
            ensure!(bytes.len() <= FRAME_BYTES, "original stderr bound");
            Ok(bytes)
        });
        Ok(Self {
            child,
            input: Some(input),
            output,
            errors,
            budget,
            owner,
            snapshot,
            producer,
            context,
            evidence: evidence.to_owned(),
            sent: 0,
            received: 0,
            bytes: 0,
        })
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    async fn start(_profile: &ProfileConfig, _evidence: &Path) -> anyhow::Result<Self> {
        anyhow::bail!("native Linux x86-64 required; no execution fallback")
    }

    async fn send(&mut self, request: &[u8]) -> anyhow::Result<()> {
        ensure!(
            self.sent < 64 && request.len() <= 65_536,
            "original request quota"
        );
        self.owner.check()?;
        save(
            &self
                .evidence
                .join(format!("request-{:02}.jsonl", self.sent)),
            request,
        )?;
        self.sent += 1;
        tokio::time::timeout(
            RESPONSE_TIME,
            self.input
                .as_mut()
                .context("original input closed")?
                .write_all(request),
        )
        .await??;
        Ok(())
    }

    async fn receive(&mut self) -> anyhow::Result<(Value, Vec<u8>)> {
        ensure!(self.received < 64, "original response quota");
        let mut raw = Vec::new();
        let mut bounded = (&mut self.output).take(FRAME_BYTES as u64 + 1);
        tokio::time::timeout(RESPONSE_TIME, bounded.read_until(b'\n', &mut raw)).await??;
        self.bytes += raw.len();
        ensure!(
            !raw.is_empty()
                && raw.len() <= FRAME_BYTES
                && raw.ends_with(b"\n")
                && self.bytes <= SESSION_BYTES,
            "original complete wire line bound"
        );
        save(
            &self
                .evidence
                .join(format!("response-{:02}.jsonl", self.received)),
            &raw,
        )?;
        self.received += 1;
        self.owner.check()?;
        let value: Value = serde_json::from_slice(&raw)?;
        ensure!(
            value["jsonrpc"] == "2.0"
                && value["id"].as_u64().is_some()
                && (value.get("result").is_some() ^ value.get("error").is_some()),
            "original response shape"
        );
        Ok((value, raw))
    }

    async fn exchange(&mut self, request: &[u8]) -> anyhow::Result<(Value, Vec<u8>)> {
        let expected: Value = serde_json::from_slice(request)?;
        self.send(request).await?;
        let result = self.receive().await?;
        ensure!(
            result.0["id"] == expected["id"],
            "original response ID mismatch"
        );
        Ok(result)
    }

    async fn initialize(&mut self) -> anyhow::Result<()> {
        let (reply, _) = self
            .exchange(&wire(json!({"jsonrpc":"2.0","id":1,
            "method":"initialize","params":{"protocolVersion":"2025-11-25",
            "capabilities":{},"clientInfo":{"name":"sou156-owned-component","version":"1"}}}))?)
            .await?;
        git::validate_initialization(&reply["result"])?;
        self.send(&wire(
            json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        )?)
        .await?;
        let (reply, _) = self
            .exchange(&wire(json!({"jsonrpc":"2.0","id":2,
            "method":"tools/list","params":{}}))?)
            .await?;
        ensure!(
            reply["result"] == git::original_manifest(),
            "original discovery pin mismatch"
        );
        Ok(())
    }

    async fn success(&mut self, id: u64, revision: &str) -> anyhow::Result<(Value, Value)> {
        let request = show(id, revision)?;
        let ticket = self.producer.begin(self.snapshot.clone(), &request)?;
        let (reply, raw) = self.exchange(&request).await?;
        ensure!(!error(&reply), "original successful control failed");
        let claim = self.producer.complete(&ticket, &raw)?;
        let target = self
            .producer
            .verify_local(&claim, &self.context, &request, &raw)?;
        ensure!(
            self.producer
                .verify_local(&claim, &self.context, &request, &raw)
                .is_err(),
            "local replay accepted"
        );
        let diagnostic: Value = serde_json::from_slice(&claim.diagnostic_json()?)?;
        ensure!(
            diagnostic["target"] == serde_json::to_value(target)?,
            "local typed target mismatch"
        );
        Ok((reply, diagnostic))
    }

    async fn finish(mut self) -> anyhow::Result<Value> {
        let quiesced = self.owner.quiesce().await;
        drop(self.input.take());
        let mut unexpected = Vec::new();
        let drain = tokio::time::timeout(
            RESPONSE_TIME,
            (&mut self.output)
                .take(FRAME_BYTES as u64 + 1)
                .read_to_end(&mut unexpected),
        )
        .await;
        // Run every cleanup even if a pipe failed or never closed. The existing
        // owner, not a new PID/path selector, owns descendant cleanup.
        let owner = self.owner.finish().await;
        let budget = if let Some(budget) = self.budget.as_mut() {
            budget.finish().await
        } else {
            Ok(())
        };
        let waited = tokio::time::timeout(Duration::from_secs(3), self.child.wait()).await;
        if waited.is_err() {
            terminate(&mut self.child).await?;
        }
        let stderr = tokio::time::timeout(Duration::from_secs(3), &mut self.errors).await;
        if stderr.is_err() {
            self.errors.abort();
        }
        owner?;
        budget?;
        quiesced?;
        drain??;
        ensure!(unexpected.is_empty(), "unconsumed original output");
        ensure!(waited??.success(), "original outside owner failed");
        let stderr = stderr???;
        save(&self.evidence.join("stderr.bin"), &stderr)?;
        let metadata = self.owner.metadata();
        ensure!(
            metadata["failed"] == false && metadata["cleanup"]["runtime_failure"] == false,
            "original owner/runtime failed before cleanup"
        );
        save(
            &self.evidence.join("cleanup.json"),
            &serde_json::to_vec(&metadata)?,
        )?;
        Ok(
            json!({"directory":self.evidence.file_name().and_then(|s|s.to_str()),
            "requests":self.sent,"responses":self.received,"response_bytes":self.bytes,
            "cleanup":metadata}),
        )
    }
}

fn add_object(root: &Path, kind: &str, payload: &[u8]) -> anyhow::Result<String> {
    ensure!(payload.len() < 262_000, "owned object bound");
    let mut raw = format!("{kind} {}\0", payload.len()).into_bytes();
    raw.extend_from_slice(payload);
    let id = sha1_smol::Sha1::from(&raw).digest().to_string();
    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&raw)?;
    let directory = root.join(format!(".git/objects/{}", &id[..2]));
    std::fs::create_dir_all(&directory)?;
    let path = directory.join(&id[2..]);
    // The retained fixture may already contain this exact blob. Never truncate
    // a held file or silently replace a different object at the same OID.
    let bytes = encoder.finish()?;
    if path.exists() {
        let mut decoder = flate2::read::ZlibDecoder::new(File::open(path)?);
        let mut existing = Vec::new();
        std::io::Read::read_to_end(
            &mut std::io::Read::take(&mut decoder, 262_145),
            &mut existing,
        )?;
        ensure!(existing == raw, "owned existing object mismatch");
    } else {
        save(&path, &bytes)?;
    }
    Ok(id)
}

fn tag(root: &Path, target: &str, kind: &str, name: &str) -> anyhow::Result<String> {
    add_object(root, "tag", format!("object {target}\ntype {kind}\ntag {name}\ntagger Owned <owned@example.invalid> 0 +0000\n\nOwned tag.\n").as_bytes())
}

fn inventory(root: &Path) -> anyhow::Result<Value> {
    fn visit(
        root: &Path,
        here: &Path,
        rows: &mut BTreeMap<String, Value>,
        total: &mut u64,
    ) -> anyhow::Result<()> {
        for entry in std::fs::read_dir(here)? {
            let path = entry?.path();
            ensure!(rows.len() < 1024, "owned inventory count bound");
            let metadata = path.symlink_metadata()?;
            ensure!(
                metadata.is_dir() || metadata.is_file(),
                "owned inventory type"
            );
            let value = if metadata.is_file() {
                ensure!(
                    metadata.len() <= FRAME_BYTES as u64,
                    "owned inventory file bound"
                );
                *total += metadata.len();
                ensure!(
                    *total <= 16 * FRAME_BYTES as u64,
                    "owned inventory total bound"
                );
                json!({"mode":metadata.mode() & 0o777,"sha256":format!("{:x}",Sha256::digest(std::fs::read(&path)?))})
            } else {
                json!({"mode":metadata.mode() & 0o777,"directory":true})
            };
            rows.insert(
                path.strip_prefix(root)?
                    .to_str()
                    .context("owned path encoding")?
                    .to_owned(),
                value,
            );
            if metadata.is_dir() {
                visit(root, &path, rows, total)?;
            }
        }
        Ok(())
    }
    let mut rows = BTreeMap::new();
    visit(root, root, &mut rows, &mut 0)?;
    Ok(serde_json::to_value(rows)?)
}

async fn seed(
    profile: &ProfileConfig,
    evidence: &Path,
    commit: &str,
) -> anyhow::Result<(Vec<u8>, Value)> {
    let mut original = Original::start(profile, evidence).await?;
    let result = async {
        original.initialize().await?;
        let (reply, claim) = original.success(10, commit).await?;
        let content = reply["result"]["content"]
            .as_array()
            .context("original content absent")?;
        ensure!(
            content.len() == 1 && content[0]["type"] == "text",
            "original content shape"
        );
        Ok::<_, anyhow::Error>((
            content[0]["text"]
                .as_str()
                .context("original text absent")?
                .as_bytes()
                .to_vec(),
            claim,
        ))
    }
    .await;
    let mut cleanup = original.finish().await?;
    let (payload, claim) = result?;
    cleanup["local_claim"] = claim;
    Ok((payload, cleanup))
}

async fn cases(
    profile: &ProfileConfig,
    evidence: &Path,
    ids: &BTreeMap<&str, String>,
    rows: &mut Vec<Value>,
) -> anyhow::Result<Value> {
    let mut original = Original::start(profile, evidence).await?;
    let result = async {
        original.initialize().await?;
        rows.push(json!({"case":"original_initialize_discovery","passed":true}));
        let mut commit_result = Value::Null;
        for (offset, (name, kind, depth)) in [("commit", witness::ObjectKind::Commit, 0),
            ("plain_blob", witness::ObjectKind::Blob, 0),
            ("commit_looking_blob", witness::ObjectKind::Blob, 0),
            ("tag_commit", witness::ObjectKind::Tag, 1),
            ("nested_tag", witness::ObjectKind::Tag, 2)].into_iter().enumerate() {
            let (reply, claim) = original.success(10 + offset as u64, &ids[name]).await?;
            ensure!(claim["target"]["requested"]["kind"] == serde_json::to_value(kind)?
                && claim["target"]["tag_chain"].as_array().context("tag chain")?.len() == depth,
                "actual typed object control mismatch");
            if name == "commit" { commit_result = reply["result"].clone(); }
            if matches!(name, "commit_looking_blob" | "tag_commit" | "nested_tag") {
                ensure!(reply["result"] == commit_result, "original result ambiguity/tag formatting changed");
            }
            rows.push(json!({"case":name,"passed":true,"claim":claim}));
        }
        rows.push(json!({"case":"local_replay_refused","passed":true}));
        for (offset, name) in ["direct_tree", "tag_blob", "tag_tree", "missing_oid"].into_iter().enumerate() {
            let request = show(20 + offset as u64, &ids[name])?;
            let ticket = original.producer.begin(original.snapshot.clone(), &request);
            ensure!(ticket.is_ok() == (name == "direct_tree"), "local error-target resolution changed");
            let (reply, raw) = original.exchange(&request).await?;
            ensure!(error(&reply), "original error control unexpectedly succeeded");
            if let Ok(ticket) = ticket { ensure!(original.producer.complete(&ticket, &raw).is_err(), "error acquired completion"); }
            rows.push(json!({"case":name,"passed":true,"original_is_error":true,"response_sha256":format!("{:x}",Sha256::digest(raw))}));
        }
        for revision in ["HEAD~1", "main", "HEAD:notes.txt", "--help", "0d5ba95"] {
            ensure!(original.producer.begin(original.snapshot.clone(), &show(30, revision)?).is_err(), "local revision grammar widened");
        }
        rows.push(json!({"case":"revision_grammar","passed":true}));
        let mut pending = BTreeMap::new();
        for (id, name) in [(31, "commit"), (32, "plain_blob")] {
            let request = show(id, &ids[name])?;
            let ticket = original.producer.begin(original.snapshot.clone(), &request)?;
            original.send(&request).await?;
            pending.insert(id, (ticket, request, ids[name].clone()));
        }
        for _ in 0..2 {
            let (reply, raw) = original.receive().await?;
            let (ticket, request, expected) = pending.remove(&reply["id"].as_u64().context("concurrent ID")?).context("unbound concurrent response")?;
            let claim = original.producer.complete(&ticket, &raw)?;
            let target = original.producer.verify_local(&claim, &original.context, &request, &raw)?;
            ensure!(target.requested.oid == expected, "concurrent target crossed");
        }
        ensure!(pending.is_empty(), "concurrent response missing");
        rows.push(json!({"case":"concurrent_calls","passed":true,"actual_pending_requests":2}));
        let request = show(33, &ids["commit"])?;
        let ticket = original.producer.begin(original.snapshot.clone(), &request)?;
        original.send(&request).await?;
        original.producer.cancel(&ticket)?;
        let (reply, raw) = original.receive().await?;
        ensure!(reply["id"] == 33 && !error(&reply) && original.producer.complete(&ticket, &raw).is_err(), "local cancellation failed");
        original.success(34, &ids["commit"]).await?;
        rows.push(json!({"case":"local_cancel_then_fresh","passed":true,"scope":"local slot; original reply drained"}));
        let request = show(35, &ids["commit"])?;
        let ticket = original.producer.begin(original.snapshot.clone(), &request)?;
        original.send(&request).await?;
        let path = profile.workspace.join(".git/refs/heads/main");
        let moved = profile.workspace.join(".git/refs/heads/main-held");
        let before = std::fs::read(&path)?;
        std::fs::rename(&path, &moved)?;
        ensure!(!path.exists() && std::fs::read(&moved)? == before, "owned source rename calibration");
        std::fs::rename(&moved, &path)?;
        ensure!(std::fs::read(&path)? == before, "owned source restore calibration");
        let (reply, raw) = original.receive().await?;
        ensure!(reply["id"] == 35 && !error(&reply), "original sealed read failed");
        ensure!(original.producer.complete(&ticket, &raw).is_err()
            && original.producer.begin(original.snapshot.clone(), &show(36, "HEAD")?).is_err(), "restored source revived local view");
        rows.push(json!({"case":"local_inflight_source_change","passed":true,"scope":"request written before source change; no authenticated Ask"}));
        Ok::<_, anyhow::Error>(())
    }.await;
    let cleanup = original.finish().await?;
    result?;
    Ok(cleanup)
}

async fn local_wait_before_write(
    profile: &ProfileConfig,
    evidence: &Path,
    rows: &mut Vec<Value>,
) -> anyhow::Result<Value> {
    let mut original = Original::start(profile, evidence).await?;
    let result = async {
        original.initialize().await?;
        // Hold the Snapshot while locally waiting; reserve only after the wait.
        // No SOU-155 admission or authenticated Ask capability is simulated.
        let sent_before = original.sent;
        let path = profile.workspace.join(".git/refs/heads/main");
        let moved = profile.workspace.join(".git/refs/heads/main-wait-held");
        let before = std::fs::read(&path)?;
        std::fs::rename(&path, &moved)?;
        ensure!(
            !path.exists() && std::fs::read(&moved)? == before,
            "owned wait rename calibration"
        );
        std::fs::rename(&moved, &path)?;
        ensure!(
            std::fs::read(&path)? == before,
            "owned wait restore calibration"
        );
        ensure!(
            original
                .producer
                .begin(original.snapshot.clone(), &show(10, "HEAD")?)
                .is_err(),
            "withdrawn local wait acquired a slot"
        );
        ensure!(
            original.sent == sent_before,
            "withdrawn local wait wrote original request"
        );
        rows.push(json!({"case":"local_wait_before_write","passed":true,
            "sent_before":sent_before,"sent_after":original.sent,"original_request_written":false,
            "scope":"retain while locally waiting; begin after wait; no authenticated Ask"}));
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let cleanup = original.finish().await?;
    result?;
    Ok(cleanup)
}

async fn run_component() -> anyhow::Result<()> {
    ensure!(!witness::PRODUCTION_AUTHENTICATION_ENABLED);
    let output = PathBuf::from(
        std::env::var_os("SOU156_TEST_OUTPUT").context("explicit owned output required")?,
    );
    std::fs::create_dir(&output)?;
    let mut profile = ProfileConfig::read(&std::fs::read(
        std::env::var_os("SOU68_SANDBOX_TEST_PROFILE")
            .context("explicit installed profile required")?,
    )?)?;
    ensure!(
        git::is_profile(&profile.format),
        "existing Git profile required"
    );
    let owned = tempfile::tempdir()?;
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/sou156-original-object-confusion.json"
    ))?;
    for path in [".git/objects/info", ".git/objects/pack", ".git/refs/tags"] {
        std::fs::create_dir_all(owned.path().join(path))?;
    }
    for (path, encoded) in fixture["images_base64"]
        .as_object()
        .context("retained images")?
    {
        let path = owned.path().join(path);
        std::fs::create_dir_all(path.parent().context("fixture parent")?)?;
        save(
            &path,
            &base64::engine::general_purpose::STANDARD
                .decode(encoded.as_str().context("fixture base64")?)?,
        )?;
    }
    save(
        &owned.path().join("notes.txt"),
        b"Owned synthetic object-kind fixture.\n",
    )?;
    profile.workspace = owned.path().to_owned();
    profile.workspace_identity = Some(
        super::super::server_profile::WorkspaceIdentity::from_metadata(&std::fs::metadata(
            owned.path(),
        )?),
    );
    let commit = fixture["commit_oid"]
        .as_str()
        .context("fixture commit")?
        .to_owned();
    let before_seed = inventory(owned.path())?;
    let (payload, seed_cleanup) = seed(&profile, &output.join("seed"), &commit).await?;
    ensure!(
        inventory(owned.path())? == before_seed,
        "seed read changed repository"
    );
    let blob = add_object(owned.path(), "blob", &payload)?;
    let plain = add_object(owned.path(), "blob", b"Owned raw blob.\n")?;
    let tree = "30d69c168c8bfa6f613c882b2ed4cf8c9693ddba".to_owned();
    let commit_tag = tag(owned.path(), &commit, "commit", "owned-commit")?;
    let nested = tag(owned.path(), &commit_tag, "tag", "owned-nested")?;
    let blob_tag = tag(owned.path(), &blob, "blob", "owned-blob")?;
    let tree_tag = tag(owned.path(), &tree, "tree", "owned-tree")?;
    ensure!(blob != commit, "distinct object control failed");
    let ids = BTreeMap::from([
        ("commit", commit.clone()),
        ("plain_blob", plain),
        ("commit_looking_blob", blob),
        ("direct_tree", tree),
        ("tag_commit", commit_tag),
        ("nested_tag", nested),
        ("tag_blob", blob_tag),
        ("tag_tree", tree_tag),
        ("missing_oid", "0".repeat(40)),
    ]);
    let before = inventory(owned.path())?;
    let mut rows = Vec::new();
    let main_cleanup = cases(&profile, &output.join("same-snapshot"), &ids, &mut rows).await?;
    ensure!(
        inventory(owned.path())? == before,
        "same-view reads changed repository"
    );
    let wait_cleanup =
        local_wait_before_write(&profile, &output.join("local-wait"), &mut rows).await?;
    ensure!(
        inventory(owned.path())? == before,
        "local wait changed repository"
    );
    let (_, fresh_cleanup) = seed(&profile, &output.join("fresh"), &commit).await?;
    rows.push(json!({"case":"fresh_capture_after_restore","passed":true}));
    ensure!(
        inventory(owned.path())? == before,
        "fresh read changed repository"
    );
    rows.push(json!({"case":"cleanup_repository_unchanged","passed":true}));
    save(
        &output.join("report.json"),
        &serde_json::to_vec_pretty(&json!({
        "format":"sou156-same-snapshot-component/1","status":"pass","skipped":0,
        "production_authentication":"disabled","common_join":"not exercised; SOU-155",
        "whole_response_lines_retained":true,"concurrent_ids_unique":true,
        "ambiguity":"same decoded original result; different request IDs retained verbatim",
        "cases":rows,"sessions":[seed_cleanup,main_cleanup,wait_cleanup,fresh_cleanup],
        "repository_before":before,"repository_after":inventory(owned.path())?,
        "profile":profile,"limits":{"frame_bytes":FRAME_BYTES,"session_bytes":SESSION_BYTES,
            "requests_per_session":64,"response_seconds":RESPONSE_TIME.as_secs()}}))?,
    )?;
    Ok(())
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[tokio::test]
#[ignore = "requires explicit pinned native Linux Git/Python profile, Agent and owned evidence directory"]
async fn original_git_same_snapshot_component() -> anyhow::Result<()> {
    run_component().await
}
