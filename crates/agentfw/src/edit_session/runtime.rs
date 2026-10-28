// SPDX-License-Identifier: Apache-2.0
//! One private daemon epoch and one supervised genuine host. No resumption or
//! automatic retry is permitted after the host has obtained edit authority.
use super::{launch, profile, record, transport, FORMAT, SERVER};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use soup_wall_agent::{AgentFirewall, DEFAULT_TAINT_CAP};
use std::{
    fs,
    path::PathBuf,
    sync::{atomic::Ordering, Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RunRecord {
    pub format: String,
    pub run: PathBuf,
    pub home: PathBuf,
    pub(super) profile_sha256: String,
    pub(super) host_session: String,
    pub(super) instance_id: String,
}

pub(super) fn run(
    plan: PathBuf,
    digest: String,
    parent: PathBuf,
    prompt_file: PathBuf,
    seconds: u64,
    model: String,
) -> Result<()> {
    ensure!((1..=180).contains(&seconds), "edit_timeout_out_of_bounds");
    ensure!(
        !model.is_empty()
            && model.len() <= 128
            && model
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b)),
        "edit_model_invalid"
    );
    let profile = launch::load(&plan, &digest)?;
    launch::private_dir(&parent)?;
    ensure!(
        !parent.starts_with(&profile.root) && !profile.root.starts_with(&parent),
        "edit_state_overlaps_output"
    );
    let prompt = launch::bytes(&prompt_file, 16384)?;
    ensure!(
        !prompt.is_empty() && std::str::from_utf8(&prompt).is_ok(),
        "edit_prompt_invalid"
    );
    let provider = crate::pilot_host::provider_inputs(None)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(owned(
        profile, digest, parent, prompt, seconds, model, provider,
    ))
}

async fn capture<R: AsyncRead + Unpin>(mut reader: R, path: PathBuf) -> Result<()> {
    use sha2::{Digest, Sha256};
    let mut received = 0usize;
    let mut buffer = [0u8; 8192];
    let mut digest = Sha256::new();
    loop {
        let available = (1024 * 1024usize)
            .saturating_sub(received)
            .saturating_add(1)
            .min(buffer.len());
        let n = reader.read(&mut buffer[..available]).await?;
        if n == 0 {
            let report = json!({"bytes":received,"sha256":format!("{:x}",digest.finalize()),"raw_retained":false});
            launch::write(&path, &profile::canonical(&report)?, 0o400)?;
            return Ok(());
        }
        received += n;
        ensure!(received <= 1024 * 1024, "edit_host_output_cap");
        digest.update(&buffer[..n]);
        buffer.fill(0);
    }
}
async fn guarded_capture<R: AsyncRead + Unpin>(
    reader: R,
    path: PathBuf,
    failed: Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    let result = capture(reader, path).await;
    if result.is_err() {
        failed.store(true, Ordering::Release);
    }
    result
}

async fn owned(
    profile: super::Profile,
    digest: String,
    parent: PathBuf,
    prompt: Vec<u8>,
    seconds: u64,
    model: String,
    provider: Vec<(std::ffi::OsString, std::ffi::OsString)>,
) -> Result<()> {
    use std::os::{
        fd::AsRawFd,
        unix::{fs::DirBuilderExt, process::CommandExt},
    };
    // Register interception before any child can exist.
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let run = parent.join(format!("edit-{}", crate::pilot_launcher::random_uuid_v4()));
    fs::DirBuilder::new().mode(0o700).create(&run)?;
    let home = run.join(crate::token::generate());
    fs::DirBuilder::new().mode(0o700).create(&home)?;
    let token = crate::token::generate();
    let native_token = crate::token::generate();
    launch::write(&home.join("token"), token.as_bytes(), 0o600)?;
    launch::write(&home.join("native-token"), native_token.as_bytes(), 0o600)?;
    launch::write(&home.join("policy.yaml"), launch::POLICY.as_bytes(), 0o400)?;
    let registry = profile::canonical(&profile.registry()?)?;
    launch::write(&home.join("registry.json"), &registry, 0o400)?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let config = crate::Config {
        bind: "127.0.0.1".into(),
        port: listener.local_addr()?.port(),
        enforce: true,
        policy: Some(home.join("policy.yaml")),
        audit: Some(home.join("audit.jsonl")),
        native: Some(crate::config::NativeCfg {
            execution: None,
            git_execution: None,
            registry_path: home.join("registry.json"),
            registry_sha256: crate::mcp::replace_file::content_sha256(&registry),
            approval: Some(crate::config::NativeApprovalCfg { ttl_seconds: 120 }),
            liveness: Some(crate::config::NativeLivenessCfg {
                default_lease_seconds: 4,
                max_lease_seconds: 4,
                maintenance_interval_ms: 100,
            }),
        }),
        ..Default::default()
    };
    launch::write(
        &home.join("config.yaml"),
        serde_yaml::to_string(&config)?.as_bytes(),
        0o400,
    )?;
    let host = crate::pilot_launcher::random_uuid_v4().to_string();
    let service = transport::Service::new(profile.clone(), host.clone())?;
    let mut native = crate::native::NativeState::from_bytes(
        &registry,
        &crate::mcp::replace_file::content_sha256(&registry),
        native_token.clone(),
    )?
    .with_approval(&home, &crate::grant::derive_key(&token), 120)?;
    native.edit = Some(service.clone());
    let record = RunRecord {
        format: FORMAT.into(),
        run: run.clone(),
        home: home.clone(),
        profile_sha256: digest.clone(),
        host_session: host.clone(),
        instance_id: native.instance_id().into(),
    };
    launch::write(&run.join("run.json"), &profile::canonical(&record)?, 0o400)?;
    // Retain the exact descriptive plan, not a reference that diagnosis would
    // have to re-open or revalidate against an already changed output target.
    launch::write(
        &run.join("profile.json"),
        &profile::canonical(&profile)?,
        0o400,
    )?;
    launch::write(&run.join("profile.sha256"), digest.as_bytes(), 0o400)?;
    let diagnostic = record::Context {
        format: record::FORMAT.into(),
        run: run.clone(),
        home: home.clone(),
        profile_sha256: digest.clone(),
        host_session: host.clone(),
        instance_id: native.instance_id().into(),
        config_sha256: crate::protection_status::config_digest(&config),
        listener: record::listener_identity(listener.as_raw_fd())?,
        started_at_ms: crate::protection_status::now_ms(),
        owner: record::process_identity(std::process::id())?,
    };
    diagnostic.validate()?;
    launch::write(
        &run.join("diagnostic-context.json"),
        &profile::canonical(&diagnostic)?,
        0o400,
    )?;
    let control = super::control::Guard::create(&run, &record)?;
    let tools = profile
        .tools()
        .as_array()
        .context("edit_declarations")?
        .iter()
        .map(|t| t["name"].as_str().expect("generated tool").to_string())
        .collect::<Vec<_>>();
    let grant = crate::child_authority::mint_scoped(
        &crate::child_authority::derive_key(&native_token),
        &host,
        SERVER,
        &tools,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
            .try_into()?,
        seconds * 1000,
        format!("{}.{}", native.instance_id(), crate::token::generate()),
        Some(SERVER.into()),
        None,
        Some(
            profile
                .targets
                .iter()
                .map(|t| profile.root.join(&t.name).to_string_lossy().into_owned())
                .collect(),
        ),
    );
    let mcp = run.join("mcp.json");
    launch::write(
        &mcp,
        &serde_json::to_vec(
            &json!({"mcpServers":{(SERVER):{"command":profile.agent.path,
        "args":["edit-session","relay","--home",home,"--host-session",host,"--child-authority",crate::child_authority::encode_token(&grant),"--profile-sha256",digest],"env":{}}}}),
        )?,
        0o600,
    )?;
    let mut command = std::process::Command::new(&profile.claude.path);
    command
        .arg("--restricted")
        .arg("-p")
        .arg("--strict-mcp-config")
        .arg("--mcp-config")
        .arg(&mcp)
        .arg("--session-id")
        .arg(&host)
        .arg("--tools")
        .arg("")
        .arg("--allowedTools")
        .arg(
            tools
                .iter()
                .flat_map(|t| [t.clone(), format!("mcp__{SERVER}__{t}")])
                .collect::<Vec<_>>()
                .join(","),
        )
        .arg("--no-session-persistence")
        .arg("--output-format")
        .arg("stream-json")
        .arg("--verbose")
        .arg("--permission-mode")
        .arg("dontAsk")
        .arg("--model")
        .arg(model)
        .current_dir(&profile.root);
    crate::pilot_host::isolate(&mut command, &run, provider)?;
    let guard = crate::pilot_host::ChildEnvironmentGuard::install(&mut command, &run)?;
    for key in [
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
        "CLAUDE_CODE_DISABLE_OFFICIAL_MARKETPLACE_AUTOINSTALL",
        "DISABLE_UPDATES",
        "DISABLE_AUTOUPDATER",
        "DISABLE_BUG_REPORTING",
        "DISABLE_GROWTHBOOK",
        "CLAUDE_CODE_DISABLE_CLAUDE_MDS",
        "CLAUDE_CODE_DISABLE_AUTO_MEMORY",
        "CLAUDE_CODE_DISABLE_BACKGROUND_TASKS",
        "CLAUDE_CODE_DISABLE_BUNDLED_SKILLS",
        "CLAUDE_AGENT_SDK_DISABLE_BUILTIN_AGENTS",
    ] {
        command.env(key, "1");
    }
    command
        .env("ENABLE_CLAUDEAI_MCP_SERVERS", "false")
        .env("CLAUDE_CODE_MAX_RETRIES", "0");
    let parent_pid = std::process::id() as libc::pid_t;
    // Only async-signal-safe operations between fork/exec. OwnedChild also
    // retains the leader unreaped until its complete process group is cleaned.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0
                || libc::getppid() != parent_pid
            {
                return Err(std::io::Error::other("edit_owner_lost"));
            }
            Ok(())
        });
    }
    // Last read-only verification is adjacent to launching the pinned image.
    launch::verify(&profile)?;
    let state: crate::Shared = Arc::new(crate::AppState {
        firewall: Mutex::new(AgentFirewall::with_taint_limits(
            launch::policy()?,
            DEFAULT_TAINT_CAP,
            config.provenance.clone(),
        )?),
        sessions: Default::default(),
        audit: crate::audit::AuditSink::open(&home.join("audit.jsonl"))?,
        spans: crate::spans::SpanCache::new(64, config.judge.max_span_bytes),
        judge: crate::judge::Judge::new(config.judge.clone()),
        manifests: crate::mcp::store::ManifestStore::new(&home.join("manifests")),
        tools: crate::mcp::store::ToolRegistry::with_builtins(),
        grants: crate::grant::GrantStore::new(&home.join("grants")),
        grant_ledger: crate::grant::GrantLedger::open(&home.join("grants-spent.json")),
        grant_key: crate::grant::derive_key(&token),
        token,
        config,
        native: Some(native),
    });
    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let maintenance = tokio::spawn(crate::native::liveness::run_maintenance_loop(
        state.clone(),
        stop_rx.clone(),
    ));
    let daemon = state.clone();
    let mut server = tokio::spawn(async move {
        axum::serve(listener, crate::app(daemon))
            .with_graceful_shutdown(async move {
                let _ = stop_rx.changed().await;
            })
            .await
    });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(seconds);
    let mut child =
        match crate::mcp::OwnedChild::spawn(&mut tokio::process::Command::from(command)).await {
            Ok(child) => child,
            Err(_) => {
                let _ = stop_tx.send(true);
                server.abort();
                maintenance.abort();
                anyhow::bail!("edit_host_spawn_failed");
            }
        };
    // The leader remains owned and unreaped until cleanup. Capturing an
    // identity is only a diagnostic observation, never new process authority.
    let host_identity = child
        .child_mut()
        .id()
        .context("edit_host_identity")
        .and_then(record::process_identity)
        .and_then(|identity| profile::canonical(&identity))
        .and_then(|bytes| launch::write(&run.join("host-process.json"), &bytes, 0o400));
    if host_identity.is_err() {
        let _ = child.cleanup(false).await;
        let _ = stop_tx.send(true);
        server.abort();
        maintenance.abort();
        anyhow::bail!("edit_host_identity_unavailable");
    }
    let stream_failure = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stdout = tokio::spawn(guarded_capture(
        child
            .child_mut()
            .stdout
            .take()
            .context("edit_host_stdout")?,
        run.join("host-stdout.json"),
        stream_failure.clone(),
    ));
    let stderr = tokio::spawn(guarded_capture(
        child
            .child_mut()
            .stderr
            .take()
            .context("edit_host_stderr")?,
        run.join("host-stderr.json"),
        stream_failure.clone(),
    ));
    let mut stdin = child.child_mut().stdin.take().context("edit_host_stdin")?;
    let input = tokio::spawn(async move {
        stdin.write_all(&prompt).await?;
        stdin.shutdown().await
    });
    println!(
        "{}",
        json!({"format":FORMAT,"state":"running","run":run,"profile_sha256":record.profile_sha256,"host_session":host})
    );
    let mut reason = "host_completed";
    if guard.confirm_until(deadline.into_std()).is_err() {
        reason = "provider_child_environment_unavailable";
    } else {
        loop {
            tokio::select! {biased;
                _=term.recv()=>{reason=match control.requested(){Ok(true)=>"operator_stop",Ok(false)=>"cancelled",Err(_)=>"invalid_stop_request"};break;},
                _=interrupt.recv()=>{reason="cancelled";break;},
                _=tokio::time::sleep_until(deadline)=>{reason="deadline";break;},
                _=tokio::time::sleep(Duration::from_millis(25))=>{
                    if stream_failure.load(Ordering::Acquire){reason="host_stream_failure";break;}
                    if child.exit_observed().await {break;}
                    if server.is_finished(){reason="daemon_lost";break;}
                }
            }
        }
    }
    // Stop admission/result release at the same native lock used by execution.
    // A publication that already held that lock may have committed; no rollback
    // or automatic retry follows cancellation. The adapter is then joined before
    // any owner receipt can confirm cleanup.
    let authority = crate::mcp::replace_file::content_sha256(
        crate::child_authority::encode_token(&grant).as_bytes(),
    );
    let revoked = crate::native::pilot_stop::revoke_selected(
        &state,
        &host,
        &std::collections::BTreeMap::from([(SERVER.into(), authority)]),
        grant.expires_at_ms,
    )
    .is_ok();
    service.close();
    let adapter_clean = service.wait_idle().await;
    let cleanup = child.cleanup(false).await;
    let _ = stop_tx.send(true);
    let daemon_clean = match tokio::time::timeout(Duration::from_secs(3), &mut server).await {
        Ok(Ok(Ok(()))) => true,
        _ => {
            server.abort();
            let _ = server.await;
            false
        }
    };
    let _ = maintenance.await;
    let mut streams_ok = true;
    for mut task in [stdout, stderr] {
        if !matches!(
            tokio::time::timeout(Duration::from_secs(1), &mut task).await,
            Ok(Ok(Ok(())))
        ) {
            task.abort();
            let _ = task.await;
            streams_ok = false;
        }
    }
    let mut input = input;
    let input_ok = matches!(
        tokio::time::timeout(Duration::from_secs(1), &mut input).await,
        Ok(Ok(Ok(())))
    );
    if !input_ok {
        input.abort();
        let _ = input.await;
    }
    let quota_usage = service.quota.as_ref().map(|q| q.snapshot());
    let quota_complete = quota_usage.as_ref().is_none_or(|usage| {
        usage.as_ref().is_ok_and(|u| {
            u.indeterminate_publications == 0 && u.pending_prepublication_attempts == 0
        })
    });
    let cleanup_confirmed =
        cleanup.cleaned && cleanup.reaped && daemon_clean && adapter_clean && streams_ok;
    let receipt = control.finish(revoked, cleanup_confirmed, reason);
    let stopped = reason == "operator_stop" && revoked && cleanup_confirmed && receipt.is_ok();
    let complete = reason == "host_completed"
        && cleanup.cleaned
        && cleanup.reaped
        && cleanup.exit_success
        && daemon_clean
        && streams_ok
        && input_ok
        && adapter_clean
        && revoked
        && receipt.is_ok()
        && quota_complete;
    let mut outcome = json!({"format":FORMAT,"state":if complete {"host_completed"} else {"failed"},"reason":reason,
        "run":run,"profile_sha256":record.profile_sha256,"cleanup":cleanup,"daemon_clean":daemon_clean,
        "mutation_dispatches":service.dispatches.load(Ordering::Acquire),
        "effect_status":"consult-native-audit; interrupted-or-withheld-result-is-indeterminate; no-automatic-retry"});
    if let Some(usage) = quota_usage {
        outcome["mutation_quota"] = match usage {
            Ok(usage) => serde_json::to_value(super::quota::RetainedQuota::Known(usage))?,
            Err(_) => serde_json::to_value(super::quota::RetainedQuota::unavailable())?,
        };
    }
    launch::write(
        &run.join("terminal.json"),
        &profile::canonical(&outcome)?,
        0o400,
    )?;
    println!("{outcome}");
    ensure!(complete || stopped, "edit_session_incomplete");
    Ok(())
}
