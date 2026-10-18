// SPDX-License-Identifier: Apache-2.0
//! Uses the accepted owned-file publication and daemon lifecycle primitives.
use super::*;
use crate::mcp::profile_lifecycle::{verify_bundle_files, ProfileManager};
use crate::mcp::profile_upgrade::{Command, Target};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Classifier {
    source: PathBuf,
    sha256: String,
    python: PathBuf,
    python_sha256: String,
    workspace: PathBuf,
}

fn classifier_bytes(path: &Path) -> Result<Vec<u8>> {
    let dir = directory(path.parent().context("classifier parent absent")?)?;
    let file = open_at(
        &dir,
        path.file_name().context("classifier name absent")?,
        libc::O_RDONLY,
    )?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.nlink() == 1
            && meta.mode() & 0o022 == 0
            && (meta.uid() == 0 || meta.uid() == unsafe { libc::geteuid() })
            && meta.len() <= LIMIT as u64,
        "unsafe classifier source"
    );
    let mut bytes = Vec::new();
    file.take(LIMIT as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= LIMIT, "classifier exceeds bound");
    Ok(bytes)
}
fn classifier_path(o: &Options, c: &Classifier) -> PathBuf {
    o.home
        .join("mcp-profiles")
        .join(format!("classifier-{}.py", c.sha256))
}
fn stage_classifier(o: &Options, c: &Classifier) -> Result<()> {
    let bytes = classifier_bytes(&c.source)?;
    ensure!(
        sha(&bytes) == c.sha256 && executable(&c.python)? == c.python_sha256,
        "classifier identity changed"
    );
    let path = classifier_path(o, c);
    if path.try_exists()? {
        ensure!(
            sha(&read_private(&path)?) == c.sha256,
            "staged classifier changed"
        );
    } else {
        let dir = directory(path.parent().unwrap())?;
        ConfigFile::write_new(
            &dir,
            path.file_name()
                .unwrap()
                .to_str()
                .context("invalid classifier name")?,
            &bytes,
        )?;
        dir.sync_all()?;
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Installed {
    format: String,
    path: PathBuf,
    server: String,
    home: PathBuf,
    classifier: Option<Classifier>,
    host_session: String,
    profile_server_id: String,
    original_binary_sha256: String,
    current: String,
    previous: Option<String>,
    generation: u64,
    registry: String,
    config: String,
    policy: String,
    agent: String,
    host_reload: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    format: String,
    operation: String,
    phase: String,
    before: Owner,
    before_host_sha256: String,
    source_path: PathBuf,
    source_bundle: String,
    source_registry_path: PathBuf,
    target_path: PathBuf,
    target_bundle: String,
    target_registry: String,
    generation: u64,
    policy: String,
    rollback: bool,
    classifier: Option<Classifier>,
    host_session: String,
    profile_server_id: String,
    original_binary_sha256: String,
    proposed: Option<Owner>,
}

fn id(o: &Options) -> String {
    sha(format!("{}\0{}", o.path.display(), o.server).as_bytes())
}
fn state_name(o: &Options) -> String {
    format!(".soup-wall-profile-{}.json", id(o))
}
fn journal_name(o: &Options) -> String {
    format!(".soup-wall-profile-transition-{}.json", id(o))
}
fn read_record<T: serde::de::DeserializeOwned>(
    config: &ConfigFile,
    name: &str,
) -> Result<Option<T>> {
    match std::fs::symlink_metadata(config.path.parent().unwrap().join(name)) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
        Ok(_) => Ok(Some(serde_json::from_value(parse(
            &read_at(&config.dir, name.as_ref())?.0,
        )?)?)),
    }
}
fn save<T: Serialize>(config: &ConfigFile, name: &str, record: &T) -> Result<()> {
    let bytes = serde_json::to_vec(record)?;
    ensure!(
        bytes.len() <= LIMIT,
        "profile transaction metadata exceeds bound"
    );
    config.atomic(name.as_ref(), &bytes)
}
fn remove(config: &ConfigFile, name: &str) -> Result<()> {
    let name = CString::new(name)?;
    ensure!(
        unsafe { libc::unlinkat(config.dir.as_raw_fd(), name.as_ptr(), 0) } == 0,
        "cannot retire profile transition metadata"
    );
    config.dir.sync_all()?;
    Ok(())
}
fn validate_installed(state: &Installed, o: &Options) -> Result<()> {
    ensure!(
        state.format == "sw-mcp/owned-profile/1"
            && state.path == o.path
            && state.server == o.server
            && state.home == o.home,
        "profile ownership mismatch"
    );
    ensure!(
        state.generation > 0
            && [
                &state.current,
                &state.registry,
                &state.config,
                &state.policy,
                &state.agent,
                &state.original_binary_sha256
            ]
            .iter()
            .all(|s| crate::native::is_digest(s))
            && state
                .previous
                .as_deref()
                .is_none_or(crate::native::is_digest),
        "invalid installed profile identity"
    );
    ensure!(
        !state.host_session.is_empty()
            && state.host_session.len() <= 128
            && !state.profile_server_id.is_empty()
            && state.profile_server_id.len() <= 128,
        "invalid installed session identity"
    );
    if let Some(c) = &state.classifier {
        ensure!(
            crate::native::is_digest(&c.sha256)
                && crate::native::is_digest(&c.python_sha256)
                && c.source.is_absolute()
                && c.python.is_absolute()
                && c.workspace.is_absolute(),
            "invalid classifier identity"
        );
    }
    Ok(())
}
fn manager(o: &Options, journal: &Journal) -> ProfileManager {
    ProfileManager::new(&o.home)
        .with_owned_source(
            journal.source_bundle.clone(),
            journal.source_registry_path.clone(),
        )
        .with_owned_operation(journal.operation.clone())
}
fn guard_path(o: &Options) -> PathBuf {
    o.home.join("mcp-profiles/connection-transition.json")
}
fn has_guard(o: &Options) -> Result<bool> {
    match std::fs::symlink_metadata(guard_path(o)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
fn guard_bytes(o: &Options, j: &Journal) -> Vec<u8> {
    format!("{}\n{}\n{}", j.operation, o.path.display(), o.server).into_bytes()
}
fn reserve(o: &Options, j: &Journal) -> Result<()> {
    let root = o.home.join("mcp-profiles");
    if !root.exists() {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        File::open(&o.home)?.sync_all()?;
    }
    let dir = directory(&root)?;
    let dm = dir.metadata()?;
    ensure!(
        dm.uid() == unsafe { libc::geteuid() } && dm.mode() & 0o077 == 0,
        "profile transaction directory is not private"
    );
    ConfigFile::write_new(&dir, "connection-transition.json", &guard_bytes(o, j))?;
    dir.sync_all()?;
    Ok(())
}
fn release(o: &Options, j: &Journal) -> Result<()> {
    if has_guard(o)? {
        ensure!(
            read_private(&guard_path(o))? == guard_bytes(o, j),
            "profile transaction was superseded"
        );
        let dir = directory(guard_path(o).parent().unwrap())?;
        let name = CString::new("connection-transition.json")?;
        ensure!(
            unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) } == 0,
            "cannot retire profile reservation"
        );
        dir.sync_all()?;
    }
    Ok(())
}

async fn native_request(
    o: &Options,
    method: reqwest::Method,
    route: &str,
    host: Option<&str>,
    activation: bool,
) -> Result<Value> {
    use futures_util::StreamExt;
    let config = crate::Config::from_yaml(std::str::from_utf8(&read_private(
        &o.home.join("config.yaml"),
    )?)?)?;
    let address: std::net::IpAddr = config
        .bind
        .parse()
        .context("numeric loopback Agent bind required")?;
    ensure!(
        address.is_loopback(),
        "profile control requires a loopback Agent"
    );
    let token = read_private(&o.home.join("native-token"))?;
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()?;
    let mut request = client
        .request(method, format!("http://{}{route}", config.socket_address()))
        .bearer_auth(std::str::from_utf8(&token)?.trim());
    if let Some(host) = host {
        request = request.header("x-agentfw-host-session", host);
    }
    if activation {
        request = request.header("x-agentfw-profile-activation", "true");
    }
    let response = request
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("native control endpoint unavailable"))?;
    ensure!(
        response.status().is_success(),
        "native control endpoint refused transition"
    );
    let mut stream = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| anyhow::anyhow!("native control response incomplete"))?;
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= LIMIT,
            "native control response exceeds bound"
        );
        bytes.extend_from_slice(&chunk);
    }
    parse(&bytes)
}

async fn preview(target: &Target, config: &ConfigFile) -> Result<(Value, Owner, String, String)> {
    let o = &target.connection;
    ensure!(
        !target.host_session.is_empty()
            && target.host_session.len() <= 128
            && target
                .host_session
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"-_.:".contains(&c)),
        "invalid host session identity"
    );
    ensure!(
        o.probe_tool.is_none(),
        "profile transitions do not execute preview probes"
    );
    ensure!(
        target.source_profile.is_absolute() && target.profile.is_absolute(),
        "absolute reviewed profile paths required"
    );
    ensure!(
        config.publication()?.is_none(),
        "unfinished host publication requires recovery"
    );
    ensure!(
        read_record::<Journal>(config, &journal_name(o))?.is_none(),
        "profile transition requires recovery"
    );
    ensure!(
        !has_guard(o)?,
        "another owned profile transaction is pending"
    );
    let owner = config
        .state(&o.server)?
        .context("selected connection is not owned")?;
    ensure!(
        owner.phase == "connected"
            && owner.agent == o.agent
            && owner.home == o.home
            && hash(&config.entry(&o.server)?) == owner.wrapped_sha256,
        "selected connection ownership changed"
    );
    config.validate_transaction(&owner)?;
    let native = preflight(o).await?;
    ensure!(
        native.binary == owner.agent_sha256
            && native.registry == owner.registry_sha256
            && native.config == owner.native_config_sha256,
        "selected Agent or native configuration changed"
    );
    let source = verify_bundle_files(&target.source_profile)?;
    let candidate = verify_bundle_files(&target.profile)?;
    ensure!(
        source.registry_sha256 == native.registry,
        "reviewed source registry differs from owned connection"
    );
    let source_profile = crate::mcp::profile_author::parse_profile_bytes(&std::fs::read(
        target.source_profile.join("profile.json"),
    )?)?;
    let candidate_profile = crate::mcp::profile_author::parse_profile_bytes(&std::fs::read(
        target.profile.join("profile.json"),
    )?)?;
    ensure!(
        candidate_profile.server_id == source_profile.server_id
            && source_profile.server_id == format!("claude-{}", &id(o)[..24]),
        "profile original server identity mismatch"
    );
    let registry_config: crate::native::Registry =
        serde_json::from_slice(&std::fs::read(target.profile.join("registry.json"))?)?;
    let policies: Vec<_> = registry_config
        .tools
        .iter()
        .filter_map(|t| t.resource_policy.as_ref())
        .collect();
    let classifier = if let Some(path) = &target.classifier_script {
        ensure!(path.is_absolute(), "absolute classifier path required");
        let digest = sha(&classifier_bytes(path)?);
        let workspace = policies
            .first()
            .map(|p| p.workspace.clone())
            .unwrap_or_else(|| o.home.clone());
        ensure!(
            policies
                .iter()
                .all(|p| p.classifier_sha256 == digest && p.workspace == workspace),
            "classifier revision or workspace differs from reviewed resource authority"
        );
        let python = Path::new("/usr/bin/python3").canonicalize()?;
        Some(Classifier {
            source: path.clone(),
            sha256: digest,
            python_sha256: executable(&python)?,
            python,
            workspace,
        })
    } else {
        ensure!(
            policies.is_empty(),
            "resource profile requires a reviewed classifier script"
        );
        None
    };
    let state = ProfileManager::new(&o.home).load_state()?;
    ensure!(
        state.in_progress.is_none(),
        "daemon profile transition requires recovery"
    );
    if let Some(active) = &state.active_bundle_sha256 {
        ensure!(*active == source.bundle_sha256, "active profile changed");
    }
    let installed = read_record::<Installed>(config, &state_name(o))?;
    if let Some(installed) = &installed {
        validate_installed(installed, o)?;
        ensure!(
            installed.current == source.bundle_sha256
                && installed.generation == state.generation
                && installed.host_session == target.host_session
                && installed.profile_server_id == source_profile.server_id
                && executable(Path::new(
                    owner.original["command"]
                        .as_str()
                        .context("original command absent")?
                ))? == installed.original_binary_sha256,
            "profile revision or generation changed"
        );
        if target.rollback {
            ensure!(
                installed.previous.as_deref() == Some(candidate.bundle_sha256.as_str()),
                "rollback requires the previous explicitly reviewed snapshot"
            );
        }
    } else {
        ensure!(
            !target.rollback,
            "no owned profile rollback snapshot recorded"
        );
    }
    let generation = state
        .generation
        .checked_add(1)
        .context("profile generation exhausted")?;
    let runtime =
        native_request(o, reqwest::Method::GET, "/native/v1/instance", None, false).await?;
    let diff =
        crate::mcp::profile_author::compute_profile_diff(&target.source_profile, &target.profile)?;
    let binding = json!({"domain":"agentfw/owned-profile-preview/v1", "path":o.path,"server":o.server,
        "home":o.home,"owner":owner,"installed":installed,
        "profile_state_sha256":crate::mcp::profile_author::digest(&serde_json::to_value(&state)?),
        "host_config":sha(&config.bytes),"agent":native.binary,
        "agent_config":native.config,"registry":native.registry,"policy":native.policy,
        "native_instance":runtime["instance_id"],"original_binary_sha256":executable(Path::new(owner.original["command"].as_str().context("original command absent")?))?,"source":source.bundle_sha256,"target":candidate.bundle_sha256,
        "generation":generation,"rollback":target.rollback,"classifier":classifier,"host_session":target.host_session,"profile_server_id":source_profile.server_id});
    let approval = crate::mcp::profile_author::digest(&binding);
    config.snapshot_unchanged(&o.server, &Some(owner.clone()))?;
    Ok((
        json!({"format":"sw-mcp/owned-profile-preview/1","status":"preview","approval":approval,
        "identities":binding,"diff":diff,"host_reload":"pending_after_apply","runtime_execution":"not_probed"}),
        owner,
        source.bundle_sha256,
        candidate.bundle_sha256,
    ))
}

fn launcher(o: &Options, original: &Value, generation: u64) -> Result<Value> {
    let mut entry = original.clone();
    entry["command"] = json!("/usr/bin/env");
    entry["args"] = json!([
        "-i",
        "PATH=/usr/bin:/bin",
        format!(
            "HOME={}",
            o.home.parent().context("missing home parent")?.display()
        ),
        o.agent,
        "mcp-connection",
        "profile",
        "collector",
        "--path",
        o.path,
        "--server",
        o.server,
        "--home",
        o.home,
        "--agent",
        o.agent,
        "--generation",
        generation.to_string()
    ]);
    validate_entry(&entry)?;
    Ok(entry)
}

async fn finish(o: &Options, config: &mut ConfigFile, j: &mut Journal) -> Result<Value> {
    let state = manager(o, j).load_state()?;
    ensure!(
        state.in_progress.is_none()
            && state.active_bundle_sha256.as_deref() == Some(j.target_bundle.as_str())
            && state.generation == j.generation,
        "target profile activation is incomplete"
    );
    let native = preflight(o).await?;
    ensure!(
        native.registry == j.target_registry
            && native.binary == j.before.agent_sha256
            && native.policy == j.policy,
        "candidate daemon identity or policy changed"
    );
    ensure!(
        executable(Path::new(
            j.before.original["command"]
                .as_str()
                .context("original command absent")?
        ))? == j.original_binary_sha256,
        "original server binary changed"
    );
    let mut proposed = j.before.clone();
    proposed.wrapped = launcher(o, &j.before.original, j.generation)?;
    proposed.wrapped_sha256 = hash(&proposed.wrapped);
    proposed.native_config_sha256 = native.config.clone();
    proposed.registry_sha256 = native.registry.clone();
    proposed.phase = "connected".into();
    config.validate_transaction(&proposed)?;
    let current = config
        .state(&o.server)?
        .context("connection ownership disappeared")?;
    ensure!(
        current == j.before || current == proposed,
        "connection owner was superseded"
    );
    let selected = config.entry(&o.server)?;
    if selected != proposed.wrapped {
        ensure!(
            selected == j.before.wrapped && sha(&config.bytes) == j.before_host_sha256,
            "host configuration changed; conflict preserved"
        );
        j.proposed = Some(proposed.clone());
        j.phase = "publishing".into();
        save(config, &journal_name(o), j)?;
        config.replace(&o.server, &proposed.wrapped)?;
    } else {
        // A completed atomic exchange is recognized only from its retained journal.
        ensure!(
            j.proposed.as_ref() == Some(&proposed),
            "unrecorded host publication; conflict preserved"
        );
    }
    config.save(&proposed)?;
    let installed = Installed {
        format: "sw-mcp/owned-profile/1".into(),
        path: o.path.clone(),
        server: o.server.clone(),
        home: o.home.clone(),
        classifier: j.classifier.clone(),
        host_session: j.host_session.clone(),
        profile_server_id: j.profile_server_id.clone(),
        original_binary_sha256: j.original_binary_sha256.clone(),
        current: j.target_bundle.clone(),
        previous: Some(j.source_bundle.clone()),
        generation: j.generation,
        registry: native.registry,
        config: native.config,
        policy: native.policy,
        agent: native.binary,
        host_reload: "pending".into(),
    };
    save(config, &state_name(o), &installed)?;
    let activation = native_request(
        o,
        reqwest::Method::POST,
        crate::native::continuity::BARRIER,
        Some(&j.host_session),
        true,
    )
    .await?;
    ensure!(
        activation["registry_sha256"].as_str() == Some(j.target_registry.as_str()),
        "candidate changed before authority activation"
    );
    release(o, j)?;
    remove(config, &journal_name(o))?;
    Ok(
        json!({"status":"configured","generation":installed.generation,"bundle_sha256":installed.current,
        "daemon":"configuration_verified","host_reload":"pending","runtime_execution":"not_probed"}),
    )
}

async fn apply(target: Target, approval: String) -> Result<Value> {
    let o = &target.connection;
    let mut config = ConfigFile::read(&o.path)?;
    let _lock = config.lock()?;
    let (report, owner, source_bundle, target_bundle) = preview(&target, &config).await?;
    ensure!(
        report["approval"].as_str() == Some(&approval),
        "exact owned profile preview approval required"
    );
    let cfg = crate::Config::from_yaml(std::str::from_utf8(&read_private(
        &o.home.join("config.yaml"),
    )?)?)?;
    let source_registry_path = cfg.native.context("native config absent")?.registry_path;
    let mut j = Journal {
        format: "sw-mcp/owned-profile-journal/1".into(),
        operation: format!("op-{}", crate::token::generate()),
        phase: "prepared".into(),
        before: owner,
        before_host_sha256: sha(&config.bytes),
        source_path: target.source_profile.clone(),
        source_bundle,
        source_registry_path,
        target_path: target.profile.clone(),
        target_bundle,
        target_registry: verify_bundle_files(&target.profile)?.registry_sha256,
        generation: report["identities"]["generation"]
            .as_u64()
            .context("invalid preview generation")?,
        policy: report["identities"]["policy"]
            .as_str()
            .context("invalid preview policy")?
            .into(),
        rollback: target.rollback,
        classifier: serde_json::from_value(report["identities"]["classifier"].clone())?,
        host_session: target.host_session.clone(),
        original_binary_sha256: report["identities"]["original_binary_sha256"]
            .as_str()
            .context("missing original binary identity")?
            .into(),
        profile_server_id: report["identities"]["profile_server_id"]
            .as_str()
            .context("missing server identity")?
            .into(),
        proposed: None,
    };
    save(&config, &journal_name(o), &j)?;
    reserve(o, &j)?;
    if let Some(c) = &j.classifier {
        stage_classifier(o, c)?;
    }
    let mgr = manager(o, &j);
    let staged_source = mgr.stage_owned_revision(&target.source_profile, &j.source_bundle)?;
    let staged_target = mgr.stage_owned_revision(&target.profile, &j.target_bundle)?;
    let barrier = native_request(
        o,
        reqwest::Method::POST,
        crate::native::continuity::BARRIER,
        Some(&j.host_session),
        false,
    )
    .await?;
    ensure!(
        barrier["registry_sha256"] == report["identities"]["registry"]
            && barrier["instance_id"] == report["identities"]["native_instance"],
        "source daemon changed before checkpoint"
    );
    j.phase = "checkpointed".into();
    save(&config, &journal_name(o), &j)?;
    mgr.adopt_owned_source(&staged_source, &j.before.native_config_sha256)?;
    let rollback = j.rollback;
    let target_bundle = j.target_bundle.clone();
    let prior_generation = j.generation - 1;
    // The accepted synchronous lifecycle manager owns its bounded HTTP runtime.
    // Keep it outside this CLI's async runtime instead of nesting runtimes.
    let activated = tokio::task::spawn_blocking(move || {
        if rollback {
            let token = mgr.preview_rollback(Some(&target_bundle))?.approval_sha256;
            mgr.rollback(Some(&target_bundle), Some(prior_generation), Some(&token))
        } else {
            let token = mgr.preview_upgrade(&staged_target)?.approval_sha256;
            mgr.upgrade(
                &staged_target,
                Some(&target_bundle),
                Some(prior_generation),
                Some(&token),
            )
        }
    })
    .await
    .context("profile lifecycle worker failed")??;
    ensure!(
        activated.verified && activated.daemon_restarted,
        "candidate daemon activation was not verified"
    );
    finish(o, &mut config, &mut j).await
}

async fn recover(o: Options) -> Result<Value> {
    let mut config = ConfigFile::read(&o.path)?;
    let _lock = config.lock()?;
    let Some(mut j) = read_record::<Journal>(&config, &journal_name(&o))? else {
        return Ok(json!({"status":"no_pending_transition"}));
    };
    ensure!(
        j.format == "sw-mcp/owned-profile-journal/1"
            && j.before.path == o.path
            && j.before.server == o.server
            && j.before.home == o.home
            && j.before.agent == o.agent,
        "profile recovery ownership mismatch"
    );
    if has_guard(&o)? {
        ensure!(
            read_private(&guard_path(&o))? == guard_bytes(&o, &j),
            "another transaction owns profile recovery"
        );
    } else {
        reserve(&o, &j)?;
    }
    if let Some(publication) = config.publication()? {
        config.finish_publication(&publication)?;
        config = ConfigFile::read(&o.path)?;
    }
    let mgr = manager(&o, &j);
    let state = mgr.load_state()?;
    if let Some(inner) = &state.in_progress {
        ensure!(
            inner.operation_id == j.operation,
            "foreign daemon transition preserved"
        );
        let recovery = manager(&o, &j);
        tokio::task::spawn_blocking(move || recovery.recover())
            .await
            .context("profile recovery worker failed")??;
    }
    let state = mgr.load_state()?;
    if state.active_bundle_sha256.as_deref() == Some(j.target_bundle.as_str())
        && state.generation == j.generation
    {
        return finish(&o, &mut config, &mut j).await;
    }
    ensure!(
        config.state(&o.server)?.as_ref() == Some(&j.before)
            && sha(&config.bytes) == j.before_host_sha256,
        "baseline host ownership changed; conflict preserved"
    );
    let native = preflight(&o).await?;
    ensure!(
        native.config == j.before.native_config_sha256
            && native.registry == j.before.registry_sha256
            && native.binary == j.before.agent_sha256
            && native.policy == j.policy,
        "baseline runtime recovery is incomplete"
    );
    release(&o, &j)?;
    remove(&config, &journal_name(&o))?;
    Ok(json!({"status":"recovered_baseline","host_reload":"pending","risk_history":"retained"}))
}

async fn collector(o: Options, generation: u64) -> Result<Value> {
    use std::os::unix::process::CommandExt;
    let config = ConfigFile::read(&o.path)?;
    let _lock = config.lock()?;
    ensure!(
        !has_guard(&o)? && read_record::<Journal>(&config, &journal_name(&o))?.is_none(),
        "profile transition is incomplete"
    );
    let installed: Installed =
        read_record(&config, &state_name(&o))?.context("owned profile state absent")?;
    validate_installed(&installed, &o)?;
    ensure!(
        installed.generation == generation,
        "stale profile launcher generation"
    );
    let active = ProfileManager::new(&o.home).load_state()?;
    ensure!(
        active.in_progress.is_none()
            && active.generation == generation
            && active.active_bundle_sha256.as_deref() == Some(installed.current.as_str()),
        "active profile was superseded"
    );
    let active_bundle = verify_bundle_files(
        &o.home
            .join("mcp-profiles/revisions")
            .join(&installed.current),
    )?;
    ensure!(
        active_bundle.bundle_sha256 == installed.current
            && active_bundle.registry_sha256 == installed.registry,
        "installed reviewed bundle changed"
    );
    let owner = config
        .state(&o.server)?
        .context("owned connection absent")?;
    ensure!(
        owner.phase == "connected"
            && owner.home == o.home
            && owner.agent == o.agent
            && config.entry(&o.server)? == owner.wrapped
            && owner.wrapped == launcher(&o, &owner.original, generation)?,
        "owned launcher was changed"
    );
    let native = preflight(&o).await?;
    ensure!(
        native.binary == installed.agent
            && native.config == installed.config
            && native.registry == installed.registry
            && native.policy == installed.policy,
        "installed profile identity changed"
    );
    let registry_cfg = crate::Config::from_yaml(std::str::from_utf8(&read_private(
        &o.home.join("config.yaml"),
    )?)?)?;
    let token = read_private(&o.home.join("native-token"))?;
    let native_state = crate::native::NativeState::load(
        registry_cfg
            .native
            .as_ref()
            .context("native registry absent")?,
        std::str::from_utf8(&token)?.trim().to_string(),
    )?;
    let snapshot =
        native_request(&o, reqwest::Method::GET, "/native/v1/instance", None, false).await?;
    let instance = snapshot["instance_id"]
        .as_str()
        .context("native instance unavailable")?;
    let tools: Vec<_> = native_state
        .registry
        .tools
        .iter()
        .map(|t| t.name.clone())
        .collect();
    let mut resources = Vec::new();
    for policy in native_state
        .registry
        .tools
        .iter()
        .filter_map(|t| t.resource_policy.as_ref())
    {
        for resource in &policy.allowed_resources {
            use crate::mcp::resources::Resource;
            resources.push(match resource {
                Resource::Path { canonical } | Resource::Url { canonical, .. } => canonical.clone(),
                Resource::Domain { host } => host.clone(),
                Resource::Recipient { address, .. } => address.clone(),
            });
        }
    }
    resources.sort();
    resources.dedup();
    let host = installed.host_session.clone();
    let grant = crate::native::child_authority::mint_scoped(
        &crate::native::child_authority::derive_key(std::str::from_utf8(&token)?.trim()),
        &host,
        &installed.profile_server_id,
        &tools,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis()
            .try_into()?,
        3_600_000,
        format!("{instance}.{}", crate::token::generate()),
        Some(format!("profile-root-{}", crate::token::generate())),
        None,
        Some(resources),
    );
    let original = &owner.original;
    ensure!(
        executable(Path::new(
            original["command"]
                .as_str()
                .context("original command absent")?
        ))? == installed.original_binary_sha256,
        "original server binary changed"
    );
    config.snapshot_unchanged(&o.server, &Some(owner.clone()))?;
    // Release the host publication lock before replacing the process image.
    drop(_lock);
    let mut command = std::process::Command::new(&o.agent);
    command
        .args([
            "mcp",
            "--id",
            &installed.profile_server_id,
            "--native-admission",
            "--",
        ])
        .arg(original["command"].as_str().unwrap())
        .args(
            original["args"]
                .as_array()
                .into_iter()
                .flatten()
                .map(|v| v.as_str().unwrap()),
        )
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", o.home.parent().unwrap())
        .env("AGENTFW_HOST_SESSION", host)
        .env(
            "AGENTFW_CHILD_AUTHORITY",
            crate::native::child_authority::encode_token(&grant),
        );
    if let Some(c) = &installed.classifier {
        let path = classifier_path(&o, c);
        ensure!(
            sha(&read_private(&path)?) == c.sha256 && executable(&c.python)? == c.python_sha256,
            "installed classifier changed"
        );
        command
            .env("AGENTFW_CLASSIFIER", "rule-baseline")
            .env("AGENTFW_RULE_BASELINE", path)
            .env("AGENTFW_CLASSIFIER_PYTHON", &c.python)
            .env("AGENTFW_WORKSPACE", &c.workspace)
            .current_dir(&c.workspace);
    }
    Err(command.exec().into())
}

pub(crate) async fn run(command: Command) -> Result<Value> {
    match command {
        Command::Preview(target) => {
            let config = ConfigFile::read(&target.connection.path)?;
            Ok(preview(&target, &config).await?.0)
        }
        Command::Apply { target, approval } => apply(target, approval).await,
        Command::Recover(o) => recover(o).await,
        Command::Collector {
            connection,
            generation,
        } => collector(connection, generation).await,
        Command::Status(o) => {
            let config = ConfigFile::read(&o.path)?;
            let pending = read_record::<Journal>(&config, &journal_name(&o))?.is_some()
                || has_guard(&o)?
                || config.publication()?.is_some();
            let installed = read_record::<Installed>(&config, &state_name(&o))?;
            if let Some(state) = &installed {
                validate_installed(state, &o)?;
            }
            let owner = config.state(&o.server)?;
            let selected = config.entry(&o.server)?;
            let owned = owner.as_ref().is_some_and(|owner| {
                owner.phase == "connected"
                    && owner.home == o.home
                    && owner.agent == o.agent
                    && selected == owner.wrapped
            });
            let runtime = preflight(&o).await;
            let verified = installed.as_ref().is_some_and(|i| {
                runtime.as_ref().is_ok_and(|n| {
                    n.binary == i.agent
                        && n.registry == i.registry
                        && n.config == i.config
                        && n.policy == i.policy
                })
            });
            let active = ProfileManager::new(&o.home).load_state()?;
            let consistent = installed.as_ref().is_some_and(|i| {
                active.in_progress.is_none()
                    && active.active_bundle_sha256.as_deref() == Some(i.current.as_str())
                    && active.generation == i.generation
                    && owner.as_ref().is_some_and(|owner| {
                        launcher(&o, &owner.original, i.generation).is_ok_and(|v| v == selected)
                    })
            });
            config.snapshot_unchanged(&o.server, &owner)?;
            Ok(
                json!({"status":if pending {"incomplete"} else if installed.is_none(){"not_configured"}
                else if !owned || !consistent {"conflict"} else {"configured"},
                "profile":installed,"daemon":if verified {"configuration_verified"}else if runtime.is_err(){"unavailable"}else{"identity_mismatch"},
                "host_reload":"pending","runtime_execution":"not_probed"}),
            )
        }
    }
}
