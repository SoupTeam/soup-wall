// SPDX-License-Identifier: Apache-2.0
//! SOU-231: one explicit installed managed connection; no enrollment secrets in reports.
#[cfg(unix)]
use anyhow::Context;
use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

#[cfg(unix)]
mod fs;
#[cfg(all(test, unix))]
mod tests;
const PROFILE: &str = "managed-console.json";
#[cfg(unix)]
const MAX_PROFILE: usize = 16 * 1024;
#[cfg(unix)]
const MAX_CONFIG: usize = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, clap::Args)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Approved single Console origin, HTTPS except an explicit loopback fixture.
    #[arg(long)]
    pub console: String,
    #[arg(long)]
    pub tenant: String,
    #[arg(long)]
    pub agent: String,
    /// Existing private credential; never put a bearer token in argv.
    #[arg(long)]
    pub credential_file: PathBuf,
    /// Independently selected local issuer keyring; never obtained by this command.
    #[arg(long)]
    pub issuer_keyring: PathBuf,
    #[arg(long)]
    pub ca_file: Option<PathBuf>,
}
#[derive(clap::Subcommand)]
pub enum Command {
    /// Read-only preview, including the exact confirmation needed by apply.
    Preview {
        #[command(flatten)]
        settings: Settings,
    },
    /// Atomically select this connection. Refuses active or uncertain lifecycle state.
    Apply {
        #[command(flatten)]
        settings: Settings,
        #[arg(long)]
        confirm: String,
    },
    /// Show configured vs authenticated running identity and recorded application.
    Inspect,
    /// Read-only Console authentication/signature probe; never applies or acknowledges.
    Verify,
    /// Read-only disconnect preview; leaves active policy and all user files intact.
    DisconnectPreview,
    /// Stop future sync. Stop the Agent first; retains last accepted signed policy.
    Disconnect {
        #[arg(long)]
        confirm: String,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectionIdentity {
    pub generation: String,
    pub settings_sha256: String,
    pub enabled: bool,
    pub ca_sha256: Option<String>,
}
#[cfg(unix)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    schema_version: u32,
    generation: String,
    enabled: bool,
    settings: Settings,
    ca_sha256: Option<String>,
    receipt: Receipt,
}
#[cfg(unix)]
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    confirmation: String,
    inputs_sha256: String,
    result_sha256: String,
}
#[cfg(unix)]
impl Profile {
    fn identity(&self) -> ConnectionIdentity {
        ConnectionIdentity {
            generation: self.generation.clone(),
            settings_sha256: hash_value(&self.settings),
            enabled: self.enabled,
            ca_sha256: self.ca_sha256.clone(),
        }
    }
}
#[cfg(unix)]
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
#[cfg(unix)]
fn hash_value(value: &impl Serialize) -> String {
    hash(&serde_json::to_vec(value).expect("bounded connection value serializes"))
}
#[cfg(unix)]
fn digest_valid(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
#[cfg(unix)]
fn equal(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.as_bytes().ct_eq(b.as_bytes()).into()
}
#[cfg(unix)]
fn parse(bytes: &[u8]) -> Result<Profile> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_PROFILE,
        "managed_connection_profile_size"
    );
    let profile: Profile = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("managed_connection_invalid_profile"))?;
    ensure!(
        profile.schema_version == 1
            && profile.generation.len() == 43
            && profile
                .generation
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b))
            && digest_valid(&profile.receipt.confirmation)
            && digest_valid(&profile.receipt.inputs_sha256)
            && digest_valid(&profile.receipt.result_sha256),
        "managed_connection_invalid_profile_contract"
    );
    ensure!(
        profile.ca_sha256.as_deref().is_none_or(digest_valid)
            && profile.ca_sha256.is_some() == profile.settings.ca_file.is_some(),
        "managed_connection_invalid_ca_binding"
    );
    ensure!(
        equal(
            &profile.receipt.result_sha256,
            &hash_value(&profile.identity())
        ),
        "managed_connection_receipt_result_mismatch"
    );
    validate_settings(&profile.settings)?;
    Ok(profile)
}
#[cfg(unix)]
fn validate_settings(s: &Settings) -> Result<()> {
    let origin = crate::managed_sync::parse_console_origin(&s.console)?;
    ensure!(
        origin.as_str() == s.console,
        "managed_connection_use_canonical_origin_with_trailing_slash"
    );
    for id in [&s.tenant, &s.agent] {
        ensure!(
            !id.is_empty()
                && id.len() <= 128
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
            "managed_connection_invalid_audience"
        );
    }
    for path in [&s.credential_file, &s.issuer_keyring]
        .into_iter()
        .chain(s.ca_file.iter())
    {
        let raw = path.as_os_str().as_encoded_bytes();
        ensure!(
            path.is_absolute()
                && path.to_str().is_some()
                && path.file_name().is_some()
                && raw.len() <= 4096
                && !raw.iter().any(|b| b.is_ascii_control())
                && raw[1..]
                    .split(|b| *b == b'/')
                    .all(|p| !p.is_empty() && p != b"." && p != b".."),
            "managed_connection_invalid_reference"
        );
    }
    ensure!(
        s.ca_file.is_none() || origin.scheme() == "https",
        "managed_connection_ca_requires_https"
    );
    Ok(())
}
#[cfg(unix)]
fn reject_mixed_environment() -> Result<()> {
    ensure!(
        !std::env::vars_os()
            .any(|(key, _)| key.as_encoded_bytes().starts_with(b"SOUP_MANAGED_AGENT_")),
        "managed_connection_mixed_environment_refused_clear_SOUP_MANAGED_AGENT_settings"
    );
    Ok(())
}

#[cfg(unix)]
fn inputs(settings: &Settings, credential: bool) -> Result<Vec<fs::Snapshot>> {
    validate_settings(settings)?;
    let mut snapshots = vec![];
    if credential {
        let token = fs::selected(&settings.credential_file, 64)?;
        crate::managed_credential::validate_token(
            std::str::from_utf8(&token.bytes).context("managed_connection_credential_encoding")?,
        )?;
        snapshots.push(token);
    }
    let keys = fs::selected(
        &settings.issuer_keyring,
        crate::managed_policy::MAX_KEYRING_BYTES,
    )?;
    let parsed = crate::managed_policy::parse_keyring(&keys.bytes)?;
    ensure!(
        parsed.iter().any(|key| !key.revoked),
        "managed_connection_no_active_trust_anchor"
    );
    snapshots.push(keys);
    if let Some(path) = &settings.ca_file {
        let ca = fs::selected(path, 64 * 1024)?;
        crate::managed_sync::validate_private_ca(&ca.bytes)?;
        snapshots.push(ca);
    }
    Ok(snapshots)
}

#[cfg(unix)]
fn profile_inputs(profile: &Profile) -> Result<Vec<fs::Snapshot>> {
    let snapshots = if profile.enabled {
        inputs(&profile.settings, true)?
    } else {
        let key = fs::selected(
            &profile.settings.issuer_keyring,
            crate::managed_policy::MAX_KEYRING_BYTES,
        )?;
        crate::managed_policy::parse_keyring(&key.bytes)?;
        vec![key]
    };
    if profile.enabled {
        ensure!(
            profile.ca_sha256
                == profile
                    .settings
                    .ca_file
                    .as_ref()
                    .map(|_| hash(&snapshots.last().unwrap().bytes)),
            "managed_connection_ca_changed_preview_and_apply_before_restart"
        );
    }
    Ok(snapshots)
}

#[cfg(unix)]
pub(crate) fn read_private_reference(path: &Path, cap: usize) -> Result<Vec<u8>> {
    Ok(fs::selected(path, cap)?.bytes)
}
#[cfg(not(unix))]
pub(crate) fn read_private_reference(_path: &Path, _cap: usize) -> Result<Vec<u8>> {
    anyhow::bail!("managed_connection_requires_linux")
}

/// The explicit selector's absence is the ONLY path to environment-only behavior.
/// A disabled selector retains pinned trust/audience for offline policy restoration.
pub struct Startup {
    pub sync: Option<crate::managed_sync::ManagedSync>,
    pub identity: Option<ConnectionIdentity>,
    pub enabled: bool,
}
pub fn startup(home: &Path) -> Result<Startup> {
    #[cfg(unix)]
    if match std::fs::symlink_metadata(home.join(PROFILE)) {
        Ok(_) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => anyhow::bail!("managed_connection_selector_unavailable"),
    } {
        ensure!(
            cfg!(target_os = "linux"),
            "managed_connection_requires_linux"
        );
        reject_mixed_environment()?;
        let root = fs::Root::open(home)?;
        let selected = root.snapshot(PROFILE, MAX_PROFILE)?;
        let profile = parse(&selected.bytes)?;
        let loaded = profile_inputs(&profile)?;
        let mut sync = crate::managed_sync::ManagedSync::from_connection(
            home,
            &profile.settings,
            profile.enabled,
        )?;
        sync.bind_connection(home, profile.identity());
        ensure!(
            selected == root.snapshot(PROFILE, MAX_PROFILE)? && loaded == profile_inputs(&profile)?,
            "managed_connection_changed_during_startup"
        );
        root.recheck()?;
        return Ok(Startup {
            sync: Some(sync),
            identity: Some(profile.identity()),
            enabled: profile.enabled,
        });
    }
    #[cfg(not(unix))]
    ensure!(
        std::fs::symlink_metadata(home.join(PROFILE)).is_err(),
        "managed_connection_requires_linux"
    );
    Ok(Startup {
        sync: crate::managed_sync::ManagedSync::from_environment(home)?,
        identity: None,
        enabled: true,
    })
}

pub(crate) fn still_selected(home: &Path, expected: &ConnectionIdentity) -> bool {
    #[cfg(unix)]
    {
        fs::Root::open(home)
            .and_then(|root| parse(&root.snapshot(PROFILE, MAX_PROFILE)?.bytes))
            .is_ok_and(|p| p.identity() == *expected)
    }
    #[cfg(not(unix))]
    {
        let _ = (home, expected);
        false
    }
}

#[cfg(unix)]
#[derive(Serialize)]
struct Binding<'a> {
    domain: &'static str,
    enabled: bool,
    settings: &'a Settings,
    home: &'a fs::Object,
    config: fs::Snapshot,
    lifecycle: fs::Snapshot,
    active_policy: fs::Snapshot,
    inputs: &'a [fs::Snapshot],
}
#[cfg(unix)]
struct Transition {
    selected: fs::Snapshot,
    profile: Option<Profile>,
    inputs_sha256: String,
    confirmation: String,
    probe_inputs: Vec<fs::Snapshot>,
}
#[cfg(unix)]
fn transition(
    root: &fs::Root,
    home: &Path,
    settings: &Settings,
    enabled: bool,
) -> Result<Transition> {
    reject_mixed_environment()?;
    let selected = root.snapshot(PROFILE, MAX_PROFILE)?;
    let profile = selected
        .identity
        .as_ref()
        .map(|_| parse(&selected.bytes))
        .transpose()?;
    if !enabled {
        let current = profile
            .as_ref()
            .context("managed_connection_no_selected_connection")?;
        ensure!(
            current.settings == *settings,
            "managed_connection_disconnect_target_changed"
        );
    }
    // Disconnect is intentionally independent of a missing/revoked credential or
    // unavailable key/CA file. It must remain possible to stop future requests.
    let input_snapshots = if enabled {
        inputs(settings, true)?
    } else {
        vec![]
    };
    let config = root.snapshot("config.yaml", MAX_CONFIG)?;
    if config.identity.is_some() {
        crate::Config::from_yaml(
            std::str::from_utf8(&config.bytes).context("managed_connection_config_encoding")?,
        )?;
    }
    let lifecycle = if home.join("versions").exists() {
        fs::Root::open(&home.join("versions"))?.snapshot("lifecycle.json", MAX_CONFIG)?
    } else {
        fs::Snapshot::absent()
    };
    let active_policy = root.snapshot(
        "managed-policy-active.json",
        crate::managed_policy::MAX_BUNDLE_BYTES,
    )?;
    if enabled && active_policy.identity.is_some() {
        let saved = crate::managed_policy::parse_bounded(&active_policy.bytes)?;
        let keys = crate::managed_policy::parse_keyring(&input_snapshots[1].bytes)?;
        crate::managed_policy::verify_candidate(
            &saved,
            &keys,
            &settings.tenant,
            &settings.agent,
            0,
            saved.issued_at_unix,
        )
        .context("managed_connection_retained_policy_incompatible_preserved_previous_connection")?;
    }
    let binding = Binding {
        domain: "sw-managed-connection/1",
        enabled,
        settings,
        home: &root.identity,
        config,
        lifecycle,
        active_policy,
        inputs: &input_snapshots,
    };
    let inputs_sha256 = hash_value(&binding);
    let confirmation = hash_value(&("sw-managed-connection-consent/1", &inputs_sha256, &selected));
    root.recheck()?;
    Ok(Transition {
        selected,
        profile,
        inputs_sha256,
        confirmation,
        probe_inputs: input_snapshots,
    })
}
#[cfg(unix)]
#[derive(Serialize)]
struct Preview<'a> {
    contract: &'static str,
    action: &'static str,
    settings: &'a Settings,
    previous: Option<ConnectionIdentity>,
    confirmation: String,
    requires_stopped_agent: bool,
    preserves_policy_and_user_files: bool,
}
#[cfg(unix)]
fn preview(home: &Path, settings: &Settings, enabled: bool) -> Result<serde_json::Value> {
    let root = fs::Root::open(home)?;
    let t = transition(&root, home, settings, enabled)?;
    Ok(serde_json::to_value(Preview {
        contract: "sw-managed-connection-preview/1",
        action: if enabled { "apply" } else { "disconnect" },
        settings,
        previous: t.profile.map(|p| p.identity()),
        confirmation: t.confirmation,
        requires_stopped_agent: true,
        preserves_policy_and_user_files: true,
    })?)
}
#[cfg(unix)]
fn apply(
    home: &Path,
    settings: &Settings,
    enabled: bool,
    confirm: &str,
) -> Result<serde_json::Value> {
    ensure!(
        digest_valid(confirm),
        "managed_connection_invalid_confirmation"
    );
    let root = fs::Root::open(home)?;
    let manager = crate::lifecycle::Manager::new(home);
    let config = root.snapshot("config.yaml", MAX_CONFIG)?;
    let cfg = if config.identity.is_some() {
        crate::Config::from_yaml(std::str::from_utf8(&config.bytes)?)?
    } else {
        crate::Config::default()
    };
    let _guard = manager.managed_connection_guard(&cfg)?;
    let t = transition(&root, home, settings, enabled)?;
    if let Some(current) = &t.profile {
        if current.enabled == enabled
            && current.settings == *settings
            && equal(&current.receipt.confirmation, confirm)
            && equal(&current.receipt.inputs_sha256, &t.inputs_sha256)
        {
            return Ok(
                serde_json::json!({"status":"already_committed","configured":current.identity(),"running":"stopped","requires_start":true}),
            );
        }
    }
    ensure!(
        equal(&t.confirmation, confirm),
        "managed_connection_stale_preview"
    );
    let mut profile = Profile {
        schema_version: 1,
        generation: crate::token::generate(),
        enabled,
        settings: settings.clone(),
        ca_sha256: if enabled {
            settings
                .ca_file
                .as_ref()
                .map(|path| read_private_reference(path, 64 * 1024).map(|bytes| hash(&bytes)))
                .transpose()?
        } else {
            t.profile.as_ref().and_then(|p| p.ca_sha256.clone())
        },
        receipt: Receipt {
            confirmation: confirm.into(),
            inputs_sha256: t.inputs_sha256.clone(),
            result_sha256: String::new(),
        },
    };
    profile.receipt.result_sha256 = hash_value(&profile.identity());
    let bytes = serde_json::to_vec(&profile)?;
    ensure!(
        bytes.len() <= MAX_PROFILE,
        "managed_connection_profile_size"
    );
    root.publish(&bytes, || {
        let checked = transition(&root, home, settings, enabled)?;
        ensure!(
            checked.selected == t.selected && equal(&checked.confirmation, confirm),
            "managed_connection_changed_before_commit"
        );
        Ok(())
    })?;
    Ok(
        serde_json::json!({"status":"committed","configured":profile.identity(),"running":"stopped","requires_start":true,"preserved_policy_cache_and_replay_state":true}),
    )
}
#[cfg(unix)]
fn selected_profile(home: &Path) -> Result<Profile> {
    parse(&fs::Root::open(home)?.snapshot(PROFILE, MAX_PROFILE)?.bytes)
}

pub fn run(home: &Path, command: Command) -> Result<()> {
    ensure!(
        cfg!(target_os = "linux"),
        "managed_connection_requires_linux"
    );
    #[cfg(unix)]
    {
        let report = match command {
            Command::Preview { settings } => preview(home, &settings, true)?,
            Command::Apply { settings, confirm } => {
                // Consent is checked before any credential-bearing network request.
                let root = fs::Root::open(home)?;
                let t = transition(&root, home, &settings, true)?;
                let replay = t.profile.as_ref().is_some_and(|p| {
                    p.enabled
                        && p.settings == settings
                        && equal(&p.receipt.confirmation, &confirm)
                        && equal(&p.receipt.inputs_sha256, &t.inputs_sha256)
                });
                ensure!(
                    equal(&t.confirmation, &confirm) || replay,
                    "managed_connection_stale_preview"
                );
                if !replay {
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()?;
                    let probe = rt.block_on(probe_snapshots(home, &settings, &t.probe_inputs));
                    ensure!(
                        matches!(
                            probe["state"].as_str(),
                            Some("verified_candidate" | "authenticated_bound_no_policy")
                        ),
                        "managed_connection_verification_failed_previous_connection_preserved"
                    );
                }
                apply(home, &settings, true, &confirm)?
            }
            Command::DisconnectPreview => {
                let p = selected_profile(home)?;
                ensure!(p.enabled, "managed_connection_already_disconnected");
                preview(home, &p.settings, false)?
            }
            Command::Disconnect { confirm } => {
                let p = selected_profile(home)?;
                apply(home, &p.settings, false, &confirm)?
            }
            Command::Inspect | Command::Verify => {
                let verify = matches!(command, Command::Verify);
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                rt.block_on(inspect(home, verify))?
            }
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
        if report.get("verification").is_some_and(|v| !v.is_null()) {
            ensure!(
                matches!(
                    report["verification"]["state"].as_str(),
                    Some("verified_candidate" | "authenticated_bound_no_policy")
                ),
                "managed_connection_verification_incomplete_or_failed"
            );
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (home, command);
        anyhow::bail!("managed_connection_requires_linux")
    }
}
#[cfg(unix)]
async fn probe_snapshots(
    home: &Path,
    settings: &Settings,
    snapshots: &[fs::Snapshot],
) -> serde_json::Value {
    let token = std::str::from_utf8(&snapshots[0].bytes)
        .expect("validated credential")
        .to_owned();
    let keys =
        crate::managed_policy::parse_keyring(&snapshots[1].bytes).expect("validated keyring");
    let ca = settings
        .ca_file
        .as_ref()
        .map(|_| snapshots[2].bytes.clone());
    crate::managed_sync::ManagedSync::probe_connection(home, settings, token, keys, ca).await
}

#[cfg(unix)]
async fn inspect(home: &Path, verify: bool) -> Result<serde_json::Value> {
    if verify {
        reject_mixed_environment()?;
    }
    let root = fs::Root::open(home)?;
    let raw = root.snapshot(PROFILE, MAX_PROFILE)?;
    let profile = raw
        .identity
        .as_ref()
        .map(|_| parse(&raw.bytes))
        .transpose()?;
    let config = root.snapshot("config.yaml", MAX_CONFIG)?;
    let cfg = if config.identity.is_some() {
        crate::Config::from_yaml(std::str::from_utf8(&config.bytes)?)?
    } else {
        crate::Config::default()
    };
    let token = root.snapshot("token", 1024)?;
    let runtime = if token.identity.is_some() {
        crate::protection_status::query(
            &cfg,
            std::str::from_utf8(&token.bytes)?.trim(),
            &Default::default(),
            std::time::Duration::from_secs(2),
        )
        .await
        .ok()
    } else {
        None
    };
    let configured = profile.as_ref().map(Profile::identity);
    let loaded = runtime
        .as_ref()
        .and_then(|r| r.runtime.managed_connection.clone());
    let matches = runtime.is_some() && configured.is_some() && configured == loaded;
    let local_inputs_valid = profile.as_ref().map(|p| profile_inputs(p).is_ok());
    let probe = if verify {
        if let Some(p) = profile.as_ref().filter(|p| p.enabled) {
            match profile_inputs(p) {
                Ok(snapshots) => probe_snapshots(home, &p.settings, &snapshots).await,
                Err(_) => serde_json::json!({"state":"invalid_local_inputs","applied":false}),
            }
        } else {
            serde_json::json!({"state":"disconnected_or_unconfigured","applied":false})
        }
    } else {
        serde_json::Value::Null
    };
    ensure!(
        raw == root.snapshot(PROFILE, MAX_PROFILE)?
            && config == root.snapshot("config.yaml", MAX_CONFIG)?,
        "managed_connection_changed_during_inspection"
    );
    root.recheck()?;
    Ok(
        serde_json::json!({"contract":"sw-managed-connection-inspection/1","configured":configured,"settings":profile.as_ref().map(|p|&p.settings),"running":loaded,"runtime_authenticated":runtime.is_some(),"running_matches_configured":matches,"pending_restart":runtime.is_some() && (((configured.is_some() || loaded.is_some()) && !matches) || local_inputs_valid == Some(false)),"local_inputs_valid":local_inputs_valid,"transport":runtime.as_ref().and_then(|r|r.managed_transport.as_ref()),"recorded_application":runtime.as_ref().map(|r|&r.policy),"enrollment":probe.get("enrollment").cloned().unwrap_or(serde_json::json!("not_probed")),"verification":probe}),
    )
}
