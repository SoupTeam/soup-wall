// SPDX-License-Identifier: Apache-2.0
//! Private authenticated provenance checkpoints. Authority is deliberately absent.
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use anyhow::{ensure, Context, Result};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;
use soup_wall_agent::{AgentFirewall, ProvenanceSnapshot};
use subtle::ConstantTimeEq;

use super::NativeState;
use crate::Shared;

pub const BARRIER: &str = "/native/v1/profile-barrier";
const LIMIT: u64 = 16 * 1024 * 1024;
const FORMAT: &str = "sw-native/provenance-checkpoint/1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    format: String,
    sequence: u64,
    require_scoped_authority: bool,
    scoped_hosts: Vec<String>,
    provenance: ProvenanceSnapshot,
    signature: String,
}

pub struct Continuity {
    root: PathBuf,
    enabled: AtomicBool,
    require_scoped_authority: AtomicBool,
    sequence: AtomicU64,
    gate: tokio::sync::Mutex<()>,
}

fn encode_bounded<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    struct Bounded(Vec<u8>);
    impl Write for Bounded {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0.len().saturating_add(bytes.len()) > LIMIT as usize {
                return Err(std::io::Error::other(
                    "continuity serialization exceeds bound",
                ));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut writer = Bounded(Vec::new());
    serde_json::to_writer(&mut writer, value)?;
    Ok(writer.0)
}

fn signature(checkpoint: &Checkpoint, token: &str) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(token.as_bytes())?;
    mac.update(b"agentfw/provenance-checkpoint/v1\0");
    // The stored signature is excluded from authenticated material.
    mac.update(&encode_bounded(&(
        &checkpoint.format,
        checkpoint.sequence,
        checkpoint.require_scoped_authority,
        &checkpoint.scoped_hosts,
        &checkpoint.provenance,
    ))?);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn read_private(path: &Path) -> Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.len() <= LIMIT,
        "invalid continuity file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            meta.uid() == unsafe { libc::geteuid() }
                && meta.nlink() == 1
                && meta.mode() & 0o077 == 0,
            "continuity file must be owned and private"
        );
    }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= LIMIT, "continuity file exceeds bound");
    Ok(bytes)
}

impl Continuity {
    fn ensure_root(&self) -> Result<()> {
        if !self.root.exists() {
            let mut builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&self.root)?;
            #[cfg(windows)]
            crate::private_file_windows::ensure_private_directory(&self.root)?;
        }
        let meta = fs::symlink_metadata(&self.root)?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "unsafe continuity directory"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            ensure!(
                meta.uid() == unsafe { libc::geteuid() } && meta.mode() & 0o077 == 0,
                "continuity directory must be owned and private"
            );
            fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))?;
        }
        Ok(())
    }

    fn atomic(&self, name: &str, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() as u64 <= LIMIT,
            "continuity checkpoint exceeds bound"
        );
        self.ensure_root()?;
        let temporary = self
            .root
            .join(format!(".risk-{}.tmp", crate::token::generate()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| -> Result<()> {
            let mut file = options.open(&temporary)?;
            #[cfg(windows)]
            crate::token::restrict(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, self.root.join(name))?;
            self.sync()
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    fn sync(&self) -> Result<()> {
        #[cfg(unix)]
        File::open(&self.root)?.sync_all()?;
        Ok(())
    }

    pub fn attach(
        home: &Path,
        native: &mut NativeState,
        firewall: &mut AgentFirewall,
    ) -> Result<Self> {
        let root = home.join("mcp-profiles");
        let state = Self {
            root,
            enabled: AtomicBool::new(false),
            require_scoped_authority: AtomicBool::new(false),
            sequence: AtomicU64::new(0),
            gate: tokio::sync::Mutex::new(()),
        };
        let saved = state.root.join("risk-checkpoint.json");
        let marker = state.root.join("risk-inflight.json");
        if saved.try_exists()? || marker.try_exists()? {
            state.ensure_root()?;
            if saved.try_exists()? {
                let checkpoint: Checkpoint = serde_json::from_slice(&read_private(&saved)?)?;
                ensure!(
                    checkpoint.format == FORMAT
                        && checkpoint.scoped_hosts.len() <= super::MAX_SESSIONS,
                    "unsupported continuity checkpoint"
                );
                let actual = URL_SAFE_NO_PAD.decode(&checkpoint.signature)?;
                ensure!(
                    actual.len() == 32
                        && bool::from(
                            actual
                                .as_slice()
                                .ct_eq(signature(&checkpoint, &native.token)?.as_slice())
                        ),
                    "continuity checkpoint authentication failed"
                );
                let sessions = native
                    .sessions
                    .get_mut()
                    .map_err(|_| anyhow::anyhow!("native state unavailable"))?;
                for host in checkpoint.scoped_hosts {
                    ensure!(
                        super::identifier(&host) && sessions.scoped_hosts.insert(host),
                        "invalid continuity host binding"
                    );
                }
                firewall
                    .restore_provenance_snapshot(checkpoint.provenance)
                    .map_err(anyhow::Error::msg)?;
                state.sequence.store(checkpoint.sequence, Ordering::Relaxed);
                state
                    .require_scoped_authority
                    .store(checkpoint.require_scoped_authority, Ordering::Release);
            }
            if marker.try_exists()? {
                ensure!(
                    read_private(&marker)? == b"sw-native/provenance-inflight/1\n",
                    "invalid continuity intent"
                );
                firewall.mark_all_provenance_incomplete();
            }
            state.enabled.store(true, Ordering::Release);
        }
        Ok(state)
    }

    pub(crate) fn requires_scoped_authority(&self) -> bool {
        self.require_scoped_authority.load(Ordering::Acquire)
    }

    /// An exact reviewed manifest change is explicit operator intent, not discovery
    /// reapproval. All injection/shadowing policy checks still run on the live data.
    pub(crate) fn reviewed_manifest(&self, server: &str, hash: &str, registry: &str) -> bool {
        (|| -> Result<bool> {
            if !self.requires_scoped_authority() {
                return Ok(false);
            }
            let home = self.root.parent().context("continuity home absent")?;
            let state = crate::mcp::profile_lifecycle::ProfileManager::new(home).load_state()?;
            ensure!(state.in_progress.is_none(), "profile transition pending");
            let active = state
                .active_bundle_sha256
                .context("active profile absent")?;
            ensure!(
                crate::native::is_digest(&active),
                "invalid active profile identity"
            );
            let dir = self.root.join("revisions").join(&active);
            let bundle = crate::mcp::profile_lifecycle::verify_bundle_files(&dir)?;
            ensure!(
                bundle.bundle_sha256 == active && bundle.registry_sha256 == registry,
                "active profile changed"
            );
            let snapshot: serde_json::Value =
                serde_json::from_slice(&read_private(&dir.join("source-snapshot.json"))?)?;
            if snapshot["server_id"].as_str() != Some(server) {
                return Ok(false);
            }
            let mut tools = Vec::new();
            for tool in snapshot["tools"]
                .as_array()
                .context("reviewed tools absent")?
            {
                let mut description = tool["description"].as_str().unwrap_or("").to_owned();
                if let Some(title) = tool["annotations"]["title"].as_str() {
                    description.push('\n');
                    description.push_str(title);
                }
                tools.push(soup_wall_agent::ToolDecl {
                    name: tool["name"]
                        .as_str()
                        .context("tool identity absent")?
                        .into(),
                    description,
                    schema: tool["inputSchema"].clone(),
                });
            }
            Ok(crate::mcp::manifest::manifest_hash(&tools) == hash)
        })()
        .unwrap_or(false)
    }

    fn begin(&self) -> Result<()> {
        self.atomic("risk-inflight.json", b"sw-native/provenance-inflight/1\n")
    }

    fn commit(&self, st: &Shared, native: &NativeState) -> Result<()> {
        let sessions = native
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("native state unavailable"))?;
        let firewall = st
            .firewall
            .lock()
            .map_err(|_| anyhow::anyhow!("firewall unavailable"))?;
        let mut hosts: Vec<_> = sessions.scoped_hosts.iter().cloned().collect();
        hosts.sort();
        let sequence = self
            .sequence
            .load(Ordering::Relaxed)
            .checked_add(1)
            .context("continuity sequence exhausted")?;
        let mut checkpoint = Checkpoint {
            format: FORMAT.into(),
            sequence,
            require_scoped_authority: self.requires_scoped_authority(),
            scoped_hosts: hosts,
            provenance: firewall.provenance_snapshot(),
            signature: String::new(),
        };
        checkpoint.signature = URL_SAFE_NO_PAD.encode(signature(&checkpoint, &native.token)?);
        self.atomic("risk-checkpoint.json", &encode_bounded(&checkpoint)?)?;
        self.sequence.store(sequence, Ordering::Relaxed);
        fs::remove_file(self.root.join("risk-inflight.json"))?;
        self.sync()
    }
}

fn refused(path: &str) -> Response {
    let value = if path == "/hook" {
        json!({"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"provenance persistence unavailable"}})
    } else {
        json!({"contract_version":super::CONTRACT,"release":false,"verdict":"deny","error_code":"native_continuity_unavailable"})
    };
    // Hook clients consume permissionDecision only on a successful HTTP reply.
    // A storage outage must never turn enforcement into no-opinion.
    let status = if path == "/hook" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(value)).into_response()
}

/// Persist risk before releasing an authenticated decision/result. The durable
/// intent makes any interrupted handler a sticky incomplete-history floor.
pub async fn middleware(State(st): State<Shared>, request: Request, next: Next) -> Response {
    let Some(native) = &st.native else {
        return next.run(request).await;
    };
    let Some(store) = &native.continuity else {
        return next.run(request).await;
    };
    if request.method() != axum::http::Method::POST {
        return next.run(request).await;
    }
    let path = request.uri().path().to_owned();
    let auth = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::token::verify(&native.token, auth) && !crate::token::verify(&st.token, auth) {
        return next.run(request).await;
    }
    let _gate = store.gate.lock().await;
    if matches!(path.as_str(), "/native/v1" | "/native/approval/v1" | "/mcp")
        && !matches!(fs::symlink_metadata(store.root.join("connection-transition.json")),
            Err(ref error) if error.kind() == std::io::ErrorKind::NotFound)
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"contract_version":super::CONTRACT,
            "release":false,"verdict":"deny","error_code":"native_profile_transition_pending"})),
        )
            .into_response();
    }
    let enable = path == BARRIER && crate::token::verify(&native.token, auth);
    if !store.enabled.load(Ordering::Acquire) && !enable {
        return next.run(request).await;
    }
    if store.begin().is_err() {
        return refused(&path);
    }
    if enable {
        let Ok(mut firewall) = st.firewall.lock() else {
            return refused(&path);
        };
        // Late host deliveries cannot be attested across a process transition.
        // Keep exact evidence and impose the conservative floor as well.
        firewall.mark_all_provenance_incomplete();
        store.enabled.store(true, Ordering::Release);
    }
    let response = next.run(request).await;
    if store.commit(&st, native).is_err() {
        return refused(&path);
    }
    response
}

pub async fn barrier(State(st): State<Shared>, headers: axum::http::HeaderMap) -> Response {
    let Some(native) = &st.native else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !crate::token::verify(
        &native.token,
        headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
    ) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if native.continuity.is_none() {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    let Some(host) = headers
        .get("x-agentfw-host-session")
        .and_then(|v| v.to_str().ok())
        .filter(|h| super::identifier(h))
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(mut sessions) = native.sessions.lock() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    if !sessions.scoped_hosts.contains(host) && sessions.scoped_hosts.len() >= super::MAX_SESSIONS {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    sessions.scoped_hosts.insert(host.to_owned());
    drop(sessions);
    if headers
        .get("x-agentfw-profile-activation")
        .is_some_and(|v| v == "true")
    {
        native
            .continuity
            .as_ref()
            .unwrap()
            .require_scoped_authority
            .store(true, Ordering::Release);
    }
    Json(
        json!({"instance_id":native.instance_id(), "registry_sha256":native.registry_sha256,
        "status":"provenance_barrier","authority_restored":false}),
    )
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use soup_wall_agent::{AgentEvent, AgentPolicySet, EventKind, Provenance, DEFAULT_TAINT_CAP};

    fn fresh() -> (NativeState, AgentFirewall) {
        let bytes = serde_json::to_vec(&json!({"contract_version":super::super::CONTRACT,
            "registry_id":"continuity-test","tools":[{"name":"read_document","schema_sha256":"1".repeat(64),
            "action_class":"read_only","result_provenance":"untrusted","egress":[]}]})).unwrap();
        let native = NativeState::from_bytes(
            &bytes,
            &super::super::hash(&bytes),
            "private-test-native-key".into(),
        )
        .unwrap();
        let firewall = AgentFirewall::new(
            AgentPolicySet::from_yaml("default: allow\n").unwrap(),
            DEFAULT_TAINT_CAP,
        );
        (native, firewall)
    }

    fn save(store: &Continuity, native: &NativeState, firewall: &AgentFirewall) {
        let mut checkpoint = Checkpoint {
            format: FORMAT.into(),
            sequence: 7,
            require_scoped_authority: true,
            scoped_hosts: vec!["host".into()],
            provenance: firewall.provenance_snapshot(),
            signature: String::new(),
        };
        checkpoint.signature =
            URL_SAFE_NO_PAD.encode(signature(&checkpoint, &native.token).unwrap());
        store
            .atomic(
                "risk-checkpoint.json",
                &serde_json::to_vec(&checkpoint).unwrap(),
            )
            .unwrap();
    }

    #[test]
    fn restart_preserves_taint_floor_and_scoped_host_but_no_authority() {
        let dir = tempfile::tempdir().unwrap();
        let (mut native, mut firewall) = fresh();
        let store = Continuity::attach(dir.path(), &mut native, &mut firewall).unwrap();
        firewall.admit_native_result(&AgentEvent { session:"host".into(), agent:"old-agent".into(), parent:None,
            seq:1,at_ms:1,kind:EventKind::ToolResult {tool:"read_document".into(),
            content:"Quarterly inventory and pending retention schedule for archived records in the warehouse.".into(),
            source:Provenance::McpServer{name:"server-a".into()}} });
        firewall.mark_provenance_incomplete("host");
        firewall.set_root("host", "old-agent", &["read_document".into()]);
        assert!(firewall.taint_len("host") > 0);
        save(&store, &native, &firewall);
        let (mut new_native, mut new_firewall) = fresh();
        let restored = Continuity::attach(dir.path(), &mut new_native, &mut new_firewall).unwrap();
        assert!(restored.enabled.load(Ordering::Acquire));
        assert_eq!(restored.sequence.load(Ordering::Relaxed), 7);
        assert_eq!(new_firewall.taint_len("host"), firewall.taint_len("host"));
        assert!(new_firewall.provenance_incomplete("host"));
        assert!(new_native
            .sessions
            .lock()
            .unwrap()
            .scoped_hosts
            .contains("host"));
        assert_eq!(new_firewall.agent_tools("host", "old-agent"), None);
        assert_ne!(new_native.instance_id(), native.instance_id());
    }

    #[test]
    fn interrupted_handler_imposes_floor_even_before_first_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let (mut native, mut firewall) = fresh();
        let store = Continuity::attach(dir.path(), &mut native, &mut firewall).unwrap();
        store.begin().unwrap();
        let (mut native, mut firewall) = fresh();
        Continuity::attach(dir.path(), &mut native, &mut firewall).unwrap();
        assert!(firewall.provenance_incomplete("previous-host"));
        assert!(firewall.provenance_incomplete("future-context"));
    }

    #[test]
    fn corrupt_or_cross_key_checkpoint_refuses_startup() {
        let dir = tempfile::tempdir().unwrap();
        let (mut native, mut firewall) = fresh();
        let store = Continuity::attach(dir.path(), &mut native, &mut firewall).unwrap();
        save(&store, &native, &firewall);
        let (mut other, mut fw) = fresh();
        other.token = "different-key".into();
        assert!(Continuity::attach(dir.path(), &mut other, &mut fw).is_err());
        let path = dir.path().join("mcp-profiles/risk-checkpoint.json");
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["scoped_hosts"] = json!(["other-host"]);
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let (mut other, mut fw) = fresh();
        assert!(Continuity::attach(dir.path(), &mut other, &mut fw).is_err());
        assert!(!fw.provenance_incomplete("host"));
    }

    #[cfg(unix)]
    #[test]
    fn public_and_symlink_checkpoints_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let (mut native, mut firewall) = fresh();
        let store = Continuity::attach(dir.path(), &mut native, &mut firewall).unwrap();
        save(&store, &native, &firewall);
        let path = dir.path().join("mcp-profiles/risk-checkpoint.json");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let (mut other, mut fw) = fresh();
        assert!(Continuity::attach(dir.path(), &mut other, &mut fw).is_err());
        let moved = dir.path().join("retained");
        fs::rename(&path, &moved).unwrap();
        symlink(&moved, &path).unwrap();
        assert!(Continuity::attach(dir.path(), &mut other, &mut fw).is_err());
    }
    #[test]
    fn reviewed_manifest_exception_requires_exact_validated_installed_authority() {
        use crate::mcp::{profile_author, profile_lifecycle};
        let dir = tempfile::tempdir().unwrap();
        let inputs = tempfile::tempdir().unwrap();
        let schema = json!({"type":"object","properties":{},"additionalProperties":false});
        let snapshot = json!({"format":"sw-mcp/operator-discovery/1","server_id":"reviewed-server",
            "server_version":"1","tools":[{"name":"read_note","description":"Reviewed local read.","inputSchema":schema}]});
        let declarations = json!({"format":"sw-mcp/operator-declaration/1","server_id":"reviewed-server","server_version":"1",
            "snapshot_sha256":profile_author::digest(&snapshot),"registry_id":"reviewed-registry","tools":[{
                "name":"read_note","schema_sha256":profile_author::digest(&schema),"reviewed":true,
                "operator_review":"Owned read fixture implementation review","authority":{"kind":"read_only"}}]});
        let snap = inputs.path().join("snapshot.json");
        let decl = inputs.path().join("declarations.json");
        fs::write(&snap, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        fs::write(&decl, serde_json::to_vec(&declarations).unwrap()).unwrap();
        let bundle = inputs.path().join("bundle");
        fs::create_dir(&bundle).unwrap();
        for (name, bytes) in profile_author::compiled_bundle_files(&snap, &decl, &bundle).unwrap() {
            fs::write(bundle.join(name), bytes).unwrap();
        }
        let manager = profile_lifecycle::ProfileManager::new(dir.path());
        let installed = manager.install(&bundle, None).unwrap();
        let native_cfg =
            crate::Config::from_yaml(&fs::read_to_string(dir.path().join("config.yaml")).unwrap())
                .unwrap()
                .native
                .unwrap();
        let (mut native, mut fw) = fresh();
        let store = Continuity::attach(dir.path(), &mut native, &mut fw).unwrap();
        let tools = vec![soup_wall_agent::ToolDecl {
            name: "read_note".into(),
            description: "Reviewed local read.".into(),
            schema,
        }];
        let hash = crate::mcp::manifest::manifest_hash(&tools);
        assert!(!store.reviewed_manifest("reviewed-server", &hash, &native_cfg.registry_sha256));
        store
            .require_scoped_authority
            .store(true, Ordering::Release);
        assert!(store.reviewed_manifest("reviewed-server", &hash, &native_cfg.registry_sha256));
        assert!(!store.reviewed_manifest("other-server", &hash, &native_cfg.registry_sha256));
        assert!(!store.reviewed_manifest(
            "reviewed-server",
            &"0".repeat(64),
            &native_cfg.registry_sha256
        ));
        assert!(!store.reviewed_manifest("reviewed-server", &hash, &"0".repeat(64)));
        let cached = dir
            .path()
            .join("mcp-profiles/revisions")
            .join(installed.bundle_sha256)
            .join("operator-declarations.json");
        let mut revoked = declarations;
        revoked["tools"][0]["reviewed"] = json!(false);
        fs::write(cached, serde_json::to_vec(&revoked).unwrap()).unwrap();
        assert!(!store.reviewed_manifest("reviewed-server", &hash, &native_cfg.registry_sha256));
    }
}
