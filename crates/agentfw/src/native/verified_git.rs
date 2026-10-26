// SPDX-License-Identifier: Apache-2.0
//! Explicit daemon-owned original Git execution. An ingress token, receipt,
//! response-shaped text or object witness alone is never an origin proof.
use super::*;
use crate::config::NativeGitExecutionCfg;
#[cfg(target_os = "linux")]
use crate::mcp::server_profile::ProfileConfig;

pub(crate) const ENDPOINT: &str = "/native/git-execute/v1";
pub(crate) const CONTRACT_EXECUTE: &str = "sw-native-git-execute/1";
pub(crate) const MAX_RESPONSE: usize = 2 * MAX_MCP_RESULT_CONTENT + 32 * 1024;

pub(super) struct Runtime {
    #[cfg(target_os = "linux")]
    config: NativeGitExecutionCfg,
    #[cfg(target_os = "linux")]
    profile: ProfileConfig,
    #[cfg(target_os = "linux")]
    slots: tokio::sync::Semaphore,
}

impl Runtime {
    pub(super) fn load(config: &NativeGitExecutionCfg) -> anyhow::Result<Self> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = config;
            anyhow::bail!("daemon Git execution requires Linux");
        }
        #[cfg(target_os = "linux")]
        {
            anyhow::ensure!(
                config.profile_path.is_absolute()
                    && is_digest(&config.profile_sha256)
                    && identifier(&config.server_id),
                "invalid operator Git execution configuration"
            );
            let profile = read_profile(config)?;
            anyhow::ensure!(
                crate::mcp::server_profile::git_selected(&profile.format)
                    && profile.workspace_identity.is_some(),
                "daemon execution requires a pinned Git workspace identity"
            );
            Ok(Self {
                config: config.clone(),
                profile,
                slots: tokio::sync::Semaphore::new(2),
            })
        }
    }

    pub(super) fn selected(
        &self,
        server: &str,
        profile: &crate::mcp::server_profile::ProfileConfig,
    ) -> anyhow::Result<bool> {
        #[cfg(target_os = "linux")]
        {
            if server != self.config.server_id {
                return Ok(false);
            }
            anyhow::ensure!(
                serde_json::to_value(profile)? == serde_json::to_value(&self.profile)?,
                "collector profile differs from daemon-owned execution profile"
            );
            Ok(true)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (server, profile);
            anyhow::bail!("daemon Git execution requires Linux");
        }
    }

    #[cfg(target_os = "linux")]
    fn unchanged(&self) -> anyhow::Result<()> {
        let profile = read_profile(&self.config)?;
        anyhow::ensure!(
            serde_json::to_value(profile)? == serde_json::to_value(&self.profile)?,
            "operator execution profile changed"
        );
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn read_profile(config: &NativeGitExecutionCfg) -> anyhow::Result<ProfileConfig> {
    // No links in any ancestor, regular owner-controlled bounded final inode.
    for part in config.profile_path.ancestors() {
        let metadata = std::fs::symlink_metadata(part)?;
        anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "linked execution profile"
        );
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(&config.profile_path)?;
    let metadata = file.metadata()?;
    anyhow::ensure!(
        metadata.is_file() && metadata.len() <= 65_536,
        "invalid execution profile file"
    );
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        anyhow::ensure!(
            metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o022 == 0
                && metadata.nlink() == 1,
            "execution profile is not owner-controlled"
        );
    }
    let mut bytes = Vec::new();
    file.take(65_537).read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= 65_536 && hash(&bytes) == config.profile_sha256,
        "execution profile digest mismatch"
    );
    ProfileConfig::read(&bytes)
}

#[cfg(target_os = "linux")]
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Execute {
    contract_version: String,
    registry_sha256: String,
    session_id: String,
    call_id: String,
    binding_sha256: String,
}

#[cfg(target_os = "linux")]
fn decode(body: &str) -> Result<Execute, &'static str> {
    if body.len() > 4096 {
        return Err("native_git_execute_over_cap");
    }
    let crate::mcp::admission::Strict(value) =
        serde_json::from_str(body).map_err(|_| "native_git_execute_fields")?;
    let request: Execute =
        serde_json::from_value(value).map_err(|_| "native_git_execute_fields")?;
    if request.contract_version != CONTRACT_EXECUTE
        || !is_digest(&request.registry_sha256)
        || !identifier(&request.session_id)
        || !identifier(&request.call_id)
        || !is_digest(&request.binding_sha256)
    {
        return Err("native_git_execute_fields");
    }
    Ok(request)
}

/// Non-serializable, same-process ownership. Not constructible from a client
/// result, formatter range, witness or shared native ingress capability.
pub(super) struct OwnedResult {
    pub(super) call: Call,
    session_id: String,
    call_id: String,
    epoch: String,
    raw: String,
    #[cfg(target_os = "linux")]
    execution: Option<crate::mcp::verified_git::Completion>,
}

impl OwnedResult {
    pub(super) fn validate(
        &self,
        request: &Request,
        session: &Session,
        now: Instant,
    ) -> Result<(), &'static str> {
        if request.event != "result"
            || request.session_id != self.session_id
            || request.call_id.as_deref() != Some(&self.call_id)
            || session.epoch != self.epoch
            || self.call.expires <= now
            || request.content.as_deref() != Some(&self.raw)
        {
            return Err("native_git_execution_binding");
        }
        #[cfg(target_os = "linux")]
        if let Some(execution) = &self.execution {
            execution
                .validate()
                .map_err(|_| "native_git_execution_view_changed")?;
            if execution.raw() != self.raw.as_bytes() {
                return Err("native_git_execution_result_changed");
            }
        }
        Ok(())
    }

    pub(super) fn formatter_span(&self, event: &AgentEvent) -> Option<std::ops::Range<usize>> {
        #[cfg(target_os = "linux")]
        if let EventKind::ToolResult { content, .. } = &event.kind {
            return self.execution.as_ref()?.formatter_span(content);
        }
        let _ = event;
        None
    }
}

#[cfg(target_os = "linux")]
fn reserve(
    st: &Shared,
    native: &NativeState,
    runtime: &Runtime,
    input: &Execute,
    identity: &liveness::CollectorIdentity,
) -> Result<(Call, String), &'static str> {
    let mut sessions = native
        .sessions
        .lock()
        .map_err(|_| "native_state_unavailable")?;
    let firewall = st
        .firewall
        .lock()
        .map_err(|_| "native_inspection_unavailable")?;
    let now = native.monotonic_now();
    let now_ms = wall_time_ms()? + native.test_time_offset();
    let session = sessions
        .entries
        .get(&input.session_id)
        .ok_or("native_session_unknown")?;
    identity.verify(native, session)?;
    validate_lineage(&sessions, session, now_ms, now)?;
    if session.server_id.as_deref() != Some(&runtime.config.server_id)
        || session.host_session.is_none()
        || session.authority_digest.is_none()
        || session.liveness_lease.is_none()
        || session.policy_transition != native.policy_barrier.is_some()
    {
        return Err("native_git_execution_owner");
    }
    let session = sessions
        .entries
        .get_mut(&input.session_id)
        .ok_or("native_session_unknown")?;
    // Spend before examining client binding or beginning any asynchronous work.
    let call = session
        .calls
        .remove(&input.call_id)
        .ok_or("native_call_unknown_or_spent")?;
    if call.expires <= now
        || call.stage != Stage::Result
        || call.contract_version != CONTRACT
        || call.binding_sha256 != input.binding_sha256
        || call.host_call_id.is_none()
        || !matches!(call.tool.as_str(), "git_show" | "git_diff")
        || call.managed_policy != firewall.active_managed_policy()
    {
        return Err("native_git_execution_binding");
    }
    let tool = native
        .registry
        .tools
        .iter()
        .find(|tool| tool.name == call.tool)
        .ok_or("native_tool_unknown")?;
    if tool.mcp_result_profile.as_deref() != Some(&runtime.profile.format)
        || tool.action_class != ActionClass::ReadOnly
        || !matches!(tool.result_provenance, ResultProvenance::Untrusted)
        || tool.resource_policy.is_some()
        || tool.workspace_profile.is_some()
        || !tool.egress.is_empty()
    {
        return Err("native_git_execution_profile");
    }
    let args = call
        .execution_args
        .as_ref()
        .ok_or("native_git_execution_args")?;
    if args_hash(args) != call.args_sha256 {
        return Err("native_git_execution_binding");
    }
    // This Call is the already-audited final admission, including any exact
    // single-use operator Ask redemption. Do not translate that authority back
    // into an unapproved Ask by re-running the pre-approval policy here.
    // Its current managed policy, liveness, lineage, epoch, arguments, schema
    // and fixed runtime selection are checked before the one actual dispatch.
    session.seq += 1;
    st.audit
        .write_native(&json!({
            "event":"native_git_execution_reserved", "session":session.epoch, "seq":session.seq,
            "tool":call.tool, "call_id":input.call_id, "binding_sha256":call.binding_sha256,
            "profile_sha256":runtime.config.profile_sha256, "args_sha256":call.args_sha256,
            "dispatched":false, "authority":"daemon_owned_original_pipe"
        }))
        .map_err(|_| "native_audit_unavailable")?;
    Ok((call, session.epoch.clone()))
}

pub(crate) async fn handler(
    State(st): State<Shared>,
    headers: HeaderMap,
    body: String,
) -> (StatusCode, Json<Value>) {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (st, headers, body);
        failure(
            "native_git_execution_unsupported",
            StatusCode::SERVICE_UNAVAILABLE,
        )
    }
    #[cfg(target_os = "linux")]
    {
        let Some(native) = &st.native else {
            return failure("native_disabled", StatusCode::SERVICE_UNAVAILABLE);
        };
        let auth = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !crate::token::verify(&native.token, auth) {
            return failure("native_unauthorized", StatusCode::UNAUTHORIZED);
        }
        if !st.config.enforce || st.config.judge.enabled {
            return failure(
                "native_enforcement_required",
                StatusCode::SERVICE_UNAVAILABLE,
            );
        }
        let Some(runtime) = &native.git_execution else {
            return failure(
                "native_git_execution_disabled",
                StatusCode::SERVICE_UNAVAILABLE,
            );
        };
        let input = match decode(&body) {
            Ok(input) => input,
            Err(code) => return failure(code, StatusCode::BAD_REQUEST),
        };
        if input.registry_sha256 != native.registry_sha256 {
            return failure("native_registry_mismatch", StatusCode::CONFLICT);
        }
        let identity = match liveness::collector_identity(&headers) {
            Ok(Some(identity)) => identity,
            _ => return failure("native_git_execution_owner", StatusCode::BAD_REQUEST),
        };
        // A busy executor refuses without waiting or duplicating execution.
        let Ok(_slot) = runtime.slots.try_acquire() else {
            return failure("native_git_execution_busy", StatusCode::CONFLICT);
        };
        let _boundary = if let Some(barrier) = &native.policy_barrier {
            match barrier.release_boundary().await {
                Ok(boundary) => Some(boundary),
                Err(_) => return failure("native_policy_transition_busy", StatusCode::CONFLICT),
            }
        } else {
            None
        };
        if runtime.unchanged().is_err() {
            return failure("native_git_execution_profile_changed", StatusCode::CONFLICT);
        }
        let (call, epoch) = match reserve(&st, native, runtime, &input, &identity) {
            Ok(reserved) => reserved,
            Err(code) => return failure(code, StatusCode::CONFLICT),
        };
        let args = call.execution_args.clone().expect("reserved args");
        let mut original = serde_json::to_vec(&json!({
            "jsonrpc":"2.0", "id":call.host_call_id, "method":"tools/call",
            "params":{"name":call.tool,"arguments":args}
        }))
        .expect("original invocation serializes");
        original.push(b'\n');
        // This future owns the child and its completion. HTTP callers cannot
        // submit or replace any original result/witness bytes.
        let execution = match crate::mcp::verified_git::run(&runtime.profile, &original).await {
            Ok(execution) => execution,
            Err(_) => return incomplete(&st, &input, &call, &epoch),
        };
        let raw = match std::str::from_utf8(execution.raw()) {
            Ok(raw) => raw.to_owned(),
            Err(_) => return incomplete(&st, &input, &call, &epoch),
        };
        let value: Value = match serde_json::from_str(&raw) {
            Ok(value) => value,
            Err(_) => return failure("native_git_execution_result", StatusCode::CONFLICT),
        };
        let kind = if value.get("error").is_some() || value["result"]["isError"] == true {
            "error"
        } else {
            "value"
        };
        let request: Request = serde_json::from_value(json!({
            "contract_version":CONTRACT, "registry_sha256":native.registry_sha256,
            "session_id":input.session_id, "event":"result", "tool":call.tool,
            "args":args, "call_id":input.call_id, "content":raw,
            "result_kind":kind, "delivery":"mcp_host"
        }))
        .expect("daemon result request serializes");
        let owned = OwnedResult {
            call,
            session_id: input.session_id.clone(),
            call_id: input.call_id.clone(),
            epoch,
            raw: raw.clone(),
            execution: Some(execution),
        };
        match inspect_bound_with_execution(&st, native, request, Some(&identity), Some(owned)) {
            Ok(receipt) => {
                let release = receipt.release;
                (
                    StatusCode::OK,
                    Json(json!({
                        "contract_version":CONTRACT_EXECUTE,
                        "profile_sha256":canonical_digest(&serde_json::to_value(&runtime.profile).expect("profile")),
                        "completed":true, "receipt":receipt,
                        "frame":if release { Some(raw) } else { None }
                    })),
                )
            }
            Err(code) => failure(code, StatusCode::CONFLICT),
        }
    }
}

#[cfg(target_os = "linux")]
fn incomplete(st: &Shared, input: &Execute, call: &Call, epoch: &str) -> (StatusCode, Json<Value>) {
    // Authority was consumed before dispatch. Do not invent an original result,
    // inspect a synthetic replacement into Allow, or report a failed run as a
    // completed semantic refusal. No frame or runtime diagnostics leave here.
    let recorded = st.audit.write_native(&json!({
        "event":"native_git_execution_incomplete","session":epoch,
        "call_id":input.call_id,"binding_sha256":call.binding_sha256,
        "tool":call.tool,"args_sha256":call.args_sha256,
        "inspection_complete":false,"released":false
    }));
    failure(
        if recorded.is_ok() {
            "native_git_execution_incomplete"
        } else {
            "native_audit_unavailable"
        },
        StatusCode::CONFLICT,
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn fixture(dir: &std::path::Path) -> Shared {
        let mut st = super::super::tests::fixture(dir);
        let def = crate::mcp::server_profile::git::original_manifest()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["name"] == "git_show")
            .unwrap()
            .clone();
        let registry = json!({"contract_version":CONTRACT,"registry_id":"owned-git","tools":[{
            "name":"git_show","schema_sha256":canonical_digest(&def["inputSchema"]),
            "action_class":"read_only","result_provenance":"untrusted","egress":[],
            "mcp_result_profile":crate::mcp::server_profile::git::FORMAT
        }]})
        .to_string()
        .into_bytes();
        let profile: ProfileConfig = serde_json::from_value(json!({
            "format":crate::mcp::server_profile::git::FORMAT,"workspace":dir,
            "workspaceIdentity":{"device":1,"inode":1,"uid":0},
            "runtimePath":dir.join("python"),"runtimeSha256":"a".repeat(64),
            "packageRoot":dir.join("package"),"packageTreeSha256":"b".repeat(64),
            "bwrapPath":dir.join("bwrap"),"bwrapSha256":"c".repeat(64),"libraries":[],
            "git":{"path":dir.join("git"),"sha256":"d".repeat(64)},
            "gitLauncher":{"path":dir.join("launcher"),"sha256":"e".repeat(64)}
        }))
        .unwrap();
        let mut native =
            NativeState::from_bytes(&registry, &hash(&registry), "native-unit-key".into()).unwrap();
        native.git_execution = Some(Runtime {
            config: NativeGitExecutionCfg {
                profile_path: dir.join("profile.json"),
                profile_sha256: "f".repeat(64),
                server_id: "git".into(),
            },
            profile,
            slots: tokio::sync::Semaphore::new(2),
        });
        let state = Arc::get_mut(&mut st).unwrap();
        state.native = Some(native);
        *state.firewall.get_mut().unwrap() = soup_wall_agent::AgentFirewall::new(
            soup_wall_agent::AgentPolicySet::from_yaml(include_str!(
                "../../../../profiles/pilot/linux-readonly-v1/policy.yaml"
            ))
            .unwrap(),
            soup_wall_agent::DEFAULT_TAINT_CAP,
        );
        st
    }

    fn start(st: &Shared) -> liveness::CollectorIdentity {
        let native = st.native.as_ref().unwrap();
        let grant = child_authority::mint_scoped(
            &child_authority::derive_key(&native.token),
            "owned-host",
            "git",
            &["git_show".into()],
            wall_time_ms().unwrap(),
            60_000,
            format!("{}.{}", native.instance_id(), crate::token::generate()),
            Some("owned-agent".into()),
            None,
            None,
        );
        let request = parse(
            &json!({"contract_version":CONTRACT,"registry_sha256":native.registry_sha256,
            "session_id":"owned-test","event":"session_start", "host_session":"owned-host",
            "server_id":"git","child_authority":child_authority::encode_token(&grant)})
            .to_string(),
        )
        .unwrap();
        inspect_bound(st, native, request, None).unwrap();
        let mut sessions = native.sessions.lock().unwrap();
        let s = sessions.entries.get_mut("owned-test").unwrap();
        s.server_id = Some("git".into());
        s.liveness_lease = Some(liveness::Lease::new(
            "owned-test".into(),
            s.epoch.clone(),
            native.instance_id.clone(),
            Duration::from_secs(60),
            native.monotonic_now(),
        ));
        serde_json::from_value(json!({"contract_version":liveness::LIVENESS_CONTRACT,
            "instance_id":native.instance_id,"epoch":s.epoch,"owner_token":s.owner_token}))
        .unwrap()
    }

    fn admit(st: &Shared, identity: &liveness::CollectorIdentity) -> Execute {
        let native = st.native.as_ref().unwrap();
        let request = parse(
            &json!({"contract_version":CONTRACT,"registry_sha256":native.registry_sha256,
                "session_id":"owned-test","event":"call","tool":"git_show",
                "args":{"repo_path":"/workspace","revision":"HEAD"},
                "schema_sha256":native.registry.tools[0].schema_sha256,"mcp_host_call_id":17
            })
            .to_string(),
        )
        .unwrap();
        let receipt = inspect_bound(st, native, request, Some(identity)).unwrap();
        assert!(receipt.release);
        Execute {
            contract_version: CONTRACT_EXECUTE.into(),
            registry_sha256: native.registry_sha256.clone(),
            session_id: "owned-test".into(),
            call_id: receipt.call_id.unwrap(),
            binding_sha256: receipt.binding_sha256.unwrap(),
        }
    }

    #[test]
    fn reserve_is_one_use_and_bad_binding_is_terminal() {
        let dir = tempfile::tempdir().unwrap();
        let st = fixture(dir.path());
        let identity = start(&st);
        let native = st.native.as_ref().unwrap();
        let runtime = native.git_execution.as_ref().unwrap();
        let input = admit(&st, &identity);
        let (call, _) = reserve(&st, native, runtime, &input, &identity).unwrap();
        assert!(call.execution_args.is_some());
        assert_eq!(
            reserve(&st, native, runtime, &input, &identity).err(),
            Some("native_call_unknown_or_spent")
        );
        let mut other = admit(&st, &identity);
        other.binding_sha256 = "0".repeat(64);
        assert_eq!(
            reserve(&st, native, runtime, &other, &identity).err(),
            Some("native_git_execution_binding")
        );
        assert_eq!(
            reserve(&st, native, runtime, &other, &identity).err(),
            Some("native_call_unknown_or_spent")
        );
    }

    #[test]
    fn no_execution_proof_preserves_legacy_result_decision_and_exact_epoch() {
        let dir = tempfile::tempdir().unwrap();
        let st = fixture(dir.path());
        let identity = start(&st);
        let native = st.native.as_ref().unwrap();
        let runtime = native.git_execution.as_ref().unwrap();
        let input = admit(&st, &identity);
        let (call, epoch) = reserve(&st, native, runtime, &input, &identity).unwrap();
        let raw = json!({"jsonrpc":"2.0","id":17,"result":{"content":[{"type":"text",
            "text":"commit 0123456789abcdef0123456789abcdef01234567\n---\na\n---\nb\n---\nc"}]}})
        .to_string();
        let request: Request = serde_json::from_value(json!({"contract_version":CONTRACT,
            "registry_sha256":native.registry_sha256,"session_id":"owned-test","event":"result",
            "tool":"git_show","args":call.execution_args,"call_id":input.call_id,
            "content":raw,"result_kind":"value","delivery":"mcp_host"}))
        .unwrap();
        let owned = OwnedResult {
            call,
            session_id: input.session_id.clone(),
            call_id: input.call_id.clone(),
            epoch,
            raw,
            execution: None,
        };
        let session = native.sessions.lock().unwrap().entries["owned-test"].clone();
        assert!(owned
            .validate(&request, &session, native.monotonic_now())
            .is_ok());
        let mut replaced = session.clone();
        replaced.epoch = "another-epoch".into();
        assert_eq!(
            owned
                .validate(&request, &replaced, native.monotonic_now())
                .err(),
            Some("native_git_execution_binding")
        );
        let response =
            inspect_bound_with_execution(&st, native, request, Some(&identity), Some(owned))
                .unwrap();
        assert!(!response.release);
    }

    #[test]
    fn failed_worker_never_becomes_an_allow_result_and_stays_spent() {
        let dir = tempfile::tempdir().unwrap();
        let st = fixture(dir.path());
        let identity = start(&st);
        let native = st.native.as_ref().unwrap();
        let runtime = native.git_execution.as_ref().unwrap();
        let input = admit(&st, &identity);
        let (call, epoch) = reserve(&st, native, runtime, &input, &identity).unwrap();
        let (status, Json(reply)) = incomplete(&st, &input, &call, &epoch);
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(reply["error_code"], "native_git_execution_incomplete");
        assert_ne!(reply["release"], true);
        assert!(reply.get("frame").is_none());
        assert_eq!(
            reserve(&st, native, runtime, &input, &identity).err(),
            Some("native_call_unknown_or_spent")
        );
        let audit = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        let row: Value = serde_json::from_str(audit.lines().last().unwrap()).unwrap();
        assert_eq!(row["event"], "native_git_execution_incomplete");
        assert_eq!(row["inspection_complete"], false);
        assert_eq!(row["released"], false);
    }

    #[test]
    fn execute_wire_cannot_supply_a_result_or_trust_root() {
        let base = json!({"contract_version":CONTRACT_EXECUTE,"registry_sha256":"a".repeat(64),
            "session_id":"session","call_id":"call","binding_sha256":"b".repeat(64)});
        assert!(decode(&base.to_string()).is_ok());
        for key in [
            "content",
            "proof",
            "runtime",
            "profile",
            "formatter_span",
            "trusted",
        ] {
            let mut forged = base.clone();
            forged[key] = json!("attacker");
            assert_eq!(
                decode(&forged.to_string()).err(),
                Some("native_git_execute_fields")
            );
        }
        let duplicate = base
            .to_string()
            .replacen("{", "{\"call_id\":\"another\",", 1);
        assert_eq!(decode(&duplicate).err(), Some("native_git_execute_fields"));
    }
}
