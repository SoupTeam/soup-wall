// SPDX-License-Identifier: Apache-2.0
//! One-use daemon-owned relay, with a compiled declaration-only adapter.
//! No server command or execution/provenance claim arrives from the client.
use super::{profile, Profile, FORMAT, SERVER};
use crate::native::execution::transport::{framed_body, read_preamble_for};
use anyhow::{ensure, Result};
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::StreamExt;
use serde_json::json;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use tokio::{
    io::{AsyncWriteExt, BufReader},
    sync::{oneshot, watch},
};

pub(crate) const MEDIA_TYPE: &str = "application/vnd.soup-wall.installed-edit.v1";
pub(crate) struct Service {
    pub profile: Profile,
    pub host: String,
    pub digest: String,
    pub quota: Option<Arc<super::quota::Ledger>>,
    used: AtomicBool,
    closed: watch::Sender<bool>,
    active: AtomicUsize,
    pub dispatches: Arc<AtomicUsize>,
}
impl Service {
    #[cfg(any(test, target_os = "linux"))]
    pub fn new(profile: Profile, host: String) -> Result<Arc<Self>> {
        profile.validate()?;
        ensure!(crate::native::identifier(&host), "edit_host_invalid");
        let digest = profile::digest(&profile)?;
        let quota = profile
            .mutation_quota
            .as_ref()
            .map(|limits| {
                super::quota::Ledger::new(
                    limits.clone(),
                    profile::digest(&profile.registry()?)?,
                    host.clone(),
                )
            })
            .transpose()?;
        Ok(Arc::new(Self {
            profile,
            host,
            digest,
            quota,
            used: AtomicBool::new(false),
            closed: watch::channel(false).0,
            active: AtomicUsize::new(0),
            dispatches: Arc::new(AtomicUsize::new(0)),
        }))
    }
    #[cfg(any(test, target_os = "linux"))]
    pub fn close(&self) {
        self.used.store(true, Ordering::Release);
        self.closed.send_replace(true);
    }
    #[cfg(any(test, target_os = "linux"))]
    pub async fn wait_idle(&self) -> bool {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        while self.active.load(Ordering::Acquire) != 0 {
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        true
    }
    fn admission(
        &self,
        state: &crate::Shared,
        authority: String,
    ) -> Result<crate::mcp::admission::AdmissionCfg> {
        let native = state
            .native
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("edit_native_unavailable"))?;
        ensure!(
            native.registry_sha256 == profile::digest(&self.profile.registry()?)?,
            "edit_registry_changed"
        );
        let classifier = crate::mcp::admission::explicit_rule_baseline(
            &self.profile.component.classifier.path,
            &self.profile.component.classifier.sha256,
            &self.profile.component.python.path,
            &self.profile.component.python.sha256,
        )?;
        Ok(crate::mcp::admission::AdmissionCfg {
            host_session: Some(self.host.clone()),
            child_authority: Some(authority),
            daemon_url: state.config.endpoint_url("/native/v1"),
            manifest_url: state.config.endpoint_url("/mcp"),
            manifest_token: state.token.clone(),
            server_id: SERVER.into(),
            native: native.collector_view(),
            // There is no spawn: run_builtin_streams supplies only the compiled adapter.
            command: self.profile.agent.path.to_string_lossy().into(),
            args: Vec::new(),
            classifier: Some(classifier),
            resource_profiles: Default::default(),
            approval: Some(crate::mcp::admission::ApprovalWait {
                url: state.config.endpoint_url("/native/approval/v1"),
                wait: std::time::Duration::from_secs(120),
            }),
            liveness_url: Some(state.config.endpoint_url("/native/liveness/v1")),
            liveness_lease_seconds: Some(4),
        })
    }
}
fn refusal(status: StatusCode, code: &str) -> Response {
    (
        status,
        axum::Json(json!({"contract":FORMAT,"error_code":code,"complete":false})),
    )
        .into_response()
}

struct Cancel(watch::Sender<bool>);
impl Drop for Cancel {
    fn drop(&mut self) {
        let _ = self.0.send(true);
    }
}
struct Activity(Arc<Service>);
impl Drop for Activity {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) async fn handler(
    State(state): State<crate::Shared>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(native) = &state.native else {
        return refusal(StatusCode::SERVICE_UNAVAILABLE, "native_disabled");
    };
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::token::verify(&native.token, auth) {
        return refusal(StatusCode::UNAUTHORIZED, "native_unauthorized");
    }
    let Some(service) = native.edit.clone() else {
        return refusal(StatusCode::SERVICE_UNAVAILABLE, "edit_not_installed");
    };
    if !state.config.enforce || state.config.judge.enabled {
        return refusal(StatusCode::SERVICE_UNAVAILABLE, "edit_enforcement_required");
    }
    service.active.fetch_add(1, Ordering::AcqRel);
    let activity = Activity(service.clone());
    let mut revoked = service.closed.subscribe();
    // Authenticated malformed or interrupted attempts also spend this run's one
    // transport slot. A retry needs a separately selected new run/daemon epoch.
    if *revoked.borrow() || service.used.swap(true, Ordering::AcqRel) {
        return refusal(StatusCode::CONFLICT, "edit_run_spent");
    }
    let mut stream = body.into_data_stream();
    let preamble = tokio::select! {biased;
        _=revoked.changed()=>return refusal(StatusCode::CONFLICT, "edit_run_revoked"),
        value=read_preamble_for(&mut stream, FORMAT)=>value,
    };
    let (request, leftover) = match preamble {
        Ok(value) => value,
        Err(_) => return refusal(StatusCode::BAD_REQUEST, "edit_preamble_invalid"),
    };
    if request.catalogue_sha256 != service.digest
        || request.server_id != SERVER
        || request.host_session != service.host
    {
        return refusal(StatusCode::CONFLICT, "edit_selection_changed");
    }
    let config = match service.admission(&state, request.child_authority) {
        Ok(value) => value,
        Err(_) => return refusal(StatusCode::CONFLICT, "edit_runtime_changed"),
    };
    let (tx, mut stop) = watch::channel(false);
    let cancel = Cancel(tx.clone());
    let (mut incoming, client) = tokio::io::duplex(16384);
    let (output, outgoing) = tokio::io::duplex(16384);
    let mut input_stop = stop.clone();
    let input_tx = tx.clone();
    let input = tokio::spawn(async move {
        let copy = async {
            incoming.write_all(&leftover).await?;
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(std::io::Error::other)?;
                if chunk.len() > crate::MAX_ROUTE_BODY {
                    return Err(std::io::Error::other("chunk over cap"));
                }
                incoming.write_all(&chunk).await?;
            }
            incoming.shutdown().await
        };
        tokio::select! {biased;_=input_stop.changed()=>{},result=copy=>{if result.is_err(){let _=input_tx.send(true);}}}
    });
    let (done_tx, done_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _activity = activity;
        let mut client = BufReader::new(client);
        let result = crate::mcp::admission::run_builtin_streams(
            config,
            (
                service.profile.root.clone(),
                service.profile.root_identity.clone(),
                service.quota.clone(),
            ),
            service.profile.tools(),
            &mut client,
            output,
            async move {
                if !*stop.borrow() && !*revoked.borrow() {
                    tokio::select! {biased;
                        _=revoked.changed()=>{},
                        _=stop.changed()=>{},
                    }
                }
            },
            service.dispatches.clone(),
        )
        .await;
        let _ = tx.send(true);
        let joined = input.await.is_ok();
        let no_dispatch = service.dispatches.load(Ordering::Acquire) == 0;
        eprintln!(
            "{}",
            json!({"event":"edit_adapter_terminal","mutation_dispatches":service.dispatches.load(Ordering::Acquire),
            "complete":result.is_ok()&&joined&&no_dispatch,"profile_sha256":service.digest})
        );
        let _ = done_tx.send(result.is_ok() && joined && no_dispatch);
    });
    (
        [(axum::http::header::CONTENT_TYPE, MEDIA_TYPE)],
        framed_body(outgoing, done_rx, cancel, FORMAT),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{handlers::Sessions, native::NativeState};
    use std::sync::Mutex;
    use tower::ServiceExt;

    fn state(home: &std::path::Path, installed: bool) -> crate::Shared {
        let token = crate::token::generate();
        let raw=serde_json::to_vec(&json!({"contract_version":crate::native::CONTRACT,"registry_id":"edit-test","tools":[{"name":"fixture_read","schema_sha256":"a".repeat(64),"action_class":"read_only","result_provenance":"untrusted","egress":[]}]})).unwrap();
        let mut native = NativeState::from_bytes(
            &raw,
            &crate::mcp::replace_file::content_sha256(&raw),
            crate::token::generate(),
        )
        .unwrap();
        if installed {
            native.edit = Some(Service::new(profile::fixture(), "host".into()).unwrap());
        }
        Arc::new(crate::AppState {
            native: Some(native),
            firewall: Mutex::new(soup_wall_agent::AgentFirewall::with_default_policy()),
            sessions: Sessions::default(),
            audit: crate::audit::AuditSink::open(&home.join("audit")).unwrap(),
            config: crate::Config {
                enforce: true,
                ..Default::default()
            },
            token: token.clone(),
            spans: crate::spans::SpanCache::new(64, 262144),
            judge: crate::judge::Judge::new(Default::default()),
            manifests: crate::mcp::store::ManifestStore::new(&home.join("manifests")),
            tools: crate::mcp::store::ToolRegistry::with_builtins(),
            grants: crate::grant::GrantStore::new(&home.join("grants")),
            grant_ledger: crate::grant::GrantLedger::open(&home.join("spent")),
            grant_key: crate::grant::derive_key(&token),
        })
    }

    #[tokio::test]
    async fn authentication_and_default_off_are_checked_before_reading_body() {
        let dir = tempfile::tempdir().unwrap();
        for installed in [false, true] {
            let state = state(dir.path(), installed);
            for authenticated in [false, true] {
                if installed && authenticated {
                    continue;
                }
                let read = Arc::new(AtomicUsize::new(0));
                let count = read.clone();
                let body = Body::from_stream(futures_util::stream::once(async move {
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"untrusted"))
                }));
                let mut request = axum::http::Request::post(super::super::ENDPOINT);
                if authenticated {
                    request = request.header(
                        "authorization",
                        format!("Bearer {}", state.native.as_ref().unwrap().token),
                    );
                }
                let response = crate::app(state.clone())
                    .oneshot(request.body(body).unwrap())
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    if authenticated {
                        StatusCode::SERVICE_UNAVAILABLE
                    } else {
                        StatusCode::UNAUTHORIZED
                    }
                );
                assert_eq!(read.load(Ordering::SeqCst), 0);
            }
        }
    }

    #[tokio::test]
    async fn wrong_selection_spends_run_without_opening_collector_or_dispatching() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path(), true);
        let native = state.native.as_ref().unwrap();
        let service = native.edit.as_ref().unwrap();
        for expected in [StatusCode::CONFLICT, StatusCode::CONFLICT] {
            let body=json!({"contract":FORMAT,"catalogue_sha256":"f".repeat(64),"server_id":SERVER,"host_session":"host","child_authority":"invalid"}).to_string()+"\n";
            let response = crate::app(state.clone())
                .oneshot(
                    axum::http::Request::post(super::super::ENDPOINT)
                        .header("authorization", format!("Bearer {}", native.token))
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
        }
        assert_eq!(service.dispatches.load(Ordering::Acquire), 0);
        assert!(native.active_host_sessions().is_empty());
    }

    #[tokio::test]
    async fn edit_stop_revocation_cancels_a_stalled_preamble_and_spends_unused_authority() {
        let dir = tempfile::tempdir().unwrap();
        let state = state(dir.path(), true);
        let native = state.native.as_ref().unwrap();
        let service = native.edit.as_ref().unwrap().clone();
        let request = axum::http::Request::post(super::super::ENDPOINT)
            .header("authorization", format!("Bearer {}", native.token))
            .body(Body::from_stream(futures_util::stream::pending::<
                Result<axum::body::Bytes, std::io::Error>,
            >()))
            .unwrap();
        let task = tokio::spawn(crate::app(state.clone()).oneshot(request));
        while service.active.load(Ordering::Acquire) == 0 {
            tokio::task::yield_now().await;
        }
        let authority = "e".repeat(64);
        crate::native::pilot_stop::revoke_selected(
            &state,
            "host",
            &std::collections::BTreeMap::from([(SERVER.into(), authority.clone())]),
            crate::native::now_ms() + 10000,
        )
        .unwrap();
        service.close();
        let response = tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(service.wait_idle().await);
        assert!(native
            .sessions
            .lock()
            .unwrap()
            .spent_authorities
            .contains_key(&authority));
        assert_eq!(service.dispatches.load(Ordering::Acquire), 0);
    }
}
