// SPDX-License-Identifier: Apache-2.0
//! Bounded private transport. MCP payload bytes and terminal daemon control are
//! framed separately; an upstream server cannot forge the terminal receipt.

use super::*;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{Stream, StreamExt};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{oneshot, watch};

pub const MEDIA_TYPE: &str = "application/vnd.soup-wall.original-execution.v1";
const PREAMBLE_BYTES: usize = 8192;
const CHUNK_BYTES: usize = 16384;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Preamble {
    pub contract: String,
    pub catalogue_sha256: String,
    pub server_id: String,
    pub host_session: String,
    pub child_authority: String,
}

fn refusal(status: StatusCode, reason: &'static str) -> Response {
    if status != StatusCode::UNAUTHORIZED && reason != "native_disabled" {
        eprintln!(
            "{}",
            json!({"event":"verified_execution_refused","failure_code":reason})
        );
    }
    (
        status,
        axum::Json(json!({"contract":FORMAT,"error_code":reason,"complete":false})),
    )
        .into_response()
}

struct Cancel {
    sender: watch::Sender<bool>,
    withdrawn: Arc<AtomicBool>,
}
impl Drop for Cancel {
    fn drop(&mut self) {
        self.withdrawn.store(true, Ordering::Release);
        let _ = self.sender.send(true);
    }
}
struct HostPermit {
    service: Arc<Service>,
    host: String,
    context: Arc<SessionContext>,
}
impl Drop for HostPermit {
    fn drop(&mut self) {
        // Unknown owner cleanup is sticky. Never relaunch over unresolved state.
        if self.context.reusable() {
            if let Ok(mut hosts) = self.service.hosts.lock() {
                hosts.remove(&self.host);
            }
        }
    }
}

async fn read_preamble(
    stream: &mut (impl Stream<Item = Result<Bytes, axum::Error>> + Unpin),
) -> anyhow::Result<(Preamble, Vec<u8>)> {
    let mut prefix = Vec::new();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let bytes = tokio::time::timeout_at(deadline, stream.next())
            .await?
            .context("verified_execution_preamble_missing")??;
        ensure!(
            bytes.len() <= crate::MAX_ROUTE_BODY,
            "verified_execution_chunk_over_cap"
        );
        if let Some(end) = bytes.iter().position(|byte| *byte == b'\n') {
            ensure!(
                prefix.len() + end <= PREAMBLE_BYTES,
                "verified_execution_preamble_over_cap"
            );
            prefix.extend_from_slice(&bytes[..end]);
            let crate::mcp::admission::Strict(value) = serde_json::from_slice(&prefix)?;
            let request: Preamble = serde_json::from_value(value)?;
            ensure!(
                request.contract == FORMAT
                    && super::super::identifier(&request.host_session)
                    && !request.child_authority.is_empty()
                    && request.child_authority.len() <= PREAMBLE_BYTES,
                "verified_execution_preamble_invalid"
            );
            return Ok((request, bytes[end + 1..].to_vec()));
        }
        ensure!(
            prefix.len() + bytes.len() <= PREAMBLE_BYTES,
            "verified_execution_preamble_over_cap"
        );
        prefix.extend_from_slice(&bytes);
    }
}

pub async fn handler(State(st): State<Shared>, headers: HeaderMap, body: Body) -> Response {
    let Some(native) = &st.native else {
        return refusal(StatusCode::SERVICE_UNAVAILABLE, "native_disabled");
    };
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !crate::token::verify(&native.token, auth) {
        return refusal(StatusCode::UNAUTHORIZED, "native_unauthorized");
    }
    if !st.config.enforce || st.config.judge.enabled {
        return refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "native_enforcement_required",
        );
    }
    let Some(service) = native.execution.clone() else {
        return refusal(
            StatusCode::SERVICE_UNAVAILABLE,
            "verified_execution_unavailable",
        );
    };
    let Ok(slot) = service.slots.clone().try_acquire_owned() else {
        return refusal(StatusCode::TOO_MANY_REQUESTS, "verified_execution_capacity");
    };
    let mut stream = body.into_data_stream();
    let (request, leftover) = match read_preamble(&mut stream).await {
        Ok(value) => value,
        Err(_) => {
            return refusal(
                StatusCode::BAD_REQUEST,
                "verified_execution_preamble_invalid",
            )
        }
    };
    if request.catalogue_sha256 != service.digest
        || request.server_id != service.catalogue.server_id
    {
        return refusal(StatusCode::CONFLICT, "verified_execution_selection_changed");
    }
    let selected = match &service.catalogue.budget {
        Some(budget) => match crate::pilot_budget::verify_daemon_launch(
            &budget.binding,
            &budget.budget_sha256,
            &request.host_session,
            &request.server_id,
        ) {
            Ok(selected) => Some(selected),
            Err(_) => {
                return refusal(
                    StatusCode::CONFLICT,
                    "verified_execution_budget_unavailable",
                )
            }
        },
        None => None,
    };
    let config = match service.admission(&st, request.host_session.clone(), request.child_authority)
    {
        Ok(config) => config,
        Err(_) => {
            return refusal(
                StatusCode::SERVICE_UNAVAILABLE,
                "verified_execution_configuration_invalid",
            )
        }
    };
    let context = Arc::new(SessionContext {
        daemon: st.clone(),
        runtime: service.runtime.clone(),
        catalogue: service.digest.clone(),
        host: request.host_session.clone(),
        channel: crate::token::generate(),
        withdrawn: Arc::new(AtomicBool::new(false)),
        process: OnceLock::new(),
        stage: AtomicU8::new(0),
    });
    let reserved = match service.hosts.lock() {
        Ok(mut hosts) => hosts.len() < 128 && hosts.insert(request.host_session.clone()),
        Err(_) => false,
    };
    if !reserved {
        return refusal(StatusCode::CONFLICT, "verified_execution_host_busy");
    }
    let host_permit = HostPermit {
        service: service.clone(),
        host: request.host_session,
        context: context.clone(),
    };
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let cancelled = Cancel {
        sender: cancel_tx.clone(),
        withdrawn: context.withdrawn.clone(),
    };
    let (mut incoming, client) = tokio::io::duplex(CHUNK_BYTES);
    let (host, outgoing) = tokio::io::duplex(CHUNK_BYTES);
    let mut input_cancel = cancel_rx.clone();
    let input_context = context.clone();
    let input_cancel_tx = cancel_tx.clone();
    let input_task = tokio::spawn(async move {
        let copied = async {
            if !leftover.is_empty() {
                incoming.write_all(&leftover).await?;
            }
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(std::io::Error::other)?;
                if chunk.len() > crate::MAX_ROUTE_BODY {
                    return Err(std::io::Error::other("chunk over cap"));
                }
                incoming.write_all(&chunk).await?;
            }
            incoming.shutdown().await
        };
        tokio::select! {
            biased;
            _=input_cancel.changed()=>{},
            result=copied=>{if result.is_err(){input_context.withdrawn.store(true,Ordering::Release);let _=input_cancel_tx.send(true);}},
        }
    });
    let (done_tx, done_rx) = oneshot::channel();
    let profile = service.catalogue.profile.clone();
    tokio::spawn(async move {
        let observed = context.clone();
        let result = crate::mcp::admission::run_daemon_streams(
            config,
            profile,
            selected,
            BufReader::new(client),
            host,
            async move {
                if !*cancel_rx.borrow() {
                    let _ = cancel_rx.changed().await;
                }
            },
            context,
        )
        .await;
        if let Err(error) = &result {
            eprintln!(
                "{}",
                json!({"event":"verified_execution_session_failed",
                "failure_code":failure_code(error),
                "launch_stage":observed.stage.load(Ordering::Acquire),
                "original_generation_bound":observed.process.get().is_some()})
            );
        }
        let _ = cancel_tx.send(true);
        let _ = input_task.await;
        drop(host_permit);
        drop(slot);
        let _ = done_tx.send(result.is_ok());
    });
    let frames = futures_util::stream::try_unfold(
        (outgoing, Some(done_rx), Some(cancelled)),
        |(mut reader, mut done, cancel)| async move {
            let mut buffer = vec![0u8; CHUNK_BYTES];
            let count = reader.read(&mut buffer).await?;
            if count > 0 {
                buffer.truncate(count);
                let mut frame = Vec::with_capacity(count + 5);
                frame.push(1);
                frame.extend_from_slice(&(count as u32).to_be_bytes());
                frame.extend_from_slice(&buffer);
                return Ok::<_, std::io::Error>(Some((frame, (reader, done, cancel))));
            }
            if let Some(done) = done.take() {
                let complete = done.await.unwrap_or(false);
                let raw = serde_json::to_vec(&json!({"contract":FORMAT,"complete":complete}))
                    .expect("finite receipt");
                let mut frame = Vec::with_capacity(raw.len() + 5);
                frame.push(2);
                frame.extend_from_slice(&(raw.len() as u32).to_be_bytes());
                frame.extend_from_slice(&raw);
                return Ok(Some((frame, (reader, None, cancel))));
            }
            Ok(None)
        },
    );
    (
        [(axum::http::header::CONTENT_TYPE, MEDIA_TYPE)],
        Body::from_stream(frames),
    )
        .into_response()
}

fn input_stream<R: AsyncRead + Unpin + Send + 'static>(
    reader: R,
) -> impl Stream<Item = Result<Vec<u8>, std::io::Error>> + Send {
    futures_util::stream::try_unfold(reader, |mut reader| async move {
        let mut bytes = vec![0u8; CHUNK_BYTES];
        let count = reader.read(&mut bytes).await?;
        if count == 0 {
            Ok(None)
        } else {
            bytes.truncate(count);
            Ok(Some((bytes, reader)))
        }
    })
}

/// Forwarder only: no local upstream command, classifier, snapshot or evidence.
async fn client<R, W>(
    url: String,
    token: String,
    preamble: Preamble,
    input: R,
    mut output: W,
) -> anyhow::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin,
{
    let parsed = reqwest::Url::parse(&url)?;
    let loopback = parsed
        .host_str()
        .and_then(|host| {
            host.trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .ok()
        })
        .is_some_and(|ip| ip.is_loopback());
    ensure!(
        parsed.scheme() == "http"
            && loopback
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.query().is_none()
            && parsed.fragment().is_none()
            && parsed.path() == ENDPOINT,
        "verified_execution_local_daemon_required"
    );
    let mut prefix = serde_json::to_vec(&preamble)?;
    ensure!(
        prefix.len() <= PREAMBLE_BYTES,
        "verified_execution_preamble_over_cap"
    );
    prefix.push(b'\n');
    let stream = futures_util::stream::once(async { Ok::<_, std::io::Error>(prefix) })
        .chain(input_stream(input));
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .http1_only()
        .connect_timeout(std::time::Duration::from_secs(3))
        .build()?;
    let response = client
        .post(url)
        .bearer_auth(token)
        .header("content-type", MEDIA_TYPE)
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "verified_execution_transport_refused"
    );
    ensure!(
        response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            == Some(MEDIA_TYPE),
        "verified_execution_transport_contract"
    );
    let mut chunks = response.bytes_stream();
    let mut pending = Vec::new();
    let mut final_receipt = false;
    while let Some(chunk) = chunks.next().await {
        let chunk = chunk?;
        let mut cursor = 0;
        while cursor < chunk.len() {
            ensure!(!final_receipt, "verified_execution_after_terminal");
            let needed = if pending.len() < 5 {
                5 - pending.len()
            } else {
                let size = u32::from_be_bytes(pending[1..5].try_into().expect("header")) as usize;
                ensure!(
                    size > 0 && size <= CHUNK_BYTES,
                    "verified_execution_frame_over_cap"
                );
                5 + size - pending.len()
            };
            let count = needed.min(chunk.len() - cursor);
            pending.extend_from_slice(&chunk[cursor..cursor + count]);
            cursor += count;
            if pending.len() < 5 {
                continue;
            }
            let size = u32::from_be_bytes(pending[1..5].try_into().expect("header")) as usize;
            ensure!(
                size > 0 && size <= CHUNK_BYTES,
                "verified_execution_frame_over_cap"
            );
            if pending.len() < 5 + size {
                continue;
            }
            match pending[0] {
                1 => {
                    output.write_all(&pending[5..]).await?;
                    output.flush().await?;
                }
                2 => {
                    let crate::mcp::admission::Strict(value) =
                        serde_json::from_slice(&pending[5..])?;
                    ensure!(
                        value.as_object().is_some_and(|fields| fields.len() == 2)
                            && value["contract"] == FORMAT
                            && value["complete"] == true,
                        "verified_execution_incomplete"
                    );
                    final_receipt = true;
                }
                _ => anyhow::bail!("verified_execution_frame_invalid"),
            }
            pending.clear();
        }
    }
    ensure!(
        final_receipt && pending.is_empty(),
        "verified_execution_terminal_missing"
    );
    Ok(())
}

pub async fn run_client(url: String, token: String, preamble: Preamble) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        client(
            url,
            token,
            preamble,
            crate::mcp::stdio::Pipe::stdin()?,
            crate::mcp::stdio::Pipe::stdout()?,
        )
        .await
    }
    #[cfg(not(unix))]
    {
        client(
            url,
            token,
            preamble,
            tokio::io::stdin(),
            tokio::io::stdout(),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn preamble() -> Preamble {
        Preamble {
            contract: FORMAT.into(),
            catalogue_sha256: "a".repeat(64),
            server_id: "filesystem".into(),
            host_session: "fixture-host".into(),
            child_authority: "fixture-signed-claim".into(),
        }
    }
    fn wire(kind: u8, bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![kind];
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
        out
    }
    fn final_frame(complete: bool) -> Vec<u8> {
        wire(
            2,
            &serde_json::to_vec(&json!({"contract":FORMAT,"complete":complete})).unwrap(),
        )
    }

    #[tokio::test]
    async fn preamble_keeps_exact_following_mcp_bytes() {
        let mut first = serde_json::to_vec(&preamble()).unwrap();
        first.push(b'\n');
        let raw = b"{ \"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\" }\n";
        first.extend_from_slice(raw);
        let body = Body::from(first);
        let (request, left) = read_preamble(&mut body.into_data_stream()).await.unwrap();
        assert_eq!(request.host_session, "fixture-host");
        assert_eq!(left, raw);
    }
    #[tokio::test]
    async fn malformed_duplicate_truncated_and_oversized_preambles_are_refused() {
        let base = serde_json::to_string(&preamble()).unwrap();
        let mut duplicate = base[..base.len() - 1].to_owned();
        duplicate.push_str(",\"host_session\":\"other\"}\n");
        for raw in [
            duplicate.into_bytes(),
            vec![b'x'; PREAMBLE_BYTES + 1],
            vec![0xff, b'\n'],
            base.into_bytes(),
            b"{\"metadata\":{\"contract\":\"sw-mcp/verified-original-execution/1\"}}\n".to_vec(),
        ] {
            assert!(read_preamble(&mut Body::from(raw).into_data_stream())
                .await
                .is_err());
        }
    }
    #[tokio::test]
    async fn body_error_never_becomes_a_successful_preamble() {
        let body = Body::from_stream(futures_util::stream::iter(vec![
            Ok(Bytes::from_static(b"{\"contract\":")),
            Err(std::io::Error::other("fixture I/O failure")),
        ]));
        assert!(read_preamble(&mut body.into_data_stream()).await.is_err());
    }

    async fn decode(bytes: Vec<u8>, fragment: bool) -> (anyhow::Result<()>, Vec<u8>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let bytes = Arc::new(bytes);
        let route = axum::routing::post(move || {
            let bytes = bytes.clone();
            async move {
                let chunks = if fragment {
                    bytes
                        .chunks(1)
                        .map(Bytes::copy_from_slice)
                        .collect::<Vec<_>>()
                } else {
                    vec![Bytes::copy_from_slice(&bytes)]
                };
                (
                    [(axum::http::header::CONTENT_TYPE, MEDIA_TYPE)],
                    Body::from_stream(futures_util::stream::iter(
                        chunks.into_iter().map(Ok::<_, std::io::Error>),
                    )),
                )
            }
        });
        let app = axum::Router::new().route(ENDPOINT, route);
        let (stop, stopped) = oneshot::channel();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap()
        });
        let mut output = Vec::new();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client(
                format!("http://{address}{ENDPOINT}"),
                "fixture-native-key".into(),
                preamble(),
                tokio::io::empty(),
                &mut output,
            ),
        )
        .await
        .unwrap();
        let _ = stop.send(());
        server.await.unwrap();
        (result, output)
    }
    #[tokio::test]
    async fn fragmented_payloads_preserve_bytes_and_need_a_real_terminal_control() {
        let payload = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"complete\":true}}\n";
        let mut frames = wire(1, payload);
        frames.extend(final_frame(true));
        let (result, output) = decode(frames, true).await;
        assert!(result.is_ok());
        assert_eq!(output, payload);
        let (result, output) = decode(wire(1, payload), false).await;
        assert!(result.is_err());
        assert_eq!(output, payload);
    }
    #[tokio::test]
    async fn decoder_refuses_failure_duplicate_extra_and_oversized_control() {
        let mut extra = final_frame(true);
        extra.extend(wire(1, b"after-completion"));
        let mut oversized = vec![1];
        oversized.extend_from_slice(&((CHUNK_BYTES + 1) as u32).to_be_bytes());
        let duplicate = wire(
            2,
            format!("{{\"contract\":\"{FORMAT}\",\"complete\":true,\"complete\":true}}").as_bytes(),
        );
        for bytes in [
            final_frame(false),
            extra,
            oversized,
            duplicate,
            vec![1, 0, 0],
            wire(3, b"invalid"),
        ] {
            let (result, _) = decode(bytes, false).await;
            assert!(result.is_err());
        }
    }
    #[tokio::test]
    async fn forwarding_refuses_non_loopback_or_credentialed_destinations_before_io() {
        for url in [
            "https://example.com/native/execution/v1",
            "http://127.0.0.1.evil.invalid/native/execution/v1",
            "http://secret@127.0.0.1:1/native/execution/v1",
            "http://127.0.0.1:1/other",
        ] {
            assert!(client(
                url.into(),
                "fixture-native-key".into(),
                preamble(),
                tokio::io::empty(),
                tokio::io::sink()
            )
            .await
            .is_err());
        }
    }
}
