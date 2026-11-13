// SPDX-License-Identifier: Apache-2.0
//! Fixed-host single TLS socket, no proxy/redirect/retry/configurable URL.
use super::*;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio_rustls::rustls;

const HEADER_LIMIT: usize = 8192;
const ENCRYPTED_LIMIT: usize = 131_072;

// Only fixed error identifiers may be persisted; library errors may contain secrets.
pub(super) fn failure_code(error: &anyhow::Error) -> &'static str {
    match error.to_string().as_str() {
        "gemini_chunk_framing" => "gemini_chunk_framing",
        "gemini_chunk_size" => "gemini_chunk_size",
        "gemini_chunk_trailer" => "gemini_chunk_trailer",
        "gemini_compression_refused" => "gemini_compression_refused",
        "gemini_connect" => "gemini_connect",
        "gemini_content_type" => "gemini_content_type",
        "gemini_dns" => "gemini_dns",
        "gemini_dns_private" => "gemini_dns_private",
        "gemini_encrypted_limit" => "gemini_encrypted_limit",
        "gemini_extra_http" => "gemini_extra_http",
        "gemini_header_limit" => "gemini_header_limit",
        "gemini_http" => "gemini_http",
        "gemini_http_eof" => "gemini_http_eof",
        "gemini_http_framing" => "gemini_http_framing",
        "gemini_http_status" => "gemini_http_status",
        "gemini_incomplete_http" => "gemini_incomplete_http",
        "gemini_length" => "gemini_length",
        "gemini_metadata_body" => "gemini_metadata_body",
        "gemini_peer" => "gemini_peer",
        "gemini_quota_stop" => "gemini_quota_stop",
        "gemini_redirect_refused" => "gemini_redirect_refused",
        "gemini_request_limit" => "gemini_request_limit",
        "gemini_request_limit_or_expired" => "gemini_request_limit_or_expired",
        "gemini_response_limit" => "gemini_response_limit",
        "gemini_timeout_unknown" => "gemini_timeout_unknown",
        "gemini_tls" => "gemini_tls",
        "gemini_transfer_encoding" => "gemini_transfer_encoding",
        "gemini_write_unknown" => "gemini_write_unknown",
        _ => "gemini_transport_unclassified",
    }
}

#[test]
fn gemini_transport_failure_code_redacts_unrecognized_errors() {
    assert_eq!(failure_code(&anyhow::anyhow!("gemini_tls")), "gemini_tls");
    assert_eq!(
        failure_code(&anyhow::anyhow!("secret synthetic value")),
        "gemini_transport_unclassified"
    );
    assert_eq!(
        failure_code(&anyhow::anyhow!("gemini_tls: secret synthetic value")),
        "gemini_transport_unclassified"
    );
}

pub(super) struct Rejection {
    status: u16,
    pub(super) body: Vec<u8>,
}
impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.status {
            429 => "gemini_quota_stop",
            300..=399 => "gemini_redirect_refused",
            _ => "gemini_http_status",
        })
    }
}
impl std::fmt::Debug for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for Rejection {}

struct Counted<T> {
    inner: T,
    read: usize,
}
impl<T: AsyncRead + Unpin> AsyncRead for Counted<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let remaining = ENCRYPTED_LIMIT
            .saturating_sub(this.read)
            .min(buf.remaining());
        if remaining == 0 {
            return Poll::Ready(Err(io::Error::other("gemini_encrypted_limit")));
        }
        let mut scratch = [0; 4096];
        let capacity = remaining.min(scratch.len());
        let mut limited = ReadBuf::new(&mut scratch[..capacity]);
        match Pin::new(&mut this.inner).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                this.read += limited.filled().len();
                buf.put_slice(limited.filled());
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Counted<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

fn tls_config() -> Result<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

/// Affine component API. Not wired to any operator or production endpoint.
/// No test invokes this real network method; tests exercise its wire routines.
async fn execute(prepared: Prepared, key: Key, ledger: &std::path::Path) -> Result<Vec<u8>> {
    reserve_attempt(ledger, &prepared)?;
    let response = request(Operation::Generate, &prepared.body, &key, prepared.deadline).await?;
    decode(&prepared, &response)
}

#[derive(Clone, Copy)]
pub(super) enum Operation {
    Generate,
    Metadata,
    Count,
}
impl Operation {
    fn wire(self) -> (&'static str, &'static str) {
        match self {
            Self::Generate => ("POST", PATH),
            Self::Metadata => ("GET", METADATA_PATH),
            Self::Count => ("POST", COUNT_PATH),
        }
    }
}

pub(super) async fn request(
    operation: Operation,
    body: &[u8],
    key: &Key,
    deadline: Instant,
) -> Result<Vec<u8>> {
    ensure!(
        body.len() <= REQUEST_LIMIT && Instant::now() < deadline,
        "gemini_request_limit_or_expired"
    );
    ensure!(
        !matches!(operation, Operation::Metadata) || body.is_empty(),
        "gemini_metadata_body"
    );
    let deadline = tokio::time::Instant::from_std(deadline);
    let response = tokio::time::timeout_at(deadline, async {
        let addresses: Vec<_> = tokio::net::lookup_host((HOST, 443))
            .await
            .map_err(|_| anyhow::anyhow!("gemini_dns"))?
            .collect();
        ensure!(
            !addresses.is_empty()
                && addresses
                    .iter()
                    .all(|x| crate::mcp::https_get::is_public_address(x.ip())),
            "gemini_dns_private"
        );
        // Freeze one address from this lookup; no fallback reconnect/re-resolution.
        let address = addresses[0];
        let socket = tokio::net::TcpStream::connect(address)
            .await
            .map_err(|_| anyhow::anyhow!("gemini_connect"))?;
        ensure!(socket.peer_addr().ok() == Some(address), "gemini_peer");
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_config()?));
        let name = rustls_pki_types::ServerName::try_from(HOST).unwrap();
        let mut stream = connector
            .connect(
                name,
                Counted {
                    inner: socket,
                    read: 0,
                },
            )
            .await
            .map_err(|_| anyhow::anyhow!("gemini_tls"))?;
        exchange_operation(&mut stream, operation, body, key).await
    })
    .await
    .map_err(|_| anyhow::anyhow!("gemini_timeout_unknown"))?;
    response
}

async fn exchange(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    body: &[u8],
    key: &Key,
) -> Result<Vec<u8>> {
    exchange_operation(stream, Operation::Generate, body, key).await
}

async fn exchange_operation(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    operation: Operation,
    body: &[u8],
    key: &Key,
) -> Result<Vec<u8>> {
    ensure!(body.len() <= REQUEST_LIMIT, "gemini_request_limit");
    let (method, path) = operation.wire();
    let header = zeroize::Zeroizing::new(format!("{method} {path} HTTP/1.1\r\nHost: {HOST}\r\nx-goog-api-key: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nAccept: application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",key.0,body.len()));
    stream
        .write_all(header.as_bytes())
        .await
        .map_err(|_| anyhow::anyhow!("gemini_write_unknown"))?;
    stream
        .write_all(body)
        .await
        .map_err(|_| anyhow::anyhow!("gemini_write_unknown"))?;
    stream
        .flush()
        .await
        .map_err(|_| anyhow::anyhow!("gemini_write_unknown"))?;
    read_response(stream).await
}

async fn exact(stream: &mut (impl AsyncRead + Unpin), bytes: &mut [u8]) -> Result<()> {
    stream
        .read_exact(bytes)
        .await
        .map_err(|_| anyhow::anyhow!("gemini_incomplete_http"))?;
    Ok(())
}

async fn read_response(stream: &mut (impl AsyncRead + Unpin)) -> Result<Vec<u8>> {
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        ensure!(header.len() < HEADER_LIMIT, "gemini_header_limit");
        let mut byte = [0];
        exact(stream, &mut byte).await?;
        header.push(byte[0]);
    }
    let mut slots = [httparse::EMPTY_HEADER; 64];
    let mut parsed = httparse::Response::new(&mut slots);
    ensure!(
        parsed
            .parse(&header)
            .map_err(|_| anyhow::anyhow!("gemini_http"))?
            == httparse::Status::Complete(header.len())
            && parsed.version == Some(1),
        "gemini_http"
    );
    let status = parsed.code.unwrap_or(0);
    let mut length = None;
    let mut chunked = false;
    let mut content_type = false;
    for h in parsed.headers {
        if h.name.eq_ignore_ascii_case("content-length") {
            ensure!(
                length.is_none() && !h.value.is_empty() && h.value.iter().all(u8::is_ascii_digit),
                "gemini_length"
            );
            length = Some(
                std::str::from_utf8(h.value)?
                    .parse::<usize>()
                    .map_err(|_| anyhow::anyhow!("gemini_length"))?,
            );
        } else if h.name.eq_ignore_ascii_case("transfer-encoding") {
            ensure!(
                !chunked && h.value == b"chunked",
                "gemini_transfer_encoding"
            );
            chunked = true;
        } else if h.name.eq_ignore_ascii_case("content-encoding") {
            anyhow::bail!("gemini_compression_refused");
        } else if h.name.eq_ignore_ascii_case("content-type") {
            ensure!(
                !content_type
                    && matches!(
                        h.value,
                        b"application/json"
                            | b"application/json; charset=UTF-8"
                            | b"application/json; charset=utf-8"
                    ),
                "gemini_content_type"
            );
            content_type = true;
        }
    }
    ensure!(
        (content_type || status != 200) && (length.is_some() != chunked),
        "gemini_http_framing"
    );
    let mut body = Vec::new();
    if let Some(length) = length {
        ensure!(length <= RESPONSE_LIMIT, "gemini_response_limit");
        body.resize(length, 0);
        exact(stream, &mut body).await?;
    } else {
        let mut framing = 0;
        loop {
            let mut line = Vec::new();
            while !line.ends_with(b"\r\n") {
                ensure!(
                    line.len() < 10 && framing < HEADER_LIMIT,
                    "gemini_chunk_framing"
                );
                let mut byte = [0];
                exact(stream, &mut byte).await?;
                line.push(byte[0]);
                framing += 1;
            }
            let digits = &line[..line.len() - 2];
            ensure!(
                !digits.is_empty() && digits.iter().all(u8::is_ascii_hexdigit),
                "gemini_chunk_size"
            );
            let count = usize::from_str_radix(std::str::from_utf8(digits)?, 16)
                .map_err(|_| anyhow::anyhow!("gemini_chunk_size"))?;
            ensure!(
                count <= RESPONSE_LIMIT.saturating_sub(body.len()),
                "gemini_response_limit"
            );
            if count > 0 {
                let start = body.len();
                body.resize(start + count, 0);
                exact(stream, &mut body[start..]).await?;
            }
            let mut end = [0; 2];
            exact(stream, &mut end).await?;
            framing += 2;
            ensure!(
                end == *b"\r\n" && framing <= HEADER_LIMIT,
                "gemini_chunk_trailer"
            );
            if count == 0 {
                break;
            }
        }
    }
    // HTTP framing above proves the body is complete. Rustls reports a missing
    // close_notify as UnexpectedEof; accept it only here, after complete framing.
    let mut tail = [0];
    match stream.read(&mut tail).await {
        Ok(0) => {}
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
        Ok(_) => anyhow::bail!("gemini_extra_http"),
        Err(_) => anyhow::bail!("gemini_http_eof"),
    }
    if status != 200 {
        return Err(anyhow::Error::new(Rejection { status, body }));
    }
    Ok(body)
}

#[tokio::test]
async fn gemini_transport_bounds_quota_redirect_framing_and_encrypted_reads() {
    for (status, code) in [
        (429, "gemini_quota_stop"),
        (302, "gemini_redirect_refused"),
        (401, "gemini_http_status"),
    ] {
        let text = format!("HTTP/1.1 {status} Error\r\nContent-Length: 0\r\n\r\n");
        assert_eq!(
            read_response(&mut text.as_bytes())
                .await
                .unwrap_err()
                .to_string(),
            code
        );
    }
    for header in [
        "Content-Length: 65537",
        "Content-Length: 1\r\nContent-Length: 1",
        "Content-Length: 1\r\nTransfer-Encoding: chunked",
        "Transfer-Encoding: gzip",
        "Content-Length: 1\r\nContent-Encoding: gzip",
    ] {
        let text =
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{header}\r\n\r\nx");
        assert!(read_response(&mut text.as_bytes()).await.is_err());
    }
    for text in [b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n".as_slice(), b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"] {
        assert_eq!(read_response(&mut &text[..]).await.unwrap(),b"{}");
        let mut extra = text.to_vec();extra.push(1);assert!(read_response(&mut extra.as_slice()).await.is_err());
        assert!(read_response(&mut &text[..text.len()-1]).await.is_err());
    }
    let oversized = vec![b'x'; HEADER_LIMIT + 1];
    assert!(read_response(&mut oversized.as_slice()).await.is_err());
    let bytes = vec![0; ENCRYPTED_LIMIT + 1];
    let mut counted = Counted {
        inner: bytes.as_slice(),
        read: 0,
    };
    let mut output = Vec::new();
    assert!(counted.read_to_end(&mut output).await.is_err());
    assert_eq!(output.len(), ENCRYPTED_LIMIT);
    // Compile the real connector, but never invoke it in unattended tests.
    let _connector = execute;
    assert!(!tls_config().unwrap().enable_early_data);
}

#[tokio::test]
async fn gemini_transport_key_only_in_header_no_retry_and_deadline_cancellation() {
    let key = Key::new("synthetic_key_for_test_only".into()).unwrap();
    let (mut client, mut server) = tokio::io::duplex(4096);
    let work = async {
        tokio::time::timeout(
            std::time::Duration::from_millis(20),
            exchange(&mut client, b"{}", &key),
        )
        .await
    };
    assert!(work.await.is_err());
    drop(client);
    let mut wire = Vec::new();
    server.read_to_end(&mut wire).await.unwrap();
    let wire = String::from_utf8(wire).unwrap();
    assert!(wire.starts_with(&format!("POST {PATH} HTTP/1.1\r\nHost: {HOST}\r\n")));
    assert_eq!(wire.matches("synthetic_key_for_test_only").count(), 1);
    assert_eq!(wire.matches("POST ").count(), 1);
    assert!(wire.ends_with("\r\n\r\n{}"));
    assert!(!wire.contains("Authorization:") && !wire.contains("?key="));
}

#[tokio::test]
async fn gemini_transport_preflight_only_fixed_model_paths() {
    let key = Key::new(crate::token::generate()).unwrap();
    for operation in [Operation::Metadata, Operation::Count] {
        let (mut client, mut server) = tokio::io::duplex(4096);
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            exchange_operation(&mut client, operation, &[], &key),
        )
        .await;
        drop(client);
        let mut bytes = Vec::new();
        server.read_to_end(&mut bytes).await.unwrap();
        let wire = String::from_utf8(bytes).unwrap();
        let (method, path) = operation.wire();
        assert!(wire.starts_with(&format!("{method} {path} HTTP/1.1\r\nHost: {HOST}\r\n")));
        assert_eq!(wire.matches(&key.0).count(), 1);
        assert!(!wire.contains("?key="));
    }
    let body = br#"{"error":{"code":429,"message":"quota exhausted"}}"#;
    let wire = [
        format!(
            "HTTP/1.1 429 Error\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes(),
        body.to_vec(),
    ]
    .concat();
    let error = read_response(&mut wire.as_slice()).await.unwrap_err();
    assert_eq!(error.to_string(), "gemini_quota_stop");
    assert_eq!(error.downcast_ref::<Rejection>().unwrap().body, body);
    assert!(!format!("{error:?}").contains("quota exhausted"));
}

#[tokio::test]
async fn gemini_transport_unclean_tls_close_requires_complete_http_body() {
    struct Abrupt {
        bytes: Vec<u8>,
        position: usize,
        error: io::ErrorKind,
    }
    impl AsyncRead for Abrupt {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.position == self.bytes.len() {
                return Poll::Ready(Err(io::Error::from(self.error)));
            }
            let count = buf.remaining().min(self.bytes.len() - self.position);
            buf.put_slice(&self.bytes[self.position..self.position + count]);
            self.position += count;
            Poll::Ready(Ok(()))
        }
    }
    for framing in [
        "Content-Length: 2\r\n\r\n{}",
        "Transfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
    ] {
        let bytes =
            format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n{framing}").into_bytes();
        let reader = |bytes| Abrupt {
            bytes,
            position: 0,
            error: io::ErrorKind::UnexpectedEof,
        };
        assert_eq!(
            read_response(&mut reader(bytes.clone())).await.unwrap(),
            b"{}"
        );
        for end in 0..bytes.len() {
            assert!(read_response(&mut reader(bytes[..end].to_vec()))
                .await
                .is_err());
        }
        let mut extra = bytes.clone();
        extra.push(b'x');
        assert!(read_response(&mut reader(extra)).await.is_err());
        let mut reset = reader(bytes);
        reset.error = io::ErrorKind::ConnectionReset;
        assert_eq!(
            read_response(&mut reset).await.unwrap_err().to_string(),
            "gemini_http_eof"
        );
    }
}
