// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! One bounded HTTPS GET, issued by the native broker after real Allow.
//!
//! An operator installs an exact URL, one connection address, and (only for a
//! deliberately private endpoint) an exact HTTPS identity/address exception.
//! Current DNS must match that address both at preparation and dispatch. The
//! connector uses only the frozen address; it never resolves again, follows a
//! redirect, retries, inherits a proxy, or relaxes TLS verification. Counted
//! encrypted and plaintext reads also bound framing and TLS overhead, not just
//! the returned document. Only one Content-Length response is supported.
//!
//! The executor is single use. Dropping its future cancels its client request,
//! but cancellation/result refusal cannot undo a GET already received by the
//! endpoint. Error accounting is deliberately conservative: `request_issued`
//! means a GET write was attempted and may have reached the receiver. Only a
//! receiver ledger can establish the exact effect of a transport failure.

use std::fmt;
#[cfg(target_os = "linux")]
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_os = "linux")]
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

#[cfg(any(target_os = "linux", test))]
use reqwest::header::CONTENT_TYPE;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
#[cfg(target_os = "linux")]
use tokio_rustls::rustls;

pub const MAX_HTTPS_BODY_BYTES: usize = 4096;
pub const MAX_HTTPS_URL_BYTES: usize = 2048;
pub const MAX_HTTPS_ROOT_PEM_BYTES: usize = 16_384;
pub const MAX_HTTPS_ENCRYPTED_BYTES: usize = 65_536;
pub const MAX_HTTPS_HTTP_BYTES: usize = 16_384;
pub const MAX_HTTPS_HEADER_BYTES: usize = 8192;
pub const HTTPS_CONNECT_TIMEOUT_SECS: u64 = 3;
pub const HTTPS_TOTAL_TIMEOUT_SECS: u64 = 5;
pub const EXECUTOR_PROFILE: &str = "sw-native/https-get/linux-pinned/1";

/// This is operator configuration. It is never accepted from tool arguments.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpsGetAuthority {
    pub exact_url: String,
    /// Version 1 intentionally permits exactly one frozen connection address.
    pub approved_addresses: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_endpoint: Option<PrivateEndpointException>,
    /// A literal operator-owned CA certificate, with ordinary hostname/expiry
    /// verification. This does not permit an insecure TLS mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_certificate_pem: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PrivateEndpointException {
    pub host: String,
    pub port: u16,
    pub address: IpAddr,
}

/// No URL, hostname, certificate, response, or underlying transport diagnostic
/// is included in display/debug output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpsGetError {
    pub code: &'static str,
    /// False means no GET write was attempted (TCP/TLS may have happened).
    /// True conservatively records that a GET may have reached the endpoint.
    pub request_issued: bool,
}

impl HttpsGetError {
    fn new(code: &'static str) -> Self {
        Self {
            code,
            request_issued: false,
        }
    }

    #[cfg(any(target_os = "linux", test))]
    fn issued(code: &'static str) -> Self {
        Self {
            code,
            request_issued: true,
        }
    }
}

impl fmt::Display for HttpsGetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "constrained HTTPS GET refused: code={} request_issued={}",
            self.code, self.request_issued
        )
    }
}

impl std::error::Error for HttpsGetError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpsGetResult {
    pub status: u16,
    pub content_type: String,
    pub text: String,
    pub received_bytes: usize,
    pub received_encrypted_bytes: usize,
    pub received_http_bytes: usize,
    pub request_issued: bool,
}

/// Return the exact canonical URL, its unbracketed host and effective port.
/// The intentionally conservative ASCII scope has no percent escapes, user
/// information, fragment, backslash, URL parser normalization or default-port
/// aliases. The original MCP URL therefore has one admitted spelling.
pub fn canonical_url(text: &str) -> Result<(String, String, u16), HttpsGetError> {
    if text.is_empty()
        || text.len() > MAX_HTTPS_URL_BYTES
        || !text.is_ascii()
        || text.bytes().any(|b| b <= b' ' || b >= 0x7f)
        || text.contains(['%', '\\', '#'])
        || !text.starts_with("https://")
    {
        return Err(HttpsGetError::new("invalid_url"));
    }
    let url = reqwest::Url::parse(text).map_err(|_| HttpsGetError::new("invalid_url"))?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.as_str() != text
    {
        return Err(HttpsGetError::new("noncanonical_url"));
    }
    let host = url
        .host_str()
        .ok_or_else(|| HttpsGetError::new("invalid_host"))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let literal = host.parse::<IpAddr>();
    if literal.is_err()
        && (host.ends_with('.')
            || (!host.contains('.') && host != "localhost")
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }))
    {
        return Err(HttpsGetError::new("invalid_host"));
    }
    let port = url
        .port_or_known_default()
        .filter(|port| *port != 0)
        .ok_or_else(|| HttpsGetError::new("invalid_port"))?;
    Ok((text.to_owned(), host, port))
}

impl HttpsGetAuthority {
    /// Validate the closed configuration without DNS or HTTP effects.
    pub fn validate(&self) -> Result<(), HttpsGetError> {
        let (_, host, port) = canonical_url(&self.exact_url)?;
        let [address] = self.approved_addresses.as_slice() else {
            return Err(HttpsGetError::new("unsupported_address_count"));
        };
        if let Ok(literal) = host.parse::<IpAddr>() {
            if literal != *address {
                return Err(HttpsGetError::new("address_substitution"));
            }
        }
        if let Some(exception) = &self.private_endpoint {
            if exception.host != host || exception.port != port || exception.address != *address {
                return Err(HttpsGetError::new("invalid_private_exception"));
            }
            // Disposable private fixtures may use RFC1918/loopback or IPv6
            // loopback/ULA. Metadata/link-local and other reserved ranges
            // remain unsupported even with an exact operator exception.
            if !exception_address_supported(*address) {
                return Err(HttpsGetError::new("unsupported_exception_address"));
            }
        } else if !is_public_address(*address) || reserved_hostname(&host) {
            return Err(HttpsGetError::new("forbidden_address"));
        }
        if let Some(pem) = &self.root_certificate_pem {
            if pem.is_empty() || pem.len() > MAX_HTTPS_ROOT_PEM_BYTES {
                return Err(HttpsGetError::new("invalid_root_certificate"));
            }
            reqwest::Certificate::from_pem(pem.as_bytes())
                .map_err(|_| HttpsGetError::new("invalid_root_certificate"))?;
        }
        Ok(())
    }

    /// Bind all exact authority, including private exception and trust root.
    pub fn executor_id(&self) -> Result<String, HttpsGetError> {
        self.validate()?;
        let bytes = serde_json::to_vec(&(executor_profile_sha256(), self))
            .map_err(|_| HttpsGetError::new("invalid_authority"))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
}

/// Versioned semantic identity. The fixed limits, address filters and transport
/// contract of this module belong to `/1`; changing them requires a new profile.
pub fn executor_profile_sha256() -> String {
    format!("{:x}", Sha256::digest(EXECUTOR_PROFILE.as_bytes()))
}

/// An immutable one-use execution capability. It confers no native Allow;
/// callers must finish admission/release and cancellation checks first.
pub struct PreparedHttpsGet {
    #[cfg(target_os = "linux")]
    authority: HttpsGetAuthority,
    #[cfg(target_os = "linux")]
    host: String,
    #[cfg(target_os = "linux")]
    port: u16,
    #[cfg(target_os = "linux")]
    tls_config: Arc<rustls::ClientConfig>,
}

impl fmt::Debug for PreparedHttpsGet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedHttpsGet").finish_non_exhaustive()
    }
}

impl PreparedHttpsGet {
    /// Validate exact authority, resolve current DNS, and pin the connector.
    /// This performs no HTTP request and opens no target TCP connection.
    pub async fn prepare(
        authority: &HttpsGetAuthority,
        original_url: &str,
    ) -> Result<Self, HttpsGetError> {
        authority.validate()?;
        if original_url != authority.exact_url {
            return Err(HttpsGetError::new("url_substitution"));
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(HttpsGetError::new("unsupported_platform"))
        }
        #[cfg(target_os = "linux")]
        {
            let (_, host, port) = canonical_url(original_url)?;
            verify_current_addresses(&host, port, &authority.approved_addresses).await?;
            let tls_config = tls_configuration(authority.root_certificate_pem.as_deref())?;
            Ok(Self {
                authority: authority.clone(),
                host,
                port,
                tls_config: Arc::new(tls_config),
            })
        }
    }

    /// Consume the capability and issue at most one GET. Cancellation drops
    /// the request future; no detached task can continue execution.
    pub async fn execute(self) -> Result<HttpsGetResult, HttpsGetError> {
        #[cfg(not(target_os = "linux"))]
        {
            Err(HttpsGetError::new("unsupported_platform"))
        }
        #[cfg(target_os = "linux")]
        {
            let mut request_issued = false;
            let outcome = tokio::time::timeout(
                Duration::from_secs(HTTPS_TOTAL_TIMEOUT_SECS),
                async {
                    // The complete dispatch deadline includes current DNS,
                    // connect, TLS verification, write and complete body read.
                    self.authority.validate()?;
                    verify_current_addresses(&self.host, self.port, &self.authority.approved_addresses)
                        .await?;
                    let expected = SocketAddr::new(self.authority.approved_addresses[0], self.port);
                    let socket = tokio::time::timeout(
                        Duration::from_secs(HTTPS_CONNECT_TIMEOUT_SECS),
                        tokio::net::TcpStream::connect(expected),
                    )
                    .await
                    .map_err(|_| HttpsGetError::new("connect_timeout"))?
                    .map_err(|_| HttpsGetError::new("connect_failed"))?;
                    if socket.peer_addr().ok() != Some(expected) {
                        return Err(HttpsGetError::new("peer_substitution"));
                    }
                    let encrypted_count = Arc::new(AtomicUsize::new(0));
                    let counted = CountedSocket {
                        socket,
                        received: encrypted_count.clone(),
                    };
                    let server_name = rustls_pki_types::ServerName::try_from(self.host.clone())
                        .map_err(|_| HttpsGetError::new("invalid_tls_identity"))?;
                    let mut stream = tokio_rustls::TlsConnector::from(self.tls_config)
                        .connect(server_name, counted)
                        .await
                        .map_err(|_| HttpsGetError::new(if encrypted_count.load(Ordering::Relaxed) >= MAX_HTTPS_ENCRYPTED_BYTES {
                            "encrypted_response_limit"
                        } else {
                            "tls_verification_failed"
                        }))?;
                    let after_scheme = self.authority.exact_url.strip_prefix("https://")
                        .ok_or_else(|| HttpsGetError::new("invalid_url"))?;
                    let (host_header, target) = after_scheme.split_once('/')
                        .ok_or_else(|| HttpsGetError::new("invalid_url"))?;
                    let request = format!(
                        "GET /{target} HTTP/1.1\r\nHost: {host_header}\r\nAccept: text/plain, application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
                    );
                    // No HTTP bytes are written until ordinary certificate,
                    // hostname and expiry verification has completed.
                    request_issued = true;
                    stream.write_all(request.as_bytes()).await
                        .map_err(|_| HttpsGetError::issued("request_write_failed"))?;
                    stream.flush().await
                        .map_err(|_| HttpsGetError::issued("request_write_failed"))?;
                    let (content_type, bytes, received_http_bytes) = read_response(&mut stream).await?;
                    let text = String::from_utf8(bytes)
                        .map_err(|_| HttpsGetError::issued("invalid_response_utf8"))?;
                    if content_type == "application/json" {
                        serde_json::from_str::<serde_json::Value>(&text)
                            .map_err(|_| HttpsGetError::issued("invalid_response_json"))?;
                    }
                    Ok(HttpsGetResult {
                        status: 200,
                        received_bytes: text.len(),
                        received_encrypted_bytes: encrypted_count.load(Ordering::Relaxed),
                        received_http_bytes,
                        content_type,
                        text,
                        request_issued: true,
                    })
                },
            ).await;
            outcome.map_err(|_| HttpsGetError {
                code: "request_timeout",
                request_issued,
            })?
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn supported_content_type(headers: &reqwest::header::HeaderMap) -> Result<String, HttpsGetError> {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let value = values
        .next()
        .filter(|_| values.next().is_none())
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| HttpsGetError::issued("unsupported_content_type"))?;
    let mut parts = value.split(';').map(str::trim);
    let mime = parts.next().unwrap_or_default();
    if mime != "text/plain" && mime != "application/json" {
        return Err(HttpsGetError::issued("unsupported_content_type"));
    }
    match (parts.next(), parts.next()) {
        (None, None) | (Some("charset=utf-8"), None) => Ok(mime.to_owned()),
        _ => Err(HttpsGetError::issued("unsupported_content_type")),
    }
}

#[cfg(target_os = "linux")]
fn tls_configuration(pem: Option<&str>) -> Result<rustls::ClientConfig, HttpsGetError> {
    use rustls_pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(pem) = pem {
        let mut count = 0;
        for certificate in rustls_pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()) {
            let certificate =
                certificate.map_err(|_| HttpsGetError::new("invalid_root_certificate"))?;
            roots
                .add(certificate)
                .map_err(|_| HttpsGetError::new("invalid_root_certificate"))?;
            count += 1;
        }
        if count == 0 {
            return Err(HttpsGetError::new("invalid_root_certificate"));
        }
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| HttpsGetError::new("tls_configuration"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config.enable_early_data = false;
    config.resumption = rustls::client::Resumption::disabled();
    Ok(config)
}

/// Count encrypted reads including the handshake before TLS can read ahead.
/// The caller provides one exact socket; there is no hostname connect API,
/// proxy layer, redirect path, connection pool, or retry mechanism.
#[cfg(target_os = "linux")]
struct CountedSocket {
    socket: tokio::net::TcpStream,
    received: Arc<AtomicUsize>,
}

#[cfg(target_os = "linux")]
impl AsyncRead for CountedSocket {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let remaining =
            MAX_HTTPS_ENCRYPTED_BYTES.saturating_sub(this.received.load(Ordering::Relaxed));
        if remaining == 0 {
            return Poll::Ready(Err(io::Error::other("encrypted response limit")));
        }
        let limit = remaining.min(buf.remaining());
        let mut limited = ReadBuf::new(buf.initialize_unfilled_to(limit));
        match Pin::new(&mut this.socket).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                let read = limited.filled().len();
                this.received.fetch_add(read, Ordering::Relaxed);
                buf.advance(read);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

#[cfg(target_os = "linux")]
impl AsyncWrite for CountedSocket {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().socket).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().socket).poll_shutdown(cx)
    }
}

#[cfg(target_os = "linux")]
async fn read_response<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<(String, Vec<u8>, usize), HttpsGetError> {
    let mut received = Vec::with_capacity(MAX_HTTPS_HTTP_BYTES);
    let mut scratch = [0u8; 1024];
    let header_end = loop {
        if let Some(position) = received.windows(4).position(|part| part == b"\r\n\r\n") {
            let end = position + 4;
            if end > MAX_HTTPS_HEADER_BYTES {
                return Err(HttpsGetError::issued("response_headers_too_large"));
            }
            break end;
        }
        if received.len() >= MAX_HTTPS_HEADER_BYTES {
            return Err(HttpsGetError::issued("response_headers_too_large"));
        }
        let read = stream
            .read(&mut scratch)
            .await
            .map_err(|_| HttpsGetError::issued("response_read_failed"))?;
        if read == 0 {
            return Err(HttpsGetError::issued("incomplete_response_headers"));
        }
        received.extend_from_slice(&scratch[..read]);
    };
    let (content_type, length) = parse_response_head(&received[..header_end])?;
    let expected = header_end
        .checked_add(length)
        .filter(|total| *total <= MAX_HTTPS_HTTP_BYTES)
        .ok_or_else(|| HttpsGetError::issued("response_too_large"))?;
    if received.len() > expected {
        return Err(HttpsGetError::issued("unexpected_response_bytes"));
    }
    while received.len() < expected {
        let limit = (expected - received.len()).min(scratch.len());
        let read = stream
            .read(&mut scratch[..limit])
            .await
            .map_err(|_| HttpsGetError::issued("response_read_failed"))?;
        if read == 0 {
            return Err(HttpsGetError::issued("incomplete_response_body"));
        }
        received.extend_from_slice(&scratch[..read]);
    }
    let body = received[header_end..].to_vec();
    Ok((content_type, body, received.len()))
}

#[cfg(any(target_os = "linux", test))]
fn parse_response_head(bytes: &[u8]) -> Result<(String, usize), HttpsGetError> {
    let mut header_slots = [httparse::EMPTY_HEADER; 32];
    let mut response = httparse::Response::new(&mut header_slots);
    let parsed = response
        .parse(bytes)
        .map_err(|_| HttpsGetError::issued("invalid_response_headers"))?;
    if parsed != httparse::Status::Complete(bytes.len()) || response.version != Some(1) {
        return Err(HttpsGetError::issued("unsupported_http_response"));
    }
    let status = response.code.unwrap_or_default();
    if status != 200 {
        return Err(HttpsGetError::issued(if (300..400).contains(&status) {
            "redirect_refused"
        } else {
            "unsupported_status"
        }));
    }
    let mut length = None;
    let mut content_types = reqwest::header::HeaderMap::new();
    for header in response.headers {
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(HttpsGetError::issued("unsupported_transfer_encoding"));
        }
        if header.name.eq_ignore_ascii_case("content-encoding") {
            return Err(HttpsGetError::issued("unsupported_content_encoding"));
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            if length.is_some()
                || header.value.is_empty()
                || !header.value.iter().all(u8::is_ascii_digit)
                || (header.value.len() > 1 && header.value[0] == b'0')
            {
                return Err(HttpsGetError::issued("invalid_content_length"));
            }
            length = Some(
                std::str::from_utf8(header.value)
                    .ok()
                    .and_then(|text| text.parse::<usize>().ok())
                    .ok_or_else(|| HttpsGetError::issued("invalid_content_length"))?,
            );
        }
        if header.name.eq_ignore_ascii_case("content-type") {
            content_types.append(
                CONTENT_TYPE,
                reqwest::header::HeaderValue::from_bytes(header.value)
                    .map_err(|_| HttpsGetError::issued("unsupported_content_type"))?,
            );
        }
    }
    let length = length.ok_or_else(|| HttpsGetError::issued("missing_content_length"))?;
    if length > MAX_HTTPS_BODY_BYTES {
        return Err(HttpsGetError::issued("response_too_large"));
    }
    Ok((supported_content_type(&content_types)?, length))
}

#[cfg(target_os = "linux")]
async fn verify_current_addresses(
    host: &str,
    port: u16,
    approved: &[IpAddr],
) -> Result<(), HttpsGetError> {
    let mut current = if let Ok(literal) = host.parse::<IpAddr>() {
        vec![literal]
    } else {
        tokio::time::timeout(
            Duration::from_secs(HTTPS_CONNECT_TIMEOUT_SECS),
            tokio::net::lookup_host((host, port)),
        )
        .await
        .map_err(|_| HttpsGetError::new("dns_timeout"))?
        .map_err(|_| HttpsGetError::new("dns_failed"))?
        .map(|address| address.ip())
        .collect::<Vec<_>>()
    };
    verify_address_set(&mut current, approved)
}

#[cfg(any(target_os = "linux", test))]
fn verify_address_set(current: &mut Vec<IpAddr>, approved: &[IpAddr]) -> Result<(), HttpsGetError> {
    current.sort_unstable();
    current.dedup();
    if current.as_slice() != approved {
        return Err(HttpsGetError::new("dns_address_substitution"));
    }
    Ok(())
}

fn reserved_hostname(host: &str) -> bool {
    [
        "localhost",
        "local",
        "internal",
        "home.arpa",
        "invalid",
        "test",
    ]
    .iter()
    .any(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
}

fn exception_address_supported(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => address.is_loopback() || address.is_private(),
        IpAddr::V6(address) => address.is_loopback() || (address.segments()[0] & 0xfe00) == 0xfc00,
    }
}

/// Conservative public-unicast profile, intentionally denying special-purpose
/// ranges rather than treating `!is_private()` as sufficient egress authority.
pub fn is_public_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let n = u32::from(address);
            let denied = [
                (0x00000000, 8),  // this network
                (0x0a000000, 8),  // RFC1918
                (0x64400000, 10), // shared address space
                (0x7f000000, 8),  // loopback
                (0xa9fe0000, 16), // link-local and metadata
                (0xac100000, 12), // RFC1918
                (0xc0000000, 24), // protocol assignments
                (0xc0000200, 24), // documentation
                (0xc01fc400, 24), // AS112
                (0xc034c100, 24), // AMT
                (0xc0586300, 24), // deprecated 6to4 relay
                (0xc0a80000, 16), // RFC1918
                (0xc0af3000, 24), // AS112
                (0xc6120000, 15), // benchmark
                (0xc6336400, 24), // documentation
                (0xcb007100, 24), // documentation
                (0xe0000000, 4),  // multicast
                (0xf0000000, 4),  // reserved and limited broadcast
            ];
            !denied
                .iter()
                .any(|(base, bits)| n & (u32::MAX << (32 - bits)) == *base)
        }
        IpAddr::V6(address) => {
            let n = u128::from(address);
            let in_range =
                |base: Ipv6Addr, bits: u32| n & (u128::MAX << (128 - bits)) == u128::from(base);
            // Only the ordinary global-unicast allocation is supported. This
            // excludes mapped IPv4, NAT64, unique-local, link-local, multicast,
            // loopback and unspecified without ambiguous embedded addresses.
            in_range(Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0), 3)
                && !in_range(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23)
                && !in_range(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32)
                && !in_range(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16)
                && !in_range(Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20)
                && !in_range(Ipv6Addr::new(0x2620, 0x4f, 0x8000, 0, 0, 0, 0, 0), 48)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority(url: &str, address: &str) -> HttpsGetAuthority {
        HttpsGetAuthority {
            exact_url: url.to_owned(),
            approved_addresses: vec![address.parse().unwrap()],
            private_endpoint: None,
            root_certificate_pem: None,
        }
    }

    #[test]
    fn exact_url_scope_rejects_parser_and_authority_aliases() {
        for bad in [
            "http://example.com/",
            "HTTPS://example.com/",
            "https://EXAMPLE.com/",
            "https://example.com:443/",
            "https://example.com",
            "https://example.com./",
            "https://user:secret@example.com/",
            "https://@example.com/",
            "https://example.com/#fragment",
            "https://example.com/%2e%2e/secrets",
            "https://example.com/a/../b",
            "https://example.com/\\evil",
            "https://example.com/?key=%41",
            "https://example.com/white space",
            "https://example.com/\n",
            "https://éxample.com/",
            "https://127.1/",
            "https://2130706433/",
            "https://0x7f000001/",
            "https://example.com:0/",
        ] {
            assert!(canonical_url(bad).is_err(), "accepted {bad:?}");
        }
        assert_eq!(
            canonical_url("https://example.com:8443/document?item=7").unwrap(),
            (
                "https://example.com:8443/document?item=7".to_owned(),
                "example.com".to_owned(),
                8443
            )
        );
    }

    #[test]
    fn default_denies_private_reserved_and_embedded_addresses() {
        for address in [
            "0.1.2.3",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.9",
            "192.0.2.3",
            "192.168.1.1",
            "198.18.1.1",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
            "::",
            "::1",
            "::ffff:8.8.8.8",
            "64:ff9b::808:808",
            "fc00::1",
            "fe80::1",
            "ff02::1",
            "2001:db8::1",
            "2001::1",
            "2002:808:808::1",
            "3fff::1",
        ] {
            assert!(
                !is_public_address(address.parse().unwrap()),
                "allowed {address}"
            );
        }
        for address in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(
                is_public_address(address.parse().unwrap()),
                "denied {address}"
            );
        }
    }

    #[test]
    fn private_exception_is_exact_and_never_a_global_switch() {
        let mut a = authority("https://127.0.0.1:8443/document?item=7", "127.0.0.1");
        assert_eq!(a.validate().unwrap_err().code, "forbidden_address");
        a.private_endpoint = Some(PrivateEndpointException {
            host: "127.0.0.1".to_owned(),
            port: 8443,
            address: "127.0.0.1".parse().unwrap(),
        });
        assert!(a.validate().is_ok());
        for changed in [
            PrivateEndpointException {
                host: "localhost".to_owned(),
                ..a.private_endpoint.clone().unwrap()
            },
            PrivateEndpointException {
                port: 8444,
                ..a.private_endpoint.clone().unwrap()
            },
            PrivateEndpointException {
                address: "127.0.0.2".parse().unwrap(),
                ..a.private_endpoint.clone().unwrap()
            },
        ] {
            let mut substituted = a.clone();
            substituted.private_endpoint = Some(changed);
            assert_eq!(
                substituted.validate().unwrap_err().code,
                "invalid_private_exception"
            );
        }
    }

    #[test]
    fn authority_is_closed_and_identity_binds_all_fields() {
        let a = authority("https://example.com/document?item=7", "8.8.8.8");
        let id = a.executor_id().unwrap();
        let mut b = a.clone();
        b.exact_url = "https://example.com/document?item=8".to_owned();
        assert_ne!(id, b.executor_id().unwrap());
        b = a.clone();
        b.approved_addresses = vec!["1.1.1.1".parse().unwrap()];
        assert_ne!(id, b.executor_id().unwrap());
        b.approved_addresses.push("8.8.8.8".parse().unwrap());
        assert_eq!(b.validate().unwrap_err().code, "unsupported_address_count");
        let mut json = serde_json::to_value(a).unwrap();
        json["danger_accept_invalid_certs"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HttpsGetAuthority>(json).is_err());
        assert_eq!(executor_profile_sha256().len(), 64);
    }

    #[test]
    fn literal_addresses_cannot_override_the_url() {
        let a = authority("https://8.8.8.8/", "1.1.1.1");
        assert_eq!(a.validate().unwrap_err().code, "address_substitution");
        let a = authority("https://[2606:4700:4700::1111]/", "2606:4700:4700::1111");
        assert!(a.validate().is_ok());
    }

    #[test]
    fn response_scope_requires_one_explicit_utf8_text_or_json_type() {
        for accepted in [
            "text/plain",
            "text/plain; charset=utf-8",
            "application/json",
        ] {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(CONTENT_TYPE, accepted.parse().unwrap());
            assert!(supported_content_type(&headers).is_ok());
        }
        for refused in [
            "text/html",
            "application/octet-stream",
            "text/plain; charset=latin1",
            "application/json; charset=UTF-8",
            "text/plain; charset=utf-8; x=y",
        ] {
            let mut headers = reqwest::header::HeaderMap::new();
            headers.insert(CONTENT_TYPE, refused.parse().unwrap());
            assert_eq!(
                supported_content_type(&headers).unwrap_err().code,
                "unsupported_content_type"
            );
        }
        let mut headers = reqwest::header::HeaderMap::new();
        assert!(supported_content_type(&headers).is_err());
        headers.append(CONTENT_TYPE, "text/plain".parse().unwrap());
        headers.append(CONTENT_TYPE, "application/json".parse().unwrap());
        assert!(supported_content_type(&headers).is_err());
    }

    #[test]
    fn errors_do_not_disclose_endpoint_or_response() {
        let error = HttpsGetError::issued("request_failed");
        assert_eq!(
            error.to_string(),
            "constrained HTTPS GET refused: code=request_failed request_issued=true"
        );
        let a = authority("https://example.com/", "8.8.8.8");
        assert!(a.validate().is_ok());
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn non_linux_never_dispatches() {
        let a = authority("https://example.com/", "8.8.8.8");
        let error = PreparedHttpsGet::prepare(&a, &a.exact_url)
            .await
            .unwrap_err();
        assert_eq!(error.code, "unsupported_platform");
        assert!(!error.request_issued);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn dns_and_exact_arguments_refuse_before_http_effect() {
        let a = authority("https://localhost.test:8443/", "8.8.8.8");
        let error = PreparedHttpsGet::prepare(&a, &a.exact_url)
            .await
            .unwrap_err();
        assert_eq!(error.code, "forbidden_address");
        assert!(!error.request_issued);
        let a = authority("https://127.0.0.1:8443/", "127.0.0.1");
        let error = PreparedHttpsGet::prepare(&a, "https://127.0.0.1:8444/")
            .await
            .unwrap_err();
        assert!(!error.request_issued);
    }

    #[test]
    fn current_dns_must_equal_the_frozen_set() {
        let approved = ["8.8.8.8".parse().unwrap()];
        let mut same = vec![approved[0], approved[0]];
        assert!(verify_address_set(&mut same, &approved).is_ok());
        for mut changed in [
            vec![],
            vec!["1.1.1.1".parse().unwrap()],
            vec![approved[0], "1.1.1.1".parse().unwrap()],
            vec!["127.0.0.1".parse().unwrap()],
        ] {
            let error = verify_address_set(&mut changed, &approved).unwrap_err();
            assert_eq!(error.code, "dns_address_substitution");
            assert!(!error.request_issued);
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn encrypted_reads_are_capped_before_polling_the_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socket = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let writer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = stream
                .write_all(&vec![0u8; MAX_HTTPS_ENCRYPTED_BYTES + 4096])
                .await;
        });
        let received = Arc::new(AtomicUsize::new(0));
        let mut counted = CountedSocket {
            socket,
            received: received.clone(),
        };
        let mut bytes = Vec::new();
        assert!(counted.read_to_end(&mut bytes).await.is_err());
        assert_eq!(bytes.len(), MAX_HTTPS_ENCRYPTED_BYTES);
        assert_eq!(received.load(Ordering::Relaxed), MAX_HTTPS_ENCRYPTED_BYTES);
        drop(counted);
        writer.await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn preparation_and_substitution_do_not_open_a_target_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("https://127.0.0.1:{}/document?item=7", address.port());
        let mut a = authority(&url, "127.0.0.1");
        a.private_endpoint = Some(PrivateEndpointException {
            host: "127.0.0.1".to_owned(),
            port: address.port(),
            address: address.ip(),
        });
        let prepared = PreparedHttpsGet::prepare(&a, &url).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
        drop(prepared);
        let replaced = url.replace("item=7", "item=8");
        let error = PreparedHttpsGet::prepare(&a, &replaced).await.unwrap_err();
        assert_eq!(error.code, "url_substitution");
        assert!(!error.request_issued);
        assert!(
            tokio::time::timeout(Duration::from_millis(30), listener.accept())
                .await
                .is_err()
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn invalid_tls_is_refused_after_one_connection_attempt() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let url = format!("https://127.0.0.1:{}/", address.port());
        let mut a = authority(&url, "127.0.0.1");
        a.private_endpoint = Some(PrivateEndpointException {
            host: "127.0.0.1".to_owned(),
            port: address.port(),
            address: address.ip(),
        });
        let prepared = PreparedHttpsGet::prepare(&a, &url).await.unwrap();
        let receiver = tokio::spawn(async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            connection.write_all(b"not TLS").await.unwrap();
            connection.shutdown().await.unwrap();
            drop(connection);
            assert!(
                tokio::time::timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
        });
        let error = prepared.execute().await.unwrap_err();
        assert_eq!(error.code, "tls_verification_failed");
        assert!(!error.request_issued);
        receiver.await.unwrap();
    }

    #[test]
    fn strict_response_framing_refuses_unsupported_or_ambiguous_material() {
        let valid = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\n";
        assert_eq!(
            parse_response_head(valid).unwrap(),
            ("text/plain".to_owned(), 2)
        );
        for refused in [
            "HTTP/1.1 100 Continue\r\n\r\n",
            "HTTP/1.1 302 Found\r\nLocation: https://evil.test/\r\n\r\n",
            "HTTP/1.0 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 02\r\nContent-Type: text/plain\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length: 4097\r\nContent-Type: text/plain\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Encoding: identity\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\n",
        ] {
            assert!(parse_response_head(refused.as_bytes()).is_err(), "accepted {refused:?}");
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn complete_body_read_refuses_short_extra_and_oversized_headers() {
        let valid = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok";
        let mut input = valid.as_slice();
        let (mime, bytes, count) = read_response(&mut input).await.unwrap();
        assert_eq!(mime, "text/plain");
        assert_eq!(bytes, b"ok");
        assert_eq!(count, valid.len());
        let mut short = &valid[..valid.len() - 1];
        assert_eq!(
            read_response(&mut short).await.unwrap_err().code,
            "incomplete_response_body"
        );
        let mut extra = [valid.as_slice(), b"extra"].concat();
        assert_eq!(
            read_response(&mut extra.as_slice()).await.unwrap_err().code,
            "unexpected_response_bytes"
        );
        extra = [
            b"HTTP/1.1 200 OK\r\nX-Huge: ".as_slice(),
            &vec![b'x'; MAX_HTTPS_HEADER_BYTES],
        ]
        .concat();
        assert_eq!(
            read_response(&mut extra.as_slice()).await.unwrap_err().code,
            "response_headers_too_large"
        );
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn maximum_complete_body_is_accepted_without_truncation() {
        let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {MAX_HTTPS_BODY_BYTES}\r\nContent-Type: text/plain\r\n\r\n");
        let input = [header.as_bytes(), &vec![b'x'; MAX_HTTPS_BODY_BYTES]].concat();
        let (mime, body, received) = read_response(&mut input.as_slice()).await.unwrap();
        assert_eq!(mime, "text/plain");
        assert_eq!(body, vec![b'x'; MAX_HTTPS_BODY_BYTES]);
        assert_eq!(received, input.len());
        assert!(received <= MAX_HTTPS_HTTP_BYTES);
        let oversized = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n",
            MAX_HTTPS_BODY_BYTES + 1
        );
        assert_eq!(
            read_response(&mut oversized.as_bytes())
                .await
                .unwrap_err()
                .code,
            "response_too_large"
        );
    }

    #[test]
    fn metadata_and_special_ranges_cannot_use_private_fixture_exception() {
        for address in [
            "169.254.169.254",
            "198.18.0.1",
            "192.0.2.1",
            "8.8.8.8",
            "fe80::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                !exception_address_supported(address.parse().unwrap()),
                "accepted {address}"
            );
        }
        for address in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.1.2",
            "192.168.1.2",
            "::1",
            "fd00::1",
        ] {
            assert!(
                exception_address_supported(address.parse().unwrap()),
                "refused {address}"
            );
        }
        let a = authority("https://localhost/", "8.8.8.8");
        assert_eq!(a.validate().unwrap_err().code, "forbidden_address");
    }
}
