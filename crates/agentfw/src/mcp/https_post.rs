// SPDX-License-Identifier: Apache-2.0
//! Single-use, exact-body HTTPS POST. Cancellation never rolls back a receiver.
#[cfg(target_os = "linux")]
use super::https_get::{
    canonical_url, read_response, tls_configuration, verify_current_addresses, CountedSocket,
    HTTPS_CONNECT_TIMEOUT_SECS, HTTPS_TOTAL_TIMEOUT_SECS, MAX_HTTPS_ENCRYPTED_BYTES,
};
use super::https_get::{HttpsGetAuthority, HttpsGetError, HttpsGetResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
#[cfg(target_os = "linux")]
use std::{net::SocketAddr, sync::Arc, time::Duration};
#[cfg(target_os = "linux")]
use tokio::io::AsyncWriteExt;
#[cfg(target_os = "linux")]
use tokio_rustls::rustls;

pub const EXECUTOR_PROFILE: &str = "sw-native/https-post/linux-pinned/1";
pub const MAX_POST_BODY_BYTES: usize = 4096;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpsPostAuthority {
    pub endpoint: HttpsGetAuthority,
    pub content_type: String,
    pub max_body_bytes: usize,
}
impl HttpsPostAuthority {
    pub fn validate(&self) -> Result<(), HttpsGetError> {
        self.endpoint.validate()?;
        if !matches!(
            self.content_type.as_str(),
            "text/plain" | "application/json"
        ) || self.max_body_bytes != MAX_POST_BODY_BYTES
        {
            return Err(HttpsGetError::new("unsupported_post_authority"));
        }
        Ok(())
    }
    pub fn validate_body(&self, body: &str) -> Result<(), HttpsGetError> {
        self.validate()?;
        if body.len() > self.max_body_bytes {
            return Err(HttpsGetError::new("request_body_too_large"));
        }
        if self.content_type == "application/json"
            && serde_json::from_str::<serde_json::Value>(body).is_err()
        {
            return Err(HttpsGetError::new("invalid_request_json"));
        }
        Ok(())
    }
    pub fn executor_id(&self) -> Result<String, HttpsGetError> {
        self.validate()?;
        Ok(format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(EXECUTOR_PROFILE, self))
                    .map_err(|_| HttpsGetError::new("invalid_authority"))?
            )
        ))
    }
}
pub fn executor_profile_sha256() -> String {
    format!("{:x}", Sha256::digest(EXECUTOR_PROFILE.as_bytes()))
}

/// Survives dropping the execution future. Accepted bytes refer to the local
/// TLS writer, never proof of delivery. Only the independent receiver knows
/// whether the payload committed. There are no retries or detached workers.
#[derive(Default)]
pub struct PostProgress {
    attempted: AtomicBool,
    body_bytes_accepted: AtomicUsize,
    response_received: AtomicBool,
}
impl PostProgress {
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({"request_attempted":self.attempted.load(Ordering::SeqCst),
            "body_bytes_accepted_by_tls":self.body_bytes_accepted.load(Ordering::SeqCst),
            "response_received":self.response_received.load(Ordering::SeqCst),
            "receiver_observed":"unknown"})
    }
}

pub struct PreparedHttpsPost {
    #[cfg(target_os = "linux")]
    authority: HttpsPostAuthority,
    #[cfg(target_os = "linux")]
    body: String,
    #[cfg(target_os = "linux")]
    host: String,
    #[cfg(target_os = "linux")]
    port: u16,
    #[cfg(target_os = "linux")]
    tls_config: Arc<rustls::ClientConfig>,
}

impl fmt::Debug for PreparedHttpsPost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedHttpsPost").finish_non_exhaustive()
    }
}

impl PreparedHttpsPost {
    /// Validate exact authority, resolve current DNS, and pin the connector.
    /// This performs no HTTP request and opens no target TCP connection.
    pub async fn prepare(
        authority: &HttpsPostAuthority,
        original_url: &str,
        body: &str,
    ) -> Result<Self, HttpsGetError> {
        authority.validate_body(body)?;
        if original_url != authority.endpoint.exact_url {
            return Err(HttpsGetError::new("url_substitution"));
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(HttpsGetError::new("unsupported_platform"))
        }
        #[cfg(target_os = "linux")]
        {
            let (_, host, port) = canonical_url(original_url)?;
            verify_current_addresses(&host, port, &authority.endpoint.approved_addresses).await?;
            let tls_config = tls_configuration(authority.endpoint.root_certificate_pem.as_deref())?;
            Ok(Self {
                authority: authority.clone(),
                body: body.to_owned(),
                host,
                port,
                tls_config: Arc::new(tls_config),
            })
        }
    }

    /// Consume the capability and issue at most one POST. Cancellation drops
    /// the request future; no detached task can continue execution.
    pub async fn execute(self, progress: &PostProgress) -> Result<HttpsGetResult, HttpsGetError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = progress;
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
                    verify_current_addresses(&self.host, self.port, &self.authority.endpoint.approved_addresses)
                        .await?;
                    let expected = SocketAddr::new(self.authority.endpoint.approved_addresses[0], self.port);
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
                    let after_scheme = self.authority.endpoint.exact_url.strip_prefix("https://")
                        .ok_or_else(|| HttpsGetError::new("invalid_url"))?;
                    let (host_header, target) = after_scheme.split_once('/')
                        .ok_or_else(|| HttpsGetError::new("invalid_url"))?;
                    let request = format!(
                        "POST /{target} HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccept: text/plain, application/json\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n", self.authority.content_type, self.body.len()
                    );
                    // No HTTP bytes are written until ordinary certificate,
                    // hostname and expiry verification has completed.
                    request_issued = true;
                    progress.attempted.store(true, Ordering::SeqCst);
                    stream.write_all(request.as_bytes()).await
                        .map_err(|_| HttpsGetError::issued("request_write_failed"))?;
                    let mut written = 0;
                    while written < self.body.len() {
                        let count = stream.write(&self.body.as_bytes()[written..]).await
                            .map_err(|_| HttpsGetError::issued("request_write_failed"))?;
                        if count == 0 { return Err(HttpsGetError::issued("request_write_failed")); }
                        written += count;
                        progress.body_bytes_accepted.store(written, Ordering::SeqCst);
                    }
                    stream.flush().await
                        .map_err(|_| HttpsGetError::issued("request_write_failed"))?;
                    let (content_type, bytes, received_http_bytes) = read_response(&mut stream).await?;
                    let text = String::from_utf8(bytes)
                        .map_err(|_| HttpsGetError::issued("invalid_response_utf8"))?;
                    if content_type == "application/json" {
                        serde_json::from_str::<serde_json::Value>(&text)
                            .map_err(|_| HttpsGetError::issued("invalid_response_json"))?;
                    }
                    progress.response_received.store(true, Ordering::SeqCst);
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

#[cfg(test)]
mod tests {
    use super::*;
    fn authority() -> HttpsPostAuthority {
        HttpsPostAuthority {
            endpoint: HttpsGetAuthority {
                exact_url: "https://example.com/inbox?item=7".into(),
                approved_addresses: vec!["93.184.216.34".parse().unwrap()],
                private_endpoint: None,
                root_certificate_pem: None,
            },
            content_type: "text/plain".into(),
            max_body_bytes: 4096,
        }
    }
    #[test]
    fn body_limit_counts_utf8_bytes_and_json_is_not_reserialized() {
        let mut a = authority();
        assert!(a.validate_body(&"a".repeat(4096)).is_ok());
        assert!(a.validate_body(&"a".repeat(4097)).is_err());
        assert!(a.validate_body(&"é".repeat(2048)).is_ok());
        assert!(a.validate_body(&"é".repeat(2049)).is_err());
        a.content_type = "application/json".into();
        assert!(a.validate_body("{\"a\": 1}\n").is_ok());
        assert!(a.validate_body("{unfinished").is_err());
    }
    #[test]
    fn operator_authority_is_closed_and_identifies_content_type() {
        let a = authority();
        let mut changed = a.clone();
        changed.content_type = "application/json".into();
        assert_ne!(a.executor_id().unwrap(), changed.executor_id().unwrap());
        changed.content_type = "text/plain\r\nAuthorization: unexpected".into();
        assert!(changed.validate().is_err());
        changed = a.clone();
        changed.max_body_bytes = 8192;
        assert!(changed.validate().is_err());
        changed = a.clone();
        changed.endpoint.approved_addresses = vec!["169.254.169.254".parse().unwrap()];
        assert!(changed.validate().is_err());
        let mut value = serde_json::to_value(a).unwrap();
        value["headers"] = serde_json::json!({"cookie":"unexpected"});
        assert!(serde_json::from_value::<HttpsPostAuthority>(value).is_err());
    }
    #[test]
    fn progress_never_infers_receiver_commit_from_local_write() {
        let progress = PostProgress::default();
        assert_eq!(progress.snapshot()["request_attempted"], false);
        progress.attempted.store(true, Ordering::SeqCst);
        progress.body_bytes_accepted.store(12, Ordering::SeqCst);
        assert_eq!(progress.snapshot()["receiver_observed"], "unknown");
        assert_eq!(progress.snapshot()["response_received"], false);
    }
}
