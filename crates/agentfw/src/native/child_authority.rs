// SPDX-License-Identifier: Apache-2.0
//! Authenticated child authority bound to a host session and MCP server.
//!
//! Only the trusted issuer may hold the daemon token or derived key. Grants are
//! reusable until expiry; nonce consumption and tool enforcement belong to the
//! caller. Decoding alone does not authenticate a token.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

pub const CHILD_AUTHORITY_CONTRACT: &str = "sw-child-authority/1";

// Match the approval grant's tolerance for issuer clock jitter.
const FUTURE_SKEW_MS: u64 = 5_000;
type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildAuthorityGrant {
    pub contract_version: String,
    pub host_session: String,
    pub server_id: String,
    pub granted_tools: Vec<String>,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
    pub nonce: String,
    /// Unpadded base64url HMAC-SHA256 over all preceding fields.
    pub signature: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildAuthorityError {
    BadSignature,
    Expired,
    NotYetValid,
    HostSessionMismatch,
    ServerIdMismatch,
    InvalidContract,
    MalformedToken,
}

impl ChildAuthorityError {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::BadSignature => "child authority signature does not verify",
            Self::Expired => "child authority has expired",
            Self::NotYetValid => "child authority is dated in the future",
            Self::HostSessionMismatch => "child authority host session does not match",
            Self::ServerIdMismatch => "child authority server id does not match",
            Self::InvalidContract => "child authority contract is invalid",
            Self::MalformedToken => "child authority token is malformed",
        }
    }
}

/// Derive a separate signing key using the daemon token as the HMAC key.
/// Anyone holding the daemon token can derive this key and mint grants.
pub fn derive_key(daemon_token: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(daemon_token.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(b"agentfw/child-authority-key/v1\0");
    mac.finalize().into_bytes().to_vec()
}

fn field(mac: &mut HmacSha256, bytes: &[u8]) {
    mac.update(&(bytes.len() as u64).to_be_bytes());
    mac.update(bytes);
}

fn sign(key: &[u8], grant: &ChildAuthorityGrant) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(b"agentfw/child-authority-signature/v1\0");
    field(&mut mac, grant.contract_version.as_bytes());
    field(&mut mac, grant.host_session.as_bytes());
    field(&mut mac, grant.server_id.as_bytes());
    // The count prevents tools from absorbing a subsequent field. Each tool
    // has its own length, so neither separators nor empty strings are ambiguous.
    mac.update(&(grant.granted_tools.len() as u64).to_be_bytes());
    for tool in &grant.granted_tools {
        field(&mut mac, tool.as_bytes());
    }
    field(&mut mac, &grant.issued_at_ms.to_be_bytes());
    field(&mut mac, &grant.expires_at_ms.to_be_bytes());
    field(&mut mac, grant.nonce.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// Mint a grant with an exclusive expiry. Overflow saturates at `u64::MAX`.
pub fn mint(
    key: &[u8],
    host_session: &str,
    server_id: &str,
    granted_tools: &[String],
    issued_at_ms: u64,
    ttl_ms: u64,
    nonce: String,
) -> ChildAuthorityGrant {
    let mut grant = ChildAuthorityGrant {
        contract_version: CHILD_AUTHORITY_CONTRACT.into(),
        host_session: host_session.into(),
        server_id: server_id.into(),
        granted_tools: granted_tools.to_vec(),
        issued_at_ms,
        expires_at_ms: issued_at_ms.saturating_add(ttl_ms),
        nonce,
        signature: String::new(),
    };
    grant.signature = sign(key, &grant);
    grant
}

/// Authenticate before checking claims. Issuance tolerates at most five seconds
/// of future clock skew; expiry is exclusive and has no grace period.
pub fn verify(
    key: &[u8],
    grant: &ChildAuthorityGrant,
    host_session: &str,
    server_id: &str,
    now_ms: u64,
) -> Result<(), ChildAuthorityError> {
    let expected = sign(key, grant);
    if !bool::from(expected.as_bytes().ct_eq(grant.signature.as_bytes())) {
        return Err(ChildAuthorityError::BadSignature);
    }
    if grant.contract_version != CHILD_AUTHORITY_CONTRACT {
        return Err(ChildAuthorityError::InvalidContract);
    }
    if grant.expires_at_ms < grant.issued_at_ms {
        return Err(ChildAuthorityError::MalformedToken);
    }
    if grant.issued_at_ms > now_ms.saturating_add(FUTURE_SKEW_MS) {
        return Err(ChildAuthorityError::NotYetValid);
    }
    if now_ms >= grant.expires_at_ms {
        return Err(ChildAuthorityError::Expired);
    }
    if grant.host_session != host_session {
        return Err(ChildAuthorityError::HostSessionMismatch);
    }
    if grant.server_id != server_id {
        return Err(ChildAuthorityError::ServerIdMismatch);
    }
    Ok(())
}

pub fn encode_token(grant: &ChildAuthorityGrant) -> String {
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(grant).expect("grant fields serialize"))
}

/// Parse untrusted wire data; use [`verify_token`] to authenticate its claims.
pub fn decode_token(token: &str) -> Result<ChildAuthorityGrant, ChildAuthorityError> {
    let json = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|_| ChildAuthorityError::MalformedToken)?;
    serde_json::from_slice(&json).map_err(|_| ChildAuthorityError::MalformedToken)
}

pub fn verify_token(
    key: &[u8],
    token: &str,
    host_session: &str,
    server_id: &str,
    now_ms: u64,
) -> Result<ChildAuthorityGrant, ChildAuthorityError> {
    let grant = decode_token(token)?;
    verify(key, &grant, host_session, server_id, now_ms)?;
    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Vec<u8>, ChildAuthorityGrant) {
        let key = derive_key("test-only-daemon-token");
        let grant = mint(
            &key,
            "host",
            "server",
            &["read".into(), "search".into()],
            10_000,
            20_000,
            "test-nonce".into(),
        );
        (key, grant)
    }

    #[test]
    fn token_round_trip_and_verification() {
        let (key, grant) = fixture();
        let token = encode_token(&grant);
        assert!(token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)));
        assert_eq!(decode_token(&token), Ok(grant.clone()));
        assert_eq!(
            verify_token(&key, &token, "host", "server", 10_000),
            Ok(grant.clone())
        );
        assert_eq!(verify(&key, &grant, "host", "server", 29_999), Ok(()));
    }

    #[test]
    fn key_derivation_known_vector_and_separation() {
        // Independently generated HMAC-SHA256 vector (key = daemon token).
        let key = derive_key("test-only-daemon-token");
        assert_eq!(
            key,
            [
                122, 238, 143, 186, 50, 216, 24, 83, 188, 103, 30, 85, 13, 117, 211, 180, 137, 130,
                65, 3, 16, 169, 104, 245, 196, 1, 87, 248, 207, 47, 83, 128
            ]
        );
        assert_eq!(key, derive_key("test-only-daemon-token"));
        assert_ne!(key, derive_key("other-token"));
        assert_ne!(key, crate::grant::derive_key("test-only-daemon-token"));
    }

    #[test]
    fn expiry_and_future_skew_boundaries() {
        let (key, grant) = fixture();
        assert_eq!(
            verify(&key, &grant, "host", "server", 30_000),
            Err(ChildAuthorityError::Expired)
        );
        assert_eq!(
            verify(&key, &grant, "host", "server", 30_001),
            Err(ChildAuthorityError::Expired)
        );
        assert_eq!(verify(&key, &grant, "host", "server", 5_000), Ok(()));
        assert_eq!(
            verify(&key, &grant, "host", "server", 4_999),
            Err(ChildAuthorityError::NotYetValid)
        );
        let zero = mint(&key, "host", "server", &[], 10_000, 0, "n".into());
        assert_eq!(
            verify(&key, &zero, "host", "server", 10_000),
            Err(ChildAuthorityError::Expired)
        );
        let overflow = mint(&key, "host", "server", &[], u64::MAX - 1, 10, "n".into());
        assert_eq!(overflow.expires_at_ms, u64::MAX);
        assert_eq!(
            verify(&key, &overflow, "host", "server", u64::MAX - 1),
            Ok(())
        );
        assert_eq!(
            verify(&key, &overflow, "host", "server", u64::MAX),
            Err(ChildAuthorityError::Expired)
        );
    }

    #[test]
    fn rejects_mismatched_authority_and_wrong_key() {
        let (key, grant) = fixture();
        for (host, server, error) in [
            ("other", "server", ChildAuthorityError::HostSessionMismatch),
            ("host", "other", ChildAuthorityError::ServerIdMismatch),
        ] {
            assert_eq!(
                verify_token(&key, &encode_token(&grant), host, server, 10_000),
                Err(error)
            );
        }
        assert_eq!(
            verify(b"wrong-key", &grant, "host", "server", 10_000),
            Err(ChildAuthorityError::BadSignature)
        );
    }

    #[test]
    fn every_claim_is_authenticated() {
        let (key, grant) = fixture();
        let original = serde_json::to_value(&grant).unwrap();
        for (field, value) in [
            ("contract_version", serde_json::json!("other")),
            ("host_session", serde_json::json!("other")),
            ("server_id", serde_json::json!("other")),
            ("granted_tools", serde_json::json!(["admin"])),
            ("issued_at_ms", serde_json::json!(11_000)),
            ("expires_at_ms", serde_json::json!(40_000)),
            ("nonce", serde_json::json!("other")),
            ("signature", serde_json::json!("")),
            (
                "signature",
                serde_json::json!("A".repeat(grant.signature.len())),
            ),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            let changed: ChildAuthorityGrant = serde_json::from_value(changed).unwrap();
            assert_eq!(
                verify(&key, &changed, "host", "server", 10_000),
                Err(ChildAuthorityError::BadSignature),
                "{field}"
            );
        }
    }

    #[test]
    fn rejects_authenticated_invalid_contract_and_interval() {
        let (key, mut grant) = fixture();
        grant.contract_version = "sw-child-authority/2".into();
        grant.signature = sign(&key, &grant);
        assert_eq!(
            verify(&key, &grant, "host", "server", 10_000),
            Err(ChildAuthorityError::InvalidContract)
        );
        grant.contract_version = CHILD_AUTHORITY_CONTRACT.into();
        grant.expires_at_ms = grant.issued_at_ms - 1;
        grant.signature = sign(&key, &grant);
        assert_eq!(
            verify(&key, &grant, "host", "server", 10_000),
            Err(ChildAuthorityError::MalformedToken)
        );
    }

    #[test]
    fn rejects_malformed_wire_data() {
        let (key, grant) = fixture();
        let json = serde_json::to_string(&grant).unwrap();
        let extra = json.replacen('{', "{\"unknown\":true,", 1);
        let duplicate = json.replacen('{', "{\"host_session\":\"spoof\",", 1);
        for token in [
            String::new(),
            "%%%".into(),
            URL_SAFE_NO_PAD.encode(b"not json"),
            URL_SAFE_NO_PAD.encode(b"{}"),
            URL_SAFE_NO_PAD.encode(b"null"),
            URL_SAFE_NO_PAD.encode(extra),
            URL_SAFE_NO_PAD.encode(duplicate),
            URL_SAFE_NO_PAD.encode(json.replace("10000", "-1")),
        ] {
            assert_eq!(
                decode_token(&token),
                Err(ChildAuthorityError::MalformedToken)
            );
            assert_eq!(
                verify_token(&key, &token, "host", "server", 10_000),
                Err(ChildAuthorityError::MalformedToken)
            );
        }
    }

    #[test]
    fn signing_boundaries_cannot_be_shifted() {
        let (key, grant) = fixture();
        let mut signatures = std::collections::BTreeSet::new();
        for (host, server, tools, nonce) in [
            ("ab", "c", vec!["read".into()], "n"),
            ("a", "bc", vec!["read".into()], "n"),
            ("host", "server", vec!["ab".into(), "c".into()], "n"),
            ("host", "server", vec!["a".into(), "bc".into()], "n"),
            ("host", "server", vec![], "n"),
            ("host", "server", vec!["".into()], "n"),
            ("host", "server", vec!["read\0search".into()], "n"),
            ("host", "server", vec!["read".into(), "search".into()], "n"),
        ] {
            let candidate = mint(
                &key,
                host,
                server,
                &tools,
                grant.issued_at_ms,
                20_000,
                nonce.into(),
            );
            assert!(signatures.insert(candidate.signature));
        }
        let tools = |items: &[&str]| items.iter().map(|s| (*s).into()).collect::<Vec<String>>();
        let issue = |host, server, items: Vec<String>| {
            mint(&key, host, server, &items, 10_000, 20_000, "n".into()).signature
        };
        assert_ne!(issue("ab", "c", tools(&[])), issue("a", "bc", tools(&[])));
        assert_ne!(
            issue("h", "s", tools(&["ab", "c"])),
            issue("h", "s", tools(&["a", "bc"]))
        );
        assert_ne!(issue("h", "s", tools(&[])), issue("h", "s", tools(&[""])));
    }

    #[test]
    fn concurrent_verification_keeps_session_bindings_isolated() {
        let (key, grant) = fixture();
        let token = encode_token(&grant);
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    assert_eq!(
                        verify_token(&key, &token, "host", "server", 10_000),
                        Ok(grant.clone())
                    );
                    assert_eq!(
                        verify_token(&key, &token, "spoof", "server", 10_000),
                        Err(ChildAuthorityError::HostSessionMismatch)
                    );
                });
            }
        });
    }

    #[test]
    fn reasons_are_distinct_and_nonempty() {
        let reasons = [
            ChildAuthorityError::BadSignature,
            ChildAuthorityError::Expired,
            ChildAuthorityError::NotYetValid,
            ChildAuthorityError::HostSessionMismatch,
            ChildAuthorityError::ServerIdMismatch,
            ChildAuthorityError::InvalidContract,
            ChildAuthorityError::MalformedToken,
        ]
        .map(|error| error.reason());
        assert!(reasons.iter().all(|reason| !reason.is_empty()));
        assert_eq!(
            reasons
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            7
        );
    }
}
