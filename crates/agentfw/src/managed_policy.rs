// SPDX-License-Identifier: Apache-2.0
//! SOU-30: versioned, pinned-issuer policy envelope.
//!
//! This module ONLY verifies a candidate. It must not mutate the running
//! firewall, accept a new trust key from the network, or acknowledge application.

use std::path::Path;

use anyhow::{bail, ensure, Context, Result};
use aws_lc_rs::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use soup_wall_agent::AgentPolicySet;

pub const SCHEMA_VERSION: u16 = 1;
pub const KEYRING_SCHEMA_VERSION: u32 = 1;
pub const MAX_BUNDLE_BYTES: usize = 96 * 1024;
pub const MAX_KEYRING_BYTES: usize = 64 * 1024;
pub const MAX_POLICY_BYTES: usize = 64 * 1024;
pub const MAX_TTL_SECS: i64 = 86_400;
const DOMAIN: &[u8] = b"soup-wall-agent-policy-bundle-v1\0";

/// Exact trust anchor, provisioned by the operator independently of Console.
/// Revocation takes effect even for an otherwise valid old signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedIssuerKey {
    pub key_id: String,
    pub public_key: [u8; 32],
    pub revoked: bool,
}

/// Versioned keyring document stored on disk.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyringStore {
    pub schema_version: u32,
    pub issuers: Vec<PinnedIssuerKeyEntry>,
}

/// Keyring entry as serialized/deserialized in operator-provisioned trusted-issuers.json.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PinnedIssuerKeyEntry {
    pub key_id: String,
    pub public_key_hex: String,
    #[serde(default)]
    pub revoked: bool,
}

/// The signature covers the ordered length-prefixed transcript of all fields
/// except signature_hex. The payload is the AgentPolicySet YAML, NOT the
/// Gateway's TenantPolicyDocument JSON.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAgentPolicy {
    pub schema_version: u16,
    pub tenant_id: String,
    pub agent_id: String,
    pub revision: String,
    pub deployment_sequence: u64,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub issuer_key_id: String,
    pub policy_yaml: String,
    pub policy_sha256: String,
    pub signature_hex: String,
}

/// Only a successfully parsed, signed and audience-bound payload reaches here.
#[derive(Debug)]
pub struct VerifiedAgentPolicy {
    pub revision: String,
    pub deployment_sequence: u64,
    pub policy_sha256: String,
    pub policy: AgentPolicySet,
}

fn put_field(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let len: u32 = bytes
        .len()
        .try_into()
        .context("policy transcript field too long")?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

impl SignedAgentPolicy {
    /// No JSON canonicalization ambiguities: sign these exact UTF-8 bytes in
    /// this order with a unique domain separator. All lengths are u32 BE.
    pub fn signing_transcript(&self) -> Result<Vec<u8>> {
        let mut out = DOMAIN.to_vec();
        put_field(&mut out, self.schema_version.to_string().as_bytes())?;
        put_field(&mut out, self.tenant_id.as_bytes())?;
        put_field(&mut out, self.agent_id.as_bytes())?;
        put_field(&mut out, self.revision.as_bytes())?;
        put_field(&mut out, self.deployment_sequence.to_string().as_bytes())?;
        put_field(&mut out, self.issued_at_unix.to_string().as_bytes())?;
        put_field(&mut out, self.expires_at_unix.to_string().as_bytes())?;
        put_field(&mut out, self.issuer_key_id.as_bytes())?;
        put_field(&mut out, self.policy_yaml.as_bytes())?;
        put_field(&mut out, self.policy_sha256.as_bytes())?;
        Ok(out)
    }
}

/// Ingress MUST call this before deserialization to cap attacker-controlled JSON.
pub fn parse_bounded(input: &[u8]) -> Result<SignedAgentPolicy> {
    ensure!(
        !input.is_empty() && input.len() <= MAX_BUNDLE_BYTES,
        "invalid policy bundle length"
    );
    serde_json::from_slice(input).context("invalid policy bundle JSON")
}

fn decode_fixed_hex<const N: usize>(text: &str) -> Result<[u8; N]> {
    ensure!(
        text.len() == N * 2 && text.is_ascii(),
        "invalid fixed-length hex"
    );
    let mut out = [0u8; N];
    for (index, item) in out.iter_mut().enumerate() {
        let offset = index * 2;
        let slice = &text.as_bytes()[offset..offset + 2];
        fn digit(c: u8) -> Result<u8> {
            match c {
                b'0'..=b'9' => Ok(c - b'0'),
                b'a'..=b'f' => Ok(c - b'a' + 10),
                _ => bail!("non-canonical lowercase hex"),
            }
        }
        *item = (digit(slice[0])? << 4) | digit(slice[1])?;
    }
    Ok(out)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0f) as usize] as char);
    }
    text
}

#[derive(Deserialize)]
#[serde(untagged)]
enum KeyringPayload {
    Versioned(KeyringStore),
    Raw(Vec<PinnedIssuerKeyEntry>),
}

/// Parse an operator-provisioned keyring containing one or more pinned issuer keys.
pub fn parse_keyring(input: &[u8]) -> Result<Vec<PinnedIssuerKey>> {
    ensure!(
        !input.is_empty() && input.len() <= MAX_KEYRING_BYTES,
        "invalid keyring length"
    );
    let payload: KeyringPayload = serde_json::from_slice(input).context("invalid keyring JSON")?;
    let entries = match payload {
        KeyringPayload::Versioned(store) => {
            ensure!(
                store.schema_version == KEYRING_SCHEMA_VERSION,
                "unsupported keyring schema_version {}; expected {}",
                store.schema_version,
                KEYRING_SCHEMA_VERSION
            );
            store.issuers
        }
        KeyringPayload::Raw(entries) => entries,
    };
    ensure!(
        !entries.is_empty(),
        "keyring must contain at least one issuer key"
    );
    ensure!(entries.len() <= 64, "excessive issuer keys in keyring");
    let mut keys = Vec::with_capacity(entries.len());
    let mut seen_ids = std::collections::HashSet::new();
    for entry in entries {
        ensure!(
            !entry.key_id.is_empty() && entry.key_id.len() <= 128,
            "invalid issuer key id in keyring"
        );
        ensure!(
            entry
                .key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')),
            "issuer key id contains invalid characters"
        );
        ensure!(
            seen_ids.insert(entry.key_id.clone()),
            "duplicate issuer key id in keyring"
        );
        let public_key = decode_fixed_hex::<32>(&entry.public_key_hex)
            .context("invalid public key hex in keyring")?;
        keys.push(PinnedIssuerKey {
            key_id: entry.key_id,
            public_key,
            revoked: entry.revoked,
        });
    }
    Ok(keys)
}

/// Serialize a list of pinned issuer keys to canonical versioned operator-provisioned keyring JSON.
pub fn serialize_keyring(keys: &[PinnedIssuerKey]) -> Result<Vec<u8>> {
    ensure!(!keys.is_empty(), "keyring cannot be empty");
    let issuers: Vec<PinnedIssuerKeyEntry> = keys
        .iter()
        .map(|k| PinnedIssuerKeyEntry {
            key_id: k.key_id.clone(),
            public_key_hex: hex_lower(&k.public_key),
            revoked: k.revoked,
        })
        .collect();
    let store = KeyringStore {
        schema_version: KEYRING_SCHEMA_VERSION,
        issuers,
    };
    let data = serde_json::to_vec_pretty(&store)?;
    ensure!(
        data.len() <= MAX_KEYRING_BYTES,
        "serialized keyring too large"
    );
    Ok(data)
}

/// Read an operator keyring file, bounding bytes read and refusing non-regular files.
pub fn read_keyring_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect keyring path {:?}", path))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "keyring path {:?} must not be a symlink",
        path
    );
    ensure!(
        metadata.is_file(),
        "keyring path {:?} must be a regular file",
        path
    );
    ensure!(
        metadata.len() <= MAX_KEYRING_BYTES as u64,
        "keyring file {:?} size {} exceeds maximum allowed {} bytes",
        path,
        metadata.len(),
        MAX_KEYRING_BYTES
    );
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("cannot open keyring file {:?}", path))?;
    use std::io::Read;
    let mut buffer = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take((MAX_KEYRING_BYTES + 1) as u64)
        .read_to_end(&mut buffer)
        .with_context(|| format!("cannot read keyring file {:?}", path))?;
    ensure!(
        buffer.len() <= MAX_KEYRING_BYTES,
        "keyring file content exceeds maximum allowed {} bytes",
        MAX_KEYRING_BYTES
    );
    Ok(buffer)
}

/// Verify independently pinned signer, exact tenant/Agent audience, bounded
/// expiry and monotonic sequence BEFORE interpreting the untrusted policy.
/// Caller must durably advance last_accepted_sequence only after successful
/// in-process activation; downloading/verifying is not an applied ack.
pub fn verify_candidate(
    bundle: &SignedAgentPolicy,
    keys: &[PinnedIssuerKey],
    expected_tenant: &str,
    expected_agent: &str,
    last_accepted_sequence: u64,
    now_unix: i64,
) -> Result<VerifiedAgentPolicy> {
    ensure!(
        bundle.schema_version == SCHEMA_VERSION,
        "unsupported policy schema"
    );
    ensure!(
        !expected_tenant.is_empty() && !expected_agent.is_empty(),
        "missing pinned audience"
    );
    ensure!(
        bundle.tenant_id == expected_tenant && bundle.agent_id == expected_agent,
        "wrong policy audience"
    );
    ensure!(
        !bundle.revision.is_empty() && bundle.revision.len() <= 128,
        "invalid policy revision"
    );
    ensure!(
        bundle.deployment_sequence > last_accepted_sequence,
        "replayed or stale policy deployment"
    );
    ensure!(
        bundle.issued_at_unix <= now_unix.saturating_add(60),
        "policy bundle issued in future"
    );
    ensure!(now_unix < bundle.expires_at_unix, "expired policy bundle");
    let lifetime = bundle
        .expires_at_unix
        .checked_sub(bundle.issued_at_unix)
        .context("invalid policy lifetime")?;
    ensure!(
        lifetime > 0 && lifetime <= MAX_TTL_SECS,
        "invalid policy lifetime"
    );
    ensure!(
        !bundle.policy_yaml.is_empty() && bundle.policy_yaml.len() <= MAX_POLICY_BYTES,
        "invalid Agent policy size"
    );
    ensure!(
        bundle.issuer_key_id.len() <= 128 && !bundle.issuer_key_id.is_empty(),
        "invalid issuer key id"
    );
    ensure!(
        bundle.tenant_id.len() <= 128 && bundle.agent_id.len() <= 128,
        "policy audience too long"
    );

    // A key supplied *inside* the signed envelope is never trusted. Trust roots
    // come from the Agent's local independently provisioned key list.
    let key = keys
        .iter()
        .find(|key| key.key_id == bundle.issuer_key_id)
        .context("unknown issuer signing key")?;
    ensure!(!key.revoked, "revoked issuer signing key");
    let actual_digest = hex_lower(&Sha256::digest(bundle.policy_yaml.as_bytes()));
    ensure!(
        bundle.policy_sha256 == actual_digest,
        "Agent policy digest mismatch"
    );

    let signature = decode_fixed_hex::<64>(&bundle.signature_hex)?;
    UnparsedPublicKey::new(&ED25519, key.public_key)
        .verify(&bundle.signing_transcript()?, &signature)
        .map_err(|_| anyhow::anyhow!("invalid Agent policy signature"))?;

    // The parser rejects unknown security fields and escalation defaults. Do
    // NOT map Gateway tenant model policies into this independent payload.
    let policy =
        AgentPolicySet::from_yaml(&bundle.policy_yaml).context("invalid AgentPolicySet YAML")?;
    Ok(VerifiedAgentPolicy {
        revision: bundle.revision.clone(),
        deployment_sequence: bundle.deployment_sequence,
        policy_sha256: actual_digest,
        policy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};

    fn fixture() -> (SignedAgentPolicy, PinnedIssuerKey) {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap();
        let yaml = "default: deny\n".to_string();
        let mut bundle = SignedAgentPolicy {
            schema_version: 1,
            tenant_id: "tenant-1".into(),
            agent_id: "agent-1".into(),
            revision: "approved-v1".into(),
            deployment_sequence: 1,
            issued_at_unix: 1000,
            expires_at_unix: 2000,
            issuer_key_id: "issuer-1".into(),
            policy_sha256: hex_lower(&Sha256::digest(yaml.as_bytes())),
            policy_yaml: yaml,
            signature_hex: String::new(),
        };
        bundle.signature_hex = hex_lower(pair.sign(&bundle.signing_transcript().unwrap()).as_ref());
        let key = PinnedIssuerKey {
            key_id: "issuer-1".into(),
            public_key: pair.public_key().as_ref().try_into().unwrap(),
            revoked: false,
        };
        (bundle, key)
    }

    fn verify(
        bundle: &SignedAgentPolicy,
        key: &PinnedIssuerKey,
        seq: u64,
    ) -> Result<VerifiedAgentPolicy> {
        verify_candidate(
            bundle,
            std::slice::from_ref(key),
            "tenant-1",
            "agent-1",
            seq,
            1500,
        )
    }

    #[test]
    fn valid_signed_agent_policy_is_verified() {
        let (bundle, key) = fixture();
        let result = verify(&bundle, &key, 0).unwrap();
        assert_eq!(result.revision, "approved-v1");
        assert_eq!(result.deployment_sequence, 1);
        assert_eq!(result.policy_sha256, bundle.policy_sha256);
    }

    #[test]
    fn rejects_policy_tampering() {
        let (mut bundle, key) = fixture();
        bundle.policy_yaml = "default: allow\n".into();
        assert!(verify(&bundle, &key, 0).is_err());
    }

    #[test]
    fn rejects_signed_metadata_tampering() {
        let (mut bundle, key) = fixture();
        bundle.revision = "approved-v2".into();
        assert!(verify(&bundle, &key, 0).is_err());
    }

    #[test]
    fn rejects_cross_tenant_or_agent() {
        let (bundle, key) = fixture();
        assert!(verify_candidate(
            &bundle,
            std::slice::from_ref(&key),
            "tenant-2",
            "agent-1",
            0,
            1500
        )
        .is_err());
        assert!(verify_candidate(
            &bundle,
            std::slice::from_ref(&key),
            "tenant-1",
            "agent-2",
            0,
            1500
        )
        .is_err());
    }

    #[test]
    fn rejects_replay_and_stale_sequence() {
        let (bundle, key) = fixture();
        assert!(verify(&bundle, &key, 1).is_err());
        assert!(verify(&bundle, &key, 4).is_err());
    }

    #[test]
    fn rejects_expiry_and_excessive_ttl() {
        let (mut bundle, key) = fixture();
        assert!(verify_candidate(
            &bundle,
            std::slice::from_ref(&key),
            "tenant-1",
            "agent-1",
            0,
            2000
        )
        .is_err());
        bundle.expires_at_unix = 1_000_000;
        assert!(verify(&bundle, &key, 0).is_err());
    }

    #[test]
    fn rejects_unknown_or_revoked_signing_key() {
        let (bundle, mut key) = fixture();
        key.key_id = "other".into();
        assert!(verify(&bundle, &key, 0).is_err());
        key.key_id = "issuer-1".into();
        key.revoked = true;
        assert!(verify(&bundle, &key, 0).is_err());
    }

    #[test]
    fn rejects_invalid_signature() {
        let (mut bundle, key) = fixture();
        bundle.signature_hex = "00".repeat(64);
        assert!(verify(&bundle, &key, 0).is_err());
    }

    #[test]
    fn rejects_unknown_fields_and_oversize_input() {
        let (bundle, _) = fixture();
        let mut json = serde_json::to_value(&bundle).unwrap();
        json["enforce"] = serde_json::json!(false);
        assert!(parse_bounded(&serde_json::to_vec(&json).unwrap()).is_err());
        assert!(parse_bounded(&vec![b'x'; MAX_BUNDLE_BYTES + 1]).is_err());
    }

    #[test]
    fn rejects_invalid_policy_yaml_even_with_valid_signature() {
        let (mut bundle, key) = fixture();
        let pair = Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).unwrap();
        bundle.policy_yaml = "default: escalate\n".into();
        bundle.policy_sha256 = hex_lower(&Sha256::digest(bundle.policy_yaml.as_bytes()));
        bundle.signature_hex = hex_lower(pair.sign(&bundle.signing_transcript().unwrap()).as_ref());
        assert!(verify(&bundle, &key, 0).is_err());
    }

    #[test]
    fn keyring_parse_and_serialize_round_trip() {
        let key1 = PinnedIssuerKey {
            key_id: "issuer-1".into(),
            public_key: [1u8; 32],
            revoked: false,
        };
        let key2 = PinnedIssuerKey {
            key_id: "issuer-2".into(),
            public_key: [2u8; 32],
            revoked: true,
        };
        let bytes = serialize_keyring(&[key1.clone(), key2.clone()]).unwrap();
        let parsed = parse_keyring(&bytes).unwrap();
        assert_eq!(parsed, vec![key1, key2]);
    }

    #[test]
    fn keyring_rejects_empty_or_invalid_entries() {
        assert!(parse_keyring(b"[]").is_err());
        assert!(parse_keyring(b"").is_err());
        assert!(parse_keyring(b"not json").is_err());
        // duplicate key_id
        let dup = serde_json::json!([
            {"key_id": "k1", "public_key_hex": "00".repeat(32)},
            {"key_id": "k1", "public_key_hex": "11".repeat(32)},
        ]);
        assert!(parse_keyring(&serde_json::to_vec(&dup).unwrap()).is_err());
        // invalid hex
        let bad_hex = serde_json::json!([
            {"key_id": "k1", "public_key_hex": "nothex"},
        ]);
        assert!(parse_keyring(&serde_json::to_vec(&bad_hex).unwrap()).is_err());
    }

    #[test]
    fn multi_key_verification_supports_rotation_and_revocation() {
        let pair1 = Ed25519KeyPair::from_seed_unchecked(&[1u8; 32]).unwrap();
        let pair2 = Ed25519KeyPair::from_seed_unchecked(&[2u8; 32]).unwrap();
        let yaml = "default: deny\n".to_string();

        let make_bundle = |pair: &Ed25519KeyPair, issuer_id: &str, seq: u64| {
            let mut b = SignedAgentPolicy {
                schema_version: 1,
                tenant_id: "tenant-1".into(),
                agent_id: "agent-1".into(),
                revision: format!("rev-{seq}"),
                deployment_sequence: seq,
                issued_at_unix: 1000,
                expires_at_unix: 2000,
                issuer_key_id: issuer_id.into(),
                policy_sha256: hex_lower(&Sha256::digest(yaml.as_bytes())),
                policy_yaml: yaml.clone(),
                signature_hex: String::new(),
            };
            b.signature_hex = hex_lower(pair.sign(&b.signing_transcript().unwrap()).as_ref());
            b
        };

        let bundle1 = make_bundle(&pair1, "issuer-1", 1);
        let bundle2 = make_bundle(&pair2, "issuer-2", 2);

        // Keyring with both keys active
        let keys = vec![
            PinnedIssuerKey {
                key_id: "issuer-1".into(),
                public_key: pair1.public_key().as_ref().try_into().unwrap(),
                revoked: false,
            },
            PinnedIssuerKey {
                key_id: "issuer-2".into(),
                public_key: pair2.public_key().as_ref().try_into().unwrap(),
                revoked: false,
            },
        ];

        // Both verify successfully
        assert!(verify_candidate(&bundle1, &keys, "tenant-1", "agent-1", 0, 1500).is_ok());
        assert!(verify_candidate(&bundle2, &keys, "tenant-1", "agent-1", 1, 1500).is_ok());

        // Revoke issuer-1
        let keys_revoked = vec![
            PinnedIssuerKey {
                key_id: "issuer-1".into(),
                public_key: pair1.public_key().as_ref().try_into().unwrap(),
                revoked: true,
            },
            PinnedIssuerKey {
                key_id: "issuer-2".into(),
                public_key: pair2.public_key().as_ref().try_into().unwrap(),
                revoked: false,
            },
        ];

        // Bundle from issuer-1 is rejected as revoked
        let err =
            verify_candidate(&bundle1, &keys_revoked, "tenant-1", "agent-1", 0, 1500).unwrap_err();
        assert!(err.to_string().contains("revoked issuer signing key"));

        // Bundle from issuer-2 continues to succeed
        assert!(verify_candidate(&bundle2, &keys_revoked, "tenant-1", "agent-1", 1, 1500).is_ok());
    }

    #[test]
    fn keyring_versioned_format_supports_schema_version_and_denies_unknown_fields() {
        // Valid versioned keyring
        let valid = serde_json::json!({
            "schema_version": 1,
            "issuers": [
                {"key_id": "k1", "public_key_hex": "00".repeat(32), "revoked": false}
            ]
        });
        let parsed = parse_keyring(&serde_json::to_vec(&valid).unwrap()).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].key_id, "k1");

        // Unsupported schema version
        let bad_ver = serde_json::json!({
            "schema_version": 2,
            "issuers": [
                {"key_id": "k1", "public_key_hex": "00".repeat(32)}
            ]
        });
        assert!(parse_keyring(&serde_json::to_vec(&bad_ver).unwrap()).is_err());

        // Unknown fields at root rejected
        let unknown_root = serde_json::json!({
            "schema_version": 1,
            "issuers": [
                {"key_id": "k1", "public_key_hex": "00".repeat(32)}
            ],
            "extra_field": "disallowed"
        });
        assert!(parse_keyring(&serde_json::to_vec(&unknown_root).unwrap()).is_err());

        // Unknown fields in issuer entry rejected
        let unknown_entry = serde_json::json!({
            "schema_version": 1,
            "issuers": [
                {"key_id": "k1", "public_key_hex": "00".repeat(32), "unknown": 123}
            ]
        });
        assert!(parse_keyring(&serde_json::to_vec(&unknown_entry).unwrap()).is_err());
    }

    #[test]
    fn read_keyring_file_enforces_bounds_and_regular_file() {
        let temp = tempfile::tempdir().unwrap();
        let valid_path = temp.path().join("trusted-issuers.json");
        let valid = serde_json::json!({
            "schema_version": 1,
            "issuers": [
                {"key_id": "k1", "public_key_hex": "00".repeat(32)}
            ]
        });
        std::fs::write(&valid_path, serde_json::to_vec(&valid).unwrap()).unwrap();
        assert!(read_keyring_file(&valid_path).is_ok());

        // Refuses directory
        let dir_path = temp.path().join("dir");
        std::fs::create_dir(&dir_path).unwrap();
        assert!(read_keyring_file(&dir_path).is_err());

        // Refuses missing file
        let missing = temp.path().join("missing.json");
        assert!(read_keyring_file(&missing).is_err());

        // Refuses oversized file (> 64 KiB)
        let large_path = temp.path().join("large.json");
        std::fs::write(&large_path, vec![b' '; MAX_KEYRING_BYTES + 1]).unwrap();
        assert!(read_keyring_file(&large_path).is_err());
    }
}
