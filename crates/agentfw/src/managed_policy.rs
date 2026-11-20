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
/// SOU-241: the finite reason an Agent reports for rejecting a candidate,
/// attached at the exact failure boundary (`sw-agent-rejection-reason/1`
/// allowlist, mirrored by the Console). The human message stays local.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejection(pub &'static str);
impl std::fmt::Display for Rejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Rejection {}
pub fn rejected(code: &'static str, message: &'static str) -> anyhow::Error {
    anyhow::Error::new(Rejection(code)).context(message)
}
fn reject(condition: bool, code: &'static str, message: &'static str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(rejected(code, message))
    }
}
/// The reason code attached anywhere in an error chain, if any.
pub fn rejection_code(error: &anyhow::Error) -> Option<&'static str> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<Rejection>())
        .map(|r| r.0)
}

pub fn verify_candidate(
    bundle: &SignedAgentPolicy,
    keys: &[PinnedIssuerKey],
    expected_tenant: &str,
    expected_agent: &str,
    last_accepted_sequence: u64,
    now_unix: i64,
) -> Result<VerifiedAgentPolicy> {
    reject(
        bundle.schema_version == SCHEMA_VERSION,
        "schema_unsupported",
        "unsupported policy schema",
    )?;
    reject(
        !expected_tenant.is_empty() && !expected_agent.is_empty(),
        "audience_mismatch",
        "missing pinned audience",
    )?;
    reject(
        bundle.tenant_id == expected_tenant && bundle.agent_id == expected_agent,
        "audience_mismatch",
        "wrong policy audience",
    )?;
    reject(
        !bundle.revision.is_empty() && bundle.revision.len() <= 128,
        "bundle_malformed",
        "invalid policy revision",
    )?;
    reject(
        bundle.deployment_sequence > last_accepted_sequence,
        "sequence_stale",
        "replayed or stale policy deployment",
    )?;
    reject(
        bundle.issued_at_unix <= now_unix.saturating_add(60),
        "issued_in_future",
        "policy bundle issued in future",
    )?;
    reject(
        now_unix < bundle.expires_at_unix,
        "bundle_expired",
        "expired policy bundle",
    )?;
    let lifetime = bundle.expires_at_unix.checked_sub(bundle.issued_at_unix);
    reject(
        lifetime.is_some_and(|l| l > 0 && l <= MAX_TTL_SECS),
        "lifetime_invalid",
        "invalid policy lifetime",
    )?;
    reject(
        !bundle.policy_yaml.is_empty() && bundle.policy_yaml.len() <= MAX_POLICY_BYTES,
        "policy_too_large",
        "invalid Agent policy size",
    )?;
    reject(
        bundle.issuer_key_id.len() <= 128 && !bundle.issuer_key_id.is_empty(),
        "bundle_malformed",
        "invalid issuer key id",
    )?;
    reject(
        bundle.tenant_id.len() <= 128 && bundle.agent_id.len() <= 128,
        "bundle_malformed",
        "policy audience too long",
    )?;

    // A key supplied *inside* the signed envelope is never trusted. Trust roots
    // come from the Agent's local independently provisioned key list.
    let Some(key) = keys.iter().find(|key| key.key_id == bundle.issuer_key_id) else {
        return Err(rejected("issuer_key_unknown", "unknown issuer signing key"));
    };
    reject(
        !key.revoked,
        "issuer_key_revoked",
        "revoked issuer signing key",
    )?;
    let actual_digest = hex_lower(&Sha256::digest(bundle.policy_yaml.as_bytes()));
    reject(
        bundle.policy_sha256 == actual_digest,
        "digest_mismatch",
        "Agent policy digest mismatch",
    )?;

    let signature = decode_fixed_hex::<64>(&bundle.signature_hex)
        .map_err(|_| rejected("signature_invalid", "invalid Agent policy signature"))?;
    let transcript = bundle
        .signing_transcript()
        .map_err(|_| rejected("bundle_malformed", "invalid policy signing transcript"))?;
    UnparsedPublicKey::new(&ED25519, key.public_key)
        .verify(&transcript, &signature)
        .map_err(|_| rejected("signature_invalid", "invalid Agent policy signature"))?;

    // The parser rejects unknown security fields and escalation defaults. Do
    // NOT map Gateway tenant model policies into this independent payload.
    let policy = AgentPolicySet::from_yaml(&bundle.policy_yaml).map_err(|error| {
        rejected("policy_invalid", "invalid AgentPolicySet YAML")
            .context(error.to_string())
            .context("invalid AgentPolicySet YAML")
    })?;
    Ok(VerifiedAgentPolicy {
        revision: bundle.revision.clone(),
        deployment_sequence: bundle.deployment_sequence,
        policy_sha256: actual_digest,
        policy,
    })
}

#[cfg(test)]
mod tests;
