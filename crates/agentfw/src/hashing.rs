// SPDX-License-Identifier: Apache-2.0

//! The one in-memory SHA-256 helper for this crate.
//!
//! Identities throughout the agent (profiles, policies, plans, audit rows)
//! are the lowercase hexadecimal SHA-256 of exact bytes, with no prefix.
//! Callers that need a domain separator or canonical JSON build those bytes
//! first and hash them here, so every identity uses the same encoding.

use sha2::{Digest, Sha256};

/// Lowercase, unprefixed, 64-character hexadecimal SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::sha256_hex;

    #[test]
    fn matches_the_published_test_vectors() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn output_is_lowercase_unprefixed_hex() {
        let digest = sha256_hex(&[0xff; 100]);
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }
}
