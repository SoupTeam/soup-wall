// SPDX-License-Identifier: Apache-2.0

//! Helpers shared by the integration tests in this directory.
//!
//! Deliberately independent of `agentfw::hashing`: tests compute the digests
//! they expect without calling the code under test.

use sha2::{Digest, Sha256};

/// Lowercase, unprefixed hexadecimal SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
