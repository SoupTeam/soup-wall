// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! Rabin–Karp k-gram fingerprints with winnowing. Used by the taint tracker to
//! recognize untrusted content after it has been reformatted by a model.

use std::collections::BTreeSet;

/// Length of each hashed k-gram, in canonicalized bytes.
pub const K: usize = 32;
/// Winnowing window: one fingerprint is kept per window of this many k-grams.
pub const WINDOW: usize = 8;

const BASE: u64 = 257;
const MODULUS: u64 = (1 << 61) - 1;

/// Lowercase, collapse all whitespace runs to a single space, trim.
/// This is what makes a fingerprint survive an LLM re-wrapping the text.
fn canonicalize(text: &str) -> Vec<u8> {
    text.to_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .into_bytes()
}

/// Multiply two values modulo `MODULUS` without overflowing `u64`.
/// `MODULUS` is a 61-bit Mersenne prime, so both operands fit in 61 bits and
/// their product fits in 122 bits — well within `u128`, but far outside what
/// `u64::wrapping_mul` (which silently wraps mod 2^64, not mod `MODULUS`)
/// can represent correctly.
fn mul_mod(a: u64, b: u64) -> u64 {
    // 2^61 == 1 (mod MODULUS). Two folds cover even a full u64 product:
    // the first is <2^68 and the second <= MODULUS + 127. One subtraction
    // gives the exact same residue as u128 remainder, without its debug-build
    // division helper. No hash, normalization or detection threshold changes.
    let product = a as u128 * b as u128;
    let folded = (product & MODULUS as u128) + (product >> 61);
    let folded = ((folded & MODULUS as u128) + (folded >> 61)) as u64;
    if folded >= MODULUS {
        folded - MODULUS
    } else {
        folded
    }
}

/// The Rabin–Karp rolling hash of every `K`-byte window of `bytes`, computed
/// incrementally (add the incoming byte, subtract the outgoing one). Broken
/// out from `fingerprints` so `rolling_hash_matches_direct_computation` can
/// check it against a from-scratch hash of each window.
fn rolling_hashes(bytes: &[u8]) -> Vec<u64> {
    let mut hashes: Vec<u64> = Vec::new();
    if bytes.len() < K {
        return hashes;
    }
    hashes.reserve(bytes.len() - K + 1);

    let mut high = 1u64;
    for _ in 0..K - 1 {
        high = mul_mod(high, BASE);
    }
    let mut h = 0u64;
    for &b in &bytes[..K] {
        h = (mul_mod(h, BASE) + b as u64) % MODULUS;
    }
    hashes.push(h);
    for i in K..bytes.len() {
        let drop = mul_mod(bytes[i - K] as u64, high);
        h = (h + MODULUS - drop) % MODULUS;
        h = (mul_mod(h, BASE) + bytes[i] as u64) % MODULUS;
        hashes.push(h);
    }
    hashes
}

/// Winnowed Rabin–Karp fingerprints of `text`. Empty when the text is shorter than `K`.
pub fn fingerprints(text: &str) -> BTreeSet<u64> {
    let bytes = canonicalize(text);
    let mut out = BTreeSet::new();
    if bytes.len() < K {
        return out;
    }
    let hashes = rolling_hashes(&bytes);

    // Winnow: keep the minimum hash of each sliding window of WINDOW k-grams.
    // This makes the fingerprint set stable under insertions elsewhere in the text.
    if hashes.len() <= WINDOW {
        out.extend(hashes.iter().copied().min());
        return out;
    }
    let mut previous = None;
    for w in hashes.windows(WINDOW) {
        if let Some(m) = w.iter().copied().min() {
            // Adjacent windows often retain the same minimum. The set already
            // contains it; avoid an identical tree lookup without skipping a
            // byte/window or retaining anything between input invocations.
            if previous != Some(m) {
                out.insert(m);
                previous = Some(m);
            }
        }
    }
    out
}

/// Number of fingerprints two sets share.
pub fn overlap(a: &BTreeSet<u64>, b: &BTreeSet<u64>) -> usize {
    a.intersection(b).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSAGE: &str = "The quarterly revenue figures for the Asia Pacific region \
        showed a marked increase driven by semiconductor demand across all segments.";

    /// Guards against silent corruption of the rolling-hash invariant. `mul_mod`
    /// reduces modulo `MODULUS` on every multiply; if that were replaced by a
    /// plain `wrapping_mul` (which wraps mod 2^64, not mod `MODULUS`), the
    /// incremental hash would diverge from a from-scratch hash of the same
    /// window and every downstream taint match built on it would be unreliable.
    #[test]
    fn rolling_hash_matches_direct_computation() {
        // A few hundred bytes of varied content so the window slides many times.
        let text = PASSAGE.repeat(4);
        let bytes = canonicalize(&text);
        assert!(
            bytes.len() > 300,
            "need a long text to exercise many windows"
        );

        let incremental = rolling_hashes(&bytes);
        assert_eq!(incremental.len(), bytes.len() - K + 1);

        for (i, &incremental_h) in incremental.iter().enumerate() {
            let mut direct = 0u64;
            for &b in &bytes[i..i + K] {
                direct = (mul_mod(direct, BASE) + b as u64) % MODULUS;
            }
            assert_eq!(
                incremental_h, direct,
                "rolling hash diverged from direct computation at window {i}"
            );
        }
    }

    #[test]
    fn identical_text_yields_identical_fingerprints() {
        assert_eq!(fingerprints(PASSAGE), fingerprints(PASSAGE));
    }

    #[test]
    fn fingerprints_survive_whitespace_and_case_reformatting() {
        let reformatted = PASSAGE.to_uppercase().replace(' ', "\n   ");
        let a = fingerprints(PASSAGE);
        let b = fingerprints(&reformatted);
        assert_eq!(a, b, "canonicalization should make these identical");
    }

    #[test]
    fn fingerprints_partially_survive_truncation() {
        let a = fingerprints(PASSAGE);
        let truncated = &PASSAGE[..90];
        let b = fingerprints(truncated);
        let shared = overlap(&a, &b);
        assert!(
            shared >= 3,
            "expected >=3 shared fingerprints, got {shared}"
        );
    }

    #[test]
    fn unrelated_text_shares_nothing() {
        let a = fingerprints(PASSAGE);
        let b = fingerprints(
            "Docker compose configuration for the local development database service.",
        );
        assert_eq!(overlap(&a, &b), 0);
    }

    #[test]
    fn short_text_yields_no_fingerprints() {
        assert!(fingerprints("hello").is_empty());
    }
    #[test]
    fn mersenne_reduction_matches_independent_full_width_remainder() {
        let boundary = [0, 1, 2, 256, MODULUS - 1, MODULUS, MODULUS + 1, u64::MAX];
        for a in boundary {
            for b in boundary {
                assert_eq!(
                    mul_mod(a, b),
                    ((a as u128 * b as u128) % MODULUS as u128) as u64
                );
            }
        }
        let mut x = 0x8c679e741529ab03u64;
        for _ in 0..16_384 {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
            let a = x;
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
            assert_eq!(
                mul_mod(a, x),
                ((a as u128 * x as u128) % MODULUS as u128) as u64
            );
        }
    }

    /// Independent pre-change implementation. It deliberately keeps full
    /// remainder and inserts every minimum, including consecutive duplicates.
    fn legacy_fingerprints(text: &str) -> BTreeSet<u64> {
        let bytes = canonicalize(text);
        if bytes.len() < K {
            return BTreeSet::new();
        }
        let mul = |a: u64, b: u64| ((a as u128 * b as u128) % MODULUS as u128) as u64;
        let mut high = 1;
        for _ in 0..K - 1 {
            high = mul(high, BASE);
        }
        let mut h = 0;
        for &b in &bytes[..K] {
            h = (mul(h, BASE) + b as u64) % MODULUS;
        }
        let mut hashes = vec![h];
        for i in K..bytes.len() {
            let drop = mul(bytes[i - K] as u64, high);
            h = (h + MODULUS - drop) % MODULUS;
            h = (mul(h, BASE) + bytes[i] as u64) % MODULUS;
            hashes.push(h);
        }
        if hashes.len() <= WINDOW {
            return hashes.into_iter().min().into_iter().collect();
        }
        hashes
            .windows(WINDOW)
            .filter_map(|w| w.iter().copied().min())
            .collect()
    }

    #[test]
    fn optimized_fingerprints_match_legacy_at_boundaries_and_complete_large_inputs() {
        for text in ["", "A", "İ Ι Σ ß 日本語 🥣", "A \n\t B", ""]
            .into_iter()
            .map(str::to_owned)
            .chain(["x".repeat(262_144), PASSAGE.repeat(1024)])
        {
            assert_eq!(fingerprints(&text), legacy_fingerprints(&text));
        }
        let mut x = 0x12345678u64;
        for len in [
            0, 1, 31, 32, 33, 38, 39, 40, 41, 1024, 122_880, 262_144, 1_048_576,
        ] {
            let text: String = (0..len)
                .map(|_| {
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                    char::from(b' ' + ((x >> 32) % 95) as u8)
                })
                .collect();
            assert_eq!(
                fingerprints(&text),
                legacy_fingerprints(&text),
                "length {len}"
            );
        }
    }
}
