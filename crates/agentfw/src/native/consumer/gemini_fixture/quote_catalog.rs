// SPDX-License-Identifier: Apache-2.0
//! Untrusted raw-source quote suggestions for an opt-in generation profile.
//! No decoding, rewriting, permission decisions or response repair.
use std::collections::BTreeSet;

pub(super) fn candidates(source: &str) -> Vec<&str> {
    // Split at raw delimiters, not decoded JSON. Every retained slice is still
    // byte-for-byte present in the original full source. No labels/case IDs.
    let eligible = || {
        source
            .split(['\\', '"', '\n', '\r'])
            .map(str::trim)
            .filter(|s| {
                (8..=192).contains(&s.len())
                    && s.chars().any(char::is_alphabetic)
                    && s.chars().any(char::is_whitespace)
            })
    };
    let total = eligible().count();
    // Bound temporary storage even on adversarially fragmented input. Sampling
    // spans the whole input, including its end, and never removes source bytes
    // from the actual model request.
    let wanted = total.min(128);
    let mut pool = BTreeSet::new();
    let mut next = 0;
    for (i, s) in eligible().enumerate() {
        if next < wanted && i == next * (total - 1) / (wanted - 1).max(1) {
            pool.insert(s);
            next += 1;
        }
    }
    let mut bounded: Vec<_> = pool
        .into_iter()
        .filter(|quote| {
            source
                .char_indices()
                .filter(|(start, _)| source[*start..].starts_with(quote))
                .take(5)
                .count()
                <= 4
        })
        .collect();
    if bounded.len() > 64 {
        let last = bounded.len() - 1;
        bounded = (0..64).map(|i| bounded[i * last / 63]).collect();
    }
    bounded
}
