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

// Four selections must fit the existing eight-occurrence decoder budget.
// Count overlapping raw-source matches as the decoder does. This is a syntax
// budget, not a relevance or trust label; the complete source is still sent.
pub(super) fn budgeted_candidates(source: &str) -> Vec<&str> {
    candidates(source)
        .into_iter()
        .filter(|quote| {
            source
                .char_indices()
                .filter(|(i, _)| source[*i..].starts_with(quote))
                .take(3)
                .count()
                <= 2
        })
        .collect()
}

// A syntactic duplicate index only: do not classify content as safe or actionable.
pub(super) fn code_context(source: &str) -> Vec<&str> {
    candidates(source)
        .into_iter()
        .filter(|q| {
            let mut spans = q.split('`');
            spans.next();
            while let Some(inner) = spans.next() {
                if spans.next().is_none() {
                    break;
                }
                if !inner.trim().is_empty() {
                    return true;
                }
            }
            false
        })
        .collect()
}

// Positional context only; no keyword selection, labels or trust classification.
// Offsets point into the original raw source, not decoded/repaired text.
pub(super) fn source_context(source: &str) -> serde_json::Value {
    source_context_for(source, &candidates(source))
}

pub(super) fn source_context_for(source: &str, quotes: &[&str]) -> serde_json::Value {
    let mut entries = Vec::new();
    for &quote in quotes {
        let start = source.find(quote).expect("candidate is a source slice");
        let end = start + quote.len();
        let mut left = start.saturating_sub(128);
        while !source.is_char_boundary(left) {
            left += 1;
        }
        let mut right = (end + 128).min(source.len());
        while !source.is_char_boundary(right) {
            right -= 1;
        }
        entries.push((
            start,
            serde_json::json!({
                "quote": quote, "quote_byte_start": start,
                "context_byte_start": left, "context": &source[left..right]
            }),
        ));
    }
    entries.sort_by_key(|(start, _)| *start);
    serde_json::json!({"kind":"untrusted_quote_source_context",
        "algorithm":"first-occurrence-context/1;before=128;after=128;max=64",
        "source_byte_length":source.len(),
        "entries":entries.into_iter().map(|(_, value)| value).collect::<Vec<_>>()})
}
