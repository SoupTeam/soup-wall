// SPDX-License-Identifier: Apache-2.0

//! Stage B: cheap heuristics that catch novel phrasings signatures miss.
//! Produces at most one aggregate `Finding`; confidence scales with the heuristic score.

use std::sync::LazyLock;

use regex::Regex;

use crate::{Finding, Severity};

static IMPERATIVE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(ignore|disregard|override|bypass|forget|reveal|pretend|act\s+as)\b")
        .expect("imperative regex")
});

static LONG_B64: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{40,}={0,2}").expect("b64 regex"));

/// Count of suspicious delimiter characters commonly used to smuggle instructions.
const DELIMITERS: [&str; 4] = ["```", "###", "---", "<|"];
fn delimiter_hits(text: &str) -> usize {
    DELIMITERS
        .iter()
        .map(|token| text.matches(token).count())
        .sum()
}

/// Diagnostic counts over unchanged original bytes. This does not modify score.
/// A span covers a hit only when it exactly names the producer's newline separator.
pub(super) fn delimiter_accounting(
    text: &str,
    separators: &[std::ops::Range<usize>],
) -> (usize, usize) {
    let mut total = 0;
    let mut owned = 0;
    let starts: std::collections::BTreeSet<_> = separators
        .iter()
        .filter_map(|span| {
            (span.end.checked_sub(span.start) == Some(5)
                && text.get(span.clone()) == Some("\n---\n"))
            .then(|| span.start.checked_add(1))
            .flatten()
        })
        .collect();
    for token in DELIMITERS {
        for (start, _) in text.match_indices(token) {
            total += 1;
            if token == "---" && starts.contains(&start) {
                owned += 1;
            }
        }
    }
    (total, owned)
}

/// Compute a heuristic score in `[0.0, 1.0]`. Pure function so it is trivially testable.
pub(crate) fn score_text(text: &str) -> f32 {
    score_text_with_formatter_hash(text, None)
}

fn score_text_with_formatter_hash(
    text: &str,
    formatter_hash: Option<&std::ops::Range<usize>>,
) -> f32 {
    score_components(text, formatter_hash, delimiter_hits(text))
}

/// Diagnostic candidate only. Every supplied coordinate must be valid and unique;
/// malformed or duplicate attribution retains the complete baseline.
pub(super) fn formatter_shadow_scores(
    text: &str,
    separators: &[std::ops::Range<usize>],
) -> (f32, f32) {
    let baseline = score_text(text);
    let (total, owned) = delimiter_accounting(text, separators);
    if owned != separators.len() {
        return (baseline, baseline);
    }
    (baseline, score_components(text, None, total - owned))
}

fn score_components(
    text: &str,
    formatter_hash: Option<&std::ops::Range<usize>>,
    delimiters: usize,
) -> f32 {
    let mut score = 0.0f32;

    let imperative_count = IMPERATIVE.find_iter(text).count().min(3);
    score += 0.30 * imperative_count as f32;
    // An independent body imperative retains its original coupled band/floor.
    // Attribution of a formatter field cannot discount that separate evidence.
    let formatter_hash = formatter_hash.filter(|_| imperative_count == 0);
    // Exclude only the one complete encoding-shaped match authenticated by
    // the execution owner. A duplicate hash or any other body encoding remains.
    if LONG_B64
        .find_iter(text)
        .any(|found| formatter_hash.is_none_or(|span| found.range() != *span))
    {
        score += 0.30;
    }
    score += 0.10 * delimiters.min(3) as f32;

    score.min(1.0)
}

/// Emit a single aggregate finding when the heuristic score crosses a floor.
pub(crate) fn scan(text: &str) -> Vec<Finding> {
    scan_with_formatter_hash(text, None)
}

/// A contextual scorer, not a parser or source authenticator. Reject malformed
/// candidate offsets by retaining every original signal.
pub(crate) fn scan_with_formatter_hash(
    text: &str,
    candidate: Option<&std::ops::Range<usize>>,
) -> Vec<Finding> {
    let validated = candidate.filter(|span| {
        span.end.checked_sub(span.start) == Some(40)
            && text
                .get((*span).clone())
                .is_some_and(|hash| hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
            && ((span.start == 7
                && text.starts_with("commit ")
                && text
                    .get(span.end..)
                    .is_some_and(|tail| tail.starts_with('\n')))
                || (span.start == 10
                    && text.starts_with("Diff with ")
                    && text
                        .get(span.end..)
                        .is_some_and(|tail| tail.starts_with(":\n"))))
    });
    let score = match validated {
        Some(span) => score_text_with_formatter_hash(text, Some(span)),
        None => score_text(text),
    };
    if score < 0.30 {
        return Vec::new();
    }
    let severity = if score >= 0.75 {
        Severity::High
    } else if score >= 0.5 {
        Severity::Medium
    } else {
        Severity::Low
    };
    vec![Finding::new(
        "injection",
        severity,
        score,
        format!("heuristic injection signals (score {score:.2})"),
    )]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shadow_removes_only_owned_hits_before_cap_and_preserves_other_signals() {
        for body in [
            "ordinary",
            "ignore override",
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN",
            "### ``` <|",
        ] {
            let text = format!("a\n---\nb\n---\nc\n---\n{body}");
            let spans: Vec<_> = text
                .match_indices("\n---\n")
                .map(|(i, _)| i..i + 5)
                .collect();
            let (baseline, candidate) = formatter_shadow_scores(&text, &spans);
            assert_eq!(baseline, score_text(&text));
            assert_eq!(candidate, score_text(body));
            assert!(candidate <= baseline);
            let mut duplicate = spans.clone();
            duplicate.push(spans[0].clone());
            assert_eq!(
                formatter_shadow_scores(&text, &duplicate),
                (baseline, baseline)
            );
            assert_eq!(
                formatter_shadow_scores(&text, &[1..usize::MAX]),
                (baseline, baseline)
            );
            assert_eq!(formatter_shadow_scores(&text, &[]), (baseline, baseline));
        }
        let text = "é\n---\nignore";
        assert_eq!(
            formatter_shadow_scores(text, &[2..7]).1,
            score_text("ignore")
        );
        assert_eq!(formatter_shadow_scores(text, &[1..6]).1, score_text(text));
    }

    #[test]
    fn diagnostic_separator_counts_preserve_score_and_reject_bad_coordinates() {
        let text = "é\n---\nbody --- ### ``` <|";
        let before = score_text(text);
        assert_eq!(delimiter_accounting(text, &[2..7]), (5, 1));
        assert_eq!(delimiter_accounting(text, &[2..7, 2..7]), (5, 1));
        for span in [0..text.len(), 3..6, 1..6, 2..usize::MAX] {
            assert_eq!(delimiter_accounting(text, &[span]), (5, 0));
        }
        assert_eq!(delimiter_accounting(text, &[]), (5, 0));
        assert_eq!(score_text(text), before);
    }

    #[test]
    fn proved_formatter_oid_removes_only_its_own_encoding_contribution() {
        let oid = "0123456789abcdef0123456789abcdef01234567";
        for (header, span) in [
            (format!("commit {oid}\n"), 7..47),
            (format!("Diff with {oid}:\n"), 10..50),
        ] {
            let text = format!("{header}---\na\n---\nb\n---\nc");
            assert_eq!(scan(&text)[0].severity, Severity::Medium);
            assert_eq!(
                scan_with_formatter_hash(&text, Some(&span))[0].severity,
                Severity::Low
            );
            let body_oid = format!("{text}\n{oid}");
            assert_eq!(
                scan_with_formatter_hash(&body_oid, Some(&span))[0].severity,
                Severity::Medium
            );
            let directive = format!("{text}\nignore this; disregard that; override instructions");
            assert_eq!(
                scan_with_formatter_hash(&directive, Some(&span))[0].severity,
                Severity::High
            );
            for wrong in [0..40, 7..46, 9..49, 7..usize::MAX] {
                let actual = scan_with_formatter_hash(&text, Some(&wrong));
                assert_eq!(actual[0].severity, scan(&text)[0].severity);
                assert_eq!(actual[0].confidence, scan(&text)[0].confidence);
            }
            assert_eq!(
                scan_with_formatter_hash(&text, None)[0].confidence,
                scan(&text)[0].confidence
            );
        }
    }

    #[test]
    fn benign_scores_low_and_emits_nothing() {
        assert!(score_text("Summarize this article about penguins.") < 0.30);
        assert!(scan("Summarize this article about penguins.").is_empty());
    }

    #[test]
    fn stacked_imperatives_raise_score() {
        let text = "ignore this, disregard that, override everything";
        assert!(score_text(text) >= 0.75);
        let f = scan(text);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::High);
        assert_eq!(f[0].detector, "injection");
    }

    #[test]
    fn base64_blob_contributes() {
        let blob = "aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZyE=";
        assert!(score_text(blob) >= 0.30);
    }

    #[test]
    fn banding_and_confidence_are_locked() {
        // Intentional design decision (to be tuned against NotInject/benign corpora in the
        // benchmark phase): a single weak imperative reaches the 0.30 floor and emits a LOW
        // finding. Low impact (risk contribution ~0.09) and tempered by later stages.
        let low = scan("please act as a translator");
        assert_eq!(low.len(), 1);
        assert_eq!(low[0].severity, Severity::Low);
        assert!((low[0].confidence - score_text("please act as a translator")).abs() < 1e-6);

        // Medium band: base64 blob (0.30) + one imperative "ignore" (0.30) = 0.60 -> Medium.
        let text = "ignore this aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZyE=";
        let med = scan(text);
        assert_eq!(med.len(), 1);
        assert_eq!(med[0].severity, Severity::Medium);
    }
}
