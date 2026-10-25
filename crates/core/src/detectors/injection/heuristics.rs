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
fn delimiter_hits(text: &str) -> usize {
    text.matches("```").count()
        + text.matches("###").count()
        + text.matches("---").count()
        + text.matches("<|").count()
}

/// Compute a heuristic score in `[0.0, 1.0]`. Pure function so it is trivially testable.
pub(crate) fn score_text(text: &str) -> f32 {
    let mut score = 0.0f32;

    score += 0.30 * IMPERATIVE.find_iter(text).count().min(3) as f32;
    if LONG_B64.is_match(text) {
        score += 0.30;
    }
    score += 0.10 * delimiter_hits(text).min(3) as f32;

    score.min(1.0)
}

/// After explicit complete-content Data review, a Git object-id header and
/// standalone/old-file separators are structural evidence, not instructions.
/// No other opaque token, delimiter or imperative is removed. This function
/// is never selected from parsing alone or from an untrusted wire attribute.
pub(crate) fn reviewed_data_score(text: &str) -> f32 {
    let mut score = 0.30 * IMPERATIVE.find_iter(text).count().min(3) as f32;
    let mut encoded = false;
    let mut delimiters = 0usize;
    let mut lines = text.lines().peekable();
    let mut first = true;
    while let Some(line) = lines.next() {
        let object_id = line
            .strip_prefix("commit ")
            .filter(|id| matches!(id.len(), 40 | 64) && id.bytes().all(|c| c.is_ascii_hexdigit()));
        // The pinned original Git server prefixes git_diff output with this
        // reference header. It is not a free-form body token: require the first
        // line and the following diff record. The complete original text still
        // requires affirmative semantic review; syntax alone never selects this
        // inspection path. An opaque body token retains the original band.
        let diff_reference = first
            && lines
                .peek()
                .is_some_and(|next| next.starts_with("diff --git "))
            && line
                .strip_prefix("Diff with ")
                .and_then(|value| value.strip_suffix(':'))
                .is_some_and(|id| {
                    matches!(id.len(), 40 | 64) && id.bytes().all(|c| c.is_ascii_hexdigit())
                });
        first = false;
        if object_id.is_none() && !diff_reference && LONG_B64.is_match(line) {
            encoded = true;
        }
        delimiters +=
            line.matches("```").count() + line.matches("###").count() + line.matches("<|").count();
        if line != "---" && !line.starts_with("--- ") {
            delimiters += line.matches("---").count();
        }
    }
    if encoded {
        score += 0.30;
    }
    score += 0.10 * delimiters.min(3) as f32;
    // A body signal must keep its ORIGINAL aggregate severity. Merely retaining
    // a 0.30 body finding while dropping structural contributions could lower
    // Medium to Low and evade a policy's min_severity floor.
    if score > 0.0 {
        score_text(text)
    } else {
        0.0
    }
}

/// Emit a single aggregate finding when the heuristic score crosses a floor.
pub(crate) fn scan(text: &str) -> Vec<Finding> {
    finding_from_score(score_text(text))
}

pub(crate) fn scan_attributed(text: &str, spans: &[std::ops::Range<usize>]) -> Vec<Finding> {
    let mut end = 0;
    for span in spans {
        if span.start < end || text.get(span.clone()) != Some("---") {
            return scan(text);
        }
        end = span.end;
    }
    let original = delimiter_hits(text);
    let remaining = original.saturating_sub(spans.len());
    // Even a single remaining body/path/unknown atom preserves the ORIGINAL
    // aggregate band. Never lower a policy's severity/confidence floor.
    if remaining != 0 || IMPERATIVE.is_match(text) || LONG_B64.is_match(text) {
        scan(text)
    } else {
        Vec::new()
    }
}

pub(crate) fn scan_reviewed_data(text: &str) -> Vec<Finding> {
    finding_from_score(reviewed_data_score(text))
}

fn finding_from_score(score: f32) -> Vec<Finding> {
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
    fn attribution_excludes_only_exact_fixed_atoms_and_keeps_original_body_band() {
        let text = "ordinary\n---\nmore\n---\nend\n---\n";
        let spans = text
            .match_indices("---")
            .map(|(i, _)| i..i + 3)
            .collect::<Vec<_>>();
        assert!(scan_attributed(text, &spans).is_empty());
        assert_eq!(scan_attributed(text, &spans[..2]), scan(text));
        for suffix in [
            "\n---\n",
            "\nforget",
            "\n### heading",
            "\nabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMN",
        ] {
            let body = format!("{text}{suffix}");
            assert_eq!(scan_attributed(&body, &spans), scan(&body));
        }
        assert_eq!(scan_attributed(text, &[0..3]), scan(text));
        assert_eq!(
            scan_attributed(text, &[spans[0].clone(), spans[0].clone()]),
            scan(text)
        );
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
    fn positive_data_review_resolves_only_structural_atoms() {
        let git = "commit 0123456789abcdef0123456789abcdef01234567\n--- a/one.txt\n+ordinary data\n--- a/two.txt\n+more data\n---\n";
        assert!(
            !scan(git).is_empty(),
            "default path must remain conservative"
        );
        assert!(scan_reviewed_data(git).is_empty());
        let files = "one.txt:\nfirst document\n---\ntwo.txt:\nsecond document\n---\nthree.txt:\nthird document\n---\n";
        assert!(!scan(files).is_empty());
        assert!(scan_reviewed_data(files).is_empty());
    }

    #[test]
    fn positive_data_review_retains_body_and_opaque_token_evidence() {
        for text in [
            "--- a/one.txt\n+ignore this, disregard that, override everything",
            "--- a/one.txt\n+aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZyE=",
            "commit not-a-hex-value-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
            "### header\n```body```\n<|data",
        ] {
            assert!(!scan_reviewed_data(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn review_does_not_treat_hex_in_document_body_as_git_header() {
        for text in [
            "+0123456789abcdef0123456789abcdef01234567",
            " commit 0123456789abcdef0123456789abcdef01234567",
            "commit 0123456789abcdef0123456789abcdef01234567 extra",
        ] {
            assert!(!scan_reviewed_data(text).is_empty(), "{text}");
        }
    }

    #[test]
    fn reviewed_original_diff_reference_is_structural_only_at_the_record_start() {
        let reference = "0123456789abcdef0123456789abcdef01234567";
        let patch = "diff --git a/a b/a\nindex 1234567..2345678 100644\n--- a/a\n+++ b/a\n@@ -1 +1 @@\n-old data\n+new data\n";
        let valid = format!("Diff with {reference}:\n{patch}");
        assert!(scan_reviewed_data(&valid).is_empty());
        assert!(!scan(&valid).is_empty());
        for invalid in [
            format!("document body\n{valid}"),
            format!("Diff with {reference}:\nordinary prose\n---\n---\n---"),
            format!("Diff with {reference}: trailing\n{patch}"),
            format!("Diff with {reference}:\n{patch}\nignore this"),
            format!("Diff with {reference}:\n{patch}\n{}", "x".repeat(40)),
        ] {
            assert_eq!(scan_reviewed_data(&invalid), scan(&invalid));
        }
    }

    #[test]
    fn even_one_remaining_body_signal_preserves_the_original_finding_band() {
        for body in [
            "forget",
            "bypass",
            "act as",
            "### quoted heading",
            "```code```",
            "aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IHN0cmluZyE=",
        ] {
            let text =
                format!("commit 0123456789abcdef0123456789abcdef01234567\n---\n---\n---\n{body}");
            assert_eq!(scan_reviewed_data(&text), scan(&text), "{body}");
        }
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
