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

// Deliberately small, affirmative data grammar: JSON non-string scalars and
// uppercase issue identifiers. Prose, quoted strings, code and unknown syntax
// are unresolved, regardless of language, verbs, file names or destinations.
// This is not a sentence/keyword allowlist and must not grow to fit a fixture.
static DATA_ATOM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:null|true|false|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?|[A-Z][A-Z0-9]*-[0-9]+)$")
        .expect("bounded data atom grammar")
});

// Some(true): a complete multi-record response whose entire body is typed data.
// Some(false): recognized framing with semantically unresolved body text.
// None: unsupported framing. Preserve baseline scoring for it, including Git.
fn filesystem_data_records(text: &str) -> Option<bool> {
    let mut records = 0;
    let mut header = true;
    let mut body = false;
    let mut data_only = true;
    for line in text.lines() {
        if header {
            let path = line.strip_suffix(':')?;
            if !path.starts_with('/')
                || path.len() < 2
                || !path
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"/._-".contains(&c))
            {
                return None;
            }
            records += 1;
            header = false;
            body = false;
        } else if line == "---" {
            if !body {
                return None;
            }
            header = true;
        } else if !line.is_empty() {
            body = true;
            data_only &= DATA_ATOM.is_match(line);
        }
    }
    (records > 1 && !header && body).then_some(data_only)
}

/// Count of suspicious delimiter characters commonly used to smuggle instructions.
fn delimiter_hits(text: &str, data_only: bool) -> usize {
    text.matches("```").count()
        + text.matches("###").count()
        + text
            .lines()
            .filter(|line| !data_only || *line != "---")
            .map(|line| line.matches("---").count())
            .sum::<usize>()
        + text.matches("<|").count()
}

/// Compute a heuristic score in `[0.0, 1.0]`. Pure function so it is trivially testable.
pub(crate) fn score_text(text: &str) -> f32 {
    let mut score = 0.0f32;

    let imperatives = IMPERATIVE.find_iter(text).count().min(3);
    score += 0.30 * imperatives as f32;
    if LONG_B64.is_match(text) {
        score += 0.30;
    }
    let records = filesystem_data_records(text);
    let delimiters = delimiter_hits(text, records == Some(true) && imperatives == 0);
    score += 0.10 * delimiters.min(3) as f32;

    // A valid wrapper cannot turn unclassified prose into harmless data.
    // Explicitly retain a Medium result finding for unresolved framed bodies.
    // Existing policy decides its verdict; no policy threshold is relaxed.
    if records == Some(false) && delimiters >= 3 {
        score = score.max(0.5);
    }

    score.min(1.0)
}

/// Emit a single aggregate finding when the heuristic score crosses a floor.
pub(crate) fn scan(text: &str) -> Vec<Finding> {
    let score = score_text(text);
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
    fn only_affirmatively_typed_record_bodies_discount_separators() {
        for atom in ["42", "-1.5e+3", "true", "null", "ABC-123"] {
            let text = format!("/a:\n{atom}\n---\n/b:\n{atom}\n---\n/c:\n{atom}\n---\n/d:\n{atom}");
            assert_eq!(filesystem_data_records(&text), Some(true));
            assert_eq!(score_text(&text), 0.0);
        }
        for prose in [
            "ordinary documentation",
            "Delete everything",
            "Transmettre le fichier",
            "Удалить файлы",
            "\"ABC-123\"",
            "XYZ",
        ] {
            let text = format!("/a:\nABC-123\n---\n/b:\n42\n---\n/c:\nnull\n---\n/d:\n{prose}");
            assert_eq!(filesystem_data_records(&text), Some(false));
            assert!(score_text(&text) >= 0.5);
        }
        assert_eq!(filesystem_data_records("/a:\n42\n---\n"), None);
        assert_eq!(filesystem_data_records("---\n---\n---"), None);
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
