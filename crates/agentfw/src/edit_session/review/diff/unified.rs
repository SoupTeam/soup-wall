// SPDX-License-Identifier: Apache-2.0
//! Deterministic bounded full-file unified display; escaped text, never a patch.
use super::{Budget, CAP};
use anyhow::{ensure, Context as _, Result};
const INPUT: usize = 8 * 2 * 4096;
const CELLS: usize = 1024 * 1024;
const DISPLAY: usize = 32 * 1024;
#[derive(Default)]
pub(super) struct Limits {
    input: usize,
    cells: usize,
    display: usize,
}
pub(super) fn bounds() -> serde_json::Value {
    serde_json::json!({"aggregate_input_bytes":INPUT,"lcs_cells":CELLS,"escaped_display_bytes":DISPLAY,
        "response_bytes":128*1024,"line_numbering":"one_based_full_file_ranges_zero_for_empty"})
}
pub(super) fn escape(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}
#[derive(Debug)]
pub(super) struct Rendered {
    pub text: String,
    pub old_lines: usize,
    pub new_lines: usize,
    pub added: usize,
    pub removed: usize,
}
fn lines(raw: &[u8]) -> Result<Vec<&str>> {
    ensure!(raw.len() <= CAP as usize, "edit_diff_file_byte_cap");
    let value = std::str::from_utf8(raw)
        .map_err(|_| anyhow::anyhow!("edit_diff_invalid_utf8_unsupported"))?;
    ensure!(!value.contains('\0'), "edit_diff_binary_unsupported");
    Ok(value.split_inclusive('\n').collect())
}
fn push(out: &mut String, value: &str, limits: &mut Limits) -> Result<()> {
    limits.display = limits
        .display
        .checked_add(value.len())
        .context("edit_diff_display_cap")?;
    ensure!(limits.display <= DISPLAY, "edit_diff_display_cap");
    out.push_str(value);
    Ok(())
}
fn line(out: &mut String, kind: char, value: &str, limits: &mut Limits) -> Result<()> {
    let content = value.strip_suffix('\n').unwrap_or(value);
    push(out, &format!("{kind}{}\n", escape(content)), limits)?;
    if !value.ends_with('\n') {
        push(out, "\\ No newline at end of file\n", limits)?;
    }
    Ok(())
}
pub(super) fn render(
    name: &str,
    label: Option<&str>,
    old: Option<&[u8]>,
    new: &[u8],
    limits: &mut Limits,
    budget: &mut Budget,
) -> Result<Rendered> {
    ensure!(
        old.is_none_or(|b| b.len() <= CAP as usize) && new.len() <= CAP as usize,
        "edit_diff_file_byte_cap"
    );
    limits.input = limits
        .input
        .checked_add(old.map_or(0, |b| b.len()) + new.len())
        .context("edit_diff_input_cap")?;
    ensure!(limits.input <= INPUT, "edit_diff_input_cap");
    let before = lines(old.unwrap_or_default())?;
    let after = lines(new)?;
    let mut out = String::new();
    let baseline = label
        .map(|s| format!("baseline/{}", escape(s)))
        .unwrap_or_else(|| "/dev/null [no baseline selected]".into());
    push(
        &mut out,
        &format!("--- {baseline}\n+++ output/{}\n", escape(name)),
        limits,
    )?;
    let (n, m) = (before.len(), after.len());
    let mut added = 0;
    let mut removed = 0;
    if old.is_some_and(|b| b == new) {
        return Ok(Rendered {
            text: out,
            old_lines: n,
            new_lines: m,
            added,
            removed,
        });
    }
    let count = (n + 1).checked_mul(m + 1).context("edit_diff_work_cap")?;
    limits.cells = limits
        .cells
        .checked_add(count)
        .context("edit_diff_work_cap")?;
    ensure!(limits.cells <= CELLS, "edit_diff_work_cap");
    let mut table = vec![0u16; count];
    for i in (0..n).rev() {
        budget.tick(0).map_err(anyhow::Error::msg)?;
        for j in (0..m).rev() {
            table[i * (m + 1) + j] = if before[i] == after[j] {
                1 + table[(i + 1) * (m + 1) + j + 1]
            } else {
                table[(i + 1) * (m + 1) + j].max(table[i * (m + 1) + j + 1])
            };
        }
    }
    push(
        &mut out,
        &format!(
            "@@ -{},{} +{},{} @@\n",
            usize::from(n > 0),
            n,
            usize::from(m > 0),
            m
        ),
        limits,
    )?;
    let (mut i, mut j) = (0, 0);
    while i < n || j < m {
        if i < n && j < m && before[i] == after[j] {
            line(&mut out, ' ', before[i], limits)?;
            i += 1;
            j += 1;
        } else if i < n && (j == m || table[(i + 1) * (m + 1) + j] >= table[i * (m + 1) + j + 1]) {
            line(&mut out, '-', before[i], limits)?;
            i += 1;
            removed += 1;
        } else {
            line(&mut out, '+', after[j], limits)?;
            j += 1;
            added += 1;
        }
    }
    Ok(Rendered {
        text: out,
        old_lines: n,
        new_lines: m,
        added,
        removed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn view(old: Option<&[u8]>, new: &[u8]) -> Result<Rendered> {
        render(
            "result.txt",
            old.map(|_| "old.txt"),
            old,
            new,
            &mut Limits::default(),
            &mut Budget::new(),
        )
    }
    #[test]
    fn exact_ranges_and_deterministic_deletion_tie() {
        let value = view(Some(b"a\nb\n"), b"b\na\n").unwrap();
        assert_eq!(
            value.text,
            "--- baseline/old.txt\n+++ output/result.txt\n@@ -1,2 +1,2 @@\n-a\n b\n+a\n"
        );
        assert_eq!(
            (value.old_lines, value.new_lines, value.added, value.removed),
            (2, 2, 1, 1)
        );
    }
    #[test]
    fn new_empty_no_change_and_missing_newline_are_distinct() {
        assert!(view(None, b"")
            .unwrap()
            .text
            .contains("no baseline selected"));
        assert!(view(Some(b""), b"")
            .unwrap()
            .text
            .ends_with("+++ output/result.txt\n"));
        assert!(view(None, b"hello")
            .unwrap()
            .text
            .contains("@@ -0,0 +1,1 @@\n+hello\n\\ No newline at end of file\n"));
        let changed = view(Some(b"x\r\n"), b"x\n").unwrap();
        assert!(changed.text.contains("-x\\r\n+x\n"));
    }
    #[test]
    fn terminal_text_and_labels_are_ascii_escaped() {
        let value = render(
            "result.txt",
            Some("old\u{202e}\x1b\n.txt"),
            Some(b"old\n"),
            "\x1b[31m\u{202e}\u{8}\n".as_bytes(),
            &mut Limits::default(),
            &mut Budget::new(),
        )
        .unwrap();
        assert!(
            value.text.is_ascii()
                && !value.text.contains('\x1b')
                && value.text.contains("\\u{1b}")
                && value.text.contains("\\u{202e}")
        );
        assert!(view(None, b"\xff").is_err());
        assert!(view(None, b"a\0b").is_err());
    }
    #[test]
    fn repeated_lines_work_display_and_aggregate_caps_refuse_without_truncation() {
        let dense = b"a\n".repeat(2048);
        let changed = b"b\n".repeat(2048);
        assert!(view(Some(&dense), &dense).is_ok());
        assert!(view(Some(&dense), &changed)
            .unwrap_err()
            .to_string()
            .contains("work_cap"));
        let mut limits = Limits::default();
        let mut budget = Budget::new();
        for _ in 0..8 {
            assert!(render("r", None, None, b"x\n", &mut limits, &mut budget).is_ok());
        }
        let mut limits = Limits {
            input: INPUT,
            ..Limits::default()
        };
        assert!(render("r", None, None, b"x", &mut limits, &mut budget).is_err());
        let mut limits = Limits {
            display: DISPLAY,
            ..Limits::default()
        };
        assert!(render("r", None, None, b"x", &mut limits, &mut budget).is_err());
    }

    #[test]
    fn displayed_edit_script_reconstructs_both_small_inputs() {
        let words = ["", "a\n", "b\n", "a\na\n", "a\nb\n", "b\na\n", "b\nb\n"];
        for old in words {
            for new in words {
                if old == new {
                    continue;
                }
                let result = view(Some(old.as_bytes()), new.as_bytes()).unwrap();
                let mut before = String::new();
                let mut after = String::new();
                for line in result.text.lines().skip(3) {
                    let (kind, payload) = line.split_at(1);
                    if kind == " " || kind == "-" {
                        before.push_str(payload);
                        before.push('\n');
                    }
                    if kind == " " || kind == "+" {
                        after.push_str(payload);
                        after.push('\n');
                    }
                }
                assert_eq!(before, old);
                assert_eq!(after, new);
            }
        }
    }

    #[test]
    fn cell_budget_is_shared_across_all_selected_files() {
        let old = b"a\n".repeat(400);
        let new = b"b\n".repeat(400);
        let mut limits = Limits::default();
        let mut budget = Budget::new();
        for _ in 0..6 {
            assert!(render("r", Some("b"), Some(&old), &new, &mut limits, &mut budget).is_ok());
        }
        assert!(
            render("r", Some("b"), Some(&old), &new, &mut limits, &mut budget)
                .unwrap_err()
                .to_string()
                .contains("work_cap")
        );
    }
}
