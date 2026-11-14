// SPDX-License-Identifier: Apache-2.0
//! Deterministic report rendering. JSON preserves untrusted values as data;
//! text and CSV escape control, bidi and invisible characters, and CSV cells
//! are neutralized against spreadsheet formula evaluation.

use serde_json::Value;

use super::{Refusal, MAX_OUTPUT_BYTES, NON_AUTHORITY};
use crate::mcp::manifest::MAX_DESCRIPTION_EXCERPT;

const SNAPSHOT_ONLY: &str = "SNAPSHOT-ONLY MODE: no current operator declarations were supplied. \
Semantic review is UNAVAILABLE; action, resource and destination effects are unknown. This is not \
a semantic upgrade review.";

pub(super) const FILES: [&str; 5] = [
    "report.json",
    "review-pack.json",
    "findings.csv",
    "report.txt",
    "REVIEW_GUIDE.md",
];

fn invisible(c: char) -> bool {
    c.is_control()
        || matches!(c,
            '\u{200B}'..='\u{200F}' | '\u{2028}'..='\u{202E}' | '\u{2060}'..='\u{2069}'
            | '\u{FEFF}' | '\u{FFF9}'..='\u{FFFB}' | '\u{00AD}' | '\u{034F}' | '\u{061C}'
            | '\u{180E}' | '\u{E0000}'..='\u{E007F}')
}

/// One untrusted string as a single safe display line, bounded in bytes.
pub(crate) fn safe_text(text: &str, max: usize) -> String {
    let mut out = String::new();
    for (index, c) in text.char_indices() {
        if out.len() >= max {
            out.push_str(&format!("…[{} more bytes]", text.len() - index));
            break;
        }
        if invisible(c) {
            out.push_str(&format!("\\u{{{:04X}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

fn display(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::String(s) => safe_text(s, MAX_DESCRIPTION_EXCERPT),
        other => safe_text(&super::canonical_json(other), MAX_DESCRIPTION_EXCERPT),
    }
}

/// RFC 4180 cell, always quoted, with formula-trigger neutralization. Leading
/// whitespace is ignored when looking for a trigger, as spreadsheets do.
pub(crate) fn csv_cell(text: &str) -> String {
    let safe = safe_text(text, usize::MAX);
    let trigger = safe
        .trim_start_matches(|c: char| c.is_whitespace() || c == '\u{FEFF}')
        .chars()
        .next()
        .is_some_and(|c| {
            matches!(
                c,
                '=' | '+'
                    | '-'
                    | '@'
                    | '\t'
                    | '\r'
                    | '\n'
                    | '|'
                    | '%'
                    | '\u{FF1D}'
                    | '\u{FF0B}'
                    | '\u{FF0D}'
                    | '\u{FF20}'
                    | '\u{2212}'
            )
        })
        || text.starts_with(invisible);
    let body = if trigger { format!("'{safe}") } else { safe };
    format!("\"{}\"", body.replace('"', "\"\""))
}

fn csv(report: &Value) -> String {
    let header = [
        "finding_id",
        "tool",
        "area",
        "pointer",
        "argument_pointer",
        "kind",
        "nature",
        "before",
        "after",
        "review_reasons",
        "example_ids",
        "accepted_by_analyzer",
    ];
    let mut out = header.map(csv_cell).join(",");
    out.push_str("\r\n");
    for f in report["findings"].as_array().into_iter().flatten() {
        let join = |v: &Value| {
            v.as_array()
                .map(|a| a.iter().map(display).collect::<Vec<_>>().join(" | "))
                .unwrap_or_default()
        };
        let row = [
            display(&f["id"]),
            display(&f["tool"]),
            display(&f["area"]),
            display(&f["pointer"]),
            display(&f["argument_pointer"]),
            display(&f["kind"]),
            display(&f["nature"]),
            display(&f["before"]),
            display(&f["after"]),
            join(&f["review_reasons"]),
            join(&f["example_ids"]),
            "false".to_owned(),
        ];
        out.push_str(
            &row.iter()
                .map(|c| csv_cell(c))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push_str("\r\n");
    }
    out
}

fn text(report: &Value, pack: &Value) -> String {
    let s = &report["summary"];
    let i = &report["inputs"];
    let mut out = String::new();
    let mut line = |t: String| {
        out.push_str(&t);
        out.push('\n');
    };
    line("MCP original-tool schema upgrade review (offline, non-authoritative)".into());
    line(format!(
        "Format: {}",
        report["format"].as_str().unwrap_or("")
    ));
    line(String::new());
    line(format!("NOTICE: {NON_AUTHORITY}"));
    if s["analysis_mode"] == "snapshot_only" {
        line(SNAPSHOT_ONLY.into());
    }
    line(String::new());
    for side in ["before", "after"] {
        let f = &i[side];
        line(format!(
            "{side:6}: file {} raw_sha256 {} ({} bytes, {} tools, {})",
            display(&f["file_name"]),
            display(&f["raw_sha256"]),
            f["bytes"],
            f["tool_count"],
            display(&f["format"])
        ));
        line(format!(
            "        discovery_sha256 {}",
            display(&f["discovery_sha256"])
        ));
        if !f["operator_label_untrusted"].is_null() {
            line(format!(
                "        operator label (untrusted): \"{}\"",
                display(&f["operator_label_untrusted"])
            ));
        }
    }
    match &i["before_identity"] {
        Value::Null => line("before identity: NOT VERIFIED (no identity document supplied)".into()),
        v => line(format!(
            "before identity: verified {} raw_sha256 {} ({} referenced files verified)",
            display(&v["file_name"]),
            display(&v["raw_sha256"]),
            v["referenced_files"].as_array().map_or(0, Vec::len)
        )),
    }
    match &i["current_declarations"] {
        Value::Null => line("current declarations: NONE SUPPLIED (semantics unknown)".into()),
        v => line(format!(
            "current declarations: {} {} raw_sha256 {}",
            display(&v["format"]),
            display(&v["file_name"]),
            display(&v["raw_sha256"])
        )),
    }
    line(String::new());
    line(format!(
        "Outcome: {} / {} (exit {})",
        display(&s["outcome"]),
        display(&s["classification"]),
        s["exit_code"]
    ));
    line(format!(
        "Snapshots byte-identical: {}; declaration findings: {}",
        s["byte_identical"], s["declaration_findings"]
    ));
    line(format!(
        "Tools: before {} after {}; added {} removed {} changed {} unchanged {}",
        s["tools_before"],
        s["tools_after"],
        s["tools_added"],
        s["tools_removed"],
        s["tools_changed"],
        s["tools_unchanged"]
    ));
    line(format!(
        "Findings: {} (inert metadata {}, review required {}, unsupported {}, declaration requalification {})",
        s["findings"]["total"],
        s["findings"]["inert_metadata"],
        s["findings"]["review_required"],
        s["findings"]["unsupported"],
        s["findings"]["requalification_required"]
    ));
    line(format!(
        "Coverage complete: {}; review-pack records: {}",
        s["coverage_complete"], pack["generation"]["records"]
    ));
    let unaccepted: Vec<String> = s["new_unaccepted_identities"]
        .as_array()
        .into_iter()
        .flatten()
        .map(display)
        .collect();
    line(format!(
        "New UNACCEPTED tool identities ({}): {}",
        unaccepted.len(),
        if unaccepted.is_empty() {
            "none".into()
        } else {
            unaccepted.join(", ")
        }
    ));
    line("Accepted by this analyzer: nothing.".into());
    line(String::new());
    line("Findings (tool / pointer / kind / nature):".into());
    for f in report["findings"].as_array().into_iter().flatten() {
        line(format!(
            "  [{}] {} {} {} {} -> examples {}",
            display(&f["id"]),
            display(&f["tool"]),
            if f["pointer"] == "" {
                "(tool)".to_owned()
            } else {
                display(&f["pointer"])
            },
            display(&f["kind"]),
            display(&f["nature"]),
            f["example_ids"].as_array().map_or(0, Vec::len)
        ));
        for (label, key) in [("before", "before"), ("after ", "after")] {
            if !f[key].is_null() {
                line(format!("      {label} (untrusted): {}", display(&f[key])));
            }
        }
    }
    line(String::new());
    line("Coverage gaps:".into());
    for g in report["coverage"]["gaps"].as_array().into_iter().flatten() {
        line(format!("  - {}", display(g)));
    }
    line(format!(
        "Unsupported constructs reported: {}",
        report["coverage"]["unsupported_constructs"]
            .as_array()
            .map_or(0, Vec::len)
    ));
    out
}

fn guide(report: &Value) -> String {
    let i = &report["inputs"];
    let s = &report["summary"];
    let banner = if s["analysis_mode"] == "snapshot_only" {
        format!(
            "**{SNAPSHOT_ONLY}**

"
        )
    } else {
        String::new()
    };
    let digest = |v: &Value| display(&v["raw_sha256"]);
    format!(
        "# MCP schema upgrade review guide\n\n{banner}\
Generated offline by `agentfw mcp-schema-upgrade`. {NON_AUTHORITY}\n\n\
## Exact inputs\n\n\
- Before snapshot `{}` raw sha256 `{}`, discovery identity `{}`.\n\
- After snapshot `{}` raw sha256 `{}`, discovery identity `{}`.\n\
- Before identity document: {}.\n\
- Current declarations: {}.\n\n\
Outcome `{}` ({}); {} findings; {} new unaccepted tool identities; coverage complete: {}.\n\n\
## Required operator review before any deployment\n\n\
1. Confirm the exact before/after snapshot files and identities above match the upstream \
artifacts under review. Do not rely on names, descriptions or annotations: they are untrusted.\n\
2. Re-read the current operator-owned profile and semantic declarations. A declaration is bound \
to the before identity and does not cover any new exact identity.\n\
3. Review every finding in `report.json`/`findings.csv`, especially `review_required` and \
`unsupported` items and the coverage gaps. Inert metadata findings still produce new, \
unaccepted identities.\n\
4. Review the proposed examples in `review-pack.json`, including `unsupported_case` and \
`unconstructible` records. They are proposals, not labels, approvals or permission.\n\
5. Author any new declaration through the existing review workflow (`agentfw mcp-profile` or \
the selected profile's installer review), then run the applicable existing qualification and \
admission process for the new exact identities. This analyzer performs none of these steps.\n",
        display(&i["before"]["file_name"]),
        digest(&i["before"]),
        display(&i["before"]["discovery_sha256"]),
        display(&i["after"]["file_name"]),
        digest(&i["after"]),
        display(&i["after"]["discovery_sha256"]),
        match &i["before_identity"] {
            Value::Null => "not supplied; the before snapshot was NOT verified".to_owned(),
            v => format!(
                "`{}` raw sha256 `{}` (verified)",
                display(&v["file_name"]),
                digest(v)
            ),
        },
        match &i["current_declarations"] {
            Value::Null => "not supplied; semantics are unknown".to_owned(),
            v => format!("`{}` raw sha256 `{}`", display(&v["file_name"]), digest(v)),
        },
        display(&s["outcome"]),
        display(&s["classification"]),
        s["findings"]["total"],
        s["new_unaccepted_identities"]
            .as_array()
            .map_or(0, Vec::len),
        s["coverage_complete"],
    )
}

fn pretty(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec_pretty(value).expect("JSON values serialize");
    bytes.push(b'\n');
    bytes
}

pub(super) fn render(
    report: &Value,
    pack: &Value,
) -> Result<Vec<(&'static str, Vec<u8>)>, Refusal> {
    let files = vec![
        (FILES[0], pretty(report)),
        (FILES[1], pretty(pack)),
        (FILES[2], csv(report).into_bytes()),
        (FILES[3], text(report, pack).into_bytes()),
        (FILES[4], guide(report).into_bytes()),
    ];
    if files.iter().map(|(_, b)| b.len()).sum::<usize>() > MAX_OUTPUT_BYTES {
        return super::refuse("output_too_large", "rendered output exceeds its bound");
    }
    Ok(files)
}
