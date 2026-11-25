// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Arthur Lin (carbon-evolution)

//! How dangerous is this tool call? Classification is on tool name plus argument
//! patterns, and always resolves to the most severe class that matches.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// Severity ordering of what a tool call does. `Ord` derives from declaration order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    ReadOnly,
    SideEffecting,
    Network,
    PrivilegeChanging,
    Destructive,
}

/// Trusted host interpretation of argument fields, never a deserializable tool
/// annotation. Hosts may select literal fields only after validating the exact
/// installed executor/profile/schema and the complete argument envelope. These
/// roles affect command-pattern upgrades only, not detectors, taint or resources.
#[derive(Debug, Clone, Copy, Default)]
pub enum NativeArgumentRoles {
    #[default]
    CommandBearing,
    ValidatedLiteralFields(&'static [&'static str]),
}

impl NativeArgumentRoles {
    pub(crate) fn classify(self, args: &serde_json::Value, baseline: ActionClass) -> ActionClass {
        let Self::ValidatedLiteralFields(fields) = self else {
            return classify_with_baseline(args, baseline);
        };
        let Some(object) = args.as_object() else {
            return classify_with_baseline(args, baseline);
        };
        // Unreviewed fields remain command-bearing, including nested/argv
        // values. Do not remove anything from the original event itself.
        let commands: serde_json::Map<String, serde_json::Value> = object
            .iter()
            .filter(|(key, _)| !fields.contains(&key.as_str()))
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        classify_with_baseline(&serde_json::Value::Object(commands), baseline)
    }
}

/// Tools that cannot change anything.
const READ_ONLY_TOOLS: &[&str] = &["Read", "Grep", "Glob", "NotebookRead", "TodoRead"];
/// Tools that reach the network but only RETRIEVE. Classified `ReadOnly`: fetching
/// a page is not exfiltrating data, and treating it as `Network` would make the
/// taint rules prompt on the commonest agent workflow there is (read a page, follow
/// one of its links). See the constraint note on this task.
const RETRIEVAL_TOOLS: &[&str] = &["WebFetch", "WebSearch"];

struct Patterns {
    destructive: Regex,
    privilege: Regex,
    network: Regex,
    write: Regex,
    priv_paths: Regex,
}

fn patterns() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| Patterns {
        destructive: Regex::new(
            r"(?ix)
              \brm\s+(-[a-z]*\s+)*-[a-z]*[rf]  # rm -rf / rm -fr
            | \bgit\s+push\b[^|;&\n]*--force
            | \bgit\s+reset\s+--hard
            | \bdrop\s+(table|database)\b
            | \btruncate\s+table\b
            | \bmkfs(\.[a-z0-9]+)?\b
            | \bdd\s+if=.*\bof=/dev/
            | \|\s*(sudo\s+)?(ba)?sh\b                # curl ... | sh
            | \bshutdown\b | \breboot\b
            ",
        )
        .expect("destructive regex"),
        privilege: Regex::new(
            r"(?ix)
              \bsudo\b | \bsu\s+-\b
            | \bchmod\b | \bchown\b
            | \bsetcap\b | \bvisudo\b
            ",
        )
        .expect("privilege regex"),
        // `Network` means data goes OUT. Plain retrieval (`curl URL`, `git clone`,
        // `npm install`) is deliberately NOT here — it is retrieval, and counting it
        // as egress makes the taint rules unusable. Only sending qualifies.
        //
        // The curl short flags (`-d`, `-F`, `-T`) are matched in a case-SENSITIVE
        // sub-group. Under the outer `(?i)` they would otherwise collide with
        // unrelated, extremely common flags: `-f`/`--fail` (silent-fail, the single
        // most common curl flag in agent-generated commands) matching `-F`
        // (multipart upload), and `-D`/`--dump-header` (pure retrieval) matching
        // `-d`/`--data`. Measured false positive: `curl -f https://docs.rs/x` was
        // landing on `Network`. `--data`/`--form`/`--upload-file` stay
        // case-insensitive since their long forms don't collide with anything.
        network: Regex::new(
            r#"(?ix)
              \bcurl\b[^|;&\n]*(?:--data|--data-\w+|--form|--upload-file
                                |-X\s*(?:POST|PUT|PATCH|DELETE)
                                |(?-i:-d\b|-F\b|-T\b))
            | \bwget\b[^|;&\n]*(--post-data|--post-file|--method\s*=\s*(POST|PUT))
            # nc/ncat only count as egress in command position (start of the joined
            # text, or right after a pipe, semicolon, &&, or newline). A bare
            # \bnc\b matched the substring nc anywhere -- inside grep -rn 'nc' src/,
            # cat nc.md, ls nc, prose containing the word nc -- none of which
            # invoke the netcat binary.
            | (?:^|[|;\n]|&&)\s*(?:sudo\s+)?(?:nc|ncat)\b
            | \bscp\b | \brsync\b            # both copy data to a destination
            | \bgit\s+push\b
            | \b(npm|pip|pip3|cargo|gem|go)\s+publish\b
            | \bcargo\s+publish\b
            | \baws\s+s3\s+(cp|sync|mv)\b
            # Cheap, well-known egress channels beyond curl/wget/scp/rsync. Not
            # exhaustive by design -- closing every possible exfil tool is a losing
            # game; these are the ones common enough in agent environments to be
            # worth the fixed cost. gh in particular ships in essentially every
            # coding-agent sandbox, and gh gist create is a one-line public write.
            | \bgh\s+(gist\s+create|issue\s+comment|pr\s+create|release\s+upload
                     |api\b[^|;&\n]*-(f|-field|-input))
            | \baws\s+s3api\s+put-object\b
            | \b(xh|https?ie|http)\s+(POST|PUT|PATCH)\b
            | >\s*/dev/tcp/
            | \bssh\b[^|;&\n]*<
            "#,
        )
        .expect("network regex"),
        write: Regex::new(
            r"(?ix)
              \bmkdir\b | \btouch\b | \bmv\b | \bcp\b | \btee\b | \bsed\s+-i\b
            | >{1,2}\s*\S
            | \brm\b
            | \bgit\s+(commit|add|checkout|merge|rebase)\b
            ",
        )
        .expect("write regex"),
        priv_paths: Regex::new(
            r"(?ix)
              /\.ssh/ | /\.aws/ | /\.gnupg/
            | /\.config/gcloud(?:/|$|[^a-z0-9_])
            | /etc/(passwd|shadow|sudoers)
            | \.env(?:\.|$|[^a-z0-9_]) | /\.npmrc | /\.netrc
            | authorized_keys | id_rsa | credentials
            ",
        )
        .expect("priv path regex"),
    })
}

/// Concatenate every string leaf of the arguments for pattern matching.
///
/// Leaves are joined with a plain space, deliberately allowing patterns to span
/// leaf boundaries. `classify` operates on the whole call, not per-argument, so an
/// argv-array-shaped tool call like `["git", "push", "origin", "main"]` must
/// classify the same as the equivalent single string — otherwise splitting a
/// command across array elements silently drops it below its true class. This is
/// `classify`-only: `facets()` keeps its own per-leaf join (or lack of
/// one) for the core detectors, which is a separate, unrelated tradeoff.
fn args_text(args: &serde_json::Value) -> String {
    let mut leaves = Vec::new();
    crate::facet::string_leaves_pub(args, &mut leaves);
    leaves.join(" ")
}

/// Does this call touch a path that commonly holds credentials? Reported
/// separately from `ActionClass` rather than as a severity bump: reading such a
/// file is not itself dangerous (ordinary repos are full of `.env.example` and
/// `credentials.md`), but combined with taint or with egress it is worth knowing.
pub fn touches_sensitive_path(args: &serde_json::Value) -> bool {
    patterns().priv_paths.is_match(&args_text(args))
}

/// Classify a tool call. Always returns the most severe class that matches.
pub fn classify(tool: &str, args: &serde_json::Value) -> ActionClass {
    let baseline = if READ_ONLY_TOOLS.contains(&tool) || RETRIEVAL_TOOLS.contains(&tool) {
        ActionClass::ReadOnly
    } else if tool == "Bash" {
        // A bare Bash call is only as dangerous as its command.
        ActionClass::ReadOnly
    } else {
        // Write, Edit, MCP tools, anything unknown: assume it changes something.
        ActionClass::SideEffecting
    };
    classify_with_baseline(args, baseline)
}

/// Apply existing argument-pattern upgrades to a trusted host's native baseline.
/// This is a library boundary; generic hook payloads cannot supply the baseline.
pub fn classify_with_baseline(args: &serde_json::Value, baseline: ActionClass) -> ActionClass {
    let p = patterns();
    let text = args_text(args);
    let mut class = baseline;

    fn bump(class: &mut ActionClass, c: ActionClass) {
        if c > *class {
            *class = c;
        }
    }

    if p.write.is_match(&text) {
        bump(&mut class, ActionClass::SideEffecting);
    }
    // Note there is no "retrieval" bump. A plain `curl https://…` or `git clone`
    // simply fails to match `network`, so it stays `ReadOnly`. `egress::hosts()`
    // still extracts the URL independently, so the allowlist rules are unaffected.
    if p.network.is_match(&text) {
        bump(&mut class, ActionClass::Network);
    }
    // `priv_paths` only raises severity when the call is already `SideEffecting`
    // or above — i.e. it is doing something, not merely reading. Reading a file
    // named `credentials.md` or `.env.example` is not itself dangerous (ordinary
    // repos are full of them); a *write* to `~/.ssh/authorized_keys` is. This is
    // "reading is not acting" applied to paths, not just to tool choice: an
    // ordinary `Read`/`Grep`/`Glob` over a sensitive-looking path stays `ReadOnly`,
    // and exfiltration of the file's content is still caught where the harm
    // happens — at the `Network` send, which also carries the content through the
    // secret detector. `touches_sensitive_path` exposes the raw fact for policy.
    let already_acting = class >= ActionClass::SideEffecting;
    if p.privilege.is_match(&text) || (already_acting && p.priv_paths.is_match(&text)) {
        bump(&mut class, ActionClass::PrivilegeChanging);
    }
    if p.destructive.is_match(&text) {
        bump(&mut class, ActionClass::Destructive);
    }
    class
}

#[cfg(test)]
mod tests;
