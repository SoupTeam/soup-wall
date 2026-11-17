// SPDX-License-Identifier: Apache-2.0
//! JSON with comments/trailing commas, preserving bytes outside the selected entry.
//! The existing strict visitor still rejects duplicate members and invalid JSON.
use anyhow::{ensure, Context, Result};
use serde_json::Value;
use std::ops::Range;

fn string_end(bytes: &[u8], start: usize) -> Result<usize> {
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => return Ok(i + 1),
            b'\\' => i += 2,
            _ => i += 1,
        }
    }
    anyhow::bail!("unterminated JSONC string")
}

fn normalize(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut out = bytes.to_vec();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = string_end(bytes, i)?,
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && !matches!(bytes[i], b'\n' | b'\r') {
                    out[i] = b' ';
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                let start = i;
                i += 2;
                while i + 1 < bytes.len() && &bytes[i..i + 2] != b"*/" {
                    i += 1;
                }
                ensure!(i + 1 < bytes.len(), "unterminated JSONC comment");
                i += 2;
                out[start..i].fill(b' ');
            }
            _ => i += 1,
        }
    }
    i = 0;
    while i < out.len() {
        if out[i] == b'"' {
            i = string_end(&out, i)?;
            continue;
        }
        if out[i] == b',' {
            let mut j = i + 1;
            while out.get(j).is_some_and(u8::is_ascii_whitespace) {
                j += 1;
            }
            if matches!(out.get(j), Some(b'}' | b']')) {
                let previous = out[..i].iter().rfind(|b| !b.is_ascii_whitespace());
                ensure!(
                    previous.is_some_and(|b| !matches!(b, b'{' | b'[' | b',' | b':')),
                    "invalid JSONC trailing comma"
                );
                out[i] = b' ';
            }
        }
        i += 1;
    }
    Ok(out)
}

pub(super) fn parse(bytes: &[u8]) -> Result<Value> {
    let normalized = normalize(bytes)?;
    let crate::mcp::admission::Strict(value) = serde_json::from_slice(&normalized)
        .map_err(|_| anyhow::anyhow!("invalid or duplicate JSONC fields"))?;
    Ok(value)
}

fn space(bytes: &[u8], mut i: usize) -> usize {
    while bytes.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    i
}

// Called only after strict validation, on normalized bytes with unchanged offsets.
fn value_end(bytes: &[u8], start: usize) -> Result<usize> {
    if bytes[start] == b'"' {
        return string_end(bytes, start);
    }
    if matches!(bytes[start], b'{' | b'[') {
        let mut depth = 0;
        let mut i = start;
        while i < bytes.len() {
            match bytes[i] {
                b'"' => {
                    i = string_end(bytes, i)?;
                    continue;
                }
                b'{' | b'[' => depth += 1,
                b'}' | b']' => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(i + 1);
                    }
                }
                _ => {}
            }
            i += 1;
        }
        anyhow::bail!("unterminated JSONC value");
    }
    let mut i = start;
    while i < bytes.len()
        && !matches!(bytes[i], b',' | b'}' | b']')
        && !bytes[i].is_ascii_whitespace()
    {
        i += 1;
    }
    Ok(i)
}

fn field(bytes: &[u8], object: Range<usize>, name: &str) -> Result<Range<usize>> {
    let mut i = space(bytes, object.start);
    ensure!(
        bytes.get(i) == Some(&b'{'),
        "selected JSONC value must be an object"
    );
    i = space(bytes, i + 1);
    while i < object.end && bytes[i] != b'}' {
        ensure!(bytes[i] == b'"', "invalid JSONC member");
        let end = string_end(bytes, i)?;
        let key: String = serde_json::from_slice(&bytes[i..end])?;
        i = space(bytes, end);
        ensure!(bytes.get(i) == Some(&b':'), "invalid JSONC member");
        let start = space(bytes, i + 1);
        let end = value_end(bytes, start)?;
        if key == name {
            return Ok(start..end);
        }
        i = space(bytes, end);
        if bytes.get(i) == Some(&b',') {
            i = space(bytes, i + 1);
        }
    }
    anyhow::bail!("selected JSONC entry not found")
}

pub(super) fn replace(bytes: &[u8], servers: &str, name: &str, entry: &Value) -> Result<Vec<u8>> {
    let mut expected = parse(bytes)?;
    ensure!(
        expected.get(servers).and_then(|s| s.get(name)).is_some(),
        "selected JSONC entry not found"
    );
    expected[servers][name] = entry.clone();
    let normalized = normalize(bytes)?;
    let outer = field(&normalized, 0..normalized.len(), servers)?;
    let selected = field(&normalized, outer, name)?;
    let mut output = Vec::with_capacity(bytes.len());
    output.extend_from_slice(&bytes[..selected.start]);
    output.extend_from_slice(&serde_json::to_vec_pretty(entry).context("encode selected entry")?);
    output.extend_from_slice(&bytes[selected.end..]);
    ensure!(
        parse(&output)? == expected,
        "JSONC replacement changed unrelated settings"
    );
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn comments_escaped_keys_and_unrelated_secret_bytes_survive() {
        let prefix = "/* start */ {\"mcpServers\": {\"lo\\u0063al.test\": ";
        let suffix = ", // retain\n\"other\": {\"env\":{\"TOKEN\":\"synthetic-secret\"},},},\"url\":\"https://example.invalid/*text*/\",}\n";
        let input = format!("{prefix}{{\"command\":\"/bin/true\",\"args\":[],}}{suffix}");
        let entry = json!({"command":"/usr/bin/env","args":["-i","a\\b\"c"]});
        let output = replace(input.as_bytes(), "mcpServers", "local.test", &entry).unwrap();
        let text = std::str::from_utf8(&output).unwrap();
        assert!(text.starts_with(prefix));
        assert!(text.ends_with(suffix));
        assert_eq!(parse(&output).unwrap()["mcpServers"]["local.test"], entry);
        let restored = replace(
            &output,
            "mcpServers",
            "local.test",
            &json!({"command":"/bin/true","args":[]}),
        )
        .unwrap();
        assert_eq!(parse(&restored).unwrap(), parse(input.as_bytes()).unwrap());
    }

    #[test]
    fn ambiguous_and_invalid_inputs_are_refused_without_values() {
        for text in [
            "{\"a\":1,/*x*/\"a\":2}",
            "{\"a\":1,\"\\u0061\":2}",
            "{\"a\":[,]}",
            "{\"a\":1,,}",
            "{/* open",
            "{\"x\":\"synthetic-secret}",
            "{unquoted:1}",
            "{\"a\": NaN}",
            "{} trailing",
        ] {
            assert!(!parse(text.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("synthetic-secret"));
        }
    }
}
