// SPDX-License-Identifier: Apache-2.0
//! Private source attribution, not a wire permission or model Data verdict.
use super::*;
use std::ops::Range;

pub(super) const FORMATTER: &str =
    "729dc8511e779e5cd6640851a74b25283e3af1ca3a7106722f993e864a1d9935";
const MAX_TEXT: usize = 1024 * 1024;

pub(super) fn target(tool: &Tool) -> bool {
    (tool.name == "read_multiple_files"
        && tool.mcp_result_profile.as_deref() == Some(crate::mcp::server_profile::FORMAT))
        // Git's untyped flattened git_show can also be a raw blob. Until an
        // object-kind/snapshot witness exists, keep baseline, not an ML bypass.
        || (tool.name == "git_show" && tool.mcp_result_profile.as_deref().is_some_and(crate::mcp::server_profile::git_selected))
}

#[derive(Clone, Debug)]
struct Record {
    path: Range<usize>,
    header_fixed: Range<usize>,
    body: Range<usize>,
    trailer: Range<usize>,
}

/// No Deserialize, public fields, external constructor, or caller assertion.
pub(super) struct ResultEvidence {
    scope: String,
    channels: String,
    separators: Vec<Vec<Range<usize>>>,
    _records: Vec<Vec<Record>>,
}

fn scope(tool: &Tool, request: &Request, call: &Call) -> Option<String> {
    if !mcp_host_result(request)
        || request.result_kind.as_deref() != Some("value")
        || call.stage != Stage::Result
        || call.tool != tool.name
        || call.contract_version != request.contract_version
        || request.tool.as_deref() != Some(tool.name.as_str())
        || call.args_sha256 != args_hash(request.args.as_ref()?)
        || tool.mcp_result_profile.as_deref() != Some(crate::mcp::server_profile::FORMAT)
        || tool.name != "read_multiple_files"
        || !matches!(tool.result_provenance, ResultProvenance::Untrusted)
        || tool.action_class != ActionClass::ReadOnly
        || !tool.egress.is_empty()
    {
        return None;
    }
    let identity: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../profiles/mcp/filesystem-readonly-v1/upstream-identity.json"
    )))
    .ok()?;
    if identity["package"]["originalEntrypointSha256"] != FORMATTER {
        return None;
    }
    let manifest = crate::mcp::server_profile::original_manifest();
    let definition = manifest["tools"]
        .as_array()?
        .iter()
        .find(|t| t["name"] == tool.name)?;
    if canonical_digest(&definition["inputSchema"]) != tool.schema_sha256 {
        return None;
    }
    let profiles = crate::mcp::server_profile::classify_manifest(&manifest).ok()?;
    let profile = profiles.get(&tool.name)?;
    profile.validate_arguments(request.args.as_ref()?).ok()?;
    let frame: Value = serde_json::from_str(request.content.as_deref()?).ok()?;
    if frame.get("id") != Some(call.host_call_id.as_ref()?)
        || profile.validate_result(&frame).ok()? != "value"
    {
        return None;
    }
    Some(canonical_digest(&json!([
        FORMATTER,
        request.contract_version,
        request.registry_sha256,
        request.session_id,
        request.call_id,
        tool.name,
        tool.schema_sha256,
        call.binding_sha256,
        call.args_sha256,
        hash(request.content.as_deref()?.as_bytes())
    ])))
}

/// Conservative uniqueness proof for the pinned SUCCESS formatter:
/// `${path}:\n${body}\n`, joined by `\n---\n`. Each next boundary must
/// occur exactly once in the COMPLETE channel, in admitted path order.
/// Repeated paths, errors and fake headers in bodies cannot grant attribution.
fn partition(text: &str, paths: &[&str]) -> Option<(Vec<Range<usize>>, Vec<Record>)> {
    if text.len() > MAX_TEXT
        || paths.is_empty()
        || paths.len() > 256
        || paths.iter().collect::<BTreeSet<_>>().len() != paths.len()
        || !text.starts_with(&format!("{}:\n", paths[0]))
        || !text.ends_with('\n')
    {
        return None;
    }
    // Charge both full scans per path before doing any work. Across the two
    // channels attribution searches at most 64 MiB, irrespective of payload.
    if text.len().checked_mul(paths.len().checked_mul(2)?)? > 32 * 1024 * 1024 {
        return None;
    }
    let mut headers = vec![0];
    let mut boundaries = Vec::new();
    // Bounded by at most 256 * MAX_TEXT bytes searched, no recursive/backtracking
    // parser. Two candidates suffice to reject ambiguity; never choose greedily.
    for path in paths.iter().skip(1) {
        let marker = format!("\n\n---\n{path}:\n");
        let mut matches = text.match_indices(&marker);
        let start = matches.next()?.0;
        if matches.next().is_some() || start < *headers.last()? + paths[headers.len() - 1].len() + 2
        {
            return None;
        }
        boundaries.push(start);
        headers.push(start + 6);
    }
    let mut separators = Vec::new();
    let mut records = Vec::new();
    for (i, path) in paths.iter().enumerate() {
        let path_start = headers[i];
        let header = format!("{path}:\n");
        let mut occurrences = text.match_indices(&header);
        if occurrences.next()?.0 != path_start || occurrences.next().is_some() {
            return None;
        }
        let body_start = path_start + path.len() + 2;
        let body_end = boundaries.get(i).copied().unwrap_or(text.len() - 1);
        let trailer_end = headers.get(i + 1).copied().unwrap_or(text.len());
        if body_start > body_end {
            return None;
        }
        if i + 1 < paths.len() {
            separators.push(body_end + 2..body_end + 5);
        }
        records.push(Record {
            path: path_start..path_start + path.len(),
            header_fixed: path_start + path.len()..body_start,
            body: body_start..body_end,
            trailer: body_end..trailer_end,
        });
    }
    // Every received byte has one role. Path/body roles never become trusted.
    let mut cursor = 0;
    for r in &records {
        for span in [&r.path, &r.header_fixed, &r.body, &r.trailer] {
            if span.start != cursor || text.get(span.clone()).is_none() {
                return None;
            }
            cursor = span.end;
        }
    }
    if cursor != text.len() {
        return None;
    }
    Some((separators, records))
}

impl ResultEvidence {
    pub(super) fn derive(
        tool: &Tool,
        request: &Request,
        call: &Call,
        channels: &[String],
    ) -> Option<Self> {
        let scope = scope(tool, request, call)?;
        // Both original channels are inspected, never deduplicated. Equality is
        // a requirement of this exact pinned formatter, not an assumption.
        if channels.len() != 2
            || channels[0] != channels[1]
            || selected_result_texts(tool, request).ok()?.as_slice() != channels
        {
            return None;
        }
        let args = request.args.as_ref()?;
        let paths = args["paths"]
            .as_array()?
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<_>>>()?;
        let mut separators = Vec::new();
        let mut records = Vec::new();
        for channel in channels {
            let (s, r) = partition(channel, &paths)?;
            separators.push(s);
            records.push(r);
        }
        Some(Self {
            scope,
            channels: canonical_digest(&json!(channels)),
            separators,
            _records: records,
        })
    }
    pub(super) fn spans(
        &self,
        tool: &Tool,
        request: &Request,
        call: &Call,
        channels: &[String],
    ) -> Option<&[Vec<Range<usize>>]> {
        if scope(tool, request, call)? != self.scope
            || canonical_digest(&json!(channels)) != self.channels
        {
            return None;
        }
        Some(&self.separators)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(count: usize, body: &str) -> (Tool, Request, Call, Vec<String>) {
        let paths = (0..count)
            .map(|i| format!("/workspace/file_{i:03}.txt"))
            .collect::<Vec<_>>();
        let text = paths
            .iter()
            .map(|p| format!("{p}:\n{body}\n"))
            .collect::<Vec<_>>()
            .join("\n---\n");
        let channels = vec![text.clone(), text.clone()];
        let manifest = crate::mcp::server_profile::original_manifest();
        let def = manifest["tools"]
            .as_array()
            .unwrap()
            .iter()
            .find(|d| d["name"] == "read_multiple_files")
            .unwrap();
        let tool: Tool=serde_json::from_value(json!({"name":"read_multiple_files","schema_sha256":canonical_digest(&def["inputSchema"]),"action_class":"read_only","result_provenance":"untrusted","egress":[],"mcp_result_profile":crate::mcp::server_profile::FORMAT})).unwrap();
        let args = json!({"paths":paths});
        let content=json!({"jsonrpc":"2.0","id":550,"result":{"content":[{"type":"text","text":text}],"structuredContent":{"content":text}}}).to_string();
        let request: Request=serde_json::from_value(json!({"contract_version":CONTRACT,"registry_sha256":"a".repeat(64),"session_id":"proof","event":"result","tool":tool.name,"args":args,"call_id":"call1","content":content,"result_kind":"value","delivery":"mcp_host"})).unwrap();
        let call = Call {
            managed_policy: None,
            host_call_id: Some(json!(550)),
            contract_version: CONTRACT,
            tool: tool.name.clone(),
            args_sha256: args_hash(&args),
            binding_sha256: "b".repeat(64),
            stage: Stage::Result,
            expires: Instant::now() + TTL,
            result_kind: None,
        };
        (tool, request, call, channels)
    }

    #[test]
    fn private_evidence_binds_call_frame_schema_args_and_all_channels() {
        let (tool, mut request, mut call, channels) = fixture(50, "ordinary document");
        let proof = ResultEvidence::derive(&tool, &request, &call, &channels).unwrap();
        assert_eq!(
            proof.spans(&tool, &request, &call, &channels).unwrap()[0].len(),
            49
        );
        let original = call.binding_sha256.clone();
        call.binding_sha256 = "c".repeat(64);
        assert!(proof.spans(&tool, &request, &call, &channels).is_none());
        call.binding_sha256 = original;
        let original = request.args.clone();
        request.args = Some(json!({"paths":["/workspace/other"]}));
        assert!(proof.spans(&tool, &request, &call, &channels).is_none());
        request.args = original;
        let original = request.content.clone();
        request.content.as_mut().unwrap().push(' ');
        assert!(proof.spans(&tool, &request, &call, &channels).is_none());
        request.content = original;
        let mut changed = channels.clone();
        changed[1].push('x');
        assert!(proof.spans(&tool, &request, &call, &changed).is_none());
        assert!(ResultEvidence::derive(&tool, &request, &call, &changed).is_none());
        assert!(ResultEvidence::derive(&tool, &request, &call, &channels[..1]).is_none());
        let mut duplicated = channels.clone();
        duplicated.push(channels[0].clone());
        assert!(ResultEvidence::derive(&tool, &request, &call, &duplicated).is_none());
        let mut unknown = tool.clone();
        unknown.mcp_result_profile = Some("unreviewed-formatter".into());
        assert!(ResultEvidence::derive(&unknown, &request, &call, &channels).is_none());
        unknown = tool.clone();
        unknown.schema_sha256 = "d".repeat(64);
        assert!(ResultEvidence::derive(&unknown, &request, &call, &channels).is_none());
        call.host_call_id = Some(json!(551));
        assert!(ResultEvidence::derive(&tool, &request, &call, &channels).is_none());
    }

    #[test]
    fn wire_cannot_claim_trust_or_offsets() {
        let (_, request, _, _) = fixture(4, "ordinary");
        let base = json!({"contract_version":request.contract_version,"registry_sha256":request.registry_sha256,"session_id":"proof","event":"result","tool":request.tool,"args":request.args,"call_id":"call1","content":request.content,"result_kind":"value","delivery":"mcp_host"});
        for key in ["result_evidence", "trusted", "source", "formatter_spans"] {
            let mut forged = base.clone();
            forged[key] = json!({"trusted":true,"offsets":[[0,3]]});
            assert!(parse(&forged.to_string()).is_err(), "{key}");
        }
    }

    #[test]
    fn repeated_own_header_and_work_cap_fail_closed() {
        let paths = ["/workspace/a", "/workspace/b"];
        let text = "/workspace/a:\n/workspace/a:\nfake\n\n---\n/workspace/b:\nreal\n";
        assert!(partition(text, &paths).is_none());
        let large = format!(
            "/workspace/a:\n{}\n\n---\n/workspace/b:\nreal\n",
            "x".repeat(MAX_TEXT)
        );
        assert!(partition(&large, &paths).is_none());
    }
    #[test]
    fn unicode_offsets_and_full_partition() {
        let paths = ["/workspace/機能.txt", "/workspace/café.txt"];
        let text = format!("{}:\ncafé\r\n\n\n---\n{}:\n末尾\n", paths[0], paths[1]);
        let (spans, records) = partition(&text, &paths).unwrap();
        assert_eq!(&text[spans[0].clone()], "---");
        assert_eq!(&text[records[0].body.clone()], "café\r\n");
        assert_eq!(&text[records[1].body.clone()], "末尾");
    }
    #[test]
    fn ambiguous_body_headers_and_wrong_paths_retain_baseline() {
        let paths = ["/workspace/a", "/workspace/b"];
        let real = "/workspace/a:\nbody\n\n---\n/workspace/b:\nbody\n";
        assert!(partition(real, &paths).is_some());
        let fake = "/workspace/a:\nbody\n\n---\n/workspace/b:\nfake\n\n---\n/workspace/b:\nreal\n";
        assert!(partition(fake, &paths).is_none());
        assert!(partition(real, &[paths[1], paths[0]]).is_none());
        assert!(partition(real, &[paths[0], paths[0]]).is_none());
        assert!(partition(real, &[paths[0], "/workspace/unknown"]).is_none());
        assert!(partition(real.trim_end_matches('\n'), &paths).is_none());
        assert!(partition("/workspace/a: Error - denied", &paths[..1]).is_none());
    }
}
