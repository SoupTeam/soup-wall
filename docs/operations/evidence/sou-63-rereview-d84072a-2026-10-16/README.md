# SOU-63 re-review of d84072a — REQUEST CHANGES

Exact head: `d84072a40a2da6faff9b084d3084a20dead048c4`, PR #146. All six previous router witnesses now pass. All 65 shipped native endpoint tests pass. This credits the repaired empty-tool scope, active-session expiry, basic cross-collector Deny, active-child SessionEnd protection, oversized-result marker and removed accidental extractor 413. CLI/collector both-or-neither checks are present.

Five additional independent router controls reproduce four remaining blockers. Product source/tests were not changed; witnesses were added only to an exact-head source archive inside a no-network sandbox with writes restricted to review scratch.

## Findings

1. **[P1] Preserve host Ask and the incomplete-history floor when merging outcomes — `crates/agentfw/src/native.rs:947-954`.** The merge handles Deny and one Escalate case but ignores Ask. Copying `provenance_incomplete` and a reason does not recompute the verdict. Two executed witnesses show (a) a signed host-bound collector network call reusing server A's text is allowed despite the host policy returning Ask, and (b) after oversized PostToolUse correctly marks the host incomplete, a bound collector's destructive call still gets `verdict=allow`, `release=true` and an execution receipt, even with `reason_codes=["taint-history-incomplete"]`. Resolve both outcomes, preserve the strictest required disposition, and keep its matching audit metadata. Maintain exact Ask redemption and never weaken Deny.

2. **[P1] Bound body consumption before the String extractor — `crates/agentfw/src/lib.rs:59-63`, `handlers.rs:166-177`.** Disabling DefaultBodyLimit makes String extraction unbounded; authentication and max_body_bytes execute only after the entire request has been buffered. An unauthenticated streamed request with a configured 1 KiB cap consumed all eight 1 KiB chunks before returning 401. There is no stream-time cap. The same change removes protection from `/mcp`, whose handler has no max_body_bytes check at all. Authenticate early and implement bounded body reading/explicit over-cap handling; retain an actual bound on both routes. Do not restore the old accidental hook 413 as the disposition.

3. **[P1] Return an explicit enforce disposition for oversized/malformed protected PreToolUse — `crates/agentfw/src/handlers.rs:177-199`.** Marking future history incomplete does not block the current operation. An authenticated oversized PreToolUse with `enforce=true` returns HTTP 200 `{}`, which means no opinion to the host, instead of a documented Ask/Deny. The witness contains a destructive Bash command but executes nothing. The malformed-payload branch retains the same empty response. Preserve legacy compatibility explicitly; protected enforce requests need the promised explicit response even when inspection is incomplete.

4. **[P1] Record incomplete history on content truncation, not only body rejection — `crates/agentfw/src/handlers.rs:234-274`.** A valid PostToolUse below the body cap, with max_record_bytes=64 and a longer untrusted result, has `truncated=true` in audit but `provenance_incomplete(host)=false`. The discarded suffix can contain the only evidence used by a later protected call. Mark history incomplete using the authenticated shared identity whenever mapping or inspection discards result content; preserve that floor across collectors. This requirement was already explicit in SOU-63 deliverable 4.

## Reproduction

Apply `reviewer-witnesses.patch` only in a disposable checkout of the exact head:

```sh
cargo test --offline -p agentfw --test native_endpoint reviewer_ -- --nocapture
cargo test --offline -p agentfw --test native_endpoint rereview_ -- --nocapture
cargo test --offline -p agentfw --test native_endpoint -- --skip rereview_
```

Expected current results: six original witnesses pass; five additional security assertions fail; all 65 shipped tests pass. `results.json` records source hashes, patch hash and observed results without credentials or private payloads. Runtime testing was confined to an isolated copy under `/private/tmp/sou63-review/d84072a`, with separate Cargo output, no network and no actual tool execution. Full workspace tests and Clippy were not rerun here; current-head CI was still running at inspection.

This re-review also does not establish that the original authenticated actual-agent/parent identity, parent resource/destination containment, restart/revocation and support-matrix deliverables have been implemented. Those broader gaps from the first report remain separate acceptance requirements; passing the six original tests is insufficient to close the entire task.
