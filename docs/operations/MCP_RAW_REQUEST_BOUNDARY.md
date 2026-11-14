# Raw MCP request boundary (SOU-182)

The generic collector and the installed selected filesystem and Git relays read
bounded newline-delimited byte frames. Their production request path uses the
same recursive strict Rust JSON decoder in `crates/agentfw/src/mcp/admission.rs`.
It rejects duplicate members at every object depth. The selected relay also
applies its existing depth and node budget before request routing. The
classifier and original server receive a `tools/call` only after the frame,
envelope, request ID, method, selected tool, arguments and native policy pass
their respective gates. The tests added for this issue exercised the existing
decoder; no second parser or runtime rule was introduced.

| Raw request | Supported boundary | Response / continuation |
| --- | --- | --- |
| One valid ID, original advertised tool and valid arguments | Parsed, admitted and dispatched under the selected profile | Original correlated result; useful read is the positive control |
| Duplicate tool name, duplicate argument or any nested member, duplicate ID | Strict decoder refuses the entire frame | Fatal; no guessed ID or response |
| NaN, lone Unicode surrogate, invalid UTF-8, incomplete or trailing JSON | Strict decoder refuses the entire frame | Fatal; no response |
| Unterminated frame at EOF | Framer refuses the partial bytes | Fatal; no response |
| Frame above 262,144 bytes; selected JSON above depth 20 or node budget | Existing framer / selected limit refuses | Fatal; no response |
| Boolean, null, fractional, unsafe integer or otherwise invalid ID | Request ID validation refuses | Fatal; no response |
| Valid ID and unsupported tool name | Existing selected tool lookup refuses before execution | Correlated `-32601`; the same session accepts a later useful read |

An incomplete frame that remains open is pending input, not a successful
classifier test. EOF makes its terminal refusal observable. Fatal parse and ID
errors do not invent an ID, discard unsupported members or continue a session
with uncertain framing. Error diagnostics are bounded categories and must not
echo raw input. An already dispatched call is a separate execution state;
these pre-dispatch cases make no rollback claim.

## Focused native qualification

Dispatch `Real Git MCP profile` with `raw_boundary_only=true` on the exact
clean candidate SHA. That focused Ubuntu 22.04 job builds the repository-pinned
Agent, pinned Git and bubblewrap and pinned Node runtime. The private driver
`scripts/verify-sou182-raw-mcp.py` installs both original selected profiles
outside the source checkout. It runs 16 malformed/ambiguous raw byte cases per
profile, plus a recoverable refusal and useful follow-up. Each fatal case uses
a fresh owned collector and original server. A Linux inotify witness first
observes a real allowed read, is drained, and then must observe zero workspace
opens for the rejected frame. The driver also requires no response delivery,
no additional classifier event beyond the positive read, unchanged workspace
bytes and metadata, a failed fatal relay, and stopped
owned descendants. The recoverable control requires the exact ID and error
code, zero opens on refusal, and a later real read with a new kernel event.

The job uploads `report.json` and runtime input hashes even if an attempt
fails. The versioned report has the exact source commit/tree, binary and driver
digests, per-case raw SHA-256 and byte length, finite failure category, kernel
event count, response delivery, workspace state and cleanup result. It contains
no raw malformed frames or credentials. `status=pass`, both profile statuses,
all case statuses and `failed=0` are required; an incomplete or failed attempt
does not count. Inspect the workflow run and artifact together before citing
it from SOU-128.

Python's `json.loads` alone cannot establish this boundary: it accepts
duplicate members by replacing earlier values and may accept non-finite
constants. The source of truth for these probes is the Rust production
decoder through the generic and selected `tools/call` paths, followed by the
native installed-server witness. These controls do not grade an optional
classifier or change SOU-128 metamorphic labels.
