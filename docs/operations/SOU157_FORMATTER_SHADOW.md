# Verified filesystem formatter attribution: Draft/shadow plan

Review 5679214903 and TL Telegram direction on 28 October authorize diagnostic
implementation only. This builds on reviewed main db4f006d and existing affine
`native::execution::OriginalResult` custody. No launch, IPC, profile, policy,
classifier or production score changes are proposed.

## Finite public controls declared before implementation

For each B16-B19 size (50, 200, 201, 256 files), generate deterministic public
ordinary file contents and a matched destructive command in the last file.
Expect the same formatter-owned separator ranges for both, complete unchanged
inspection of both text/structured channels, and no policy relief for either.
Additional controls: a separator within file content; a path containing a newline;
missing/reordered path header; mismatched structured/text copies; partial/error
response; Unicode content; excessive paths/text. Ambiguous decomposition emits no
attribution. Native controls must reject altered result, invocation, call/session,
epoch/process/catalogue/profile binding and unauthenticated copied metadata.

## Construction and trust boundary

The locked original entrypoint SHA-256 is
`729dc8511e779e5cd6640851a74b25283e3af1ca3a7106722f993e864a1d9935`.
Its `read_multiple_files` maps each requested path to `path + ":\n" + body +
"\n"`, then joins in request order with `\n---\n`, returning identical text and
structured content. The original archive hash was checked before inspecting
the source. Errors are deliberately outside this prototype.

After existing private-custody validation, derive spans only for that exact tool
and selected profile, successful complete response, identical channels, bounded
newline-free paths, exact ordered path headers and exactly N-1 separators.
The pinned implementation necessarily inserts N-1 separators. Thus exactly N-1
occurrences leaves none inside a path or body; extra occurrences fail closed.
Only those separator byte ranges are attributed. Headers, body, errors and all
other bytes remain untrusted. Full text hash/byte coverage and both channel
coordinates accompany the diagnostic in existing execution metadata, already
bound to catalogue, closure, process/channel, epoch, invocation, call and raw
result hashes. No caller can deserialize this metadata into custody.

The parser alone proves nothing about origin. Synthetic component witnesses must
be labelled as such. A fresh Linux daemon-owned execution witness plus tamper
refusal remains required for runtime qualification; local Windows component
tests cannot substitute for it. No fresh runtime success is claimed by this plan.
