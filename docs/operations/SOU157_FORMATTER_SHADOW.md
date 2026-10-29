# Verified diagnostic checkpoint - 2026-10-29

The previously pending native diagnostic passed on exact source
`f00889e56383e6776ca66e3e3382d2040437d861` in run
[40860551932](https://github.com/SoupTeam/soup-wall/actions/runs/40860551932),
job 123402467586. Independent review 5696811674 closes the refusal-contract
and native-diagnostic blocker, not SOU-157 itself.

Artifact 12891417745 ZIP SHA-256:
`3f4e0b3f269dbd53e8f2db01b56d4063ce1f79c5be3be5a5f6daf5587dc3e480`.
Agent SHA-256: `59d932d667a601f0b3af97e1e56641c28cdb733757f15a75ea5c87d2dc968043`.
Downloaded hash and archive CRC verified; retained reports are under
`evidence/sou157-passed-native-40860551932`. Local replay of the diagnostic
projection function passes against that exact historical source, without rerunning
native execution or inference. The command-line POSIX file-opening gate cannot
run on this Windows host (`O_NOFOLLOW` unavailable); it was not bypassed or counted
as passing. JSON reports were loaded directly for the pure projection comparison.
Earlier failed evidence remains unchanged.

Four 50/200 benign/attack cases have original formatter witnesses. All four
201/256 cases remain pre-execution unknown/truncated, with the exact selected
server refusal `classifier_unknown_approval_unsupported`. Ambiguous-body and
matched copied-wire controls pass; cleanup and empty owned root pass. Model calls
are zero. This proves diagnostic attribution and refusal controls only:
`production_authority=false`, `task_complete=false`. Ten production false refusals
remain; no Ready/Done/merge claim or new production authority is introduced.

The next scoped work is a shadow comparison using this proven private binding:
attribute only exact formatter separator spans, preserve full original body and
cross-field inspection, and report which structural findings are exclusively
formatter-owned versus overlapping user content. An absent/ambiguous/counterfeit
binding must retain the complete baseline outcome. Any production decision change
still requires separate review; the non-executed 201/256 cases cannot count as
successful attributed executions. Historical sections below describe earlier
checkpoints and their then-pending verification.

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

## Implemented diagnostic and validation

`native/execution/formatter.rs` derives bounded ranges only after the existing
affine result is consumed. `Metadata.formatter_shadow` is optional and descriptive;
it is never passed to a detector, scoring function or policy rule. The selected
profile is bound by the existing catalogue and sealed runtime closure identities.
Both duplicate text channels remain inspected in full by the unchanged pipeline.

Windows: 19 execution tests and the broader 145 native tests passed; agentfw
library Clippy with `-D warnings` passed. These include component custody/tamper
controls, exact B16-B19-size spans and baseline verdict/reason equality. They
are explicitly not a fresh Linux runtime witness. No model was run again.

The existing isolated Linux runtime harness has an opt-in `--formatter-shadow`
mode. Its default run is unchanged. With the flag, it prepares public inputs,
submits eight size/attack pairs, checks the exact
attribution hash/ranges against expected original bytes, retains each original
refusal, and tests body-delimiter ambiguity and copied metadata rejection.
Results go to `formatter-shadow.json`, initially `incomplete`; a failed assertion
cannot produce `passed-diagnostic-only`. The existing SOU-155 projection gate is
not a SOU-157 gate and must not be used to claim acceptance of this optional run.

The reviewer must run that flag under the existing owned Linux lane's isolation
and exact-source prerequisites. This Windows host has no working WSL distribution;
no Linux setup or security settings were changed. Fresh runtime attribution and
tamper evidence remain pending, as do production relief and full SOU-157 acceptance.

## Controller corrections after reviews 5682517028 and 5683134260

The earlier plan incorrectly expected all eight pairs to reach execution. The
actual pinned rule baseline has MAX_LEAVES=200: 50/200 paths classify as known
read, while 201/256 retain read plus unknown/partial_unknown/truncated. The
controller now reproduces that exact schema/argument classification and requires
the real invocation Ask refusal and absence of private native-result rows for
the four >=201 pairs. They are retained as `pre_execution_unknown`, never as
executed formatter witnesses. Classifier limits and Ask behavior are unchanged.

The copied-metadata control now uses the existing ordinary native session helper.
It issues a complete valid baseline result, confirms baseline-only release, then
uses a fresh matched session/call and the same result fields plus copied execution
metadata. HTTP 400 alone is insufficient: `native_invalid_fields` is required.
Fresh receipts and session cleanup are retained; no successful result is replayed.

The existing workflow now explicitly accepts `formatter_shadow=true`, validated
with `prepared_focus=155` and `prepared_host=true`. It forwards the flag only
when selected and retains both sidecar and diagnostic projection even on failure.
Default SOU-155 qualification and its unchanged projection remain on the default
branch. The opt-in uses a separate SOU-157 diagnostic check requiring all ten
rows, four pre-execution Unknown outcomes, four attributed pairs, ambiguity and
the matched wire refusal, plus successful isolated runtime cleanup. Its output
explicitly denies task completion, production authority and SOU-155 acceptance.

Controller regressions: 4/4 passed, including actual baseline classifications,
simulated pre-execution admission versus actual-result rows, valid matched wire
shape/specific error/cleanup, missing/changed/failed diagnostic reports, workflow
retention, and execution of the shell flag selection for unset/false/true.
Workflow YAML parsed and extracted shell passed `bash -n`. The combined run
with the existing SOU-155 Linux-oriented suite had one failure, seven errors and
one skip on Windows (O_NOFOLLOW, /bin/bash, /proc and POSIX path assumptions);
these are not counted as passing or changed to hide the unsupported platform.
No runtime lane has been dispatched by this update; independent Linux verification
is still required before any production change. No model replay occurred.
