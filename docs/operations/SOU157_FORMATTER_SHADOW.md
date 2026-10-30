# Current verified shadow checkpoint - 2026-10-30

Independent review 5711682866 accepted the bounded scoring increment at
`b94acf7884015a5902f3a2aa58dbf452d7bcf047`. Linux run
[41049689556](https://github.com/SoupTeam/soup-wall/actions/runs/41049689556)
completed successfully on that exact source. Runtime artifact 12973594859 has
ZIP SHA-256 `6b0dfc8cc38c64b28df21867308b19a0b2269e4aabb299e807d5fdabd7adf71a`.
Hash, four unique archive members and CRC were verified locally. The existing
pure diagnostic projection reproduces the retained acceptance report. Its POSIX
file-opening CLI was not run on Windows. Telegram TL acceptance was read at
17:05; this accepts the shadow run, not production enablement or task closure.

Retained evidence: `evidence/sou157-passed-native-41049689556`. All four executed
50/200 cases (two benign, two attacks) have baseline heuristic about 0.3 and shadow
heuristic 0.0, with unchanged refusal. Thus the candidate number alone does NOT
separate attacks from benign results. The four 201/256 cases remain refused before
execution; ambiguity and copied-wire controls pass. Runtime cleanup passed and
model calls were zero. No native/model run was repeated locally.

The full public adapter was rebuilt at this source with an empty tracked diff.
All 51 cases were retained under `evidence/sou157-b94acf78-corpus`: 24/24 attacks
refused, zero misses, 10/24 benign false refusals, zero semantic unknowns, and
three separately reported technical cases. The gate correctly exits 1 (FAIL).
All 51 label/outcome/verdict/rule tuples match the previous destructive-evidence
checkpoint, as do every payload hash, manifest and policy. This is an unattested
Windows policy-preview regression, not native corpus execution or production relief.

Next production proposal must route opaque consumed original-result evidence into
the existing complete inspection, replace only its heuristic component, and then
recompose the full policy with signatures, directives, independent hard floors,
cross-field evidence and existing ML/budget behavior. A public score or caller
range must never enter this route. The current four native examples do not yet
prove that recomposition; quoted-signature/reviewer-bot cases remain unresolved.
This proposal needs separate review before production enablement. Do not infer
that the ten corpus refusals were repaired by the successful diagnostic run.

The following sections retain historical checkpoints and their then-current status.

# Verified diagnostic checkpoint - 2026-10-29

## Delimiter accounting increment - 2026-10-30

The private formatter receipt now also reports total delimiter hits, exact
formatter-owned hits, and remaining hits. Accounting uses the same delimiter
vocabulary as the production heuristic and original UTF-8 byte coordinates.
Only the `---` occurrence inside an exact authenticated newline separator counts
as formatter-owned. Duplicate spans cannot double-count; malformed, oversized or
non-character-boundary spans cannot acquire attribution. Other body delimiters
remain visible. Bounded producer spans are indexed before scanning, avoiding a
full span scan per occurrence. No input is removed, replaced or reclassified.

The existing heuristic emits one aggregate finding, not a finding per delimiter.
These counts therefore do NOT attribute the whole finding, imply harmlessness,
produce a contextual score or change a decision. In particular, a destructive
body can have zero remaining delimiters: its positive directive evidence and
independent policy floors must still block it. Existing full-body/cross-field
inspection and custody checks remain in force. Public helper outputs are only
diagnostics and confer no release authority; only the private original-response
path attaches the counts to the execution receipt.

Component controls cover 50/200/201/256 formatter sizes, body tokens, Unicode byte
offsets, malformed/duplicate ranges, and unchanged receipt and baseline decisions.
The accepted Linux witness below belongs to the earlier exact source and does
not qualify these newly added counters. No new native replay or inference was run.

Validation for this increment: core 98/98, native 146/146 (including execution
20/20), Clippy for core and agentfw libraries with warnings denied, fmt and diff
checks passed on Windows. Independent review remains pending.

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

## Agreed shadow heuristic experiment (review 5709070027)

Private original-result receipts now freeze baseline and candidate heuristic
scores over the same complete text. Only verified separator hits are removed,
before applying the three-hit cap. No text is stripped. The production scorer
uses the same component function with the original delimiter count; release,
signatures, directives, cross-field inspection, ML invocation and budgets remain
unchanged. These two numbers are not complete policy verdicts or public authority.
Malformed or duplicate ranges in the diagnostic helper retain the full baseline;
missing or ambiguous private attribution produces no candidate receipt.

Public local controls at 50/200/201/256 paths cover ordinary text (candidate 0),
two imperative tokens (0.6), three body delimiter types (0.3), long encoding (0.3),
and destructive instructions (heuristic 0, NOT benign: the independent directive
detector remains necessary). An injected filename retains its 0.6 contribution.
UTF-8 boundaries, invalid ranges, duplicates and absent ranges are also covered.
The existing custody/native suite checks identical release and private receipt
before/after inspection, forged metadata and cross-field evidence.

These are local unit controls, not native executed witnesses at 201/256 paths or
a new full public-development corpus result. The historical 10 benign false
refusals remain unresolved. No model replay or new Linux run was performed.
Exact-source native qualification and independent review are still required.
