# Exact-candidate internal pilot dossier

SOU-129 reconciles **explicitly selected existing files** into one bounded JSON
blocker ledger and English scorecard. It extends the accepted
[installed measurement tooling](INSTALLED_PILOT_QUALIFICATION.md), reuses the
SOU-106 gate and the [published support definitions](roadmap-support-index.json),
and does not run tools, models, installers, a daemon, a second evaluator or CI
admission. Hashes establish consistency of selected bytes, **not authenticity**
or independent witnessing. The TL still decides acceptance.

## Current record and reproduction

The [selection](evidence/sou129/selection.json) targets accepted main
`adefce2a658272e5f23c9c72ef791befe0285648`, tree
`f23e59fb3bd80e7b0666ef4a9cbdcefeb3267519`, a successor of the task's
`cdd9d36c65a592455e4f421268758adb6db744b8` starting point.
The [current scorecard](evidence/sou129/current-dossier/scorecard.md) and
[JSON dossier](evidence/sou129/current-dossier/dossier.json) are **NOT_READY**.
The measurement reporter's successful tests do not make this a passing pilot.

From the repository root, use Python 3.10+ and Git. The named candidate and
historical commit/tree objects must already be available locally. Prepare the
checkout through the normal trusted Git workflow before this offline command;
the reporter disables Git lazy fetching and never downloads evidence. A shallow
checkout may yield `source_object_unavailable`, which cannot become READY.

```sh
python3 -B scripts/pilot_dossier.py \
  --selection docs/operations/evidence/sou129/selection.json \
  --root . --repo . \
  --candidate adefce2a658272e5f23c9c72ef791befe0285648 \
  --output local-notes/sou129-reproduced
```

Create the parent directory first; the output directory must **not** exist.
On Windows use `python` instead of `python3`. The selected evidence files have
LF attributes so their original Git bytes and hashes are stable across OSes.
This does not rewrite historical measurements. Expected exit code here is **1**:
`dossier.json` and `scorecard.md` are still written. Exit **0** means complete,
consistent selected evidence for the stated narrow environment, not TL approval;
exit **2** means an invalid selection, inaccessible candidate/support objects or
output failure. Individual missing/corrupt reports are recorded as blockers and
produce exit 1; invalid top-level inputs produce exit 2. There is no success
fallback and no output overwrite.

The output pins the selection, reporter and its gate/reader/protocol dependency
hashes. `accepted_main_declared` identifies the selected accepted base and is an
operator declaration, not a GitHub merge verification. `reporter_accepted_sha`
is null until acceptance; do not substitute an approved historical runtime SHA
for acceptance of this reporter increment. A final accepted reporter SHA belongs
in a subsequent handoff record, leaving the original dossier intact.

## Meaning of the current evidence

- SOU-106 at `ce4f76d823f9f1b5a7ea1dec97a8ff260a5f94dc` remains **10/12** useful
  benign workflows, **two Ask interruptions**, **8/8** refusal variants and
  **zero forbidden effects**. The unchanged failing workflows are
  `search-read-status` and `search-exclusion`. The original gate is called to
  verify its recorded outcome; expectations and production policy are unchanged.
- Both earlier SOU-106 attempts remain explicitly selected `history` records.
  Their original schemas/inputs are not re-evaluated under a newer workload or
  promoted to candidate evidence. Their hashes, actual sources and originally
  reported statuses are retained.
- The published SOU-112 Ask report and SOU-116 prepared-run report have their own
  source SHAs, denominators and runtime identities. Their recorded successes
  remain visible but cannot establish readiness of this different candidate.
- The selection's expected binary/profile/policy identities are deliberately the
  explicitly selected SOU-106 configuration. They are **not** presented as a
  newly built `adefce2` runtime. A new exact-candidate run must supply its real
  expected selection, and discrepancies are blockers rather than inferred
  equivalence. No new installer/runtime run occurred for this dossier.
- Selected legacy reports lack a complete structured environment binding;
  some also lack policy/profile/registry/classifier bindings. The reporter
  records those gaps. It never fills them from filenames, machine assumptions,
  prose, a green PR badge or its own Windows environment.
- The existing `filesystem-linux` and `git-linux` capability definitions scope
  original read-only servers. WSL is not qualified by this selected combined
  evidence. Native Windows/macOS combined-pilot and live-model claims are outside
  scope. See [runtime preparation](PILOT_RUNTIME_PREPARATION.md) and
  [native prerequisites](PILOT_NATIVE_PREREQUISITES.md) for their exact limits.

These are reporting/integration blockers, not permission to change Ask behavior,
policy, classifier, timeouts or accepted benign expectations. A failed product
result is valid measurement evidence and does not imply a reporter defect.

## Selection and validation contract

`sw-pilot-dossier-selection/1` is a strict object with `scope`, `candidate`,
`accepted_main`, `environment`, `identities`, `support_index`, `workload` and
`evidence`. The scope is
`internal-readonly-original-filesystem-git-scripted-provider`. The environment
selects platform `linux` or `wsl2`, architecture `x86_64`, host
`Claude Code 2.1.251`, `stdio`, and `owned-scripted-loopback` provider. Selection
alone does not prove the runtime environment: a candidate report must contain
an equal `environment` object, observed by its producer, to qualify. Do not
backfill an old report with invented environment fields. Missing bindings need
new producer evidence or explicit unsupported status, not a fabricated pass.

Identity fields cover policy, both profiles/registries/classifiers, Agent,
Claude, Node, Git and bubblewrap. A missing (`null`) expected or observed identity
blocks readiness. Reports with different current-candidate identities cannot be
combined into READY even when another report passes. Explicit `history` is
always non-qualifying. A historical failing measurement is displayed as a failed
observation with its actual denominator; a separately identified matching run
can supersede it for a new candidate while preserving history.

The accepted adapters read `sw-installed-pilot-matched/1`,
`sw-prepared-pilot-acceptance/1`, and `sw-pilot-ask-acceptance/1`. They verify
required shapes, fixed case identities/denominators, clean before/after source,
recorded witness consistency, and the existing gate's stored outcome. Unknown
schemas fail closed. They project only hashes, bounded status/counts, known
case identifiers and evidence references; raw calls, provider results, process
IDs, unknown fields and raw exception text are not copied into the dossier.

Support definitions and the frozen v2 workload must match Git objects at the
selected candidate. The reporter does not define another support matrix or
change the benchmark. The ledger is a projection of these definitions and the
selected original reports. Each required item exposes pass/fail/incomplete/
unsupported, its owner, observed source, evidence reference and denominator.
Missing observations have no invented denominator. WSL stays incomplete until
its published combined-pilot support/evidence is reviewed; Linux evidence cannot
satisfy it. Unknown capabilities never expand authority.

Each file reference contains `path`, `sha256`, `member` and `member_sha256`.
Paths are bounded relative POSIX paths under `--root`, without traversal or
symlinks/reparse points. For a standalone JSON file both member fields are null.
For ZIP, both archive SHA-256 and selected member SHA-256 are mandatory. Only
that member is read; nothing is extracted. The current public selection uses
standalone published reports, so it makes no claim of original CI archive
custody. ZIP ingestion is exercised with synthetic archives in the focused
regressions. It refuses encrypted/link/duplicate/unsafe members, absent members,
malformed archives, changed hashes and expansion beyond the documented bounds.

Limits: 16 selected records, 128 KiB selection, 2 MiB per report/member/output,
64 MiB ZIP compressed/total expanded metadata, 256 ZIP entries, JSON depth 18.
Inputs are regular singly linked files; no directory scan, shell command supplied
by evidence, archive extraction, HTTP request or model access occurs. JSON
rejects duplicate keys, nonfinite values and excessive depth. Outputs use a new
private directory (0700/0600 on POSIX; inherited ACLs on Windows).

## Focused checks and future integration

```sh
python3 -B -m unittest discover -s scripts/tests -p test_pilot_dossier.py -v
python3 -B -m unittest discover -s scripts/tests -p test_pilot_measurement.py -v
python3 -B scripts/check_docs.py
```

Windows restricted environments may require TEMP/TMP pointing to an owned
writable temporary directory. Existing SOU-106 restoration tests additionally
need hard-link permission. No Rust or platform installation is needed to run
the reconciliation command or its own tests.

The new tests use synthetic reports to demonstrate READY logic and explicit
failure paths. They do not count as runtime acceptance. Draft CI adds only this
small Python suite to the existing fast-check job; no duplicate runtime matrix,
manual expensive dispatch, CI admission change or production execution is added.

When integration changes the source, create a **new selection and output** for
that exact candidate. Reuse historical reports only as history; run only the
missing/affected existing qualification producers through their established
procedures. Do not rebrand the old `ce4f76d` runtime run as the new main. Obtain
final CI admission and main integration through the TL. No public release,
Phase-4 effectiveness, live model, paid provider or private dataset is authorized
or claimed by this increment.
