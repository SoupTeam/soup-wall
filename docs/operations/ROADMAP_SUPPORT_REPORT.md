# Private ROADMAP support and evidence report

The SOU-80 tool makes a bounded, offline inventory of the stable Foundation and
Phase 1–7 readiness criteria in [ROADMAP](../ROADMAP.md). It joins the
[versioned support index](roadmap-support-index.json) to **explicitly supplied**
reports and a selected full source SHA. It does not run acceptance drivers,
inspect a Git checkout, fetch CI artifacts, contact a provider or approve a
release. The index's `supported` label describes a *scoped profile*; the report
status describes available evidence for the selected source. Neither label is
a claim that a whole ROADMAP criterion passed.

## Generate one local report

From the repository root, choose a new output directory under an operator-owned
private parent. The following public-data example uses the accepted SOU-80 base
and retains the output locally. On Windows PowerShell, choose a **new** name:

```powershell
python -B scripts/roadmap_support.py `
  --source 38c981bddbedfd2b06b80fb4c9af474b9b897ad3 `
  --evidence-dir docs/operations/evidence `
  --index docs/operations/roadmap-support-index.json `
  --roadmap docs/ROADMAP.md `
  --output "$env:LOCALAPPDATA\sou80-private-report-example"
```

On Linux, use `python3` and an output path beneath your private home directory.
The output directory must not exist. Open its `index.html` using the browser's
**Open File** action; `report.json` is the same sanitized projection for local
inspection. The generator does not open a browser or make a network request.
It creates the directory with mode `0700` and files with mode `0600` on POSIX.
Windows ACLs are inherited from the chosen parent; verify that parent is private
before using nonpublic evidence. Do not commit, upload, email or place private
output in a synchronized/public folder.

Use the **full tested candidate commit**, not a branch name or ancestor shorthand.
The tool validates the SHA's form and its agreement with indexed report source
identities; it does not certify that the commit exists or that the local checkout
has those bytes. For a fresh candidate, collect independent exact-source runtime
reports by the linked profile procedures, then explicitly review and extend the
index. A missing file remains `missing`; creating an index row cannot replace
execution. The source/evidence directory is read only.

## Read the result

Use Phase, Platform and Status filters plus Previous/Next criterion pages to
inspect criteria and their linked capabilities. At most eight criteria are
rendered at once. Expand **Profile and evidence** to see the declared scope,
current fail mode, per-report reason, source SHA, report digest, format, bounded
counts, execution class and available identity digests. The report never embeds
raw prompts, arguments, results, receiver contents, credentials, host paths,
agent/session IDs or unknown report fields. It does include publicly reviewed
profile names, source hashes and artifact digests. If those are sensitive in a
private future run, keep the output private.

| Status | Meaning |
| --- | --- |
| `unsupported` | The indexed profile explicitly refuses this platform/scope. |
| `missing` | No report is indexed, or the indexed file or a pinned companion file is absent. |
| `invalid` | Unsafe/malformed input, wrong version, digest or identity. |
| `incomplete` | Failed/skipped checks, an absent positive denominator or a contradictory run. |
| `unbound` | A readable report lacks a clean source commit, its architecture or required identities, or required proof (build receipt, independent witness, product custody) is unverified. |
| `historical` | A checked component report belongs to another source SHA. |
| `component` | A checked component report matches the source but is not integrated acceptance. |
| `pending-review` | Exact candidate, scope, identities and positive counts match mechanically; an operator decision is still absent. |
| `review-recorded` / `review-rejected` | An explicit, separately supplied decision is attached to matching candidate evidence for one criterion. No phase is closed automatically. |

The initial public selection has two readable historical native component runs
([create file](evidence/MCP_CREATE_FILE_2026-10-15.followup.md),
[HTTPS GET](evidence/MCP_HTTPS_GET_2026-10-15.md)). The Linux and macOS
[installed self-tests](SELF_TEST.md) pass their own scripted fixture, but the
retained JSON reports do not bind their **working-tree builds** to one clean
source commit; the report marks them `unbound`. The
[shared-session component](evidence/sou-63-final-hardening-2026-10-16/README.md)
has ten ignored workspace tests and remains `incomplete` for this tool. The
[original filesystem](MCP_REAL_FILESYSTEM.md), [original Git](GIT_MCP_PROFILE.md)
and [generic stderr](NATIVE_MCP_STDERR.md) procedures identify scoped profiles,
but their required exact candidate run reports are not in this selected public
directory, so they remain `missing`. macOS Intel self-test is conditional and
missing; Windows installed self-test is unsupported. The original-host scripted
interoperability in the filesystem guide and a genuine live-model evaluation
are different execution classes. The index contains no live-model result and
does not close Phase 4 or Phase 7. The three SOU-228 installed Linux capabilities
index original reports that are kept in private custody, so the public selection
shows them as `missing`; see [SOU-228](#sou-228-installed-linux-evidence).

## Index and report contract

`sw-roadmap-support/1` is a strict JSON object with `version`,
`roadmap_sha256`, `criteria`, `capabilities`, `evidence` and `profile_inputs`. It must contain all
38 stable criterion IDs (`foundation.1`–`.6`, `phase-1.1`–`.4`, and so on through
`phase-7.4`) with their phase and capability links. The ROADMAP digest detects
unreviewed text drift. Its current value was re-pinned after review in SOU-228; see the
[re-pin provenance](evidence/sou-228/README.md#roadmap-digest-re-pin). Each capability declares platform, architecture, host,
transport, original server/tool profile, support disposition, fail mode, limit
and an identity object: `implementation`, `policy`, `registry`, `runtime`,
`server` SHA-256 values or explicit `null` where no matching bound artifact is
available. For original filesystem/Git, the policy and server values identify
committed policy/upstream-identity **files**, not proof that those bytes ran.
The four `profile_inputs` records pin those relative file paths and their
digests to the matching identity fields. The validator checks the local files
against the index. This detects checkout drift in those pins, while the
operator still has to establish that the chosen source SHA is the checkout
being reviewed.

Every evidence descriptor binds a capability to one relative file path,
SHA-256, format adapter, `component` or `integrated-candidate` kind, source SHA
or `null`, platform/architecture, host, transport, server, profile and the same
five identity fields. The initial adapters are `sou54-followup/1`,
`sou56-https-get/1`, `sw-self-test/1` and `sou63-component/1`; the SOU-228
installed formats are described [below](#sou-228-installed-linux-evidence). Their curated
legacy projections check their available source, binary/config identities,
version, platform and positive denominators. Fields not present in an old
format stay unbound; rehashing or renaming a legacy report cannot upgrade it
to integrated acceptance.

New exact-candidate reports can use strict `sw-support-evidence/1` with exactly:

```json
{
  "version": "sw-support-evidence/1",
  "source": "FULL_40_CHARACTER_LOWERCASE_COMMIT_SHA",
  "platform": "linux",
  "architecture": "x86_64",
  "host": "EXACT_INDEXED_HOST",
  "transport": "EXACT_INDEXED_TRANSPORT",
  "server": "EXACT_INDEXED_SERVER",
  "profile": "EXACT_INDEXED_PROFILE",
  "identity": {
    "implementation": "SHA256_OR_NULL",
    "policy": "SHA256_OR_NULL",
    "registry": "SHA256_OR_NULL",
    "runtime": "SHA256_OR_NULL",
    "server": "SHA256_OR_NULL"
  },
  "execution": "scripted-host",
  "outcome": "passed",
  "counts": {"passed": 1, "failed": 0, "skipped": 0, "expected": 1}
}
```

The capitalized placeholders describe **types**, not valid evidence. A
candidate report needs a nonzero denominator, exact accounting, no failed or
skipped check, matching indexed identities and all five non-null digests before
it can reach `pending-review`. `execution` is one of `scripted-host`,
`original-host` or `live-model`; the type is displayed, not promoted from one
class to another. A report's own `outcome: passed` is a claim to check, not an
approval or proof of independent execution. A hash is an integrity comparison,
not a signature or attestation. Keep independent raw witnesses and reviewer
context under their normal private retention procedure.

## SOU-228 installed Linux evidence

Three index formats read the installed driver report
`sw-installed-front-door-qualification/1`. That one producer format carries two
report shapes, so the **index row selects the variant** and the adapter verifies the
report's actual structure:

| Index format | Capability | Requires |
| --- | --- | --- |
| `sw-installed-front-door/standard/1` | `installed-front-door-linux` | The 8 standard installed cases, then the 8 scope cases, in order and passed; companions `installed-pilot` (12 fixed cases) and `demo` (12 fixed cases) on the same binaries |
| `sw-installed-front-door/linux-v1-scope/1` | `linux-v1-scope` | All of the above, plus `linux-v1` `selected: true`, `conforming`, `enforce` in the live status of the useful and cancel runs, the indexed scope document digest, and the recorded facts of every scope control |
| `sw-installed-front-door/clean-user/1` | `clean-user-lifecycle-linux` | The fixed 15-case inventory; clean, equal driver, runtime, build and component sources; companions `walkthrough`, `ask`, `user-session` (bound by the hashes the report records) and `user-session-after-cleanup`; `scope.selected: false` in every run |

Each such row lists its `companions` (`role`, relative `path`, `sha256`). A missing
companion file is `missing`; a changed one is `invalid`. Native binaries are rebuilt in
every run, so these rows pin their own `runtime` digest and the capability leaves
`runtime` null. Every other identity field must still equal the capability. Legacy
formats keep exact equality and cannot carry companions.

A report that is structurally contradictory is `invalid`: an altered inventory, a
status or decision that disagrees with its cases, a dirty or mismatched source, a
forged claim field or a relabelled refusal. A consistent failed or partial report is
`incomplete`. The clean-user `decision` text and `accepted_baseline` field are checked
for consistency but never used as authority or source identity. Two failed runs named
`entered-updated-b` and `entered-rolled-back-a`, refused with `maintenance_entered`,
are expected controls and are counted as such. Any other failed run in a passed report
is `invalid`. A complete report still stays `unbound` while proof is driver-reported or
absent: a missing build receipt, receipt bytes that were not retained, driver-recorded
witnesses, sealed provenance, or a driver commit that differs from the product. It
never becomes `pending-review` on its own claims.

The original reports and artifact ZIPs contain private host data and are **not**
committed. The [SOU-228 ledger](evidence/sou-228/README.md) lists every hash and the
actual dispositions. To reproduce, start from the six original GitHub artifact ZIPs.
Run the steps from the repository root in a POSIX shell (Git Bash on Windows;
PowerShell 5.1 `>` re-encodes binary output), with an authenticated `gh`, while the
artifacts are retained (until 2026-12-04). Both private directories must be new and
outside the checkout:

```sh
set -eu
original=/private/sou228/original; evidence=/private/sou228/evidence
mkdir "$original"
for id in 13316278678 13316597197 13317206981 13316687649 13316742015 13317376240; do
  gh api "repos/SoupTeam/soup-wall/actions/artifacts/$id/zip" > "$original/$id.zip"
done
(cd "$original" && sha256sum -c) <<'EOF'
864669ba33cb5df823e44d1c52c408948bcd342754bef38a3feab3d60ba44f1b  13316278678.zip
ffa3b7a3f30f6707acdd1f5a2ac62128eab4557b1d4dca12ab8a032379faa1b1  13316597197.zip
8daccd83d0f88d49bbc5152bcedd2fdbaa32e51c49c03bace5fc15db5c95d6a3  13317206981.zip
115c0ea7fe48a48ffc12f2630d65187949fd4384b3db14a385394da4a84e2491  13316687649.zip
d837443fff09d68d11aff31d5b11efa83304ec51fb7af0de6bd34d872dd9e0a7  13316742015.zip
62ad341c459e94c8d7df3a822e4046f0155e4c7365215fd1ae3fd86206fd6264  13317376240.zip
EOF
# Per-run agentfw digests in the index must match each run's preparation artifact.
python3 -I - "$original" <<'EOF'
import json, sys, zipfile
index = json.load(open("docs/operations/roadmap-support-index.json"))
pinned = {row["id"].rsplit("-", 1)[1]: row["identity"]["runtime"]
          for row in index["evidence"] if row["id"].startswith("sou228-")}
for artifact, run in (("13316687649", "41818201020"), ("13316742015", "41818211366"),
                      ("13317376240", "41818225908")):
    with zipfile.ZipFile(f"{sys.argv[1]}/{artifact}.zip") as archive:
        summary = json.loads(archive.read("sou111-assets/source-summary.json"))
    assert summary["source_commit"] == "b4d3e7d67abe7cfc2a0e0877dbd21d1d0c8e232f", run
    assert summary["binary_sha256"]["agentfw"] == pinned[run], run
print("preparation artifacts match the pinned per-run runtime digests")
EOF
cp -R docs/operations/evidence "$evidence"
python3 -I -m zipfile -e "$original/13316278678.zip" "$evidence/sou-228/41818201020"
python3 -I -m zipfile -e "$original/13316597197.zip" "$evidence/sou-228/41818211366"
python3 -I -m zipfile -e "$original/13317206981.zip" "$evidence/sou-228/41818225908"
```

Then this single offline command produces the report; nothing else is fetched:

```sh
python3 -B scripts/roadmap_support.py --source b4d3e7d67abe7cfc2a0e0877dbd21d1d0c8e232f \
  --evidence-dir "$evidence" --index docs/operations/roadmap-support-index.json \
  --roadmap docs/ROADMAP.md --output /private/sou228/report
```

Extraction does not alter member bytes, and the tool re-checks every report and
companion against the hashes pinned in the index. The preparation ZIPs are custody
evidence for the per-run binaries only; the report itself does not read them.

The tested commit is `b4d3e7d6`. The SOU-228 merge commit `5dd30c87` has the same Git
tree but was not executed; with `--source 5dd30c87…` the same rows are `historical`.
Tree equality is not treated as tested-source equivalence.

An optional `--decisions path/to/decisions.json` is a *separate operator input*:
`sw-support-decisions/1`, with the selected `source` and a `decisions` array.
Each record has a unique operator-assigned `decision_id`, a `criterion_id`, an
`evidence_id`, that exact file's `evidence_sha256`, and `decision` (`accepted`
or `rejected`). The tool rejects stale, unrelated or conflicting bindings; a
decision is displayed only for mechanically matching integrated evidence. It
does not authenticate the decision author, create an approval, invent a reviewer,
approve a threshold or mark a criterion complete. Keep the decision file in
the operator's private evidence custody.

## Bounds and verification

Inputs must be regular singly linked files under the selected directory, with
no symlink/reparse ancestors. The index and decision file each have a 512 KiB
cap; each report and ROADMAP input has a 2 MiB cap. The index allows at most
64 criteria, 128 capabilities and 128 evidence files. JSON depth is at most
18, object members 512, array entries 4096 and strings 64 KiB. Output JSON
and HTML each have an 8 MiB cap. Unknown index/decision/new-report fields,
duplicate JSON keys and duplicate IDs are refused. Missing or invalid evidence
is visible in the report; a malformed index, ROADMAP drift or invalid decision
stops generation. The browser page uses text nodes and a hash-pinned CSP, with
no remote resources, form submission, network connections or event execution.
It renders eight criteria per page so the declared index maximum does not
create all cards at once.

Focused checks:

```sh
python3 -B -m unittest discover -s scripts/tests -p "test_roadmap_support*.py" -v
python3 scripts/check_docs.py
```

The optional `test_roadmap_support_browser.js` uses Playwright with a local
Chromium and the generated `index.html` to check filters, drilldown, small
screens, inert HTML payloads and offline silence. The
[sanitized SOU-80 checkpoint](evidence/SOU80_ROADMAP_SUPPORT_2026-10-17.md)
records the actual source selection, controls and screenshots. These checks
validate the report tool; they do not constitute platform, model or product
acceptance.

## Fresh installed-pilot custody

On native Ubuntu 24.04, run the existing owned scripted qualification with
the exact SOU-119 inputs. Pass the generation's original `receipt.json` as
`--source-build-receipt` to `qualify-installed-front-door.py`. This also
applies to `--pilot-scope-only`. The clean-user entry point already requires
this argument. The producer writes the original receipt and selection bytes
under the run's private `custody/` directory. It also retains the specific
observer source and bounded process, receiver, and dispatch observations.
Keep this directory beside its original `report.json`. For the front-door
and scope companions, use the producer's demo selection and pass the parent
`report.json` through each companion's `--parent-report` option.

The focused hosted workflows encrypt the new custody directory with the
SOU-243 qualification recipient before artifact upload. The focused clean-user
workflow also selects this recipient for new before/after process snapshots.
Historical SOU-216 user-session artifacts keep their original recipient. On an authorized
operator host, decrypt the CMS payload in a private directory, inspect the
archive member names and extract the `custody/` directory beside the original
report. Preserve original report and companion paths and SHA-256 digests.
A scope run records distinct primary and demo selections. A clean-user run
records both project selections and the walkthrough selection. The Ask
invocation reuses selected executable inputs and retains its own generated
policy and report.

Use the existing offline report command with a reviewed private index for
the executed source. Create a candidate capability and integrated evidence
row with the report and companion hashes. Copy the measured component
archive, policy, runtime, registry and server digests into the new row.
Registry and server digests are ordered SHA-256 aggregates over the selected
filesystem and Git registry and package-tree digests. See
[`selected_identities` and `combine_identities`](../../scripts/pilot_evidence_custody.py)
for the ordering. The capability keeps its per-run runtime digest null.
Review this index from the exact producer checkout, which also supplies the
observer sources for comparison.

```sh
python3 -B scripts/roadmap_support.py --source "$source" \
  --evidence-dir "$evidence" --index "$reviewed_index" \
  --roadmap docs/ROADMAP.md --output "$new_private_report"
```

The custody verifier rejects changed receipt bytes, foreign selections or
companions, missing cleanup and calibration, and malformed or oversized
files. A complete unsealed package can reach `pending-review` with all five
identities pinned in the index. Sealed user-session provenance continues to
require authorized review. Explicit operator decisions still bind separately
to a candidate report hash. See the
[focused custody controls](../../scripts/tests/test_pilot_evidence_custody.py).
