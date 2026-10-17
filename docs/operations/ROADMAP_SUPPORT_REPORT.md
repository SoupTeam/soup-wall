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
| `missing` | No report is indexed, or the indexed file is absent. |
| `invalid` | Unsafe/malformed input, wrong version, digest or identity. |
| `incomplete` | Failed/skipped checks, an absent positive denominator or a contradictory run. |
| `unbound` | A readable report lacks a clean source commit or required identities. |
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
does not close Phase 4 or Phase 7.

## Index and report contract

`sw-roadmap-support/1` is a strict JSON object with `version`,
`roadmap_sha256`, `criteria`, `capabilities`, `evidence` and `profile_inputs`. It must contain all
38 stable criterion IDs (`foundation.1`–`.6`, `phase-1.1`–`.4`, and so on through
`phase-7.4`) with their phase and capability links. The ROADMAP digest detects
unreviewed text drift. Each capability declares platform, architecture, host,
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
`sou56-https-get/1`, `sw-self-test/1` and `sou63-component/1`. Their curated
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
python3 -B -m unittest discover -s scripts/tests -p test_roadmap_support.py -v
python3 scripts/check_docs.py
```

The optional `test_roadmap_support_browser.js` uses Playwright with a local
Chromium and the generated `index.html` to check filters, drilldown, small
screens, inert HTML payloads and offline silence. The
[sanitized SOU-80 checkpoint](evidence/SOU80_ROADMAP_SUPPORT_2026-10-17.md)
records the actual source selection, controls and screenshots. These checks
validate the report tool; they do not constitute platform, model or product
acceptance.
