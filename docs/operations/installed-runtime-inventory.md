# Installed runtime dependency inventory

`scripts/generate_inventory.py` consumes an existing prepared installed pilot
selection and reuses its accepted verification contract. An upstream identity
file, tools-list text or package count cannot establish an installed graph.
The source must be the exact clean selected commit. No installation or dependency
update occurs during inventory generation.

The [private runtime clearance decisions](private-runtime-clearance.md) identify
the repaired dependency pins and the exact remaining license, advisory and native
review decisions.

Git profile preparation uses the finite `wheels.lock.json` manifest, tied to the
existing hashed requirements. Explicit downloads use a bounded standard-library
HTTPS reader for those exact files; pip always installs from a verified local
wheelhouse with `--no-index`. Supplying an offline wheelhouse never falls back to
the network. This avoids pip's vendored HTTP parser during bootstrap without
removing its installed vendored packages from advisory coverage. Accepted CI
input guards remain unchanged; new setup data and helper code still require
maintainer admission.

```bash
python3 scripts/generate_inventory.py \
  --selection /private/prepared/generations/example/selection.json \
  --expected-commit <full-clean-source-commit> \
  --native-reviews /private/reviews/native-reviews.json \
  --output /private/evidence/new-runtime-inventory.json
```

The script verifies selected executable digests, installed profile/package trees,
registries, policies and library digests through the existing preparation reader.
It enumerates the actual installed Python distributions and npm packages and
compares them with the hashed Python and npm locks. Bootstrap pip/setuptools
redistributed in the pinned interpreter archive are included in a separate exact
scanner input. The top-level Python graph must still contain every locked wheel
at its exact version, with only pip/setuptools bootstrap extras permitted.
Nested distributions cannot satisfy missing top-level wheels. Extra unrelated
top-level distributions remain blocking. It inventories
license metadata and hashes existing notice files for every installed package.
Missing declarations or notice text remain incomplete unless an exact, verified
attribution record supplies the missing factual evidence. The existing license policy remains the default. An optional, exact-material
maintainer disposition may admit a reviewed row under the conditions below.

The selected Git interpreter's stripped archive omits native dependency notices
provided in the matching full Python standalone archive. The profile ships those
exact texts with a hash-bound provenance record under
`profiles/mcp/git-readonly-v1/upstream-notices/python-3.11.18/`.
The installer verifies the complete declared local bundle before runtime probes
and before copying it into the installed profile. This retains attribution;
it does not certify license compliance or reproduce the source-to-binary build.

Python inventory walks the selected site-packages tree once, refusing symlinks,
paths outside that tree, depth above 32, more than 100,000 entries or more than
1,000 distribution directories. Metadata, manifests, records and notices have
bounded sizes. Nested `.dist-info` distributions are accepted only beneath the
bootstrap tools' `pip/_vendor` and `setuptools/_vendor` trees. Their actual
`METADATA` identities, safe `RECORD` paths and present component code establish
inventory entries. Both identity files are hashed. A RECORD hash is retained as
installed evidence; it does not invent a downloaded wheel identity or lock.

Pip's `_vendor/vendor.txt` supplies exact pins for redistributed components
without their own distribution metadata. Unpinned or duplicate declarations,
conflicting nested metadata, missing component code, and unpinned immediate
vendor modules remain blocking. Pip's setuptools pin describes its actual
`pkg_resources` subtree. The report retains each component's owner, material
path, identity-file hashes and attributable notice hashes, including pip's
per-component notices retained in its `.dist-info/licenses` tree. Raw license
declarations and classifiers are retained when metadata supplies them. AUTHORS
files and safely named `License-File` declarations are collected inside the
component's own distribution tree; unrelated sibling files do not satisfy its
notice requirement.

The Git profile's `upstream-identity.json` may declare
`runtime_license_provenance`, containing exactly `path` and `sha256`. The path is
`upstream-notices/runtime-licenses/provenance.json`, whose format is
`sw-python-runtime-license-provenance/1`. Its 23 bounded records describe exact
observed versions and origins, including vendor owners, metadata or manifest and
RECORD hashes, parent bootstrap distribution identities, attributable notice
hashes, authoritative source wheel URLs and hashes, source metadata declarations,
evidenced SPDX interpretations, and notice-retention obligations. Generic legacy
labels are not normalized globally. For example, the exact gitdb 4.0.12 wheel's
BSD text and wheel RECORD support its BSD-3-Clause interpretation; that evidence
does not reinterpret other packages labelled `BSD License` or source-only GPL
fixtures as installed wheel contents.

Inventory verifies the provenance digest against the source identity and the
actual installed copy. Prepared generations must retain the same binding in
`git-profile/installation.json` under `upstream_identity`. A missing declared
file, unequal binding, unsafe path, symlink, changed identity file, stale parent
distribution, or changed notice remains blocking. A source record alone cannot
establish installed attribution. Small fixtures without prepared receipts and
installed provenance receive no mapping. An unknown version or origin does not
inherit a nearby record. Provenance failures retain the observed inventory and
blocking errors while scanner checks continue.

The original `license`, `license_declarations`, `origin`, and identity hashes
remain in each inventory row. `original_declared_license` explicitly preserves
the raw value, including null. Only a fully matched record can supply
`effective_license`; the unchanged `judge_spdx` policy evaluates that expression.
`attribution.status: "notice_verified"` describes factual attribution separately
from `policy_disposition_required` and the existing policy result. Verified
autocommand LGPL, certifi MPL, and typing_extensions/distlib PSF evidence still
requires policy disposition. The global SPDX allowlist remains unchanged.

Exact original gitdb AUTHORS, Pygments AUTHORS, and Requests NOTICE texts are
retained as supplemental assets in the same runtime notice directory. A mapping
can append them to its notice files only after the source and actual installed
copies match their source-wheel digests. A missing or altered installed
supplement cannot be replaced by a source-only path or an approval flag.

`python_graphs.top_level` and `python_graphs.vendored` retain the separate graphs.
The scanner requirements are their union, deduplicated by name **and version**;
multiple installed origins remain in the notice evidence even for equal
identities. Parallel versions remain distinct scanner entries. This temporary
scanner input has no fabricated wheel hashes and does not change the hashed
installer lock. The existing preparation reader verifies the selected package
tree before inventory and again after scanning. A changed runtime requires a
fresh prepared selection and report; earlier reports keep their original source,
time and coverage claims and are not relabelled as complete vendor inventories.

Three bounded checks retain their commands, exit codes and raw output:

* Cargo audit on the exact Cargo lock, with database metadata and no findings or warnings.
* The repository's existing Cargo license/provenance policy, preserving its version-specific exceptions.
* OSV-Scanner v2 source scanning with JSON and all-package output for Cargo,
  installed Python and npm. Every reported source path, ecosystem, package name
  and version must match the corresponding complete graph. Missing, additional,
  swapped or unrelated rows fail even when counts match.

OSV's expected Cargo representation includes local and vendored lock entries
under its `crates.io` ecosystem label. The report separately retains each actual
Cargo lock source and checksum; that scanner label does not prove publication
or ownership in the registry. Resolution is disabled because these inputs already
enumerate the installed transitive graph; an uninstalled conditional dependency
must not be added by a resolver. Unknown/virtual sources remain incomplete.
Only numeric PyPI release zero padding is normalized for comparison (`25.2`
and `25.2.0`); prerelease, postrelease and different numeric versions remain distinct.
Findings and affected ranges are retained separately from coverage, including
when the scanner exits nonzero. Reachability is not inferred from a version match.

The invocation follows the [OSV source scanning interface](https://github.com/google/osv-scanner/blob/main/docs/scan-source.md).
All unresolved findings, including informational findings, remain blocking.
Explicit exact-material dispositions may resolve the supported cases described below;
the original observations remain in the report.
Missing scanners, timeouts, malformed JSON, empty coverage and failed exits cannot
become a successful inventory. Source, selection and scan inputs are rechecked
after scanning. Reports use new private files and never replace earlier attempts.
Cargo license verification uses a disposable report beneath the source `target/`
directory, as required by the existing policy checker, and embeds the parsed
result in the requested private inventory. Timeout diagnostics retain bounded
partial output. An explicitly pre-fetched RustSec checkout can be selected with
`--rustsec-db` together with `--rustsec-commit`; the audit then uses `--no-fetch`
without extending scan timeouts. The official origin, expected commit and clean
checkout are checked before and after scanning. An empty advisory database cannot
clear the audit. All-vulnerability output remains enabled.

When the original filesystem npm archive omits its license file, inventory uses
the exact upstream server notice already shipped and hashed by the accepted
installer. The original license declaration is preserved; this fallback does not
approve an ambiguous declaration or change the license policy.

Components outside package-manager scans require explicit reviewed evidence.
The optional `--native-reviews` input uses format `sw-pilot-native-reviews/1`, with
`components` containing exactly `git`, `bwrap`, `node`, `python` (host classifier
interpreter), and `git_python` (the original Git server's interpreter). Each entry
records `binary_sha256`, `version`, `source_sha256`, `status: "reviewed"`,
`findings: []`, a timezone-aware `checked_at`, authoritative HTTPS `sources`, and
`notices` mapping actual notice paths to SHA-256 values. Known archive versions
and hashes must equal the accepted pins; the host interpreter version is observed.
`system_libraries` maps every selected ELF dependency path to its `sha256`,
`license`, review `sources`, and hashed `notices`.

These are explicit reviewer assertions, not scanner-produced proof of source to
binary reproducibility. Do not manufacture a clean native review. Omitting the
input retains a blocking reason while package scans can still run. Confirmed
issues require a separately reviewed pinned update using the existing hashed
installers; changing dependency identities or dropping hashes to green a report
is prohibited.

Only a report with every check and review complete returns zero and records
`checks_passed`. This is scoped inventory evidence, not publication authority,
proof of exploitability, or a promise that no vulnerabilities exist.

```bash
python3 -B -m unittest discover -s scripts/tests -p 'test_runtime_inventory.py' -v
```


## Scoped maintainer review input

`--runtime-reviews /private/compliance/runtime-reviews.json` is an optional
project-maintainer decision input. Its format is `sw-pilot-runtime-reviews/1`.
Omitting it retains the default blocking behavior. A review is an explicit
AI-assisted project-maintainer disposition under delegated authority; it is not
a claim that a human lawyer reviewed the material or that upstream granted
additional rights. Treat the supplied file as a trusted maintainer input, not
as a self-authenticating approval from a runtime supplier.

The input binds the exact clean expected source identity, selection SHA-256,
selected executable identities, lock digests, complete observed package graph,
installed origin/metadata/notice material and scan-input digests. Package
decisions bind the complete row digest and exact effective license expression.
Original declarations, attribution, policy results and
`policy_disposition_required` remain unchanged in the report. A separate
`runtime_reviews` result records the scoped disposition and its conditions.

Each condition names real files beneath the review file's directory and their
SHA-256 values. Symlinks, unsafe paths, missing/changed files, unknown fields,
duplicate or unused decisions/conditions, stale source/selection/material and
new uncovered findings fail. The copied notice digests must cover all notices
of the reviewed component. Source conditions also bind the original selected
files inside the prepared generation and byte-identical supplied source copies.
MPL requires notices, exact covered source and source instructions. LGPL
additionally requires a documented replacement/recombination route and recipient
modification/debugging rights. PSF requires the original historical notices and
a modification statement. The MCP transition requires its software notices and
documentation attribution. BlueOak requires its notice text or license link.

Build a fresh compliance directory from an existing incomplete inventory:

```bash
python3 scripts/build-runtime-compliance.py \
  --selection /private/prepared/generations/example/selection.json \
  --expected-commit <full-clean-source-commit> \
  --inventory /private/evidence/current-runtime-inventory.json \
  --output /private/compliance/new-attempt
```

The copier re-verifies the generation and observed notices. It preserves all
installed package notices, supplies full GPLv3/LGPLv3/MPL2 license texts and
source/recipient instructions, and copies the exact certifi source/PEM trees
and the containing setuptools application/vendor source for autocommand.
The output contains a hash inventory and a proposal with `UNREVIEWED` decisions.
The proposal also enumerates every retained OSV finding and supported Cargo
maintenance record with its scanner, package, source, advisory aliases and full
advisory digest. Those rows remain `UNREVIEWED`, with empty evidence references
and rationale; the maintainer must supply both before admission. Cargo
vulnerabilities or unsupported warnings cannot become maintenance proposals.
Copying files does not approve them. Review the concrete material, choose the
permitted `internal` or `private-handoff` scope, record the delegated decision,
and add the exact advisory evidence before supplying the completed JSON.
The proposal cannot pass the verifier unchanged.

Every observed OSV finding requires its exact scanner/package/source identity,
advisory ID, complete aliases and canonical advisory-record digest. Demonstrably
absent affected code may receive `not_applicable`; exact Cargo unmaintained
notices may receive `accepted_maintenance_risk`. Cargo vulnerabilities, unsound
or unknown warnings, missing scanners, malformed/incomplete graph reports and
other failed exits remain blocking. Exit 1 from a completely parsed findings
report is retained as an observed scanner failure and may be discharged only by
complete supported dispositions. There is no generic vulnerability-risk or
native-risk override.

The compliance directory must accompany each permitted private handoff; an NDA
must not remove upstream source/modification/redistribution rights. Native Git,
Python and system-library corresponding-source conditions remain a separate
gate. A successful package disposition cannot clear a native security finding,
certify pilot readiness, publish an artifact or approve a release. Re-verify
all source, selection, scan inputs and compliance files after scanning; keep
earlier attempts and their original findings.

The [runtime admission handoff](runtime-admission-handoff.md) lists the
author-side evidence, remaining upstream block and the final reviewer steps.


Native system-library review covers the union of both installed profiles and
every selected ELF executable, including the Agent/helper/test launchers,
bubblewrap and the host Python. The selected Git profile interpreter is probed
separately; its packaged libraries remain in its verified tree. The pinned npm
JavaScript uses the selected Node interpreter. Reuse the installer's bounded
dependency reader, refuse unknown script interpreters, and recheck selected
binary and library hashes around probes and after scanning. A profile-only
review cannot omit a dependency used by another selected executable.
