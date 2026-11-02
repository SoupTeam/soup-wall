# Installed runtime dependency inventory

`scripts/generate_inventory.py` consumes an existing prepared installed pilot
selection and reuses its accepted verification contract. An upstream identity
file, tools-list text or package count cannot establish an installed graph.
The source must be the exact clean selected commit. No installation or dependency
update occurs during inventory generation.

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
Missing declarations or notice text remain incomplete; no legal approval is inferred.

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
declarations and classifiers are retained when metadata supplies them. A vendor
pin or a notice's text does not supply an SPDX approval: absent or opaque license
declarations still require review under the existing policy.

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
