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
scanner input. Extra unrelated distributions remain blocking. It inventories
license metadata and hashes existing notice files for every installed package.
Missing declarations or notice text remain incomplete; no legal approval is inferred.

Three bounded checks retain their commands, exit codes and raw output:

* Cargo audit on the exact Cargo lock, with database metadata and no findings or warnings.
* The repository's existing Cargo license/provenance policy, preserving its version-specific exceptions.
* OSV-Scanner v2 source scanning with JSON and all-package output for Cargo,
  installed Python and npm. Every reported source path, ecosystem, package name
  and version must match the corresponding complete graph. Missing, additional,
  swapped or unrelated rows fail even when counts match.

The invocation follows the [OSV source scanning interface](https://github.com/google/osv-scanner/blob/main/docs/scan-source.md).
All unresolved findings, including informational findings, remain blocking.
Missing scanners, timeouts, malformed JSON, empty coverage and failed exits cannot
become a successful inventory. Source, selection and scan inputs are rechecked
after scanning. Reports use new private files and never replace earlier attempts.

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
