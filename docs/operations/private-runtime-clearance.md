# Private runtime clearance decisions

The 7 November 2026 remediation updates the dependency graph and preserves
source-bound findings, notices and the existing acceptance policy. The exact
versions below are selected for the original installed Linux pilot. The
[development checkpoint](evidence/private-candidate/development-checkpoint.json)
records the executed source and remaining qualification limits.

## Dependency remediation

| Installed component | Earlier version | Selected version | Evidence |
| --- | --- | --- | --- |
| pip bootstrap distribution | 26.2.2 | 26.3 | A required, SHA-256-pinned wheel in the existing offline wheelhouse |
| pip-vendored msgpack | 1.1.2 | 1.2.4 | Official pip wheel manifest and actual installed files |
| pip-vendored urllib3 | 2.7.0 | 2.8.0 | Official pip wheel manifest and actual installed files |
| filesystem server dependency glob | 13.0.6 | 14.0.4 | Exact npm override and integrity-bound package lock |
| filesystem server dependency minimatch | 10.2.6 | 11.0.5 | Exact npm override and integrity-bound package lock |
| Candle ZIP dependency | 9.0.4 | 9.0.5 | Application Cargo lock and registry checksum |

The filesystem profile selects original server `2026.8.31`, SDK `1.32.1` and
Node `22.23.4`. The dependency overrides retain the original server archive,
entrypoint and discovery identities. The selected minimatch and glob versions
support this Node runtime. Pip installs from the verified local wheelhouse
under the existing shared installation deadline. Its replacement and vendored
components participate in the resulting installed-tree hash and inventory.

The 23 Python attribution records bind the exact source wheels, installed
identity files, pip parent distribution, vendor manifest and notice files.
The Pygments AUTHORS supplement follows version `2.21.0`. The original license
declarations and the complete installed graphs remain in the report.

The selected preset manifest now binds the two updated upstream identity files.
Its accepted base, file set, classifier, policy and discovery hashes remain
unchanged. This refresh is separate from trusted CI setup-input admission;
the CI `ACCEPTED` pointer still requires maintainer review.

## Executed verification

The inventory and explicit-selection runs use source `c8350ab4`. The original
Git and filesystem runs with `--pilot-preset` use `73834147`, which changes only
the preset's two identity hashes and its identity-tamper regression control.
Runtime inputs are identical between those sources. Later documentation changes
retain these source identities.

The subsequent integration merges reviewed main `d7567b93` and refreshes the
release documentation contract for the changed documents already in its explicit
bundle. This integration does not extend the recorded native execution claims
to a new source commit. Final current-source native qualification remains open.

The complete installed helper and mandatory notice closure contains 142 files.
The component producer, native installer and update validator now use a bounded
capacity of 160 payload files. The 32 MiB archive, 64 KiB manifest and 1 MiB file
limits, path validation, file hashes, source identities and private file modes
remain enforced. Boundary controls cover acceptance of 160 files and refusal of
161, including the update consumer.

At integrated source `12681d98`, all eight component controls and all 22 release
archive controls pass on Linux. Update controls pass 34 cases and skip one
requiring the separately supplied native Agent binary. A focused native build
of the verbatim production manifest/archive parser reproduces the old refusal
of the complete 142-file component. The repaired parser accepts 142 and 160,
rejects 161, and refuses a changed payload. This structural fixture does not
exercise the full installed Agent lifecycle. The first complete Agent unit-test
build exceeded the local resource/time budget. The subsequent build, disabling
debug symbols only for the Agent test package, passes all seven selected Rust
component tests, including lifecycle, tampering, rollback, removal and the new
count boundary. Test assertions and the production build profile remain intact.

- Fresh official RustSec and OSV scans cover exactly 443 Cargo, 102 npm and 63
  unique Python identities. All 23 attribution mappings pass without notice or
  metadata mismatches. The Rust license gate passes. Twelve runtime license
  rows, seven advisory records across three package groups and native review
  keep the complete inventory incomplete.
- The original Git qualification passes six useful reads, twelve refusals and
  sixteen overlap rounds, with no denied dispatch or repository mutation.
- The original filesystem qualification passes 51 checks, with zero failures
  or skips and unchanged source, installed profile and runtime.
- The installed-pilot explicit-selection run passes all twelve cases and both
  benign workflows, with zero false interruptions. Its selected policy and
  scripted-provider scope remain explicit; pilot readiness is not certified.
- All 95 focused Python controls pass on Linux. Windows passes 91 and skips
  four platform-specific controls. Rust formatting and the locked agent binary
  build pass with toolchain 1.94.1. Both ML archive compatibility tests pass
  against the existing NumPy and PyTorch tensor fixtures with ZIP 9.0.5.

The installed-package regression probe shows zero post-rejection directory
reads with glob 14.0.4, compared with 64 for 13.0.6. A bounded minimatch
amplification probe exhausts the old version's constrained heap; version 11.0.5
rejects the pattern within the same limits and passes normal matching controls.
Exact inputs and private runtime observations are retained separately.

## Runtime license decisions

The following twelve installed rows require explicit maintainer disposition
under the current license policy. The additional BlueOak row belongs to
minimatch's new dependency. A successful attribution check establishes the
identity and custody of the notice material. The policy checker separately
evaluates the selected expression.

| Component and installed origin | Version | Recorded terms | Decision needed |
| --- | --- | --- | --- |
| Original filesystem server | 2026.8.31 | `SEE LICENSE IN LICENSE`, with the retained MIT/Apache transition notice and documentation terms | Confirm the applicable terms for the actual packaged material and its distribution |
| npm `@isaacs/nonrecursive-glob-match` | 1.1.0 | BlueOak-1.0.0 | Approve or reject the exact package and retained notice |
| npm `glob` | 14.0.4 | BlueOak-1.0.0 | Approve or reject the exact package and retained notice |
| npm `lru-cache` | 11.5.3 | BlueOak-1.0.0 | Approve or reject the exact package and retained notice |
| npm `minimatch` | 11.0.5 | BlueOak-1.0.0 | Approve or reject the exact package and retained notice |
| npm `minipass` | 7.1.3 | BlueOak-1.0.0 | Approve or reject the exact package and retained notice |
| npm `path-scurry` | 3.0.0 | BlueOak-1.0.0 | Approve or reject the exact package and retained notice |
| Top-level Python `certifi` | 2026.10.19 | MPL-2.0 | Review redistribution obligations for the exact wheel |
| pip-vendored `certifi` | 2026.10.23 | MPL-2.0 | Review redistribution obligations for the exact vendor material |
| setuptools-vendored `autocommand` | 2.2.2 | LGPL-3.0-or-later | Review the exact vendored material and redistribution obligations |
| Top-level Python `typing_extensions` | 4.16.0 | PSF-2.0 | Approve or reject the exact wheel and retained notice |
| pip-vendored `distlib` | 0.4.4 | PSF-2.0 | Approve or reject the exact vendor material and retained notice |

Authoritative local evidence is in the
[filesystem upstream identities](../../profiles/mcp/filesystem-readonly-v1/upstream-identity.json),
the [npm lock](../../profiles/mcp/filesystem-readonly-v1/package-lock.json) and
the [Python attribution records](../../profiles/mcp/git-readonly-v1/upstream-notices/runtime-licenses/provenance.json).
Each installed inventory row retains its notice paths and SHA-256 values.
Maintainer decisions must name the exact package/version/origin and notice
identities, permitted distribution scope, required conditions and reviewer.

## Remaining advisory decisions

| Observation | Material and boundary | Required disposition |
| --- | --- | --- |
| setuptools 70.3.0, GHSA-5rjg-fvgr-3xxf / PYSEC-2025-49 | Pip redistributes `pkg_resources`. The affected `setuptools/package_index.py` download implementation is absent from that subset. | Review the exact installed file-set evidence and record advisory applicability |
| setuptools 70.3.0, GHSA-h35f-9h28-mq5c / PYSEC-2026-3447 | The affected `setuptools/command/egg_info.py` and `_distutils/filelist.py` source-distribution builders are absent from the pip subset. The selected pilot runs on Linux. | Review the exact installed file-set and supported-platform evidence |
| setuptools 70.3.0, GHSA-xmj3-9gf7-h52w | The affected legacy `setuptools/wheel.py` Windows installation path is absent from the pip subset. The selected top-level setuptools is 84.2.0. | Review the exact installed file-set and separately versioned top-level distribution |
| paste 1.0.15, RUSTSEC-2024-0436 | An unmaintained procedural macro remains in the optional ML dependency graph. Upstream lists no patched version. | Decide on a version-specific maintenance disposition or a separately qualified upstream/fork migration |
| unsafe-libyaml 0.2.11, RUSTSEC-2024-0449 | The unmaintained parser is used through serde_yaml. Existing policy APIs expose serde_yaml errors and parsing behavior. Upstream lists no patched version. | Decide on a maintenance disposition or a parser migration with policy-format and API compatibility tests |

The three setuptools rows above describe source-backed applicability evidence.
The scanner continues to report the observed package identities and every
finding, including aliases. Cargo maintenance warnings also remain visible.
Existing checks require those findings to be resolved through the established
review process.

Sources for the remaining observations are the upstream
[PackageIndex advisory](https://github.com/advisories/GHSA-5rjg-fvgr-3xxf),
[manifest advisory](https://github.com/advisories/GHSA-h35f-9h28-mq5c),
[legacy wheel advisory](https://github.com/advisories/GHSA-xmj3-9gf7-h52w),
[paste maintenance notice](https://rustsec.org/advisories/RUSTSEC-2024-0436.html)
and [unsafe-libyaml maintenance notice](https://rustsec.org/advisories/RUSTSEC-2024-0449.html).

## Native review and final qualification

The selected Git, bubblewrap, Node and Python binaries, their bundled libraries,
host Python and selected system ELF libraries require a current native review.
The checkpoint retains the earlier source/notice observations and unresolved
distribution-advisory dispositions. The responsible reviewer supplies the
exact-binary, version, source, notice and system-library assertions required by
`--native-reviews` in the [inventory procedure](installed-runtime-inventory.md).

After dependency, license and native-review decisions are admitted, the team
lead owns qualification of the current reviewed source, Ready CI, CodeQL,
candidate admission and integration. Keep earlier failed and successful
observations attributed to the source, selected binaries and archive that
produced them.
