# Source provenance and intake rules

Soup Wall contains the Agent, Gateway, Console, and supporting crates in one Apache-2.0 workspace. The project is derived from [carbon-evolution/llm-firewall](https://github.com/carbon-evolution/llm-firewall) by Arthur Lin and contributors. Upstream copyright and patent terms remain in force. Keep SPDX identifiers, [LICENSE](../LICENSE), [NOTICE](../NOTICE), and required third-party notices. A per-file copyright line should be added only when its ownership can be established.

## External source intake

Record the origin, exact version or revision, license, and required notices before introducing external code or assets:

1. **Permissive reuse:** MIT, Apache-2.0, BSD, ISC, and similar licenses may be integrated after review.
2. **Reviewed copyleft:** GPL, LGPL, MPL, AGPL, and similar terms require an explicit legal and architectural review for the exact linked binary, container, frontend bundle, or hosted use.
3. **Specification only:** proprietary, non-commercial, research-only, source-available, unknown, or incompatible sources must not be copied. An independent implementation may use public specifications, documented behavior, and independently written tests. Keep the behavioral specification free of source fragments and distinctive implementation details.

Model weights, benchmark datasets, container base images, and frontend assets need their own license and provenance review. Their terms are not changed by the Rust workspace license. Optional ML model weights are fetched separately and are not silently bundled into the source distribution. The reviewed agent-session corpus is synthetic and hand-authored; it is regression material, not customer data or a held-out benchmark.

## Dependency and advisory review

The locked workspace includes the Gateway's identity and storage dependencies. The SAML adapter uses [`saml-rs 0.6.1`](https://github.com/salasebas/saml-rs/releases/tag/v0.6.1) (MIT), `bergshamra 0.9.2` (BSD-2-Clause), and [`kryptering 0.6.0`](https://github.com/kushaldas/kryptering/releases/tag/v0.6.0) (BSD-2-Clause). Kryptering is a pinned local package with a narrowly scoped platform patch. [Its intake record](../vendor/kryptering/PATCH.md) records the original registry archive checksum, upstream revision, retained license and source, omitted development assets, exact delta and update procedure. The upstream source differs only in its platform guard and error message; cryptographic operations are unchanged. The optional ML dependency also has a reviewed local patch; see below. Other dependencies remain registry packages. The 0.6 migration explicitly retains signed assertions, signed authentication requests, audience validation, and zero clock-skew tolerance; it does not adopt the new five-minute validation default. Metadata signature verification, replay protection, and the provider boundary remain required.

The optional ML graph pins `candle-core 0.11.0` to [a reviewed local patch](../vendor/candle-core/PATCH.md) to use fixed `zip 9.0.4` without suppressing RUSTSEC-2026-0367/0368/0369. Its registry archive SHA-256 and four-file delta are recorded in the patch note; the original license and all upstream source/test fixtures are retained. Three archive-name readers propagate ZIP 9's fallible filename API, and a deprecated import is removed. Tensor computation and application ML features are unchanged. The license gate requires the exact path, version, manifest and license digests from `reviewed_paths`; unlisted or modified path dependencies fail. Both patched dependencies remain excluded from workspace membership.

All release targets select the AWS-LC document provider, using the workspace's existing `aws-lc-rs 1.18.2` dependency (Apache-2.0 OR ISC). The patch adds only non-FIPS Windows x86_64 MSVC to kryptering's existing Linux and non-FIPS macOS x86_64/aarch64 support. [AWS-LC itself supports Windows MSVC](https://aws.github.io/aws-lc-rs/platform_support.html). Windows ARM, Windows GNU and Windows FIPS are not admitted by this patch. Unsupported targets fail at the provider guard; there is no RustCrypto fallback. The complete application `Cargo.lock` and release graphs exclude `rsa`. Keep the vendored package excluded from the application workspace so upstream development dependencies do not enter that lock.

[`RUSTSEC-2023-0071`](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) concerns observable timing during RSA key-transport **decryption**. Soup Wall's SAML path does not configure an XML decryption key or advertise encrypted assertions; encrypted assertions fail closed, and regression tests protect that behavior. Provider selection does not enable encrypted assertions. The local, CI and release advisory checks run `cargo audit` without vulnerability exceptions. Informational maintenance and yanked-package warnings remain visible. Encrypted-assertion support still requires a separate threat review and new interoperability evidence.

[Issue #19](https://github.com/SoupTeam/soup-wall/issues/19) requires reviewed provider evidence, native signature and real-IdP document interoperability on every release target, absence of the vulnerable dependency from the complete locked release graph, and audit without an exception. The `saml-release-targets` CI job checks provider attestation, the resolved dependency boundary, signed SSO, signature and metadata tampering, and encrypted-assertion rejection on all four release targets. A locally manufactured IdP response is not vendor interoperability evidence; genuine vendor documents and live password/ACS acceptance must be identified separately.

The [2026-10-06 provider checkpoint](operations/evidence/SAML_PROVIDER_2026-10-06.md) records Windows-native SAML checks, live Keycloak password/ACS acceptance with successful cleanup, and the complete lock audit without an exception. Captured vendor-signed documents provide regression inputs for the four native release-target jobs. Review the candidate pull request's exact-head CI results before accepting the provider change; live vendor acceptance covers Windows. Issue closure requires every acceptance criterion above to pass.

Run a fresh locked dependency, license, and advisory review for each release. The `Cargo.lock` and generated CycloneDX SBOM describe the actual versions; this document is not a substitute for examining the current graph. A previous public Core-only audit with no exceptions does not describe the full workspace after the Gateway import.

The SAML interoperability fixture under `crates/proxy/tests/fixtures/saml/` uses a self-signed test key pair. It is not a customer credential and must not be used in a deployment. Secret scans of working files and Git history, including generated artifacts and workflow logs, are release checks before publishing material from a previously private source tree.

## Automated dependency-license and provenance check (SOU-27)

The dedicated [license-policy workflow](../.github/workflows/license-policy.yml)
runs on pull requests, pushes to main and manual dispatch. It uses the six-member
workspace's **locked, all-feature Cargo metadata without a platform filter**,
checks every resolved package against `Cargo.lock`, and requires the patched
`vendor/kryptering 0.6.0` to remain the reviewed local path with its original
BSD-2-Clause license text and [patch provenance](../vendor/kryptering/PATCH.md).
The policy and optional asset manifest are at
[`policy/license-policy.toml`](../policy/license-policy.toml) and
[`policy/asset-provenance.toml`](../policy/asset-provenance.toml).

The checker implements SPDX `WITH` before `AND` before `OR`. A dependency
passes if a **complete** offered license alternative consists of explicitly
reviewed obligations; `WITH` additions are never discarded. Unknown metadata,
unsupported expressions and unreviewed sources fail, as do missing vendor
notices and incomplete lock coverage. A package exception must match an **exact name, version, source and
Cargo.lock checksum**, preserve a real upstream license notice whose SHA-256
matches policy, and preserve any supplemental copyright or derived-code notices.
The 19 legacy slash-form packages are specifically documented at
[`policy/third-party-notices/README.md`](../policy/third-party-notices/README.md);
no general translation of `/` to `OR` is permitted. `webpki-roots 1.0.9` is
separately limited to its source CDLA-Permissive-2.0 license and pinned archive.
Final release packaging and notices for CCADB-derived trust data require an
explicit maintainer review; a green Rust check is not release approval. The
permissive allowlist is not a blanket declaration of legal compatibility.

Run with **Python 3.11+** and the Rust toolchain from the repository root:

```sh
python3 -m unittest discover -s scripts/tests -p 'test_license_policy.py' -v
python3 scripts/license_policy.py --root . --report target/license-policy/report.json
```

The check writes JSON **even on metadata/approval failures** with individual
package license expression, status, selected approved SPDX branch, exact
package source, source-manifest and lock hashes, checker/policy/asset hashes,
vendored PATCH/manifest hashes, current Git HEAD and dirty status (when
available). It returns nonzero on unreviewed/disallowed Rust licenses or
incomplete source inventories. CI uploads the report as an artifact on failure.
`cargo audit`, CycloneDX SBOM generation and CodeQL continue independently.

The asset manifest records the vendored license text separately from optional
pinned AgentDojo benchmark and SOU-13 validation Python requirements, third-party model checkpoints and
benchmark datasets. The latter are currently **unresolved**, often fetched from
mutable upstream `main`/dataset references and **not bundled**. Their hashes are
recorded only if files exist; absence or unknown license is **not approval**.
The report's `license_gate_pass` concerns only the locked Rust workspace;
`approved_for_release` is always false: this inventory never authorizes a release.
Legal/redistribution approval still requires independent source terms, notices,
immutable revisions and an authorized review for the actual redistributed assets.
Do not publish percentages as license coverage for external models or datasets.

## Selected filesystem MCP runtime (SOU-62)

The optional [filesystem read-only profile](operations/MCP_REAL_FILESYSTEM.md)
installs the original `@modelcontextprotocol/server-filesystem@2026.8.31`
and TypeScript MCP SDK `1.32.1` (MIT) from npm. The server package metadata says
`SEE LICENSE IN LICENSE`, but its published npm archive omits that file. Its
pinned source license documents an Apache-2.0/MIT transition; retain that exact
upstream notice separately with the profile rather than declaring a single
license for all upstream contributions. The committed
[upstream identity](../profiles/mcp/filesystem-readonly-v1/upstream-identity.json)
records exact package archive integrity, source revisions, original entrypoint
and discovery hashes; the adjacent npm lock pins the complete transitive graph.
Original discovery JSON is retained as a behavioral fixture with its upstream
identity. No server implementation is copied or rewritten into Agent.
`npm ci --ignore-scripts` preserves the original package tree. The installer
separately retains the pinned upstream notices outside that tree; the complete
package tree digest is verified before sandbox execution.

The acceptance runtime downloads official Node.js `22.22.0` and bubblewrap
`0.13.1` archives by SHA-256. Node.js retains its upstream license/third-party
notices; bubblewrap is a separate LGPL-2.0-or-later executable, built from its
unmodified official release source. Neither executable is linked into or
redistributed with the Apache-2.0 Rust binary by this change. The installer pins
the exact Node binary and the operator-selected bubblewrap binary, libraries and
complete npm tree in an explicit profile. Release redistribution still requires
review of the actual artifacts and notices.

The separate locked Claude Code `2.1.251` package is an acceptance-only host
installed from Anthropic's official npm packages with lifecycle scripts disabled.
Its vendor terms remain separate; it is not copied into this repository or
bundled with Agent. The owned scripted provider measures actual host protocol
interoperability, not live model efficacy. No paid model access or private data
is needed. The Cargo dependency graph remains unchanged.

## Release evidence

Review and retain the locked dependency graph, an SBOM, third-party license and notice inventory, model and dataset records, the upstream attribution, and security-scan findings for the **complete** workspace. Document any unresolved advisory or deployment limitation in the release notes.

## Optional SCIM interoperability client

The directory acceptance driver installs `scim2-client` 0.13.1 and
`scim2-models` 0.12.2 from [python-scim](https://github.com/python-scim), both
Apache-2.0 (Yaal Coop), with their packaged license notices retained by pip.
Their independent synchronous httpx2 engine drives the real local HTTP API;
no upstream library source is copied into this repository. This optional test
client is not bundled into the Gateway executable. Exact direct versions live
in [the fixture requirements](../scripts/scim-directory-requirements.txt);
run reports record the installed client/model/HTTP engine versions and source
hashes. PostgreSQL uses the existing digest-pinned disposable TLS fixture.
The pinned httpx2 2.13.1 transport is BSD-3-Clause (Pydantic Services / Tom Christie); its packaged license is retained in the isolated environment.
