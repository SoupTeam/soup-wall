# Reviewed crate license notice sources (SOU-27)

These texts are copied **byte-for-byte** from the exact 20 crate cache archives inspected on 2026-10-12.
The Cargo.lock archive checksum and SHA256 of each copied notice are pinned in `policy/license-policy.toml`.
This repository copy is not a new license grant; review the upstream crate and redistributable artifact before release.

19 crates use legacy non-SPDX slash-form metadata. The original upstream archives contain an MIT license
grant; our policy selects **MIT**, not a global translation of `/` to `OR`.
`ident_case` has only a `LICENSE` file in the collected archive, which contains the MIT text.
No Apache license alternative is assumed where the Apache text is missing.

`minimal-lexical 0.2.1` additionally has a `LICENSE.md` containing a BSD-3-Clause
attribution and disclaimer for Go-derived code used with its `compact` feature.
That original file is preserved as a supplemental notice, regardless of feature selection.
The upstream `COPYRIGHT`, `COPYING` and `copyright.txt` notices are likewise retained where collected.

**`webpki-roots 1.0.10` is a separate, version-pinned data license exception, not part of**
**the permissive software license allowlist.** Its original `LICENSE` is CDLA-Permissive-2.0;
its README describes the root-certificate material as derived from CCADB data.
CDLA section 2.1 requires making the complete agreement text available with shared data.
The release owner must review whether final binary/container/package distributions
fulfill that condition and whether other CCADB data-use conditions apply.

These local copies help release packaging but are not proof that any proposed
distribution already carries legally sufficient notices. `approved_for_release`
remains **false** while optional models, datasets and Python packages are unresolved.

| Package | Version | License selected | Primary evidence | Extra notices |
|---|---|---|---|---|
| `base64` | `0.13.1` | `MIT` | `base64-0.13.1/LICENSE-MIT` | 0 |
| `enum-as-inner` | `0.6.1` | `MIT` | `enum-as-inner-0.6.1/LICENSE-MIT` | 1 |
| `fallible-iterator` | `0.2.0` | `MIT` | `fallible-iterator-0.2.0/LICENSE-MIT` | 0 |
| `fallible-iterator` | `0.3.0` | `MIT` | `fallible-iterator-0.3.0/LICENSE-MIT` | 0 |
| `fallible-streaming-iterator` | `0.1.9` | `MIT` | `fallible-streaming-iterator-0.1.9/LICENSE-MIT` | 0 |
| `fnv` | `1.0.7` | `MIT` | `fnv-1.0.7/LICENSE-MIT` | 0 |
| `ident_case` | `1.0.1` | `MIT` | `ident_case-1.0.1/LICENSE` | 0 |
| `minimal-lexical` | `0.2.1` | `MIT` | `minimal-lexical-0.2.1/LICENSE-MIT` | 1 |
| `rayon-cond` | `0.4.0` | `MIT` | `rayon-cond-0.4.0/LICENSE-MIT` | 0 |
| `same-file` | `1.0.6` | `MIT` | `same-file-1.0.6/LICENSE-MIT` | 1 |
| `serde_plain` | `1.0.2` | `MIT` | `serde_plain-1.0.2/LICENSE-MIT` | 0 |
| `serde_urlencoded` | `0.7.1` | `MIT` | `serde_urlencoded-0.7.1/LICENSE-MIT` | 0 |
| `stringprep` | `0.1.5` | `MIT` | `stringprep-0.1.5/LICENSE-MIT` | 0 |
| `unicode-normalization-alignments` | `0.1.12` | `MIT` | `unicode-normalization-alignments-0.1.12/LICENSE-MIT` | 1 |
| `unicode-properties` | `0.1.4` | `MIT` | `unicode-properties-0.1.4/LICENSE-MIT` | 1 |
| `vcpkg` | `0.2.15` | `MIT` | `vcpkg-0.2.15/LICENSE-MIT` | 0 |
| `version_check` | `0.9.5` | `MIT` | `version_check-0.9.5/LICENSE-MIT` | 0 |
| `walkdir` | `2.5.0` | `MIT` | `walkdir-2.5.0/LICENSE-MIT` | 1 |
| `webpki-roots` | `1.0.10` | `CDLA-Permissive-2.0` | `webpki-roots-1.0.10/LICENSE` | 0 |
| `wiremock` | `0.6.5` | `MIT` | `wiremock-0.6.5/LICENSE-MIT` | 0 |
