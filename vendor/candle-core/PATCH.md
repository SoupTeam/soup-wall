# candle-core 0.11.0: patched ZIP dependency

Origin: https://crates.io/crates/candle-core/0.11.0
Upstream revision: 31f35b147389700ed2a178ee66a91c3cc25cc80d (candle-core)
Verified registry archive SHA-256: 5ecb245093b0f791b89d3420c3df9c6d49c60ab63ba54db896bf8a3baf486706
License: MIT OR Apache-2.0; the original Apache license text in LICENSE is retained.

Published tests, examples, benches, README and original manifest are byte-identical to the verified archive. The normalized Cargo.toml dependency on zip changes from 8.6.0 to 9.0.4, retaining default-features=false. Three archive filename call sites in src/npy.rs and src/pickle.rs propagate the new fallible zip 9 name API instead of discarding errors. The obsolete std::f64 import in src/cpu/erf.rs is removed so primitive associated constants resolve without deprecation warnings. All other Rust source is unchanged. The upstream development Cargo.lock and .cargo_vcs_info.json are omitted; the application root Cargo.lock resolves dependencies. No tensor computation, model format or application feature changes.

This removes RUSTSEC-2026-0367/0368/0369 without advisory ignores. candle-core uses ZipArchive new/by_name for reading tensor archives. Compatibility must be verified with the application's ML/all-features build and archive-read regression. Remove this patch when a reviewed upstream release supports fixed zip.
