# SOU-231 installed managed Console connection evidence

Final Linux run [41889836435](https://github.com/SoupTeam/soup-wall/actions/runs/41889836435) passed on exact clean source `e13c1f777af4a59f05f023aabf057e866fbd5dd1`. Runtime Rust bytes are unchanged from `8e644d668e3346662f19235701a28e4ecdfef4db`; the last follow-up corrects only the independent legacy fixture and preserves failure evidence. Implementation starts independently from accepted main `5dd30c878d0c786d4ec6c623a33ce4b554469683`; SOU-226/227 are not dependencies.

## Native installed qualification

- sqlite: 33 controls passed, no skips; artifact 13352952782; archive SHA-256 `b0eb1644e80bc2f56cee320293935b841fe3cd0a99ecdf77971c75c3d9a88ea2`; all 284 source hashes verified against exact Git.
- postgres: 34 controls passed, no skips; artifact 13351899784; archive SHA-256 `85b4fedd8dd354be96acb8998a83be5b08f0833a6efd0635c66ac4bb4948c03f`; all 284 source hashes verified against exact Git.

The installed binary and working directory are outside checkout. An owned HTTPS edge forwards to a real Console backed by SQLite or an independently provisioned TLS PostgreSQL 16 cluster. Issuer trust is derived locally from the owned test issuer, not Console discovery. Both runs prove exact signed policy application with actual hook decisions and Console applied records; wrong audience/key/CA; empty-inbox foreign credentials and forged scope metadata; stale inputs; concurrent apply; actual SIGKILL at the rename syscall, unchanged previous selector and successful retry; credential rotation/reload; online/offline restart; guarded and stale-consent disconnect; retained policy/cache/anti-replay/credentials/config/user files; no sync after disabled restart; reconnect at the next sequence; independent environment-only startup; and absence of tokens/key material in argv, CLI reports and owned logs.

Verification of a fresh pending candidate never claims application. After Console records actual application and its inbox is empty, verified authenticated scope is reported separately from the runtime application record.

`native-final.json` records independent ZIP SHA/CRC, clean commit/tree and source hash verification. `final-sqlite.json` and `final-postgres.json` contain only sanitized outcomes and hashes. Credentials, configuration contents, raw logs and strace output remain in disposable private storage and are not published.

## Local qualification

2,039 full-workspace tests passed with 15 explicit environment-dependent ignores. Final staging hardening passed all 15 connection adversarial tests; exact audience controls, all-target workspace Clippy with warnings denied, fmt and 13 CI component tests passed. Target execution used read-only source, scratch-only writes and loopback-only Seatbelt. Detailed attribution, command classes and development source/log hashes are retained in `local-validation.json`; the local suite is not presented as Linux/PostgreSQL runtime proof.

## Previous attempts

All three failed native attempts and sanitized backend reports are retained with exact source attribution and independently verified ZIP/source hashes:

1. `1fc3cc83`, run 41883743998: SIGKILL witness depended on a strace formatting annotation; later attempts explicitly prove syscall/target/SIGKILL, process exit -9 and unchanged selector. Fixture publication also changed from write-then-chmod to the existing private atomic writer; CodeQL alert 229 reports fixed.
2. `39c275e2`, run 41885067663: actual application passed; verify refused an empty pending inbox without authenticated audience evidence. Shared Console response metadata now binds exact authenticated scope for both backends; missing, duplicate and mismatched pairs are refused.
3. `8e644d66`, run 41888907395: 30 SQLite/31 PostgreSQL controls passed through disconnect and reconnect; the legacy fixture incorrectly expected delivery of an already applied deployment into a new home. Final fixture uses a separate enrollment and pending signed deployment. No runtime relaxation was made.

See [setup and recovery](../../INSTALLED_MANAGED_CONSOLE.md). The Draft PR is an author-side delivery; final Ready/security/current-main admission and integration remain maintainer-owned.
