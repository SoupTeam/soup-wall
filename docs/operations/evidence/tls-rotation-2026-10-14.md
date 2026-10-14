# TLS Rotation and Recovery Report

Date: October 14, 2026

Task: [SOU-38](https://linear.app/soup-wall/issue/SOU-38/deliver-a-reproducible-tls-edge-certificate-rotation-and-recovery)

Result: local Linux/Docker verification passed.

## Scope

The drill runs the current Gateway, Caddy 2.10.2 and separate verifying clients
in a disposable Linux container. It uses generated certificates and explicit
client CA trust. The Gateway and Caddy admin API listen on loopback. Docker`
publishes no host ports and disables external networking.

The tested revision is [`159f5ef`](https://github.com/SoupTeam/soup-wall/commit/159f5efadeb4bc811596003c93300a9e7c4bf32c).
It includes the TLS tooling on main `5fc6d72`, which contains the SOU-38 starting
commit `290e043` and the updated Gateway TLS dependencies.
The [JSON evidence](tls-rotation-2026-10-14.json) identifies the Gateway source and
the verification files by their actual content hashes.

## Method

Run from the repository root:

```sh
python scripts/tls-lifecycle.py --out target/tls-evidence/review
```

The helper stages bounded certificate/key files, checks trust, hostname, validity
and key match, then validates the Caddy configuration. It records the prior
configuration before reload and commits after an independent HTTPS client
confirms the served fingerprint and HTTP 200 health response. Each recovery
check also sends an authenticated model request to the local provider fixture.

## Results

All 49 checks passed. The focused suite passed 15 tests with no skips.
The run retained 31 client witnesses and observed 15 authenticated provider
requests. The unauthorized request did not reach the provider.

| Check | Observed result |
| --- | --- |
| Initial HTTPS and authenticated request | Verified certificate; HTTP 200; expected provider response |
| Missing client token | HTTP 401; no additional provider call |
| Metrics and admin paths | HTTP 404 at the edge |
| Request body above 4,194,304 bytes | HTTP 413; no additional provider call |
| Certificate rotation | Served fingerprint changed; authenticated request remained useful |
| Malformed PEM, mismatched key, oversized file and symlink | Replacement rejected; active configuration unchanged |
| Expired, wrong-hostname and untrusted certificates | Replacement rejected; authenticated requests still succeeded |
| Wrong client verification hostname | X.509 error 62; no HTTP response |
| Untrusted client CA | X.509 error 20; no HTTP response |
| Expired certificate served by the isolated bypass fixture | X.509 error 10; committed certificate restored |
| Native Caddy reload with a mismatched key | Reload failed; prior served certificate remained usable |
| Rotator killed before reload | Pending journal retained; prior version recovered |
| Rotator killed after reload, before confirmation | Client observed the uncommitted version; recovery restored the prior version |
| Caddy unavailable during rotation | Operation failed; journal remained; restart and recovery restored service |
| Ownership, cleanup and evidence privacy | UID 65532; private file modes; owned processes and temporary files removed |

The hostname witness uses SNI `localhost` and verifies the certificate against
`wrong.invalid`. This isolates hostname verification from Caddy's refusal to
serve a certificate for an unknown SNI. The expired-server witness bypasses the
helper only within the disposable fixture; the normal rotation path rejects
expired material before changing the active configuration.

## Runtime and Integrity

| Item | Value |
| --- | --- |
| Execution | Linux amd64 containers through Docker Desktop/WSL2 on Windows |
| Docker | 29.7.2 |
| Python | 3.12.15 |
| OpenSSL | 3.0.22 |
| Caddy | 2.10.2 |
| Kernel | `6.18.33.2-microsoft-standard-WSL2` |
| Request bound | 4,194,304 bytes at both Gateway and edge |

SHA-256 values:

- Gateway binary: `b333a983456a8c45b958fa0359fd6e7d1b3a1275ffe747a5f39666735e4c66cd`
- Gateway source manifest: `6419e825a4dac71d79e307e5d9eb1acb29d32f1bbe56a3d5a4d03db29ffeafb1`
- Verification source manifest: `47d650e455b93399a5a5cc5e28d9fce77a79f4a7e60336bc040d38e871a49027`
- Initial served certificate: `add8ed282854a08e0f61911ee3ea3fd2d33bb2da8a791c32ebde5be50f2387e0`
- Rotated served certificate: `8e71c6c0b2ecd452a2e73108ff43d764f8eefbae3045c8dc7477e848d069ebb7`

The JSON includes the pinned image digests, local image ID, Caddy binary hash,
configuration hashes, certificate fingerprints and diagnostics.
The [witness archive](tls-rotation-2026-10-14.zip) contains raw logs, public
certificates, configuration snapshots and the outer Docker cleanup record.
Archive SHA-256: `3f29872cac9ba3035ae94b014ec581810718dd8b435fe81cc426846bc0f329f1`.
The local run remains under `target/tls-evidence/pr-current-2026-10-14/`.
Source checks before and after the run matched. The evidence scan found no
private key material or generated token.

## Acceptance Boundary

This run establishes the controlled Linux/Docker TLS workflow. It does not
establish public ACME issuance, external certificate automation, customer-domain
acceptance or native Windows/macOS TLS support. The GitHub workflow is prepared
locally; hosted CI and PR review have not run for these changes.

See the [operator guide](../TLS_ROTATION.md) for initialization, rotation,
ownership requirements and recovery commands.
