# TLS Rotation and Recovery Report

Date: October 14, 2026

Task: [SOU-38](https://linear.app/soup-wall/issue/SOU-38/deliver-a-reproducible-tls-edge-certificate-rotation-and-recovery)

Result: local Linux/Docker verification passed.

## Scope

The drill runs the current Gateway, Caddy 2.10.2 and separate verifying clients
in a disposable Linux container. It uses generated certificates and explicit
client CA trust. The Gateway and Caddy admin API listen on loopback. Docker
publishes no host ports and disables external networking.

The source baseline is [`219a19d`](https://github.com/SoupTeam/soup-wall/commit/219a19dba621ed2c08de08f7ccd50c48804aa0bc),
which contains the SOU-38 starting commit `290e043`. The local changes add the
rotation tooling, tests and deployment fixture; the working tree remains modified.
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

- Gateway binary: `ffb112745ce4df20e0b7c587fe29b912aa2da729df8bac3fd90fa0ee75ee0a24`
- Gateway source manifest: `943ff842146dff98fb65b510c4e0a8d69728fbd55c3704ec3c0c3d7b443bb931`
- Verification source manifest: `47d650e455b93399a5a5cc5e28d9fce77a79f4a7e60336bc040d38e871a49027`
- Initial served certificate: `88175f5cbdb24439c5308180749fe51234208f7fde37ceefc55bace7ad7ea73e`
- Rotated served certificate: `36874b9c6cc2093cc9332ebfae63e5037ff3e1bc86135411a17de28025cf85fb`

The JSON includes the pinned image digests, local image ID, Caddy binary hash,
configuration hashes, certificate fingerprints and diagnostics. Raw logs, public
certificates, configuration snapshots and the outer Docker cleanup record remain
under `target/tls-evidence/final-2026-10-14/`. Source checks before and after the
run matched. The evidence scan found no private key material or generated token.

## Acceptance Boundary

This run establishes the controlled Linux/Docker TLS workflow. It does not
establish public ACME issuance, external certificate automation, customer-domain
acceptance or native Windows/macOS TLS support. The GitHub workflow is prepared
locally; hosted CI and PR review have not run for these changes.

See the [operator guide](../TLS_ROTATION.md) for initialization, rotation,
ownership requirements and recovery commands.
