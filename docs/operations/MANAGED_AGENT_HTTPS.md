# SOU-43 — managed Agent HTTPS transport

> **Reviewed scope pending (Oct 15, 2026):** The [real owned-network HTTPS Console→Agent demonstration](https://github.com/SoupTeam/soup-wall/actions/runs/38689382326) now passes on source head `365ff415b690de18fa38c279778dd2f2722ca9d9`, with independently downloadable non-secret artifact `sou43-remote-https-agent-evidence`. This proves the stated isolated Linux Docker-bridge test case, **not** general remote production/multi-host TLS certification. PR #121 still requires full exact-head CI and independent security review before merge.

## Configuration

The existing managed-policy Console, credential and signing-key settings from [Managed Agent Policy](MANAGED_AGENT_POLICY.md) remain mandatory.

```sh
SOUP_MANAGED_AGENT_CONSOLE="https://console.example.internal:8443/"
SOUP_MANAGED_AGENT_TLS_CA_FILE="/absolute/path/to/operator-root-ca.pem" # optional
```

- `SOUP_MANAGED_AGENT_CONSOLE` must be one **absolute origin only**: `https://HOST[:PORT]/`, no URL credentials, extra path, query or fragment. Remote plaintext `http://` is refused. For compatibility, `http://127.0.0.1:PORT/`, `http://localhost:PORT/` and `http://[::1]:PORT/` remain valid **local-only** origins.
- The HTTPS transport uses `reqwest` Rustls with standard server-certificate chain, hostname/IP SAN and validity-time verification. Invalid hostname, untrusted or expired certificates must cause TLS failure; do not disable TLS verification or use an insecure flag.
- For an operator-controlled private CA, provision a trusted PEM file **locally on the Agent host** and supply its absolute path through `SOUP_MANAGED_AGENT_TLS_CA_FILE`. The Agent reads at most 64 KiB, validates PEM syntax at startup and adds that certificate to its trust anchors. This file is a **public CA certificate**, not a private signing key. Don't copy CA private keys or the Agent Bearer token to Console logs or into evidence artifacts. For public CA deployments, omit this setting.
- A private CA setting with loopback HTTP is refused rather than silently ignored. This option does **not** pin a unique TLS certificate; it adds a local trust root. Maintain CA/key governance at the operator level.
- The Agent's HTTP client rejects redirects, disables inherited proxy routing and retains the existing five-second timeout. Only the pinned-origin `/agent/v1/policy` and `/agent/v1/policy/ack` endpoints receive Agent Bearer credentials. Unexpected 3xx is an error, never permission to forward a Bearer header to another origin.
- **Signed-policy verification is separate from TLS**: the pinned issuer public key/keyring, audience/revision, SHA-256 payload, expiry, deployment sequence and persisted grant epoch are unchanged. Invalid transport cannot grant policy authority. Console outage retains last accepted in-memory/restored signed policy.

## Test scope and acceptance gap

- Rust unit checks cover allowed HTTPS/local origins, remote plaintext refusal, embedded credentials, path/query/fragment/ambiguous URL refusal and invalid/oversized CA inputs. The dedicated hosted demo additionally executes **real TLS handshakes**, a real Console and a real Agent.
- **Implemented and passed on the stated hosted run:** a disposable Docker bridge with nonloopback HTTPS edge and operator-generated test CA routes to the existing SQLite Console. Real `agentfw serve` uses `SOUP_MANAGED_AGENT_CONSOLE=https://...` with locally installed CA and demonstrates ordered deny → defer → deny, three matched authenticated applied acknowledgements and signed monotonically increasing rollback. The edge-to-Console leg is **private bridge-local HTTP**, so this is not TLS-to-Console end-to-end certification.
- **Implemented and passed:** wrong hostname, untrusted and expired certificates, credential-forwarding redirect refusal (attacker capture receives no Agent token), revoked Agent credential refusal, unavailable Console and last accepted policy retention. Unsuccessful pre-activation exchanges create no applied acknowledgement. The artifact records exact tested Git SHA, binaries and fixture SHA-256, served certificate DER SHA-256, CA fingerprint and sanitized network/test scope; it contains no signing seed, Bearer token or private key.
- Existing SOU-30 loopback demo does not prove SOU-43. Remote production, cross-host trust distribution and edge certificate rotation are **outside this bounded issue** and require separate operational acceptance.

Tracking: [SOU-43](https://linear.app/soup-wall/issue/SOU-43/enable-verified-remote-https-console-to-agent-policy-transport) · [Draft PR #121](https://github.com/SoupTeam/soup-wall/pull/121).

## Reproduce the owned-network demonstration

Requirements: Ubuntu/Linux host with Docker Engine, Python 3, OpenSSL and a Rust toolchain. Docker will pull the pinned Python test-edge image. The script creates temporary keys, a private bridge, a disposable SQLite Console and Agent home, and removes test containers/network after execution. It never contacts an external model/provider.

```sh
python3 scripts/managed-policy-tls-demo.py
# If binaries have already been built:
python3 scripts/managed-policy-tls-demo.py --no-build
```

Inspect the sanitized generated `target/sou43-managed-policy-tls-evidence.json`, the [hosted workflow](https://github.com/SoupTeam/soup-wall/actions/workflows/managed-policy-tls.yml) and the PR source. Test identity includes Git source SHA and the actual binary/fixture/certificate digests. No public DNS or public CA is required. CI **does not** prove multi-host deployment, hardened edge termination, remote IdP enrollment or key rotation.
