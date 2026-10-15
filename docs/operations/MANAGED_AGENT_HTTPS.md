# SOU-43 — managed Agent HTTPS transport

> **Draft scope (Oct 15, 2026):** This document describes the initial Agent transport changes in PR #121. The required isolated-network HTTPS Console→Agent demo and full certificate/redirect/offline evidence are **not complete yet**. Do not claim SOU-43 accepted or production-certified.

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

- Initial Rust unit checks cover allowed HTTPS/local origins, remote plaintext refusal, embedded credentials, path/query/fragment/ambiguous URL refusal and invalid/oversized CA inputs. **These are not yet real network handshakes**.
- Required independent deliverable: use an isolated disposable nonloopback network with an HTTPS edge and operator-generated test CA to route to the existing SQLite Console; run the **real `agentfw serve`** with `SOUP_MANAGED_AGENT_CONSOLE=https://...` and its CA file; verify ordered deny → defer → deny with matched authenticated applied acknowledgements and monotonic rollback.
- Add controlled negative tests for wrong hostname, untrusted/expired certificates, redirect credential forwarding, revoked Agent credential, unreachable Console and retained last accepted policy. No rejected exchange may change the running policy or create an applied acknowledgement. Record actual source SHA, certificate fingerprint, keyring/config identity and sanitized evidence without secrets.
- Existing SOU-30 loopback demo does not prove SOU-43. Remote production, cross-host trust distribution and edge certificate rotation are **outside this bounded issue** and require separate operational acceptance.

Tracking: [SOU-43](https://linear.app/soup-wall/issue/SOU-43/enable-verified-remote-https-console-to-agent-policy-transport) · [Draft PR #121](https://github.com/SoupTeam/soup-wall/pull/121).
