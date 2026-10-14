# TLS Rotation and Recovery

## Run the Local Drill

Install Python 3.11 or newer, Git and Docker with Linux containers. From the
repository root, run:

```sh
python scripts/tls-lifecycle.py
```

On Linux, `python3` can replace `python`. The command builds the current Gateway
with the locked Cargo dependencies and runs Caddy 2.10.2 in a disposable Linux
container. The Dockerfile pins the Rust, Python and Caddy image digests. The first
build takes several minutes; later runs reuse the build cache.

The client, edge, Gateway and harmless provider fixture run inside that container.
Docker publishes no host ports and disables external networking. Caddy uses
`deploy/Caddyfile.rotation`, which follows the existing Caddy templates. The
Gateway listens on `127.0.0.1:8080`, and Caddy's admin API listens on
`127.0.0.1:2019`. The edge blocks `/metrics`, `/metrics/*`, `/admin` and `/admin/*`.
Both the edge and Gateway limit request bodies to 4 MiB.

Each client loads the generated CA for that request and checks the hostname and
certificate validity. The command does not modify the host trust store. An
authenticated request must return the fixture provider's `hello` response after
rotation and recovery. An unauthenticated request must return HTTP 401 without
reaching the provider.

Choose a new evidence directory when retaining a run:

```sh
python scripts/tls-lifecycle.py --out target/tls-evidence/review
```

The script refuses an existing destination. A failed check produces a nonzero
exit code. Retain `report.json`, `source.json`, `image.json`, `cleanup.json`, the
public certificates, configuration snapshots and logs. The report includes
independent client fingerprints, TLS verification failures, HTTP status codes,
provider counts, source hashes and runtime binary hashes. Private keys and tokens
exist only in the container's temporary filesystem. The command stops its owned
processes and removes the container after the run.

## Operator Commands

The Linux helper requires Python, OpenSSL and the pinned Caddy binary. Run it as
the same unprivileged user that owns the Caddy process and certificate directory.
Prepare an owned directory with mode `0700`. Certificate, key and CA files must
be regular files with mode `0600` and no hard links. Each material file has a
64 KiB bound. The selected template expects the certificate name `localhost`.
Use this template only for the declared local deployment.

Initialize the edge before starting Caddy:

```sh
python scripts/fixtures/tls_edge.py initialize \
  --root /path/to/edge --ca /path/to/ca.pem \
  --template deploy/Caddyfile.rotation \
  --cert /path/to/initial.pem --key /path/to/initial.key
caddy run --config /path/to/edge/Caddyfile --adapter caddyfile
```

Run rotation from another terminal:

```sh
python scripts/fixtures/tls_edge.py rotate \
  --root /path/to/edge --ca /path/to/ca.pem \
  --template deploy/Caddyfile.rotation \
  --cert /path/to/replacement.pem --key /path/to/replacement.key
```

The helper copies material into a private version directory, verifies the chain,
hostname, dates and key match, then runs `caddy validate`. It writes a recovery
journal before changing the active Caddyfile. It calls `caddy reload --force`
and commits only after a separate verifying HTTPS client observes the expected
certificate fingerprint and HTTP 200 health response. A lock prevents concurrent
rotations. Retain the prior version until the new certificate has passed the
deployment's acceptance checks.

## Restore a Working Version

If reload or client confirmation fails, the helper reloads the previous
configuration and verifies its served fingerprint. The operation still exits
nonzero: successful rollback does not mean successful rotation. If Caddy is
unavailable, the journal remains until recovery succeeds.

After a process interruption, start Caddy if needed, then run:

```sh
python scripts/fixtures/tls_edge.py recover \
  --root /path/to/edge --ca /path/to/ca.pem \
  --template deploy/Caddyfile.rotation
```

Recovery restores the journal's prior committed version, including an interruption
after reload but before confirmation. Without a pending journal, recovery reloads
the last committed configuration. The helper clears the journal only after a
verified handshake. Keep the CA used by the working version available during
rollback.

## Failure Coverage

The drill checks malformed PEM, mismatched keys, expired certificates, the wrong
hostname or CA, oversized files and symlinks. It also checks a native Caddy
reload refusal, separate client trust and hostname failures, process interruption
before and after reload, and recovery after Caddy becomes unavailable. For each
rejected replacement, the active configuration stays usable and an authenticated
Gateway request succeeds.

One isolated test bypasses the rotation helper to serve the expired fixture. The
client must reject it before receiving an HTTP response; recovery then restores
the committed certificate. This demonstrates the client boundary as well as the
helper's validation boundary.

These results cover the selected Linux/Docker setup with generated certificates.
Public ACME issuance, customer domains, external certificate automation and
native Windows or macOS deployment require separate acceptance work. Running
Linux containers from Windows does not establish native Windows TLS support.

The [October 14 local report](evidence/tls-rotation-2026-10-14.md) records the
verified run and links its machine-readable evidence.
