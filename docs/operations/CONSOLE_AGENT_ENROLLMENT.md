# Console: Agent enrollment and credential lifecycle

The Console admin page (`/admin`) has an **Agent enrollment and credentials**
panel under each tenant's Agent fleet. It drives the existing managed Agent
APIs: enrollment (`POST /admin/v1/tenants/:t/agents`), inventory (`GET`),
[credential rotation](MANAGED_AGENT_CREDENTIAL_ROTATION.md)
(`POST .../agents/:a/credential-rotations`) and revocation
(`POST .../agents/:a/revoke`). The server stays authoritative for roles,
tenants, generations and credentials.

An enrollment record, a credential generation or an applied acknowledgement is
**not** proof that an Agent is running or protected now.

## Who can do what

| Role | In the panel |
| --- | --- |
| Owner | enroll, rotate a credential, revoke |
| Operator, Viewer | read the enrollment records only |

The server checks the role on every request. A 401 (expired or invalid admin
session) or 403 (role) makes the panel read-only until you reconnect.

## Enroll an Agent

1. Select the tenant, type a new Agent ID (letters, digits, `.`, `_`, `-`) and
   press **Enroll Agent** (Enter works). A duplicate ID is refused and issues no
   credential.
2. The **one-time credential** appears in a highlighted box with numbered
   install steps. It is never put in a URL, browser storage, logs or exports.
   Other changes stay disabled until you choose **I stored it, clear it**.
   Switching tenant or **Lock console** also forgets it.
3. On the Agent host, store it in a private file without a newline and start the
   existing daemon (`agentfw serve`) with `SOUP_MANAGED_AGENT_TOKEN_FILE`, the
   tenant and Agent ID, the pinned issuer key and, for a private CA,
   `SOUP_MANAGED_AGENT_TLS_CA_FILE`. The panel shows the exact commands with
   these non-secret values filled in. Use the token **file**: only file mode can
   reload a rotated credential without restart.
4. Deploy an approved policy. The Agent fleet shows its applied acknowledgement.

If the credential is lost before it is stored, the Console cannot show it
again. Rotate the credential to issue a new one.

## Rotate a credential

**Rotate credential** asks you to type the Agent ID. The browser generates a
fresh random credential and operation ID in memory and sends one request with
the current generation. On success the new credential is shown once; replace the
Agent's token file with it (write a private `.next` file, then rename). The
running daemon re-reads the file before its next fetch. The old credential is
refused from the moment the server commits.

A refused rotation (another rotation or a revocation changed the enrollment)
discards the generated credential: it is never valid.

## Revoke

**Revoke** asks you to type the Agent ID. The credential stops working at once;
the Agent keeps its last verified policy but receives nothing new. Revocation is
final for that Agent ID.

## When the answer is unclear

If a change gets no clear answer (network loss, timeout, server error), the
panel never resends on its own. It reads the server's enrollment records once
and tells you what it found; all other changes stay disabled meanwhile.

- **Enrollment** recorded without the credential reaching you: rotate to issue
  a new one (or revoke). Not recorded: you may enroll again.
- **Rotation** committed: **Confirm with the same request** resends the
  byte-identical request; the server acknowledges an exact duplicate without
  another change, and only then is the credential shown. Not committed: send
  the same request again or **Discard**.
- **Revocation**: the records show whether the Agent is revoked.
- Server state unreadable: **Check again** when the Console is back.

Responses that arrive after you switched tenant are discarded; they are never
shown or applied to another tenant.

## Verification

```sh
python3 -B -m unittest scripts/tests/test_console_enrollment_browser.py
cargo build --locked -p llm-firewall -p agentfw
python3 -B scripts/console-enrollment-acceptance.py --no-build --backend sqlite --output /tmp/enrollment
python3 -B scripts/console-enrollment-acceptance.py --no-build --backend postgres --output /tmp/enrollment
```

The PostgreSQL run needs local PostgreSQL server binaries (`initdb`, `pg_ctl`,
`createdb`; `--pg-bin DIR`) and an ordinary user; it creates a disposable TLS
cluster. CI runs both in the Agent fleet workflow. Evidence:
[2026-10-31](evidence/CONSOLE_AGENT_ENROLLMENT_2026-10-31.md).
