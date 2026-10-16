# Constrained native MCP HTTPS GET (SOU-56)

The Linux native MCP broker implements one installed `https_get` tool. Its
original arguments are exactly `{ "url": "https://host/path?query=value" }`.
An operator must authorize that exact URL and one connection address. The broker
performs the GET after real native Allow. The discovery MCP child receives no
tool invocation. This is an operation executor, not containment of arbitrary
MCP-server code: the operator still trusts the child for startup and discovery.

## Install exact authority

The immutable native registry must install all of the following together:

- Tool name `https_get`, action class `network`, result provenance `untrusted`.
- One required egress selector `{ "pointer": "/url", "kind": "url_host", "optional": false }`.
- The fixed input schema below and its canonical SHA-256.
- One resource selector `/url`, kind `url`, with no aliases, defaults, optional
  omission or missing leaf.
- One exact URL resource including canonical URL, host and effective port.
- The exact classifier script revision and executor profile digest.
- A `network` authority containing the original URL, one approved IP address
  and any exact private-endpoint exception and additional CA certificate.
- A normal native policy that explicitly allowlists the destination host.

```json
{
  "type": "object",
  "properties": {
    "url": {"type": "string", "minLength": 1, "maxLength": 2048}
  },
  "required": ["url"],
  "additionalProperties": false
}
```

The versioned executor profile is `sw-native/https-get/linux-pinned/1`.
`executor_sha256` is SHA-256 of that UTF-8 profile string. It describes a reviewed
semantic contract, not attestation of a running binary. Record the binary digest
separately. Changes to the supported operation or limits require a new profile.
The complete authority, including any literal PEM trust root, is bound by an
additional digest. An example authority for an owned disposable receiver is:

```json
{
  "exact_url": "https://127.0.0.1:8443/document?item=7",
  "approved_addresses": ["127.0.0.1"],
  "private_endpoint": {
    "host": "127.0.0.1",
    "port": 8443,
    "address": "127.0.0.1"
  },
  "root_certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"
}
```

The actual fixture generates a real CA and leaf; the placeholder above is not
valid configuration. The additional root retains normal certificate chain,
hostname/IP SAN and validity-time verification. There is no insecure TLS option.
Its private key is never installed in the Agent. A private exception is specific
to the address and HTTPS identity and does not grant another URL, port or host.
Loopback, private, metadata, link-local and reserved addresses are denied by
default. Metadata and non-unicast addresses cannot be enabled by the test
exception. There is no global unsafe switch.

Only conservative canonical ASCII URLs are supported. Credentials, fragments,
percent escapes, backslashes, whitespace, Unicode host spellings, noncanonical
IP forms, normalized dot segments, explicit default-port aliases and URL parser
normalization are refused. Path and query must match the operator's original
string exactly. No caller headers, body, credentials or method are accepted.

## Compatibility and dispatch boundary

Network authorization adds `sw-native/resources/3`. It uses a separate optional
`network` policy and admission binding. Existing resource reads (`/1`) and
create-file execution (`/2`) retain their previous fields and behavior. Network
and create execution authority cannot coexist in one tool policy. Earlier
daemons refuse `/3`; there is no downgrade or fallback to an MCP server.

The binding covers GET action, exact original arguments, full operator policy,
approved connection address, TLS identity/trust, classifier, resource profile
and executor revision. Existing native correlation adds registry/schema,
server identity, original host call ID and the session epoch. A digest or model
prediction alone is never an execution grant.

The existing rule baseline classifies this bounded GET as `read`; only that
exact known prediction can pass the installed HTTPS profile's composition
gate. The trusted native action remains `network`. Deny, unconfirmed Ask,
unknown, mixed or invalid predictions remain blocked. The daemon separately
checks ordinary policy and explicit egress allowlisting, even under
`default: allow`. Existing parent tool grants and exact resource narrowing
remain in force. This does not add a parent URL-grant protocol or SOU-48 Ask
approval/redemption.

After actual native Allow, the broker rederives exact authority before DNS or
execution. Current resolution must equal the one approved address at preparation
and again immediately before connection. The executor connects directly to that
approved socket address; a later DNS change cannot choose another connection.
The TLS identity remains the original URL host. Connections do not inherit proxy
environment variables, cookies, authentication or client identity. One consumed
execution capability can make at most one connection attempt and one GET, with
no retries or redirect follow-up.

## Bounded response and release

Supported responses are complete HTTP/1.1 status 200 documents with an explicit
Content-Length and either `text/plain` or `application/json`, optionally with
exact `charset=utf-8`. JSON must also parse completely. Compression, transfer
encoding/chunking, unsupported statuses, content types and charsets are refused.
Redirects are errors and never contact their Location. Partial, oversized,
malformed or invalid UTF-8 documents are not released as inspected content.

The initial profile fixes these limits:

| Boundary | Limit |
| --- | --- |
| Original URL | 2,048 ASCII bytes |
| Additional root PEM | 16,384 bytes |
| Approved addresses | exactly one |
| Connection attempts / GET writes | at most one each |
| Each DNS resolution | 3 seconds |
| TCP connection | 3 seconds |
| Complete dispatch, including final DNS, TCP, TLS, request and response | 5 seconds |
| Response headers | 8,192 bytes, at most 32 fields |
| Complete decoded document | 4,096 UTF-8 bytes |
| Received encrypted TLS stream | 65,536 bytes |
| Received decrypted HTTP stream | 16,384 bytes |

Preparation DNS has a 3-second limit; the final 3-second DNS check is also
inside the 5-second dispatch deadline (at most 8 seconds together). Both
checks occur after native Allow. The
transport limits count application reads, including handshake/framing overhead;
they do not count bytes merely queued by the kernel or network hardware.

Successful MCP output has a JSON metadata text block followed by the **original
document as a separate text block**. The native inspector decodes the actual
MCP text blocks, so newlines/tabs remain visible to result inspection. Complete
value and error envelopes go through the existing correlated native result
gate. Original tool name, arguments and JSON-RPC ID remain unchanged.

`request_issued` is conservative effect accounting: true means an HTTP GET write
was attempted and may have reached the receiver. It does not prove a complete
request was received. A receiver ledger is the independent witness. A blocked
result or cancellation cannot undo an already issued GET. No response text,
URL or destination credentials are added to public audit fields.

Cancellation or unsupported overlap drops the operation and ends its native
session, clearing outstanding reservations. Ordinary executor failures complete
an inspected error result and permit useful continuation in the same session.
Only Linux has positive support; other platforms refuse before network dispatch.
The executor performs no file writes, shell execution, uploads or external
provider/model calls.

## Reproduce owned acceptance

Build a clean exact candidate on Linux. The driver generates its own temporary
CA, HTTPS receivers, append-only request ledgers, Agent home, native registry,
policy and discovery child. It requires no customer configuration or external
provider traffic. Use a fresh output path:

```sh
cargo build --locked -p agentfw --bin agentfw
python3 scripts/verify-sou56-https-get.py --run \
  --repo "$PWD" --agentfw "$PWD/target/debug/agentfw" \
  --expected-commit "$(git rev-parse HEAD)" \
  --output /tmp/sou56-https-get-results.json
```

Without `--run`, the driver prints the matrix and starts no processes. Exit 0
requires complete passing evidence; 1 records a witnessed failure; 2 records
incomplete source/environment/setup evidence. Unsupported systems do not count
as successful Linux acceptance. The report retains exact source, script,
binary/configuration digests, synthetic original calls and released bytes,
enforcing native audit, independent connection/request ledgers, continuation
and cleanup. Agent tokens and fixture private keys are not retained.

Focused checks are:

```sh
cargo test --locked -p agentfw --lib https_get -- --nocapture
cargo test --locked -p agentfw --lib sou56_ -- --nocapture
cargo test --locked -p agentfw --test native_endpoint https_get_v3 -- --nocapture
python3 -m unittest discover -s scripts/tests -p 'test_sou56_https_get.py' -v
```

The owned fixtures establish this constrained profile's behavior. Independent
review and the required checks on the final PR head still gate task acceptance;
they are not general Internet interoperability or arbitrary MCP sandbox proof.
