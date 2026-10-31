# Private named provider profiles for the installed pilot (SOU-172/SOU-181)

`agentfw pilot provider` manages a finite, explicitly selected provider profile
under the installed Agent's private home (`~/.agentfw`, or `agentfw pilot --home
DIR`). It does not change the prepared filesystem/Git selection, policy or MCP
authority. The selected profile is read when `agentfw pilot run` begins; the
existing sealed provider FD delivers its values to the selected Claude host.

Native Ubuntu 24.04 x86_64, a non-root operator, an installed verified pilot
component and a prepared pilot selection are required for a protected run.
Profile preview and management do not need a prepared selection.

## Commands

```bash
agentfw pilot provider preview
agentfw pilot provider create --name local-test \
  --model claude-sonnet-4-20250514 \
  --base-url http://127.0.0.1:19001/v1 \
  --prompt-api-key --apply
agentfw pilot provider select --name local-test --apply
agentfw pilot provider preview --name local-test
agentfw pilot status --prefix "$HOME/soup-wall-pilot"
agentfw pilot run --prefix "$HOME/soup-wall-pilot"
agentfw pilot provider update --name local-test \
  --base-url http://127.0.0.1:19002/v1 --prompt-api-key
agentfw pilot provider update --name local-test \
  --expected-version VERSION_FROM_PREVIEW \
  --base-url http://127.0.0.1:19002/v1 --prompt-api-key --apply
agentfw pilot provider preview --name local-test
agentfw pilot provider restore --name local-test \
  --version RETAINED_VERSION --expected-version CURRENT_VERSION --apply
agentfw pilot provider prune --name local-test \
  --version UNUSED_RETAINED_VERSION --apply
agentfw pilot provider remove --name local-test --apply
agentfw pilot provider select --environment --apply
```

The create prompt is hidden. Use `--prompt-auth-token` instead of
`--prompt-api-key` for a supported bearer token. For an existing explicit
secret descriptor, use `--secret-fd N` instead of a prompt. Its bounded JSON
must have exactly one key, `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN`; the FD
must refer to an owner-only regular file or a sealed anonymous memfd. The
descriptor number may be in argv; the secret value must not be. Do not put a
credential in a shell command, environment assignment, CLI argument or shared
plan. `create`, `select`, `restore`, `prune` and `remove` require `--apply`.
`provider update` without `--apply` is an inert preview: it reads no secret FD,
does not prompt, write a file, start a host or contact an endpoint, and reports
only finite changed field names, whether credential rotation was requested,
and a nonsecret current version ID. Copy that ID to `--expected-version` when
applying the update. A stale version refuses instead of overwriting another
operator's change. Omit all secret options to keep the existing credential;
use one hidden prompt or an owner-only/sealed `--secret-fd` to rotate it.
No secret value or digest is printed by preview, apply or ordinary diagnostics.
The update result includes a new version ID and `previous_version`; on the
first update, `previous_version` is the migrated legacy profile's new UUID,
which can later be passed to `restore`. The named preview lists retained
version IDs without exposing their contents. Save the IDs privately before
removing a name if later orphan cleanup is needed.
At most 16 profiles are accepted; names are lowercase
ASCII letters followed by at most 31 letters, digits, underscores or hyphens.

Supported connection fields are `--base-url`, `--http-proxy`,
`--https-proxy`, `--no-proxy` and `--ssl-cert-file`. These are the existing
`ANTHROPIC_BASE_URL`, `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` and
`SSL_CERT_FILE` inputs. The model is the existing `pilot-launch --model`
setting; it is kept in the profile's separate nonsecret section and does not
enter the credential FD. Endpoint and proxy URLs must be HTTPS, or HTTP to
literal loopback; embedded user information, query, fragment and traversal
paths are refused. An optional CA file must be a canonical, bounded regular
file not writable by a group or others. Unsupported fields and mixed API
key/auth-token profiles refuse.

The store stays in the owner-only 0700 Agent home and `pilot-providers/`
directory. Existing flat 0600 files remain usable until the first explicit
update migrates them inside that directory. Migration and later updates write
new immutable owner-private versions first, verify them, then atomically
publish one owner-private index containing the current named versions and
selection. After the first index commit, an independently validated private
`.versioned-v2` marker records that the legacy selection must never become
authoritative again. A missing index after a completed migration refuses,
including after restore or explicit environment selection; it cannot silently
reactivate an old credential. An interrupted write before the first index
commit leaves the previous selection usable. If interruption lands between
index and marker publication, reads refuse until the store is repaired; they
do not guess which version was selected. An unpublished version is never
adopted as a runtime input. The old flat files remain private as compatibility
evidence. The index uses `.index-v2`; both metadata names are outside the
accepted profile-name namespace. Existing profiles named `index` or `versioned`
and the full 16-profile capacity remain valid. Earlier private draft metadata
at `index.json`/`versioned.json` is explicitly refused rather than adopted or
used to revive an older credential. Reads use no-follow directory descriptors and refuse wrong owner,
mode, hardlink/symlink, FIFO, changed identity and over-limit data. A selection
binds the exact version bytes; malformed, changed or removed selected data
refuses before the daemon or host starts.

`create --replace --apply` remains explicit and retains previous versions;
if the profile was selected, reselect it before a later launch. `provider
update --apply` changes the selected version in the same atomic index commit
when that name is selected. A host that was already launched keeps the exact
provider settings copied into its sealed launch carrier; neither command
mutates its environment. A later explicitly started host reads the new
selection. There is no automatic network check, previous-secret retry or
fallback provider.

`provider restore` explicitly moves one name back to a retained, revalidated
version and updates its selection if that name is selected. `provider prune`
removes only the named, unselected, noncurrent retained version; it refuses a
current or selected version and never deletes another profile. Keep the
returned version IDs in an owner-private operator record for restoration.
Unpublished versions from interrupted writes stay private and unselected;
do not manually copy one into an index or delete files while a host runs.
Preview and status show names, model, nonsecret hashes and observed local
selection state only; they make no provider request or asset installation.

An explicit selected profile and ambient provider inputs conflict. The run
refuses instead of combining them. With no profile selected, the established
explicit environment mode remains available; direct `pilot-launch` use of its
accepted provider FD is unchanged. `select --environment --apply` explicitly
returns to that mode. Removing the selected file leaves a stale selection that
refuses until another profile or environment mode is explicitly selected.

These files are private by operating-system ownership and mode, **not
encrypted**. Rotating or removing one does not revoke an old provider
credential or erase a copy already held by a running Claude host. Revoke an
old credential separately at the provider after all old runs have stopped.
The exact selected values are
transiently handled by the trusted prepared entry and native launcher, then
reach only the selected host through the [existing FD boundary](PREPARED_PILOT_PROVIDER_ISOLATION.md).
They do not enter the daemon, classifier, MCP/installer children, native
grants, public plans or support exports. This local check is not a network
egress firewall or proof that external provider credentials are valid.

## Opt-in qualification

On an owned native Ubuntu 24.04 runner with the accepted pinned binaries and
assets, use the existing installed front-door qualification command with
`--provider-profiles` (the `Real filesystem MCP profile` CI job passes it).
It builds and installs the component outside the checkout, creates/selects a
profile using a sealed FD and synthetic canary, and runs the genuine Claude
host against a local scripted Messages provider and original filesystem/Git
servers. It verifies useful read/history calls, refused mutators, exact
provider authentication, successful child exec environments, redacted output,
plans, grants and retained files, bad-profile and source-conflict refusals,
removal, and return to explicit environment mode. The provider rotation
controls also exercise old-run/new-run isolation, restoration, wrong
credential/endpoint refusal, interrupted publication, concurrent stale
updates and descriptor validation. Only
bounded, canary-free results may be retained publicly; raw exec traces stay
private and are removed after inspection. A successful run does not claim
paid-provider operation, external credential correctness or live protection
outside the observed local session.

## Selected provider CA custody (SOU-195)

For an installed Linux pilot profile that needs a private provider CA, set
`--ssl-cert-file /absolute/owner-private/ca.pem` on an explicit `provider
create` or `provider update --apply`, then select that profile. The selected
source must be a canonical, regular, owner/root-owned, non-writable-by-others
PEM certificate bundle. The source is read and validated again for every
explicit `pilot run`. A symlink, hardlink, FIFO, mutation during the read,
malformed certificate or file beyond the finite limit refuses before the
provider host starts. A valid replacement between runs supplies the new
run's trust bytes, even when the named profile still points to the same
pathname. Preview and profile publication do not make a network request.

Each run snapshots the exact selected CA bytes in a sealed anonymous file
descriptor. Only its selected Claude host receives a descriptor-backed
`SSL_CERT_FILE`; children and unrelated helpers do not receive the source
path or CA descriptor. The ordinary run report contains the CA SHA-256 only,
never the path, PEM or key. An already running host retains its trust choice
if the operator replaces the source or explicitly updates the profile. A
newly launched host reads the new selected source. To roll back trust,
restore the retained provider profile version or explicitly reselect a known
CA source and launch a new run. Stop old runs and revoke an old credential
separately if it must no longer be usable. This binding does not install a
system trust anchor or make an external endpoint trustworthy by itself.

The focused native Ubuntu 24.04 qualification is an opt-in dispatch of
`Real filesystem MCP profile` with both `native_preparation_only=true` and
`provider_ca_only=true`. It builds and installs the current exact-source
component, uses the genuine selected Claude and original servers outside the
checkout, and runs two private scripted HTTPS providers with different
synthetic credentials and CAs. The witness requires authenticated old and
new requests, continued old-run TLS after source replacement, new-run TLS
with the replacement CA, a changed source before launch, and zero credential
delivery for an unrelated certificate or wrong hostname. It also checks
symlink, hardlink, FIFO, over-limit, malformed and wrong-mode source refusals,
an explicitly restored successful run, child exec environments and process
cleanup. The bounded artifact
`sou195-installed-provider-ca` retains only source/component/input hashes,
finite status, CA hashes and request/handshake counts. Private test keys,
PEMs and raw exec traces are deleted. This does not call a live provider or
claim paid-model effectiveness. The focused manual dispatch keeps its native
toolchain, prerequisite builds and owned sandbox checks, and skips unrelated
long pilot qualifiers; ordinary PR and Ready scheduling remain unchanged.
