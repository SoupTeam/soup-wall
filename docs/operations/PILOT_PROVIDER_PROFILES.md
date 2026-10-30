# Private named provider profiles for the installed pilot (SOU-172)

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
plan. `create`, `select` and `remove` require `--apply`; preview is read-only
and redacts all secret fields. `create --replace --apply` atomically replaces an
existing name. If that name was selected, select it again to bind its new
digest before running. At most 16 profiles are accepted; names are lowercase
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

The profile file and selection are mode 0600 regular files in an owner-only
0700 Agent home and `pilot-providers/` directory. Writes use owner-checked,
no-follow directory descriptors, create-new temporary files, fsync and atomic
publication. A selection binds the exact profile bytes: malformed, changed,
removed, linked, FIFO or over-limit input refuses before the daemon or host
starts. An interrupted replacement leaves the previous profile in place.
Preview and status show names, model, nonsecret hashes and observed local
selection state only; they make no provider request or asset installation.

An explicit selected profile and ambient provider inputs conflict. The run
refuses instead of combining them. With no profile selected, the established
explicit environment mode remains available; direct `pilot-launch` use of its
accepted provider FD is unchanged. `select --environment --apply` explicitly
returns to that mode. Removing the selected file leaves a stale selection that
refuses until another profile or environment mode is explicitly selected.

These files are private by operating-system ownership and mode, **not
encrypted**. Removing one does not revoke the provider credential or erase a
copy already held by a running Claude host. The exact selected values are
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
removal, and return to explicit environment mode. The regular provider tests
also exercise interrupted replacement and descriptor validation. Only
bounded, canary-free results may be retained publicly; raw exec traces stay
private and are removed after inspection. A successful run does not claim
paid-provider operation, external credential correctness or live protection
outside the observed local session.
