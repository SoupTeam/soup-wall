# Installed Linux managed Console connection

SOU-231 adds `agentfw managed-console`: preview, verified apply, inspect, verify,
and explicitly confirmed disconnect. It uses the existing managed credential,
signed-policy, TLS and lifecycle contracts. It does not create an enrollment,
obtain issuer keys from Console, approve a revision or change enforcement mode.

## Prerequisites

Use an installed Linux binary and an owner-private Agent home (0700). The
selected files must be regular, single-link, owner-private files (0600), with
absolute canonical paths and no symlinks in any component. Console origin must
be canonical, including its trailing `/`, with no userinfo, path, query or
fragment. Remote origins require verified HTTPS. HTTP is limited to explicit
loopback fixtures; redirects and inherited proxies are disabled.

Obtain the Agent credential through the existing enrollment private-file flow.
The credential file contains exactly the 52 credential bytes, without a newline.
Never pass its contents as an argument, put it in shell history, print it or
include it in a report. Select the issuer keyring independently of the server
being authenticated. Use the existing versioned `trusted-issuers.json` format.
An optional CA file contains one PEM certificate. No private signing key is
required by the Agent.

Clear all `SOUP_MANAGED_AGENT_*` variables when selecting a profile. An explicit
profile and any such environment setting are an ambiguous configuration and
fail closed. If `managed-console.json` has never been selected, tested legacy
environment-only startup is unchanged. Missing, malformed, unsafe or unsupported
explicit state never falls back to environment credentials or default trust.

## Configure and start

Stop the selected Agent first. Preview may be read while it runs, but changing
lifecycle state invalidates that preview. Commands below use example public
identifiers and file references, not credential contents:

```sh
agentfw lifecycle stop
agentfw managed-console preview \
  --console https://console.example.test/ \
  --tenant example-tenant --agent example-agent \
  --credential-file /home/operator/.agentfw/agent-credential \
  --issuer-keyring /home/operator/.agentfw/trusted-issuers.json \
  --ca-file /home/operator/.agentfw/console-ca.pem
```

Review the origin, audience, references, previous connection and confirmation.
Repeat the identical options with `managed-console apply --confirm DIGEST`,
using exactly the confirmation returned by preview. No state is changed by
preview. Apply sends a bounded, read-only policy request with the exact approved
input bytes before publishing anything. Incorrect CA, issuer, audience,
authentication, outage or stale inputs preserve the old connection. For an empty pending inbox, Console supplies `x-soup-agent-tenant` and
`x-soup-agent-id` from its revalidated authenticated enrollment. Both must match
the selected audience exactly. The result `authenticated_bound_no_policy`
verifies connection scope, but claims no fresh signed policy or application.
Older Consoles returning 204 without these fields report
`authenticated_no_policy` and cannot complete setup verification; upgrade Console
or provision an exact signed pending policy. Existing environment-only polling
continues to work with older Consoles.

```sh
agentfw lifecycle start
agentfw managed-console inspect
agentfw managed-console verify
```

`--home /absolute/agent-home` selects a non-default home for managed-console
commands. Normal `serve`, installed lifecycle startup and user-service startup
load the explicit profile without requiring managed environment variables.

## What the reports prove

- `configured`: durable profile generation, settings digest, enabled state and
  selected CA digest.
- `running`: profile identity captured by the authenticated daemon at startup.
  `runtime_authenticated: false` means running state is unknown, not stopped.
- `running_matches_configured` and `pending_restart`: compare selected and loaded
  profile identities. `local_inputs_valid` reports current input availability.
- `enrollment`: a fresh probe distinguishes authenticated audience from a
  credential accepted without a signed policy; inspection alone says `not_probed`.
- `transport`: the daemon's last observation (`online`, `auth_unavailable`,
  `offline`, `rejected`, `disconnected`, etc.). Transport alone is not application.
- `recorded_application`: exact revision, sequence and source policy digest from
  the running firewall. Confirm the corresponding `applied` record in Console.
- `verification`: a fresh non-mutating authentication, audience and signature
  probe. `applied` is always false here; the probe never activates or acknowledges
  a policy. Verify exits nonzero for failures or unbound `authenticated_no_policy`.
  `authenticated_bound_no_policy` verifies enrollment scope while existing
  application evidence remains separately attributed to the running firewall.

Credential-file atomic rotation is reloaded by the running daemon. Existing
independent issuer-keyring reload/revocation behavior remains in force. CA
content is pinned by apply: replacing it requires another preview/apply while
stopped. Runtime TLS trust never changes because an unrelated file was replaced.

## Disconnect without losing protection or user files

```sh
agentfw lifecycle stop
agentfw managed-console disconnect-preview
agentfw managed-console disconnect --confirm DIGEST
agentfw lifecycle start
agentfw managed-console inspect
```

Disconnect selects a durable disabled profile. It leaves the active signed
policy, deployment sequence, cache, spent-grant/anti-replay state, credential,
issuer files, unrelated configuration and user files intact. Startup restores
and verifies the last accepted policy using the independently pinned keyring,
but performs no managed requests and reports `disconnected`. Retain that
keyring: missing/revoked trust or corrupt cached policy fails startup rather than
silently enabling the local default. A disabled connection does not need its
credential or CA file to restore the policy.

An active direct daemon holds the existing lifecycle exclusion lock. Recorded,
unverified or interrupted lifecycle instances and occupied unowned ports block
transitions. Registered user services also block transitions because the
supervisor can restart them: stop and explicitly uninstall the service using
existing `agentfw service` commands first, then configure and register it again.
The command never kills an unverified process or modifies service ownership.

To reconnect, obtain a fresh apply preview and confirm it. Retained policy must
verify under the proposed trust/audience; incompatible changes are refused.
Existing sequence verification prevents an older deployment replacing it.

## Interrupted or stale transitions

One bounded, versioned, owner-private `managed-console.json` is the selector.
Confirmation binds action, settings, current selector, home identity, daemon
configuration, lifecycle manifest, retained policy and selected input descriptor
identities and bytes. Apply and disconnect serialize with lifecycle operations,
recheck those identities before publication, fsync private staging, atomically
rename within the pinned directory, then fsync the directory.

A crash before rename preserves the old selector (or absence); after rename the
whole new selector is visible. Inspect before retrying an uncertain commit.
An exact retry is idempotent while its bound inputs and lifecycle are unchanged;
a stale preview requires a fresh review and confirmation. Private files named
`.managed-console-stage-*` left by a killed writer are never selected, executed
or broadly cleaned up. Their presence does not block a fresh retry. No unrelated
files are removed. An invalid explicit profile needs operator recovery from a
known valid private copy; never delete the selector to force environment fallback.

The focused `managed-credential-rotation.yml` qualification runs both backends,
including a real SIGKILL injected at the publication syscall, installed binary
outside checkout, TLS controls, actual hook decisions and Console applied records.
Sanitized results and exact source/binary hashes are retained as evidence;
credentials, raw configurations and traces stay in disposable private storage.
