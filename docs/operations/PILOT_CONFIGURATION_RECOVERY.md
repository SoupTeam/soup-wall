# Private pilot configuration recovery

Use the installed `agentfw pilot configuration` commands to retain supported
declarative settings privately and restore them into a fresh Agent configuration
directory. Installing the current verified pilot component is a prerequisite;
operator use needs no checkout. The component's recorded interpreter and helpers
are verified by the existing native front door before dispatch.

Configuration recovery does not enroll an Agent, launch a daemon, contact a
provider, import execution authority or establish observed protection. A restored
configuration is reported separately from those unverified states.

## Supported configuration and exclusions

The initial scope is the default Linux read-only original filesystem/Git pilot.
The authoritative Agent `Config::from_yaml` parser validates the complete input;
the recovery projection refuses declarations it cannot preserve completely.
Supported settings are loopback bind/port, enforce/shadow, record/body/time
limits, provenance limits, native registry identity and optional Ask/liveness
limits. Optional segmented-audit limits are retained, with an explicit fresh
`destination/audit` directory role. No audit records are included.

The policy must be the accepted six-rule installed pilot baseline. Registry
tools must match the explicitly selected verified original profiles. The archive
retains their references and hashes; it does not embed arbitrary policy YAML,
registries, packages or executable bytes. Restore reconstructs the accepted
policy and merged registry from current independently verified inputs.

Nondefault judge configuration, raw capture, legacy audit paths and native
execution/git-execution declarations are refused. Unknown fields, invalid or
missing inputs and unsupported settings stop capture rather than produce a
partial backup labelled complete. The default profile does not cover special
Git execution profiles or general Agent/Console configuration.

Never included or restored:

- Provider/enrollment credentials, provider profiles and ambient secret values.
- Signing, control and HMAC keys; tokens, child grants and Ask approvals.
- Active/retained runs, session identifiers, taint/provenance history and audit
  payloads.
- Private edit outputs/backups, workspaces, executables, source trees and
  download caches.

Source paths and configuration metadata may themselves be sensitive. The bundle
is owner-private and is never uploaded automatically. Keep it in a private local
directory and apply your existing storage/transport controls. This format adds
no encryption or key service.

## Read-only inventory and private export

`COMPONENT_HOME` selects the already installed helper component. `SOURCE_HOME`
is the actual Agent configuration directory containing `config.yaml`; it is not
the operator's whole home. `SELECTION` names an existing verified
`selection.json`, and `AGENTFW` must be its exact pinned current Agent binary.
Use the full source commit that prepared that selection.

```sh
agentfw pilot --home "$COMPONENT_HOME" configuration inventory \
  --source-home "$SOURCE_HOME" --selection "$SELECTION" \
  --agentfw "$AGENTFW" --expected-commit "$SOURCE_SHA"

agentfw pilot --home "$COMPONENT_HOME" configuration backup \
  --source-home "$SOURCE_HOME" --selection "$SELECTION" \
  --agentfw "$AGENTFW" --expected-commit "$SOURCE_SHA" \
  --archive "$PRIVATE_DIRECTORY/configuration.tar" --consent

agentfw pilot --home "$COMPONENT_HOME" configuration inspect \
  --archive "$PRIVATE_DIRECTORY/configuration.tar"
```

Inventory/inspect do not write. Backup requires explicit consent and publishes
one new private regular file without overwriting an existing destination. The
archive is a bounded uncompressed canonical USTAR with exactly `manifest.json`
and `configuration.json`. Each JSON document is at most 64 KiB; the complete
archive is at most 256 KiB. Manifest identities, sizes, hashes, order and declared
scope are checked. Compression, extensions, links, special files, traversal,
absolute paths, duplicate or extra members and noncanonical data are refused.
All selected source inputs are rechecked before export publication.

## Preview and confirm a fresh-home restore

Choose a nonexistent Agent configuration directory under an existing private
owned parent. An existing or active Agent home is never overwritten. Supply
current verified runtime inputs explicitly, even when their bytes have not
changed since capture. Backup-provided paths/hashes are references, not trust.

```sh
agentfw pilot --home "$COMPONENT_HOME" configuration restore-preview \
  --archive "$PRIVATE_DIRECTORY/configuration.tar" --selection "$CURRENT_SELECTION" \
  --agentfw "$CURRENT_AGENTFW" --expected-commit "$CURRENT_SOURCE_SHA" \
  --destination "$NEW_AGENT_HOME" --port "$NEW_LOOPBACK_PORT"
```

Review the returned `plan_sha256` and binding differences. The plan binds the
archive, current verified assets, exact destination parent identity and the
explicit audit/port rebinding. Port rebinding allows an old Agent to remain
active while the new instance is later verified. Omit `--port` to retain the
backed-up port; it may then be occupied. Any changed input, path or destination
requires a new preview and confirmation; restore never silently relocates data.

```sh
agentfw pilot --home "$COMPONENT_HOME" configuration restore \
  --archive "$PRIVATE_DIRECTORY/configuration.tar" --selection "$CURRENT_SELECTION" \
  --agentfw "$CURRENT_AGENTFW" --expected-commit "$CURRENT_SOURCE_SHA" \
  --destination "$NEW_AGENT_HOME" --port "$NEW_LOOPBACK_PORT" \
  --confirm-plan "$REVIEWED_PLAN_SHA256"
```

Restore writes an owned private staging directory, checks its exact contents,
revalidates current inputs and publishes the complete directory atomically with
no replacement. The new directory contains supported config/policy/registry
files and, where selected, an empty private audit directory. It contains no old
token, key, session or approval. The original installation and runtime inputs
remain untouched.

If publication is interrupted, inspect the finite `incomplete` result and keep
the private journal/staging state. Do not rename it by hand or retry against a
different home. Use the same inputs, port and reviewed plan with recovery:

```sh
agentfw pilot --home "$COMPONENT_HOME" configuration recover \
  --archive "$PRIVATE_DIRECTORY/configuration.tar" --selection "$CURRENT_SELECTION" \
  --agentfw "$CURRENT_AGENTFW" --expected-commit "$CURRENT_SOURCE_SHA" \
  --destination "$NEW_AGENT_HOME" --port "$NEW_LOOPBACK_PORT" \
  --confirm-plan "$REVIEWED_PLAN_SHA256"
```

Recovery validates the journal's staged-directory identity and expected files.
Foreign, modified or redirected state refuses. It resumes only this declarative
publication; it never resumes a tool call, restores an approval or resets an
existing instance's risk state. Retain an incomplete outcome until recovery is
actually verified.

## Fresh authority and runtime verification

Supply credentials and enrollment anew through the existing supported flows.
Explicitly create fresh Agent authority in the restored configuration home and
start that actual home only when intended. `agentfw pilot --home` identifies the
helper component and is not proof that a pilot run consumed a restored daemon
config: the ordinary run launcher creates a separate per-run daemon home.

Verify the new instance's authenticated status, original-server useful read and
calibrated refused action with independent zero-effect observations. Verify that
an old token is unauthenticated and an old grant is refused even when submitted
with the new token. A matching config file alone proves none of these outcomes.
Do not copy authority to bypass a blocker.

The required installed qualification uses owned synthetic projects and an owned
scripted provider outside the checkout. Its report must distinguish successful,
failed, incomplete and unsupported cases and retain earlier attempts. Native
Linux evidence does not qualify Windows, macOS or WSL. Final shared CI/security
and product readiness remain separate decisions.
