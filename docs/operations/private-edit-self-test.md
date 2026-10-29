# Installed private-output edit self-test

Use the explicit private-edit mode before relying on an installed edit session.
It starts the selected genuine Claude host with an owned scripted loopback
provider and uses the accepted `edit-session` commands. No model account or paid
inference is needed. Run as an ordinary Linux x86_64 user.

The installed Agent, verified pilot component and current prepared pilot
selection must come from the same reviewed source. Prepare/install those inputs
using the existing operator flow. The self-test does not download, build,
install, update or select anything, and never discovers executables from PATH.
An older component without this helper reports `unsupported`.

## Preview and consent

Use absolute canonical paths to the installed Agent, existing Agent home and
current `generations/<generation>/selection.json`:

```sh
/absolute/installed/agentfw self-test private-edit \
  --home /absolute/agent-home \
  --selection /absolute/preparation/generations/GENERATION/selection.json
```

Preview reads identities and receipts. It creates no output directory, starts no
host, daemon, server or provider, and grants no edit authority. Supplying
`--output` without `--run` still previews only.

To consent to execution, choose a fresh output directory under an existing
private directory that you own. It must be outside the installation, selected
projects, preparation and source tree:

```sh
/absolute/installed/agentfw self-test private-edit \
  --home /absolute/agent-home \
  --selection /absolute/preparation/generations/GENERATION/selection.json \
  --run --output /absolute/private-checks/attempt-01 \
  --timeout-seconds 300
```

Each attempt requires a new directory. Never replace a failed report with a
later attempt. Execution creates synthetic files and per-run state only under
that attempt's `owned/` directory. The installed settings, component pointer,
selection, provider profiles and selected projects are not changed. A finite
before/after witness checks selected project contents and installed state; an
oversized or unreadable witness produces an incomplete result.

## What the result establishes

The fixed inventory checks useful create/read and exact replace/read, fresh
single-use Ask approvals, reject/replay refusal, aggregate mutation and byte
quota exhaustion, exact-run Stop with an independently useful peer, stopped
authority refusal, loss of the combined owner/daemon, and a fresh useful run
that rejects old authority. Target bytes and process birth identities are
observed independently of native verdicts. Matching bytes alone never establish
commit attribution or delivery after an interruption.

The edit path is the accepted native `private-output` API. The selection's
filesystem/Git runtime pins are validated; this check does not claim that edits
traverse the original filesystem/Git MCP servers. Their original-server
qualification remains separate. The synthetic provider checks this installed
path and does not measure live-model effectiveness.

The report distinguishes native Linux and WSL2. Native success does not qualify
WSL. Preserve WSL prerequisite, Ask or timing failures as observed; do not relax
the existing pending/continuation deadlines to obtain a pass.

## Reports and recovery

`report.json` uses `sw-private-edit-self-test/1`. It records the exact source,
component, selection and installed executable digests, fixed attempted/passed/
failed/incomplete/unsupported counts, independent witnesses, preservation and
cleanup. Terminal output is a short JSON summary. Reports omit raw project
paths, prompts, payloads, provider configuration, approval IDs and tokens.

Exit codes are `0` for an inert preview or a complete pass, `2` for usage errors,
`3` for a failed assertion, `4` for incomplete observation or cleanup, and `5`
for unsupported execution. Check `status` and `executed`; preview is not a pass.
An unavailable component may report directly to the terminal before an output
directory can safely be created.

By default, owned synthetic state is removed after confirmed process cleanup.
`--keep-workspace` explicitly retains it privately for inspection. Failed
cleanup retains state and reports incomplete. Never automatically resume an
interrupted mutation, replay an approval or refill a live run's quota. Inspect
the retained attempt, then start a separate fresh test if appropriate.

## Developer qualification

The existing native Ubuntu preparation job has a focused manual
`private_edit_self_test_only` input. It prepares the accepted exact-source
runtime, installs the component into a new test home, invokes the installed
command outside the checkout, and retains the positive report plus preview,
changed-selection and changed-helper refusal controls. Ordinary admission and
the final Ready/CodeQL/merge process keep their existing ownership.

For already prepared native inputs, the same bounded driver is:

```sh
python3 -B scripts/qualify-private-edit-self-test.py --run \
  --agentfw /absolute/installed/agentfw \
  --selection /absolute/preparation/generations/GENERATION/selection.json \
  --python /usr/bin/python3.12 --output /absolute/private-checks/qualification-01
```

The driver is developer setup and evidence collection; operators use the
installed front door above. Its component build requires a clean checkout.
