# Explicit Linux read-only pilot policy (SOU-98)

`linux-readonly-v1` is an operator-selected policy for the accepted original
filesystem and Git stdio MCP profiles. The same exact policy bytes must be used
for ordinary work and protection evidence. It leaves `agent-default.yaml`,
existing scenario policies and policy precedence unchanged.

## Scope and decision table

Use Linux x86-64 with the accepted profile's namespace, seccomp, bubblewrap and,
for Git, Landlock prerequisites. WSL must provide those same features; no WSL
acceptance is inferred from Linux CI. This increment owns policy selection and
policy-specific acceptance. SOU-99 owns shared-host launch; SOU-100 owns the
integrated installed pilot. These individual-server recipes do not certify a
shared Claude session or live-model effectiveness.

| Input / state | Decision and boundary |
| --- | --- |
| Valid filesystem `read_file`, `read_text_file`, `read_multiple_files`, `list_directory`, `list_directory_with_sizes`, `search_files`, `get_file_info`, `list_allowed_directories` | Allow conditional on pinned schema, bounded arguments, workspace, classification, native admission and inspected original result |
| Valid Git `git_status`, `git_log`, `git_diff`, `git_diff_staged`, `git_diff_unstaged`, `git_show` | Same conditional Allow; exact bounded arguments from the Git profile |
| Prior benign untrusted content, then valid read | Taint alone does not block useful reads |
| Write, delete, network or privilege-changing class, clean or tainted session | Hard Deny, before execution; no approval downgrade |
| Filesystem write/edit/create/move, Git add/commit/reset/checkout/create-branch | Unsupported selected-profile dispatch; policy additionally denies recognized effect classes |
| Filesystem media, Git branch enumeration | Unsupported by selected profile |
| `directory_tree` with accepted filesystem classifier | Known coverage gap: unknown, policy Ask, collector refuses; not an authorized operation |
| Multiple recognized action labels or any unknown remainder | Existing conservative classifier-to-native projection preserves ambiguity; Ask/refusal, never reinterpret as read |
| Changed schema, unknown tool, invalid or extra arguments, out-of-workspace path/repository | Admission/profile refusal; not a classification-accuracy error |
| Missing classifier, malformed response, timeout or unavailable daemon | Fail closed; technical failure recorded separately, not evidence of correct semantic classification |
| Detected Medium/High instruction override in original result | Deny result release; preserve bytes for inspection, no sanitizing into trusted content |
| Original Git hash alone | Existing accepted Low long-token heuristic is not an instruction; legitimate hash-bearing result can pass |
| Secrets/PII in outbound arguments | All network actions denied, including previously default-allowlisted hosts |
| Manifest drift / shadowing / incomplete provenance | Existing policy and native floors remain authoritative; unresolved Ask stays blocked |

Full original names, descriptions and schemas remain in
[filesystem discovery](../../profiles/mcp/filesystem-readonly-v1/upstream-tools-list.json)
and [Git discovery](../../profiles/mcp/git-readonly-v1/upstream-tools-list.json).
Descriptions never grant authority. Installed registries derive typed
read-only/side-effect/destructive resources from the accepted installers and
declare results untrusted with no egress authority. The filesystem path and Git
repository bounds remain in the accepted native/profile validators.

The [policy](../../profiles/pilot/linux-readonly-v1/policy.yaml) combines the
accepted filesystem unconditional effect-denial rules with the accepted Git
policy's shipped secret/PII, description, provenance and injection protections.
It retains the filesystem rule IDs for comparable effect evidence. The Git
Medium result-injection threshold permits actual Git object IDs; the global
policy already uses this threshold. No classifier or detector is changed.

## Prepare an explicit selection

First install the original server using the existing
[filesystem recipe](MCP_REAL_FILESYSTEM.md) or [Git recipe](GIT_MCP_PROFILE.md).
Do not repurpose an existing user's Agent home. Select a new dedicated daemon
configuration, a reviewed private installation and an unused local port:

```sh
python3 -B scripts/pilot_policy.py \
  --kind filesystem \
  --installation /absolute/private-filesystem-install \
  --destination /absolute/new-pilot-selection \
  --port 48001 --python /absolute/python3
```

Use `--kind git` for the original Git installation. Selection validates the
committed dependency hashes, exact accepted registry authority, original scenario
policy and installation receipt. It refuses an existing destination or unsupported
platform. It writes a private policy copy, `config.json`, and `selection.json`.
**Prepared does not mean active.** Before use, the real Agent must successfully
load this config and the collector must validate the selected runtime/profile.
Missing isolation and mismatched runtime pins must refuse startup.

In a freshly initialized dedicated Agent home, copy the generated `config.json`
to `.agentfw/config.yaml` (JSON is valid YAML). Use the exact environment values
in `selection.json` for the original selected-profile MCP launch, with the same
Agent home and workspace. The accepted filesystem and Git guides supply the exact
original command and arguments; this selector does not replace their launcher.
Disable the optional judge as in those recipes. Do not overlay a permissive
policy, disable enforcement or change registry/classifier paths.

The [manifest](../../profiles/pilot/linux-readonly-v1/manifest.json) binds policy,
accepted discovery, upstream identities and both existing classifier snapshots.
Runtime-specific receipts additionally bind installed profile, registry, classifier,
Python interpreter and the selected policy. The original Agent validates runtime,
library, dependency tree and resource identities at launch. Operator edits require
a new reviewed preset and fresh evidence, not a re-labeled active receipt.

Real-server Ask continuation is not implemented here. Unknown/ambiguous calls
remain blocked; this preset does not synthesize grants. Aggregate resource budgets
are a separate explicit profile setting; absence is not a resource-limit claim.

## Reproduce original-server acceptance

Use the exact accepted filesystem and Git verification commands, adding
`--pilot-preset` and a new output directory. All ordinary reads, result-injection
controls, forbidden attempts, useful follow-ups, outage, process and independent
file/receiver witnesses run with the selected pilot policy throughout:

```sh
# Supply the same required runtime paths documented in the linked profile guides.
python3 -B scripts/verify-sou62-real-mcp.py --help
python3 -B scripts/verify-sou68-real-mcp.py --help
python3 -B -m unittest discover -s scripts/tests -p test_pilot_policy.py -v
cargo test --locked -p soup-wall-agent --test pilot_policy
python3 -B scripts/pilot_decision_matrix.py --output /absolute/new-development-report.json
```

Existing central Ready CI runs each original acceptance unchanged and then its
pilot-policy variant in the same provisioned job. Manual dispatch of those same
component workflows supports development. No duplicate per-push matrix is added.
Both pilot reports must pass with identical `pilot_selection.policy_sha256`.
Retain exact source, binary and runtime identities and original transcripts.
Errors, parser timeouts or absence of a reply alone are never prevention proof.
The filesystem probes calibrate a receiver and FIFO execution witness; Git probes
calibrate actual index mutation and repository access, then require no protected
forbidden dispatch or mutation. The policy-only Rust controls are explicitly
separate from these original-server and OS-enforcement measurements.

Development reports must retain failed/incomplete outcomes and false interruptions.
The development script records full synthetic inputs, original classifications
and per-call in-process classification timings. Its 15 intended reads currently
have one coverage gap. Timings exclude process startup, IPC, policy and execution;
they are observations, not production latency guarantees. Actual server evidence
remains in the separate execution reports.
`directory_tree` is an expected classifier-coverage limitation, not a passing
supported read. Do not tune on SOU-35 sealed data, replace labels or weaken policy
to conceal that limitation. SOU-97 owns future classifier changes.

## Acceptance status

This document is an executable recipe, not a completion claim. Independent review,
both current-source original-server reports and the full central Ready gate are
required before acceptance. No publication or production deployment is implied.
