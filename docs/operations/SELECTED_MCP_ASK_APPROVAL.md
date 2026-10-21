# Original read-only MCP: one exact operator approval

SOU-105 extends the existing [native approval broker](NATIVE_ASK_APPROVAL.md).
It reuses the native key, signed scope, policy epoch, spend ledger and CLI.
Only the installed original filesystem and Git read-only profiles can resume.
Default invocation Ask remains a correlated refusal.

Enable the daemon's existing opt-in settings, retaining the installed registry:

```yaml
native:
  approval:
    ttl_seconds: 120
  liveness:
    default_lease_seconds: 10
```

Keep the reviewed original server command and `AGENTFW_MCP_SERVER_PROFILE`.
Start its collector with `--native-approval-wait-seconds 25`, an exact
current-instance `--child-authority` for the host/agent/server/tools,
`--host-session`, and `AGENTFW_NATIVE_LIVENESS=true`. Explicitly select the
installed rule baseline (`AGENTFW_CLASSIFIER=rule-baseline` and
`AGENTFW_RULE_BASELINE` pointing to its script). Tokens are private; do not paste
them into reports. No host-launcher change is required.

A known validated Ask invocation holds its original frame without server
dispatch. A supported Allow peer can proceed through the same relay. One
pending operator approval is permitted per native session, sixteen per daemon;
extra Ask calls are refused without displacing a live request. Independent
sessions can await separate decisions.

Using the daemon's protected home, inspect the exact call and decide:

```sh
agentfw native-approval list
agentfw native-approval inspect PENDING_ID
agentfw native-approval approve PENDING_ID --binding EXACT_BINDING_SHA256
# Or:
agentfw native-approval reject PENDING_ID
```

The signed binding freezes original arguments/schema, typed JSON-RPC ID and
the complete original frame digest (including correlation metadata),
session epoch, registry, server/profile, classifier/input/discovery identities
and the broker's durable policy epoch. Existing scoped host/agent authority
and private live collector identity remain authoritative. Before dispatch,
the collector rechecks the profile, runtime, package, libraries and classifier,
reruns classification and presents the same call to the current native policy.
Redemption is atomic and single-use. Approval preserves taint/incomplete history
and adds no result-release authority or model-consumption claim.

| Boundary | Behavior |
| --- | --- |
| Supported original read-only filesystem / Git on qualified Linux | Explicit invocation Ask continuation |
| No wait, daemon approval, bound host/agent or live owner | Correlated refusal |
| Unknown/partial-unknown classification, technical failure, hard Deny | Cannot be rescued |
| Mutator, network, unsupported tool/schema/profile, SOU-83 creation | Unsupported; existing floors retained |
| Result Ask / Deny | Withheld; no continuation |
| macOS / Windows original-server execution | Unsupported by these Linux profiles |
| Other native tools / resource approvals | Existing SOU-48 / SOU-88 behavior |

Waiting occupies one of eight active logical slots, with eight queued. It
occupies no server wire slot before dispatch; physical outstanding calls remain
bounded by sixteen. The wait is the minimum of configured wait, broker TTL and
the original 30-second relay deadline. Selected polling is 100 ms. It does not
extend execution deadlines. Reject, expiry, host cancel/EOF and failed
revalidation cancel unused state. Session retirement/restart closes approvals;
collector SIGKILL is handled by the existing enrolled lease maintenance.
Expired operator files are removed while pruning bounded terminal history.
Effectful calls are not automatically retried. Git cancellation still withdraws
delivery and drains its response without forwarding the problematic SDK abort.

These CLI decisions authorize explicitly as the same OS user. Automated
acceptance does not prove physical human presence or defend against same-user
or OS compromise.

## Qualification

`python3 -B scripts/verify-sou105-selected-approval.py --help` lists explicit
runtime arguments. `--run` requires native Linux x86-64, the existing pinned
installers, bubblewrap/Landlock and strace. Missing prerequisites fail; mocks,
skips and unconstrained fallback do not qualify an original server.

Private synthetic work with actual original servers and operator CLI calibrates
kernel open/exec witnesses, checks no preapproval execution, once-only release,
peer/follow-up usefulness, reject/expiry/cancel, wrong binding, changed assets,
EOF, collector SIGKILL, daemon restart and hard Deny. Exact source/config/binary
identities, failed/late logs and independent process cleanup are retained.
Focused native tests separately cover changed identities/arguments, replay,
authority loss and pruning; those are distinct evidence scopes.

The existing Ready filesystem job runs this bounded command for both families.
No new per-push matrix is added. Draft fast checks cannot replace this command.
