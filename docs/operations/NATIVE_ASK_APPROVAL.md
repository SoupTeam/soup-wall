# Native MCP Ask approval (SOU-48)

Opt-in, bounded, single-use operator approval and resume for **one outstanding**
supported native MCP `tools/call` that the policy answers with **Ask**. This is an
internal candidate increment, not a release. Default configuration keeps the
existing correlated refusal.

## What is supported

- `agentfw mcp --native-admission --native-approval-wait-seconds N` (N = 1..300) plus
  `native.approval` in the daemon `config.yaml`. Both are required; either one missing
  keeps the refusal.
- Plain native MCP calls.
- Constrained Linux native resource executors (SOU-88):
  - Linux `read_document` under direct/1 profile (`sw-native/read-document/direct/1`).
  - Linux `create_file` under linux-root-child/1 profile (`sw-native/create-file/linux-root-child/1`).
  - Linux `https_get` under constrained network executor profile.
  - Compatible operator-owned file bindings (SOU-67).
- Explicitly refused:
  - Windows and macOS native resource tools (`native_approval_resource_tool_unsupported`).
  - Confined real-fs create profile (SOU-83).
  - HTTPS POST or non-GET network mutations (SOU-73).
- Resource calls must be fully classified: `unknown=true` or `uncertainty >= 0.8` is refused before approval and rechecked after confirmation.
- One outstanding approval per collector session, 16 per daemon.
- Two Ask sources: the daemon policy (`call` receipt `verdict: ask`) and the collector
  classifier (`policy_unconfirmed_ask`).

```yaml
native:
  registry_path: '/abs/registry.json'
  registry_sha256: '<sha256>'
  approval:
    ttl_seconds: 120      # 1..300, default 120
```

## Frozen identity

When the request is opened the daemon records, in memory and in an owner-only file
`<home>/native-pending/<id>.json`: collector session id and daemon session epoch,
registry sha256 and id, tool name, schema sha256, exact arguments and their sha256,
the **binding digest** (`sw-native/call/1` over registry, epoch, tool, schema,
canonical arguments, and resource admission if present), source of the Ask, durable
approval-policy epoch, optional frozen `resource_details` (operation, canonical paths,
destination, URL, method, payload length), creation and expiry time. The pending id is
256 random bits and carries no meaning.

The held original frame stays in the collector. It is never rewritten, replaced or
retried as another call; on approval the **same** tool/arguments are re-presented to
the daemon with `approval_id`, and the child receives the original request bytes (or
native resource executor handles the call directly without invoking the child).

## State machine

```
            request                operator approve          call + approval_id
  (none) ───────────▶ pending ───────────────────▶ approved ───────────────▶ redeemed
                        │  │                          │                        (once)
         operator reject│  │ cancel / EOF / client    │ expiry / session end /
                        ▼  ▼ input / timeout          ▼ policy switch / restart
                    rejected  cancelled      closed(reason) or expired
```

- `pending → approved | rejected`: decided once by the operator command; the decision
  is claimed by an atomic rename, so approve and reject cannot both win.
- `approved → redeemed`: only by the `call` event carrying `approval_id`, under the
  daemon session lock, after the grant is verified and spent in the persistent ledger.
- Every other transition is terminal and releases nothing: `rejected`, `expired`,
  `cancelled`, `closed(<reason>)`.
- Any failed redemption attempt (wrong session, tool, schema, arguments, expired,
  policy changed, hard Deny, stale policy epoch, unknown/invalid grant, premature use)
  **closes the record**: the approval cannot be retried after observing the error.

## Limits

| Limit | Value |
|---|---|
| Pending lifetime (`ttl_seconds`) | default 120 s, max 300 s |
| Collector wait (`--native-approval-wait-seconds`) | max 300 s, bounded also by the pending lifetime |
| Poll interval | 250 ms |
| Outstanding per session / per daemon | 1 / 16 |
| Operator grant lifetime | remaining pending lifetime |

Exceeding the wait cancels the request and answers the original MCP id with a
correlated refusal containing `native_approval_timeout`.

## Redemption rules (execution gate)

At the `call` event with `approval_id` the daemon recomputes the verdict with the
**current** policy and requires all of:

1. the id exists and is still `pending` (not redeemed/closed/expired);
2. same collector session and same daemon session epoch;
3. same tool, schema sha256 and binding digest (arguments, registry, epoch, resource admission);
4. verdict is still Ask (daemon source) — Allow or Deny means the policy changed;
   Deny can never be rescued; classifier source accepts Ask/Allow and the collector
   re-runs the classifier after the wait (Deny/failure refuses);
5. the durable approval-policy epoch equals the one recorded
   (`invalidate_all_for_policy_switch` advances it);
6. for resource policies: revalidate_resource_execution confirms the resource tool is a supported
   Linux native executor, within workspace bounds and allowed resources, destination is not mutated,
   and for create_file that target file does not already exist;
7. a native grant for exactly this id exists, is signed with the **native key**, has
   the versioned scope `native-mcp/approval/v1:<tool>`, is unexpired, and is claimed in
   the persistent ledger `native-grants-spent.json`.
8. Provenance preservation: single-use approval authorizes only the specific action and
   does not clear provenance taint or incomplete history flags.

Then the result goes through the existing result-inspection/release boundary: a result
that is Ask/Deny stays blocked. Release is to the MCP host; it does not attest that the
model consumed it.

## Authority separation

- Approval comes only from the operator command, never from MCP server input,
  tool arguments, or the child environment (the child never receives daemon tokens).
- Native key = SHA-256(`agentfw/native-approval-key/v1` ‖ hook approval key); stored in
  `<home>/native-grants`, spent in `<home>/native-grants-spent.json`. Hook grants use a
  different key, directory, ledger and tool-name scope, so an old hook approval cannot
  authorize an MCP call and a native approval cannot authorize a hook.
- No default and no automatic approval.

## Operator commands

```
agentfw native-approval list                     # digests only, no raw arguments
agentfw native-approval inspect <id>             # full record incl. exact arguments
agentfw native-approval approve <id> --binding <binding_sha256>
agentfw native-approval reject  <id>
```

`approve` refuses unless `--binding` equals the digest of the pending call — a tool
name, category or description is not an identity. The collector prints a line
`mcp_native_approval_pending` (id, tool, binding digest, no arguments) to stderr.

## Local compromise limit

The operator files live in the same OS user's protected home. Approval is an explicit
authorization by whoever can run the operator command as that user; it is **not proof
of human presence**, and a compromised same-user or OS environment can approve, edit
or forge it. This feature does not defend against that.

## Not rescued (no delayed execution)

Hard Deny; changed arguments/schema/registry; policy epoch or verdict change;
incomplete resource context / unsupported executor; expiry; daemon restart (pending and
issued approvals are removed at startup); session end; collector disconnect, EOF,
cancellation, malformed or concurrent client input while waiting (the pending request is
cancelled and the session closed).

## Recovery

- Stale pending files after a crash: `agentfw native-approval list` shows only unexpired
  ones; a daemon restart removes the directories' files. Safe to delete by hand.
- Wrong decision: reject before the call is redeemed; a redeemed approval is spent.
- Policy switch: run the managed-policy activation (or `invalidate_all_for_policy_switch`);
  all issued approvals become unusable.
- Lost approval: repeat the call; a new pending request is created.
