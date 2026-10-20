# Operator-installed native admission

The opt-in `sw-native/1` path keeps native function names, argument validation,
dependencies, returned values and the original upstream formatter. It adds
declared action and result-source semantics and a separate admission boundary
before a result enters the model. The existing Claude `/hook` contract and the
default [AgentDojo fallback](agentdojo-live-fallback.md) remain available.

This is a local collector contract, not proof of attack effectiveness. HTTP
authentication does not attest that a named function actually executed. The
collector, the operator-installed registry and its accurate semantic declarations
are trust boundaries. A compromised process running as the operator can read
the private keys or change the registry before startup.

## Original AgentDojo workspace profile

The additive `workspace_profile: "agentdojo-workspace/1"` field selects the
[reviewed inventory](../../crates/agentfw/profiles/agentdojo-workspace-v1.json).
Its registry ID is `agentdojo-workspace/1`; all 24 original functions must be
present, including explicit unsupported entries. Registries without this opt-in
retain schema-1 behavior. Model descriptions never declare authority.

The inventory retains original Pydantic schemas and canonical hashes, upstream
revision, semantic sources, action classes, untrusted result provenance and
typed resource selectors. The daemon independently checks these declarations
at startup and extracts resources from validated arguments at admission.
The schemas originate from AgentDojo revision
`089ed468cf3ed0322acc66b0211f26d9d90dbf60`; its
[MIT copyright and permission notice](../../crates/agentfw/profiles/upstream-notices/agentdojo-LICENSE)
is retained with the profile. The original callable/evaluator sources remain
in the separately verified upstream checkout.
Original defaults, nested calls, callable bodies, errors and evaluator inputs
remain unchanged. Unknown functions, schema drift, incomplete profiles and
false trusted provenance cannot silently execute.

| Family | Reviewed semantics |
|---|---|
| Drive read/search/list | Logical file ID or explicit dynamic collection |
| Create/append | Side-effecting logical filename/ID, not a host path |
| Delete file/email | Destructive; email deletion moves its object to trash |
| Unread emails | Side-effecting: original code marks messages read |
| Other mailbox/contact reads | Read original mailbox/contact collection |
| Send email | Network; every recipient, cc, bcc and nested file reference |
| Share file | Privilege-changing; file ID, permission and destination |
| Add participants | Privilege-changing; event ID and all participants; original code does not send the email claimed by its docstring |
| Calendar reads/current day | Read calendar collection; result remains untrusted |

Collection `*` is an explicit query scope, never an empty unrestricted grant.
Logical resources are not filesystem/executor authority. Optional arguments
are materialized by the original Pydantic runtime. Null/empty optional recipient
lists add no destination; an empty required list refuses. Attachments are
logical references: the original email code does not fetch their file contents.
The daemon retains an extraction hash in its native audit without raw resources.

Unsupported paths refuse before the original callable:

- `create_calendar_event` adds an implicit owner recipient from environment state.
- `cancel_calendar_event` and `reschedule_calendar_event` obtain recipients from
  the existing event.
- Event/ambiguous attachment dictionaries refuse. Original `send_email` treats
  any `file_id` as a file attachment even when `type` says event; this profile
  does not silently reinterpret that ambiguity.
- Delegated host/child sessions are unsupported for this benchmark profile;
  logical workspace resources cannot silently inherit filesystem/network grants.

The other suite functions remain available. There is no coding-tool fallback.
The shipped policy is unchanged: unknown destinations may Ask, tainted
destructive effects Deny. Withholding a result never undoes an earlier effect.
The shipped PII floor also makes ordinary email recipients an unattended Ask,
including allowlisted domains. Offline controls preserve that refusal and
calibrate actual email effects separately with the unchanged undefended runtime;
they do not claim unattended protected email utility.
The original guarded runner stops a withheld/failed trajectory; no evaluator
result or fabricated prevention/utility score is reported for it.

### Offline reproduction

On Linux with Git, Python and Cargo:

```sh
bash scripts/agentdojo-workspace-acceptance.sh
```

This requires fresh `target/sou85-upstream`, `target/sou85-driver` and
`target/sou85-offline` directories. It obtains pinned public source and the
existing dependency lock, builds the actual Agent, then invokes the existing
runner. No provider/model call or credential access is performed. With prepared
inputs the acceptance command is:

```sh
python -B scripts/agentdojo-live.py --mode workspace-fixture \
  --upstream-checkout <pinned-checkout> --agent-binary <agentfw> \
  --report-out <fresh-output-directory>
```

Outputs are `registry.json`, `development-proposal.json` and `report.json`
(or `failure.json`). The shell procedure also runs the existing schema-1 native
fixture and retains `legacy-native.json`. Reports bind original source inventory, binary, adapter
sources, dependency lock, registry, profile and shipped policy. Python call
tracing counts actual original-function executions; independent environment
checks calibrate allowed effects and refused dispatch. Original user/attack
evaluators run on known positive/negative controls. These scripted controls are
not model effectiveness measurements. Failed controls fail the command;
hidden skips do not satisfy acceptance.
Original timestamps and random admission identifiers are retained, so evidence
hashes vary across runs; deterministic assertions compare effects and boundaries,
not a fabricated fixed upstream clock.

The proposal uses the existing SOU-36 plan schema and machinery. Model access,
cost and thresholds remain unapproved; this command does not freeze a plan.
Later separately authorized adoption uses `freeze-plan`, `plan-check` and
`report` from the [matched protocol](agentdojo-matched-protocol.md). Historical
fallback plans and negative baselines remain unchanged. Phase 4 stays open.

CI reuses the existing manual `ci.yml` smoke job with `smoke_only=true` and
`workspace_acceptance=true`, with no new automatic per-push job. Its artifact
retains reports and formatting diagnostics; formatting is restored before
execution so it cannot change the tested source.

## Immutable registry

The operator configures an absolute registry path and its exact SHA-256 in the
private Agent configuration:

```yaml
enforce: true
native:
  registry_path: 'C:/absolute/private/native-registry.json'
  registry_sha256: '<SHA-256 of the exact registry bytes>'
```

The daemon reads and validates that snapshot once at startup. Native admission
is disabled without it and requires enforcement and the optional judge disabled.
It uses a separately generated,
protected `.agentfw/native-token`; the regular Claude/MCP token cannot authorize
native requests. There is no HTTP registry installation/update endpoint.

Registry shape:

```json
{
  "contract_version": "sw-native/1",
  "registry_id": "operator-reviewed-runtime-v1",
  "tools": [
    {
      "name": "original_function_name",
      "schema_sha256": "<SHA-256 of canonical original JSON input schema>",
      "action_class": "read_only",
      "result_provenance": "untrusted",
      "egress": []
    }
  ]
}
```

Schema canonicalization is sorted-key compact JSON encoded as UTF-8, without
ASCII escaping or non-finite numbers. The original pinned function's
`parameters.model_json_schema()` supplies the schema; the Python adapter checks
that digest before execution. Semantics are reviewed operator inputs, never
inferred from a model-generated name, description or per-call declaration.

Action classes are `read_only`, `side_effecting`, `network`,
`privilege_changing` and `destructive`. Existing argument-pattern checks can
tighten the declared baseline. Result provenance is `untrusted`, `local_system`
or `local_project`; untrusted native content has its own `native` origin. It
does not pretend to be an MCP server or a fetched URL. The shipped policy adds
that actual origin to its existing untrusted-taint rules.

An egress selector is an explicit object such as
`{"pointer":"/recipients","kind":"email_domain","optional":false}`.
`url_host` and `email_domain` select actual destination strings or arrays from
validated arguments. Declare optional fields explicitly. Missing required or
malformed destinations fail inspection; destinations are never fabricated to
trigger a policy rule. Review tools that can send through several parameters
and include every relevant destination.

## Admission stages

Every `POST /native/v1` request includes `contract_version`, `registry_sha256`,
`session_id` and `event`. Unknown versions, fields, tools or schema identities
are errors. The collector supplies no authoritative action or trust fields.

| Event | Additional fields | Boundary |
| --- | --- | --- |
| `session_start`, `session_end` | none | Start/end the bounded native session |
| `call` | `tool`, `args`, `schema_sha256` | Validated native invocation before its real callable runs |
| `result` | `call_id`, `tool`, `args`, `result_kind`, `delivery`, `content` | Exact original formatted value or error before returning to its caller |
| `context` | `call_id`, `tool`, `args`, `content` | Exact serialized original tool-result message before release to the model |

The bounded [stdio MCP collector](../operations/MCP_STDIO_ADMISSION.md) uses
`result` delivery `mcp_host` for the exact original JSON-RPC response. The
daemon inspects decoded original text blocks or error text independently and
hashes the entire envelope. Unsupported content is refused. Successful release
records declared provenance like a parent return and completes the invocation;
it does not invent a model `context` event or attest later host serialization.

An admitted call receives an unpredictable daemon-generated invocation ID bound
to the session epoch, registry, tool, schema and canonical arguments. Result
and context stages must match that binding and occur once in order. Records
expire and are removed at session end or daemon restart. `delivery` is `parent`
for a nested return or `model` for an outer result, derived by the trusted
collector from the original runtime stack. Parent admission completes that
record immediately and records its admitted source for subsequent calls. A
model-bound result stays internal and does not update taint or spans until its
actual context is admitted; preplanned calls in a batch cannot inherit taint
from content the model has not seen. Parent admission does not fabricate a
model-context event. The server bounds
sessions, invocations and content; oversized content is rejected in full.

Every successful response explicitly names the contract, registry, session and
event and returns `verdict`, `enforced`, `release`, `call_id`,
`binding_sha256`, `content_sha256` and `reason_codes`. The collector verifies the
exact invocation/content hashes. Empty responses, a changed binding, shadow
responses, malformed envelopes and transport failures never admit a result.

The context stage inspects the actual error when the original OpenAI serializer
would prefer it; otherwise it inspects the original text blocks individually.
It hashes the entire original serialized message. This catches a formatter
whose later output differs from an earlier inspected snapshot. Detection runs
before the original ToolsExecutor returns its messages, so subsequent model
calls and logging receive only admitted content. The adapter leaves the original
function result and formatter intact.

Context audit findings are the union of actual independently inspected blocks,
and `risk_score` is their maximum observed block score. Policy decisions are
evaluated on those original blocks; the adapter does not invent a concatenated
result for inspection or scoring.

Ask and Deny withhold content. This MVP has no human native approval channel
and does not redeem action grants for results. A withheld or uninspected
trajectory stops before reporting task evaluators; it is not counted as a
successful prevention. Withholding a result cannot undo effects the function
already performed. Nested functions retain their original ordering, including
effects that occurred before an outer invocation was withheld.

Native escalation uses the policy's declared fallback (or Ask if absent). This
MVP does not call the optional local judge; configuration rejects combining
native admission with an enabled judge. Review escalation fallbacks as part of
the installed native policy.

## Explicit evaluation

The default CLI remains a traffic-free manifest. A native live run adds
`--native-registry '<reviewed registry path>'` to the existing explicit
[live command](agentdojo-live-fallback.md#operator-selected-live-run). It still
requires a frozen task plan, selected model/provider/endpoint/credential
variable and every call, byte, output and estimated-cost budget. No credential
or model is selected automatically. The registry bytes are frozen before the
run and copied into each disposable defended daemon profile; evidence binds
that exact registry, adapter, executable and policy.

The manual free fixture uses actual pinned AgentDojo classes and harmless
original fixture functions, plus a disposable native-enabled Agent:

```text
target/agentdojo-venv/Scripts/python.exe -I scripts/agentdojo-live.py --mode native-fixture --upstream-checkout target/agentdojo-upstream --agent-binary target/debug/agentfw.exe --evidence target/native-fixture-new.json
```

This mode reserves fresh atomic evidence before startup and requires no model
or provider calls. Existing CI discovers transport/registry safety regressions
without runtime downloads. The manual runtime/daemon checks remain explicitly
gated on the pinned checkout and selected executable.

Current restrictions: one original ToolsExecutor, serial nested execution,
bounded/expiring invocation state, and no recovery after transport uncertainty.
Calls failing before their validated callable boundary stop the native run;
supporting original validation-error observations needs a separate correlated
no-execution admission record. Do not silently skip inspection or turn those
aborts into benchmark success. Live defended task utility, held-out outcomes,
registry coverage for actual selected tools and shadow soaking still need their
own evidence.

The [2026-10-05 Windows checkpoint](evidence/agentdojo-native-fixture-2026-10-05.md)
records 26 passing native checks and 29 passing fallback compatibility checks,
including the actual production pipeline with a scripted loopback provider.
It also preserves earlier incomplete runs and the outstanding historical
profile-cleanup rejection.
