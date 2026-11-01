# Installed local policy candidates

`agentfw policy-candidate` is an offline Linux authoring tool. It reads explicitly
selected files and produces an **inert candidate**, never an active selection or
an approval. It requires no checkout, daemon, classifier worker, MCP server,
provider, network or project write. It uses the accepted MCP profile compiler,
AgentPolicySet parser, policy evaluator and `sw-policy-offline-input/1` replay.

## Inputs and supported restrictions

Select a complete private bundle produced by the accepted `mcp-profile compile`
command and the exact current policy YAML. The bundle is reconstructed from its
reviewed snapshot/declarations, including complete tool inventory, native config,
resource profiles and registry. Profile, registry, per-tool schema, declarations,
source snapshot and policy identities remain distinct. A supplied bundle is an
operator selection, not authenticated evidence of a running daemon's policy.

All input paths must be canonical and absolute. Inputs must be owner-private,
single-link regular files with safe, nonlinked ancestors. Copy public examples
into such a private input first. Policies/constraints are capped at 64 KiB;
compiled documents at 256 KiB each; examples retain the existing 1 MiB/64-event
replay limits. Generated policy has at most 64 rules. No arbitrary YAML patch,
condition, tool declaration or permissive rule is accepted.

For example, save this as a private `constraints.json`:

```json
{"format":"sw-operator-policy-constraints/1","deny_actions":["side_effecting"],"deny_tools":[],"allowed_destinations":null}
```

- `deny_actions` adds exact action-class Deny rules. Classes are `read_only`,
  `side_effecting`, `network`, `privilege_changing`, `destructive`.
- `deny_tools` accepts only complete groups of tools having a pinned baseline
  action class in the selected compiled registry. It compiles to Deny at that
  class **and every higher class**, across all tools. This broader effect is
  shown as `deny_action_floors`; it covers argument-based action upgrades.
  Arbitrary per-tool exceptions are unsupported because the current evaluator
  has no tool-name condition. A partial class group is refused, never silently
  widened or represented as a precise per-tool rule.
- `allowed_destinations`, when supplied, is an exact subset of existing canonical
  lowercase DNS/IPv4 hosts. Empty means no extracted egress destination. New
  hosts, wildcard/URL/port syntax and IPv6 literals are unsupported. An additional
  Deny applies outside the subset. Existing rules must be ordered from strongest
  resolved verdict to weakest, followed by an equally weak or weaker default;
  negative egress conditions are unsupported. Otherwise a changed egress
  predicate could accidentally pre-empt a stronger old rule, so authoring refuses.

Only Deny rules are added; existing rule order is preserved. Frozen mandatory
floors, detectors, resources, receipts, quotas, arguments and schemas are not
changed. Tool descriptions and model output are not semantic authority.

## Read-only review, export and validation

```sh
agentfw policy-candidate inspect --profile /private/compiled --policy /private/policy.yaml
agentfw policy-candidate preview --profile /private/compiled --policy /private/policy.yaml \
  --constraints /private/constraints.json --examples /private/examples.json --out /private/candidate
```

The preview contains old/new scope, separate identity pins, actual replay traces,
matched rule ordinals, mandatory floors, changed Allow/Ask/Deny and explicit
unsupported/insufficient-context rows. The example envelope and evaluator scope
are unchanged: **legacy agent-event inspection**, not original-server execution,
native admission, authenticated provenance or live protection. The operator
supplies complete ordered context. Unknown input never becomes an inferred Allow.

Default reports hash sensitive names/destinations and omit policy text. Add
`--show-private-scope` only when deliberately disclosing the readable old/new
policies and tool names to the local output destination. Retain that output
privately; it may contain operator policy messages and destinations.

Repeat the same arguments with `create --confirm PREVIEW_CANDIDATE_SHA256`.
The confirmation binds all original bytes/file identities, examples, ordered
restrictions, generated policy and the exact new destination/parent identity.
Any stale input or substitution requires another preview. The existing bounded
private no-clobber directory publisher stages and syncs the complete set, rechecks
inputs, then publishes once. Exports cannot overlap the selected profile or its
declared project roots. Concurrent/duplicate publication cannot replace a winner.

The output contains `candidate.json`, `candidate.sha256`, `constraints.json` and
`policy.yaml`, private from creation. `validate` repeats the same source arguments
and `--out`, plus `--exported /private/candidate --expect-candidate SHA256`. It
reconstructs the candidate, rechecks current input identities and verifies all
four exported files. It creates no directory and does not trust matching policy
bytes alone. Interrupted staging is not an active candidate; keep uncertain
leftovers for inspection and use a fresh destination rather than blind overwrite.

Activation remains a separate independently reviewed operation. Existing
`mcp-profile preview/install/upgrade` governs compiled native profiles; this
command does not call that route. A changed global Agent policy must use the
existing reviewed configuration/managed policy route and a freshly prepared,
verified pilot selection whose policy pin matches the enforcing daemon. Never
copy a candidate over a live policy or claim that simulation activates protection.

## Focused qualification

`scripts/qualify-operator-policy.py` is inert unless explicitly passed `--run`, an
Agent binary, exact clean source commit and a new report path. The focused manual
`mcp-create-file.yml` input `operator_policy_only=true` builds that source inside
the existing read-only-source/private-scratch network namespace. It exercises a
real lifecycle-installed binary outside checkout, checks finite positive/refusal
cases and uses `strace` to count actual network calls and child executable starts.
Active-policy, owned project and sibling witnesses must remain unchanged. Raw
inputs, traces and responses stay in private scratch; finite reports contain no
policy contents, paths, credentials or native authority. This is feature-focused
development evidence. Full Ready/security/current-main admission and merge remain
maintainer-owned.
