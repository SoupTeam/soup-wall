# Installed policy-candidate activation (SOU-209)

`agentfw pilot policy-activation` activates one **reviewed, deny-only** candidate from
[`agentfw policy-candidate`](OPERATOR_POLICY_CANDIDATES.md) for one **idle** owned Linux installation,
shows the policy actually selected, and reverts safely. It never copies a candidate over the live
policy: it publishes a *new verified generation* through the existing preparation, selection lock
and [maintenance](PILOT_MAINTENANCE.md) gate. It starts no daemon, host or server of its own,
copies no session, grant or approval, and never claims observed protection (`active_protection`
is always `not-observed`). The next launch starts fresh authority from the selected generation.

Native Ubuntu 24.04 x86-64 installed front door only.

## Prerequisites and refusals

* The installation must be **in maintenance** (`maintenance enter`, drained). An open, never-enrolled,
  uncertain or mismatched installation refuses (`maintenance_entry_required`,
  `maintenance_state_uncertain`, `installation_mismatch`). Any active or uncertain enrolled run
  refuses (`runs_active`, `runs_uncertain`); so does a surviving selected-program process and a held
  selection lock (`active_or_uncertain_pilot_run`, `selected_generation_in_use_or_transitioning`).
* Only the existing restricting contract is supported, and only through its reconstruction:
  the accepted `policy-candidate validate` rebuilds the candidate from the reviewed profile bundle,
  the **currently selected** policy and the constraints, and must report `restricting_only`
  (base rules unchanged and in order, preceded by Deny-only additions). Examples or a matching
  hash alone never authorize. Activation accepts only candidates built from `deny_actions`; tool-group floors
  (`deny_tools`) and destination subsets stay authoring-only (`candidate_scope_unsupported`), because the
  authoring bundle's registry cannot be proven to equal this installation's original-server registry. A candidate equal to the live policy, with a different base policy,
  or whose export, constraints, bundle or examples changed refuses.
* Refused scopes: a prefix under the coordinated updater (`current.json`/`journal.json`), selections
  with linked-worktree or filesystem-roots capabilities, and Agent homes that carry managed/Console
  enrollment names (`managed_home_unsupported`). Managed rollout and signed policy are untouched.

## Commands

```sh
H="--home /absolute/private/agent-home"; C="--prefix /abs/prefix --state-root /abs/state"
agentfw pilot $H policy-activation inspect $C
agentfw pilot $H policy-activation preview $C --candidate /abs/candidate --expect-candidate CANDIDATE_SHA256 \
  --profile /abs/profile --constraints /abs/constraints.json --examples /abs/examples.json
# Review blockers and effects, then repeat with: confirm ... --confirm CONFIRMATION_SHA256
agentfw pilot $H policy-activation revert $C --generation PREVIOUS_ID            # preview
agentfw pilot $H policy-activation revert $C --generation PREVIOUS_ID --confirm DIGEST
agentfw pilot $H policy-activation recover $C
```

* `inspect` reports the selected generation, selection and policy digests, whether the selected policy
  is the baseline or an operator candidate, the bounded activation history, any pending transition
  and the maintenance state. It is read-only.
* `preview` is inert. Its `confirmation_sha256` covers the exact installation binding, current marker,
  selection and policy digests, front-door state, transition journal, maintenance revision/marker and
  run inventory, and the candidate facts (digest, policy, base policy, constraints, schema pins).
  `confirm` recomputes everything under the **exclusive** maintenance gate and refuses a stale
  digest (`confirmation_stale`). Two concurrent confirmations cannot both proceed.
* `confirm` copies the reviewed policy into an immutable private
  `preparation/operator-policies/<candidate sha>/`, stages a complete new generation with the
  selected runtimes, profiles and workspaces but only that policy changed (explicit
  `prepare-installed-pilot.py --stage-only`; the previous marker stays selected), verifies the whole
  generation and that nothing else differs from the current one, then publishes (below). Staging
  repeats the original preparation and may download the same pinned public inputs if the original
  preparation was allowed to; preview never does.
* `revert` restores only a generation that a confirmed activation replaced and that still verifies from
  scratch with the same selection digest. It uses the same gate, journal and refusals; an unknown or
  never-confirmed generation refuses. It does not revive old session authority.

After activating or reverting, `maintenance leave` with a fresh preview adopts the changed selection
binding; only then does a launch start fresh authority from the selected generation.

## Transaction and recovery

The journal (`preparation/policy-activation-journal.json`, private, atomic, 16 history entries) records
intent, with the exact before/after marker and front-door-state hashes and the full after-state, before
anything is published. Order: journal intent, `current.json`, `front-door.json`, journal completion.
A crash at any point leaves either the valid old generation or an explicit refusal
(`selection_not_current`) until `recover`:

| Actual state | `recover` outcome |
| --- | --- |
| marker and state unchanged | `interrupted_before_publication` (the staged generation is retained, unselected) |
| marker new, state old | `completed_by_recovery` (writes only the journaled state) |
| both new | `published_before_journal_completion` |
| anything else (operator edit) | `conflicting_operator_edit`, pending intent kept, exit 2 |

A kill during staging changes nothing selected and leaves no pending intent; the orphaned staged
generation is kept for inspection, never swept or adopted. Every refusal is a finite
`policy_activation_*`, `maintenance_*` or `candidate_*` reason; private paths and policy text are not
printed.

## Qualification

`test_pilot_policy_activation.py` covers the journal, stored policy, scope comparison, blockers,
every crash point, concurrent and stale publication, revert targets, candidate facts and refusals.
The manual `installed_focus: policy-activation` workflow mode runs
`scripts/qualify-policy-activation.py` through the installed front door outside the checkout: useful
read under the base, inert candidate and preview, open/never-enrolled and live-run refusals,
tampered and stale candidates, a SIGKILL during staging, concurrent confirmation, observation of the
actually selected policy, the same read newly denied with an independent `openat` witness of zero
server reads, preserved hard Deny/Ask for write/reset/exfiltration, safe revert with disjoint run
identities and complete owned cleanup. It does not replace TL-owned final Ready qualification.
