# Explicit installed edit-plan refresh

`agentfw edit-session refresh` prepares the next explicitly authorized edit on
native Linux x86_64. It reuses the installed edit session and its existing native
executors. The ordinary pilot remains read-only. Refresh never executes an edit,
retries an interrupted call, approves Ask, or changes an existing run.

## Preview, confirm, then run

After independently inspecting the current output, supply the original immutable
plan and its saved exact digest. Choose a new plan directory outside the output
tree. Its existing parent must be private and operator-owned:

```sh
agentfw edit-session refresh --plan /absolute/plans/first-plan \
  --sha256 ORIGINAL_PROFILE_SHA256 --out /absolute/plans/second-plan
```

The default is read-only. The bounded JSON proposal shows the old and new
profiles, every selected direct-child target, root identity, observed current
file identities and SHA-256 digests, the new `profile_sha256`, and the exact
`confirmation_sha256`. It contains no file contents, prompts, provider inputs,
grants or pending authority. `before` records what the original plan declared;
`observed_targets` records what was actually observed now. A matching hash does
**not** prove the previous call ran or completed. Previous execution remains
unknown to refresh; consult the existing audit and independently read the output.

Inspect the diff, then explicitly publish precisely that proposal:

```sh
agentfw edit-session refresh --plan /absolute/plans/first-plan \
  --sha256 ORIGINAL_PROFILE_SHA256 --out /absolute/plans/second-plan \
  --apply --confirm DISPLAYED_CONFIRMATION_SHA256
```

The confirmation binds the source plan, destination, all runtime and root pins,
the exact scope and observed selected targets. Changed inputs invalidate it.
Publication checks them again after create-new staging and before atomic
no-clobber rename. The original plan and output bytes remain unchanged. An
existing destination is refused, including an empty directory. Cooperating
creators/replacers share the accepted directory flock with refresh. Concurrent
refreshes cannot replace one another's plans.

Use the displayed **new** plan digest with the existing `edit-session run` and
`edit-session ask` commands described in the
[installed edit-session guide](INSTALLED_EDIT_SESSION.md). Each run creates a new
epoch and requires its own exact single-use Ask. The old digest, grants, decisions
and receipts do not authorize the new run. Refresh neither mutates nor silently
revokes a run already pinned to an older plan. It may become stale naturally
after an authorized replacement.

## Limits and refusals

Refresh preserves the exact operation, target allowlist, read selections, private
sole-writer root and 4096-byte maximum. It cannot add a target, wildcard, larger
bound or default write permission. Existing policy floors, classifier, Ask TTL,
transport deadlines and executor behavior are unchanged. Symlinks, hardlinks,
changed roots and unsupported metadata/filesystems are refused by the existing
safe target checks.

A create plan whose target now exists is refused. To select replacement, use the
existing explicit `prepare --replace` workflow; refresh cannot change create into
replace. A refreshed plan has descriptive digest lineage even when bytes still
match. Lineage grants no authority and makes no statement about previous success.

The original plan must remain bounded, canonical, private and immutable, with
single-link mode-0400 `profile.json` and `profile.sha256`. All accepted Agent,
genuine Claude, component, interpreter, classifier and policy identities must
still match. Refresh refuses runtime upgrades; prepare explicitly for the new
installed generation instead.

A failed or interrupted publication can leave an unpublished private staging
directory. No automatic recovery selects that stage or replays an edit. Preserve
it for inspection, check the actual destination and current output, then make a
new explicit decision. A failure after publication may have committed the new
descriptive plan; inspect it rather than infer success from a command exit. No
file edit is performed by refresh on either side of this boundary. The sole-writer
assumption remains essential: this is not CAS against arbitrary external writers.

## Development qualification

`python3 -B scripts/qualify-edit-refresh.py` is inert. Its explicit `--run` mode
uses the actual installed Agent/component and pinned genuine restricted Claude
with an owned scripted loopback provider outside the read-only checkout. The
fixed inventory includes two separately approved replacements with readback,
stale bindings, changed inputs, rejected/no approval, existing live-run isolation,
links, runtime pins, concurrent publication, existing destinations and actual
SIGKILL after staging before publication. It independently checks file/sentinel
identities and bytes, no unauthorized effects and owned process cleanup. Failed
and incomplete attempts remain in its report. This is development qualification;
final shared Ready qualification, admission and merge are reviewer-owned.

The first targeted native run passed 23/23 refresh cases and all 23 existing
installed-edit cases on implementation `635f9dfdf08e904e98ad45c565f784033a33ff05`.
Independent artifact checks, exact source/binary/plan digests and all development
attempts are retained under [SOU-168 evidence](evidence/sou-168/README.md).
