# Prepared pilot generation selection and rollback (SOU-133)

This command changes only `current.json` in an existing private SOU-111
preparation directory. It does not rebuild assets or activate protection. The
next SOU-116 launch starts a fresh daemon, host session and authority from the
newly selected generation. An earlier run's approval or receipt is never reused.

Run as the ordinary owner on native Ubuntu 24.04 x86_64. Supply the **exact
clean source checkout** used to prepare each generation. Both checkouts must
include the selection lifetime lock contract. A generation prepared from older
source without this contract is refused: its accepted pilot runner has an
admission-to-launch race that an after-the-fact process snapshot cannot close.

```sh
python3 -B scripts/switch-prepared-pilot.py --output /absolute/private/preparation \
  --target 0123456789abcdef0123456789abcdef \
  --previous-source /absolute/checkout-A --target-source /absolute/checkout-B
```

The default command is a read-only plan. Review `previous`, `target`, their
source commits and trees, Agent hash, both server/profile receipts, policy and
classifier hashes. Save the emitted `plan_sha256` and then apply the same
arguments with `--apply --confirm PLAN_SHA256`. Any changed marker, source,
selected binary, package or profile invalidates the plan. A rollback uses the
same command with the former generation as `--target` and the source roots
reversed; it revalidates that generation from scratch.

```sh
python3 -B scripts/switch-prepared-pilot.py --output /absolute/private/preparation --status
python3 -B scripts/switch-prepared-pilot.py --output /absolute/private/preparation --recover
```

The private, bounded `transition-journal.json` records intent before atomic
publication. `--status` reports the actual marker and a pending plan. After an
interruption, `--recover` compares the actual marker to the journal's before
and after hashes and settles only an unambiguous result. It does not replay a
selection or overwrite an operator edit. A conflict requires operator review
of `current.json`, the two selection receipts and the private journal. Status
and recovery report marker state, not fresh generation qualification; use a
new plan for full identity verification.

SOU-111 preparation and SOU-116 launch now coordinate through a private
selection lock. An active run, preparation or another transition refuses the
switch. Before publication, the transition also checks the selected Agent and
host process identities for surviving children after an abrupt supervisor
exit. If process observation is unavailable, it refuses the transition.
Launch from each generation's exact source checkout and keep the
private preparation directory and its generation contents unchanged. This
command does not stop a run or perform hot reload. An old runner lacking the
lock cannot be switched safely while its admission-to-launch race is possible;
prepare fresh lock-capable generations to use this command.

The focused native lifecycle is opt-in via the existing **Real filesystem MCP
profile** manual workflow. It uses the accepted scripted provider and original
filesystem/Git servers; its report is not a live-model effectiveness claim.
