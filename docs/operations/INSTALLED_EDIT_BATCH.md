# Guarded installed multi-file application

`agentfw edit-session batch` is a separate local operator workflow for two to
eight explicitly mapped outputs from one completed installed edit run. It reuses
the accepted review checks and exact-file replacement executor. It grants no
MCP, Claude, tool, network or provider authority. Linux x86_64 and an ordinary
owning account are required; other platforms do not expose this operation.

Each destination must already exist as an owner-private direct-child regular
file in the same private project directory. Every preimage and replacement is
bounded to 4096 bytes; each complete set is bounded to 32768 bytes. No delete,
nested tree, arbitrary rename or missing-file creation is supported. The run,
original immutable plan, output directory, Agent home and runtime locations are
protected. The new recovery journal must be outside source and destination roots.

## Read-only preview

First review the completed run with the ordinary installed review command. Then
choose the complete ordered mapping and a new journal under an existing private
parent. Preview does not create a journal, stage files, launch subprocesses,
request a model/tool/provider or change project data.

```bash
umask 077
agentfw edit-session review --run /private/runs/edit-ID --sha256 PROFILE_SHA256
agentfw edit-session batch preview \
  --run /private/runs/edit-ID --plan /private/plans/original \
  --sha256 PROFILE_SHA256 --root /private/project \
  --map report.txt=report.txt --map summary.txt=notes.txt \
  --journal /private/recovery/batch-1
```

A versioned confirmation binds every ordered mapping, retained run/profile and
component identity, output identity/hash/size, exact destination root and target
preimages and expected replacement contents. A changed final member invalidates
the complete confirmation. Duplicates, aliases, links, hardlinks, special or
foreign files, unsafe/redirected parents and active/incomplete runs refuse before
project mutation. This is an explicit local sole-writer maintenance operation:
exclude all other writers, including programs with the same UID, for its duration.
Directory locks cannot enforce exclusion against arbitrary same-UID programs.

## Explicit apply and private proof custody

Repeat the identical selection with the fresh preview digest and both consents:

```bash
agentfw edit-session batch apply \
  --run /private/runs/edit-ID --plan /private/plans/original \
  --sha256 PROFILE_SHA256 --root /private/project \
  --map report.txt=report.txt --map summary.txt=notes.txt \
  --journal /private/recovery/batch-1 --confirm PREVIEW_SHA256 \
  --private-sole-writer --consent-private-backup > /private/recovery/batch-1.response.jsonl
```

Save stdout privately even when the process is interrupted. Each synchronized
member emits a `member_completed` JSON line with a returned `proof`. The last
line is the overall observed result; a partial or uncertain result is not a
successful complete batch. The finite protocol may return a partial result with
exit status zero: check the JSON status, not just the process exit status.

The complete ordered plan and all bounded preimages/postimages are staged and
synchronized in the private journal before the first project replacement. One
`images-NN.bin` concatenates that member's preimage and postimage with lengths
bound by the plan; this keeps the accepted private publication limit of nine
files and 144 KiB unchanged. Project replacements then use the accepted native
per-file staging/publication checks individually. Each has durable intent before
rename and completion only after file and parent directory synchronization.
The entire batch is **not** globally atomic; no automatic rollback is attempted.

A proof is `INDEX:apply|revert:RECEIPT_SHA256:PRIVATE_ACK`. Its acknowledgement is
returned after completion synchronization; only its hash is stored in the journal.
Keep proofs and stdout private. A visible completion file, matching bytes, absent
name or guessed token does not prove that a completion was returned. If a crash
or I/O failure prevents proof delivery, that member remains uncertain. Recovery
never reconstructs the acknowledgement from a journal or retries forward apply.

## Status, explicit recover and revert

Pass each retained returned proof as a separate `--proof`. Proofs are not shell
commands. In these examples `PROOF_0` and `PROOF_1` stand for the literal values
from your privately retained JSON response.

```bash
agentfw edit-session batch status --journal /private/recovery/batch-1 \
  --expect-plan PREVIEW_SHA256 --proof PROOF_0 --proof PROOF_1
agentfw edit-session batch revert-preview --journal /private/recovery/batch-1 \
  --expect-plan PREVIEW_SHA256 --proof PROOF_0 --proof PROOF_1
agentfw edit-session batch revert --journal /private/recovery/batch-1 \
  --expect-plan PREVIEW_SHA256 --proof PROOF_0 --proof PROOF_1 \
  --confirm REVERT_PREVIEW_SHA256 --private-sole-writer \
  > /private/recovery/batch-1.revert-response.jsonl
```

`revert-preview` requires the entire set to have proven, unchanged applied
postimages. `recover-preview` instead proposes only the proven unchanged applied
subset of a partial batch; it lists every excluded uncertain, changed, missing,
untouched, failed or already reverted member. Confirm that exact proposal with
`recover --confirm RECOVER_PREVIEW_SHA256 --private-sole-writer`. Both revalidate
the complete observed set and records before the first restore. Recovery restores
preimages; it never finishes forward application. Every restore uses another
single-use intent/completion and returns its own revert proof. Retain both apply
and revert proofs for subsequent status.

Files are reported separately as `untouched`, `applied`, `reverted`, `failed` or
`uncertain`. A replacement at the old name, even with identical bytes, is not
this operation's unchanged postimage. Later user edits and substituted or missing
names remain untouched by recovery. A damaged/unknown journal, changed backup or
stale restore preview refuses. No record is overwritten or automatically purged.
Original generated outputs and all recovery records remain retained.

SIGKILL before native rename can leave the accepted executor's named staging
file. Such staging remains recovery evidence and the existing native executor
conservatively blocks later replacement; this command never removes unknown
staging by name. A crash between completed publications can restore the proven
completed prefix after a fresh explicit recovery preview. A crash after rename
without a returned proof retains uncertainty rather than inventing completion.

## Qualification boundary

The opt-in `scripts/qualify-edit-batch.py --run ...` uses installed binaries and
the pinned genuine host outside checkout, owned synthetic two/eight-file projects
and only the owned scripted loopback provider. It covers actual generated output,
review, application/readback/revert, final-member preflight failures, replay,
concurrent apply, active/cancelled runs, stale recovery, later edits and identical
byte substitution. Qualification-only syscall controls interrupt between
publications, after rename and around receipt sync. Provider requests during
operator operations must be zero, source state and siblings must be preserved,
and every finite case must be attempted and pass. Raw content, proofs and local
paths are excluded from public reports. No real credentials or paid inference
are used. Final shared Ready CI, CodeQL, candidate admission and merge are TL-owned.
