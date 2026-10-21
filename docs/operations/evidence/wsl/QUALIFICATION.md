# Installed WSL2 pilot qualification

## Actual environment and source

On October 21, 2026, an ordinary UID 1000 user ran the installed pilot in Ubuntu
24.04 on actual WSL2 x86-64, kernel `6.18.54.1-microsoft-standard-WSL2`, with
Python 3.12.3 and selected Claude Code 2.1.251. The private installation and
workspaces were outside the checkout under `/home` on ext4. Original pinned
filesystem and Git MCP servers used the accepted single-file rule classifiers
and the existing installed-pilot proof policy.

The retained passing source is `ffa12fd59239b0a3ecd6fd15a551a757f709ea3c`, tree
`7740749fb504289452ebf38279cbdd096b85301d`, tracked-file digest
`384499ecc506a8a46a46d558a654ef0fb6e26101d1ab2868a60e4324ecbf709e`.
The checkout was clean, and the closing source and selected runtime digests
matched their opening observations. The report records each selected binary,
classifier, policy, profile and configuration digest.

## Retained failed prerequisite

[missing-elf-prerequisites.zip](missing-elf-prerequisites.zip) preserves the first
failed report on source `e1ba4844` and its original traceback. Preparation refused
the pinned Python extension's unresolved `libtcl8.6.so` and `libtk8.6.so` dependencies.
No host workflow ran; ten cases remained incomplete. Cleanup removed the owned
stage. A separate ELF scan identifies both missing SONAMEs.

The correction retains full ELF validation, reports bounded missing-library
identities with an operator next step, and documents explicit installation of
Ubuntu's `libtcl8.6` and `libtk8.6` runtime packages. No startup download or
unconstrained fallback was introduced.

## Passed controls and limits

[installed-wsl2-controls.zip](installed-wsl2-controls.zip) retains all **12/12**
passed cases, both useful workflows, zero false interruptions, and no remaining
blockers. It includes original owned synthetic host/provider frames, correlated
MCP transcripts, sandbox positives, audit observations and cleanup witnesses.
The required denominator and existing deadlines were preserved.

Actual Claude Code completed filesystem reads and Git history/diff work. The
derived forbidden read had no independent FIFO reader, an independent
conversation could still read it, and useful work continued. Collector death,
daemon loss, stale authority refusal, fresh-session recovery, changed assets,
missing sandbox inputs and source mismatch were exercised. Previously executed
effects and withheld results retain their original distinct witnesses.

The additional port control calibrated a separate process, required native
`EADDRINUSE`, and confirmed that process still served its marker before owned
fixture teardown. WSL/namespace-setting digests matched before and after the
exercise. Final cleanup stopped owned processes, removed the installation and
preserved the unrelated process and synthetic file until explicit teardown.
Separate actual WSL checks refused a DrvFS stage and an absent stage directory.

CPU, memory and PID controllers were observable, but writable cgroup delegation
was unavailable. Resource-budget enforcement is **not measured or advertised**.
The actual host used an owned scripted provider; no paid model call, live-model
effectiveness, ordinary-clone Git support, other architecture or WSL1 acceptance
is claimed.

## Reproduce and verify

Follow [WSL setup and qualification](../../WSL_PILOT.md) and its exact-selection
procedure. Run the opt-in command on the reviewed commit using a new private
output directory. Later candidates require a fresh run; these archives identify
their recorded source rather than automatically qualifying later edits.

[manifest.json](manifest.json) records archive SHA-256 and sizes. Each ZIP also
contains an `archive-manifest.json` with per-file SHA-256 and byte counts.
The failed ZIP SHA-256 is
`5d38cf476124138bd9103ed2219aabcdd10e3ca965bd57d17ae6030205db7d9f`;
the passing ZIP SHA-256 is
`afdde4b42dace2458eb0a839864a8f854a86c3b58a6dba0eddcba5542bae88ff`.
Host settings contents, environments and bearer/proof files are excluded;
known owned tokens are redacted by the original harness.
