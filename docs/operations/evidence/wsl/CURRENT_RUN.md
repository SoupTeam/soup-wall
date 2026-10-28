# Refreshed installed WSL2 qualification

[A newer run after the latest main integration](MAIN_REFRESH.md) qualifies
source `97729f0602516e6d6478e5498de444f4cce2546f`. This file preserves the
earlier refreshed checkpoint.

[installed-wsl2-d4aa63f.zip](installed-wsl2-d4aa63f.zip) contains the fresh actual
WSL2 run on clean source `d4aa63f297c7b1189c062577c712a093533b8b2e`, after
integrating the updated main branch. Opening observation:
`2026-10-21T18:57:28.988893+00:00`.

All **12/12** required cases passed. Both useful filesystem/Git workflows
completed with zero false interruptions. Refusal, independent conversation,
parallel cancellation, collector/daemon recovery, invalid-input controls and
final cleanup passed. The foreign-port control preserved its independent
listener. Selected inputs and guest WSL/namespace-setting digests matched before
and after; the checkout remained clean and unchanged.

The run used Ubuntu 24.04, UID 1000, x86-64 WSL2 kernel
`6.18.54.1-microsoft-standard-WSL2`, Python 3.12.3 and Claude Code 2.1.251.
An owned scripted provider was used; live-model effectiveness and active cgroup
resource-budget enforcement were not measured. Windows initially refused VM
startup with `ERROR_NO_SYSTEM_RESOURCES`; a temporary 4 GB WSL memory cap enabled
startup. The original absence of `.wslconfig` was restored after VM startup.

[d4aa63f-manifest.json](d4aa63f-manifest.json) records the exact source tree,
tracked-file digest, result counts and archive identity. The ZIP retains the
original report, selected runtime hashes, sanitized transcripts, logs, refusal
and cleanup evidence. Its internal `archive-manifest.json` lists all 68 members
with byte lengths and SHA-256 digests.

Archive: **128174 bytes**, SHA-256
`7e58626063b7cdfc4b1153e22a02d07ec776f96d24028021c98fb2cf5c46b182`.
Verify from the repository root:

```sh
sha256sum docs/operations/evidence/wsl/installed-wsl2-d4aa63f.zip
unzip -p docs/operations/evidence/wsl/installed-wsl2-d4aa63f.zip report.json
```

The evidence publication changes only documentation and evidence files; the run
identifies the tested source above, rather than claiming execution on its later
publication commit. [Earlier failed and passing archives](QUALIFICATION.md)
remain intact. [Reproduction instructions](../../WSL_PILOT.md) describe the
exact-selection procedure for later runtime changes.
