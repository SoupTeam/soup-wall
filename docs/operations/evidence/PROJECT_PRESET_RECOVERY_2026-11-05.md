# Installed project preset recovery — 5 November 2026

SOU-230, roadmap Phases 5/6. Follow the existing
[private export and guarded recovery procedure](../PILOT_INSTALLED_FRONT_DOOR.md#private-export-and-guarded-recovery-of-project-presets).
Measurements ran on 4 November UTC (delivery date: 5 November in Almaty).

## Measured source and scope

Successful [native run #611](https://github.com/SoupTeam/soup-wall/actions/runs/41894243461)
measured clean source `9d8a5fcf524c1cb57f1d05328e4005845b8a139a`, tree
`af2f98916d54063634217784baa4a65e1a9445cb`, independently based on accepted main
`5dd30c878d0c786d4ec6c623a33ce4b554469683`. Source before/after matched.
The initial evidence/procedure-only commits through
`2b7119803a4d3daeed64f6c11641b75dba7c556d` did not change that measured implementation,
qualification driver or workflow. The later output-boundary review follow-up below
requires its own source-bound qualification. The PR stays Draft; these results do
not substitute for final Ready qualification, release acceptance or live-model evaluation.

The job used native Ubuntu x86_64, an ordinary owned user, pinned runtimes,
verified CPython 3.12, the installed front door outside the checkout and owned
scripted loopback providers. Fresh provider inputs were supplied separately;
the archive restored no credentials, provider bodies, grants, sessions or authority.
SOU-225's early-diagnostics qualification is separate.

The actual installed component contained 91 files:

- Component ID: `46f0d826b8f1cb014bf0ae4ab90bbef938886f2f1e3f218ea68f9ae96a363161`.
- Component archive SHA-256: `bd7d6a4c7dc585fe8efa8397d5bb5196aaa4dad16a5bfb5a060df9400ac4ee13`.

## Outcomes, including original failures

| Run | Exact source | Original outcome |
| --- | --- | --- |
| [#603](https://github.com/SoupTeam/soup-wall/actions/runs/41881278359) | `e5f225380fde555649200ef55b66e3416bdba9de` | Failed before builds/preparation/installed observations: the legacy preset guard rejected the new focus. No acceptance report; zero observed product controls. Both guard variants are now covered by an executable regression. |
| [#604](https://github.com/SoupTeam/soup-wall/actions/runs/41882719330) | `2d1f6731d2da31c2beb949f273f2247460c6103d` | 58 Linux regressions passed. Nine recovery controls passed, then the interruption wrapper failed. Protected reads were not reached. [Unmodified original report](PROJECT_PRESET_RECOVERY_2026-11-05.run604.json). |
| [#609](https://github.com/SoupTeam/soup-wall/actions/runs/41890035177) | `22ab8b973ecc6acf8530a502b5286feb9bccc376` | All 61 Linux tests passed. Nine recovery controls passed; the bounded witness refused because staged fsync was unobserved within 120 seconds. No stage/catalog existed; owned processes stopped. Protected reads were not reached. [Unmodified original report](PROJECT_PRESET_RECOVERY_2026-11-05.run609.json). |
| [#611](https://github.com/SoupTeam/soup-wall/actions/runs/41894243461) | `9d8a5fcf524c1cb57f1d05328e4005845b8a139a` | All 62 Linux tests and all 32 installed controls passed, zero skips. [Unmodified original report](PROJECT_PRESET_RECOVERY_2026-11-05.run611.json). |

The 32 installed controls comprise 3 original front-door controls, 11 recovery
controls and all 18 existing two-project controls. Export included two presets;
read-only unresolved preview started no selected program, made zero network
connections and left the home unchanged. Wrong plans, corrupt archives, changed
catalogs and duplicates refused without overwriting existing entries. Atomic
import minted fresh versions and retained the pre-existing entry.

Both projects then completed actual protected reads with independent readback.
Native receivers/authority were distinct and cross-project authority was refused.
Running settings stayed frozen after preset removal; stopping one project left
the sibling running and able to perform another read. Credential execution
witnesses passed without exporting credentials. All owned processes stopped,
project sources/siblings were preserved and the unapproved receiver saw zero effects.

## Interruption calibration and recovery

The qualification-only supervisor observes successful fsync of the exact private
staged catalog, then sends SIGKILL only to its fresh owned process group before
publication. Output uses bounded temporary files, with a fixed 120-second witness
bound and confirmed cleanup. The tracer requests kernel filtering of the four
observed syscalls (`execve`, `execveat`, `fsync`, `renameat`) to avoid tracing every
read/stat during unchanged input validation; see the [strace manual](https://man7.org/linux/man-pages/man1/strace.1.html).
Product validation, timeouts and admission floors are unchanged. The original
failures above remain failures, not reassigned successes.

Four real Linux calibration tests passed in 2.825 seconds before heavy builds:
exact phase parsing, durable-stage SIGKILL, refusal of file existence without
fsync, and 500,000 file checks before staging within the same bound. This includes
a negative control; merely seeing a file cannot pass the witness.

The actual installed interruption attempt recorded 50,280 ms,
observed two fsync calls and two exec calls, and no rename publication. SIGKILL
exit was `-9`; the complete stage remained and the catalog was absent. Owned
processes were confirmed stopped. Installed `import-recover` with the same
explicit inputs/plan succeeded, both imported records checked, and only the final
catalog remained. Trace digest:
`e859b0ae66b6ab10306f92bfc96504b0ebc8475339f634bf34a6340c4dbdf29b`.
Raw traces/provider inputs stay private; the original report retains finite facts
and digests. Instrumented phase timing is not a product latency benchmark.

## Retained artifact integrity and other checks

The original reports are byte-for-byte copies of `installed-project-presets/report.json`
from their official GitHub artifacts. ZIP digests matched the API/UI digest and
ZIP CRC checks passed before reading either member. No report was normalized or
changed to alter its outcome.

| Run | Artifact ID | Official ZIP SHA-256 | Original report SHA-256 |
| --- | --- | --- | --- |
| #604 | `13350439361` | `ec34d0c7eb04f5c7151878ac7a8acf756eb57fdd70b377c140da7b768c475946` | `40023b5151c4c78f17d9ae4b4e9e40ec42c77a4b518338f3f07e45ce6a15d80c` |
| #609 | `13353518592` | `e92d9e7b686e9d29a5c3bfa68107e5cbd8f30a81cb0bfc161c8ead7eb0e92dea` | `cf488997d724f304e08705eb9d7ea0b0c5fd7647dcfcb4b67db71ed5b51ba6c4` |
| #611 | `13356397197` | `8317c24240a51c5ad3ba291bca1ae1fb1047b296ab3b75c4cd5456981128a969` | `d65952435bb76b822ad7d1ef152fe60fd0143dbb031c7688cc1c3cf22dca769f` |

The successful source passed Draft fast checks, trusted admission, impact
selection, all five CodeQL analyses and their rollup. Local focused coverage is
126 tests: 108 passed, 18 platform-dependent macOS skips; the final changed
qualification/dispatch subset passed (25 tests, 3 Linux skips). Source workflow
actionlint, generated workflow consistency and documentation links passed.
Direct generated-workflow lint retains the same 48 baseline undeclared-input
diagnostics, with zero introduced; it is not reported as a clean direct lint run.

Reproduce through `mcp-real-filesystem.yml` on the measured source with
`installed_focus=project-recovery`, `project_presets_only=true` and
`native_preparation_only=true`, all other modes off. Inspect all expected case
inventories and source-before/after equality, including actual refusals,
interruption/cleanup witnesses and both protected reads, rather than only the
workflow's green badge.

## Review follow-up — archive output boundary

[Review finding](https://github.com/SoupTeam/soup-wall/pull/362#discussion_r4477230643)
reproduced an ancestor-symlink escape on the initial delivery head: the lexical
export check could publish inside a preserved workspace. Native #611 did not
cover that boundary and is not evidence for the follow-up source.

The fix requires a canonical private parent, holds its no-follow descriptor and
verifies the publisher's descriptor against that identity and the current path
immediately before publication. Declared and resolved preserved roots are checked
again. Regressions cover all preserved root categories, an otherwise allowed
alias, a redirect before opening, moving the same destination inode into a
workspace during writing, private-directory replacement and successful create-new
publication. The installed qualifier adds an explicit zero-archive ancestor-alias
control. Fresh Linux/native results for this follow-up are pending.
