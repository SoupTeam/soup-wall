# Installed WSL2 qualification after the October 27 integration

The [fresh installed pilot](installed-wsl2-7bde826.zip) passed **12/12** required cases on clean source
`7bde8267cb37b7f642ed039edaa2a748a1f9a547`, tree
`07ab3b63541fccfb39b8dcbd939692dfa04683a9`. This source includes accepted main
`f4937110b58305645b7302acae99325d13354916`. Both useful filesystem/Git workflows
completed, with zero false interruptions. The run began at
`2026-10-28T09:52:43.727832+00:00`.

The actual environment was Ubuntu 24.04 on WSL2, x86-64, UID 1000, private ext4
paths under `/home`, kernel `6.18.54.1-microsoft-standard-WSL2`, Python 3.12.3,
and the pinned genuine Claude Code 2.1.251 host with an owned loopback scripted
provider. The Agent, Git sandbox launcher and Agent library-test image were
freshly built for the exact source. The selection and report retain their
SHA-256 identities; a previous candidate's runtime was not substituted.

Sandbox positives and independent witnesses passed before useful execution.
The untrusted-input refusal had no FIFO reader or repository reset effect;
an independent conversation remained useful. Parallel cancellation, collector
death/reclamation, surviving Git work, daemon death, old-authority rejection
and a fresh useful conversation passed. In-flight cancellation follows an
already executed call; it does not establish rollback. A calibrated independent
port listener survived the Agent's address-in-use refusal.

All owned processes stopped. The unrelated process/file witness survived up to
its explicit teardown, the private installation was removed, and no forced
cleanup was needed. Source identity, selected input hashes and fixed WSL/user
namespace setting digests matched before and after execution. Active cgroup
delegation remains unavailable and is not advertised. This is qualification of
the original default read-only profiles with the scripted provider; it does not
qualify extended profiles, live-model effectiveness or active resource budgets.

The earlier attempts remain [separate failed evidence](failed-wsl2-7bde826.zip):

| Attempt | Opening observation (UTC) | Result |
| --- | --- | --- |
| 1 | October 28, 09:39:00 | npm reported `Exit handler never called!` during filesystem preparation: 1 passed, 1 failed, 10 incomplete. |
| 2 | October 28, 09:42:15 | 11/12 passed; the missing-sandbox child exceeded the existing 30-second negative-control deadline. |
| 3 | October 28, 09:52:43 | 12/12 passed with the same source, selection, bounds and required inventory. |

An isolated npm installation completed with exit zero, and an isolated
missing-sandbox invocation explicitly refused with `selected_executable_unavailable`.
Neither isolated probe is counted as a complete pilot. The third full attempt
also passed all three original bad-input controls. No implementation, acceptance
threshold or timeout was relaxed to turn the attempts green.

The public evidence copies use a fixed regular-file allowlist. Private path
prefixes and known credential representations are redacted. Their internal
`archive-manifest.json` records public member sizes/hashes together with each
private original's size/hash, so sanitized publication bytes are not confused
with the original witness digests. Full original attempts remain retained
privately. Host configuration, raw process environments, credential/grant files, package
trees and binaries are excluded from the public archives.

The exact Agent and Git launcher images were additionally preserved as private
copies and rehashed against the successful selection. A subsequent library-test
build replaced the old test executable before a separate copy could be saved;
its original run-time digest and Cargo artifact record remain in the retained
selection/report. The later image is not attributed to this passing run.

This publication adds documentation and evidence after the tested source; it
does not claim execution on the later documentation commit. Historical
[October 22 evidence](OCT22_REFRESH.md) and previous failures remain intact.
See the [reproduction procedure](../../WSL_PILOT.md) for later runtime changes.

[7bde826-manifest.json](7bde826-manifest.json) binds source, runtime identities,
outcomes and both archives. The passing archive contains 74 manifest-listed
data members plus `archive-manifest.json`; the failed-attempt/control archive
contains 77 data members plus its manifest. Both archives passed CRC and every
member's published byte length/SHA-256 verification, plus a scan for known
credential representations and private workstation path prefixes.

| Archive | Bytes | SHA-256 |
| --- | ---: | --- |
| [Passing run](installed-wsl2-7bde826.zip) | 161049 | `f9f8a0b0c2dc9935e5d6f0f0e1fe3c964f6e17edd4d6ed85805cfbd603bec584` |
| [Failed attempts and isolated controls](failed-wsl2-7bde826.zip) | 145744 | `9d787380b3338b696b441cf495c2da6555e1b62a1a230e6da662774660ea87d3` |

Verify from the repository root:

```sh
sha256sum docs/operations/evidence/wsl/installed-wsl2-7bde826.zip
sha256sum docs/operations/evidence/wsl/failed-wsl2-7bde826.zip
unzip -p docs/operations/evidence/wsl/installed-wsl2-7bde826.zip report.json
```
