# Complete JSON parsing in installed qualification

The [failed integrated CI job](https://github.com/SoupTeam/soup-wall/actions/runs/40693246516/job/122841997953)
on source `b30d2bd1e6d95d94f63e52b5b234ec15c60ff401` passed the existing
23 installed edit controls and all 14 diagnostic cases. The following Stop
suite then failed in `two-live-exact-stop`: one case passed, one failed and ten
remained incomplete. The retained artifact's primary failure was
`AttributeError: 'NoneType' object has no attribute 'get'`.

The shared qualification CLI helper parsed only the last stdout line. Installed
`status --json` returns a pretty-printed JSON document whose last line is `}`,
so the helper returned `None` before the Stop suite could grade the diagnosis.

Fix source `879fac7d96986a5b7e47b572859a24de4f7e22cd` parses one complete
bounded JSON document first and retains the existing final-line framing for
multi-record run output. A missing/non-object diagnostic response now fails
with a fixed typed reason. Production status formatting, Stop behavior,
authority, runtime deadlines and acceptance inventories are unchanged.

The regression exercises pretty status JSON through the shared CLI helper,
multi-record compatibility, empty/malformed output, the existing output cap
and typed rejection of a missing response. All **23** Python controls across
edit diagnosis, Stop and refresh passed, together with source formatting and
a fresh exact-source Agent build.

Actual installed follow-up qualification used the genuine pinned Claude and
owned scripted provider outside the checkout on Linux x86-64 / WSL2:

| Suite | Passed | Failed | Incomplete |
| --- | ---: | ---: | ---: |
| Stop | 12 | 0 | 0 |
| Plan refresh | 23 | 0 | 0 |

[ci-json-fix.json](ci-json-fix.json) retains the exact failed CI source/run/job
and artifact/report hashes, successful local case inventory, executable and
component identities, and original private report hashes. Its SHA-256 is
`1ac38250f53f8eaee14aa1edb62eff8ec8e39ef70a299141e4fdcb1be40bb746`.
The original failed artifact and all local reports remain retained privately;
raw logs, private state, credentials, prompts and authority are excluded from
this typed projection. The subsequent documentation commit is not attributed
another runtime execution. A new remote CI result must be assessed on its own
head; local follow-up results do not relabel the failed CI job.
