# Guided pilot entry point: first-use evidence (2026-10-25)

Guide: [PILOT_FRONT_DOOR.md](../PILOT_FRONT_DOOR.md).

## Environment and honest limits

| Item | Value |
| --- | --- |
| Platform | hosted Ubuntu 24.04.5 x86_64 container, kernel `6.18.44-fc-v153`; `platform.kind` = `linux` (not WSL2, not a physical host) |
| User | non-root `tester` |
| Base | main `6c19914b32ddf105397ba3c124c2a6682507d2f0` (descendant of `c1a6918`) |
| Source | implementation commit of this change, tree `5b76054a1056e4b30cbd44d12f1f08e7d1830153`, clean before and after |
| Claude Code 2.1.251 | `fd5f10ff0eb58daec04900466b143ea98aab50abf208a422bc008eaec13f61f7` (locked package) |
| Node 22.22.0 | `1bec56ef...` (official binary, supplied as `--node`/`--npm`) |
| bubblewrap 0.13.1 | `f56b4f97...` |
| Classifier Python | CPython 3.12 `e50d468e...`, explicit `--python` |

This environment's network allowlist blocks `nodejs.org`, `www.kernel.org` and
`static.rust-lang.org`. Therefore the local run supplied explicit inputs instead
of the front door's own native and Agent build steps:

- Agent executables were built from this source with the locally installed
  Rust 1.97.0, not the pinned 1.94.1 (`agentfw` `26172528...`,
  `agentfw-git-sandbox` `cb096d6b...`, sandbox tests `f19146df...`);
- Git 2.51.2 was built with the pinned flags from the upstream `v2.51.2` tag
  source, not the pinned kernel.org archive (`6b6cfdbc...`);
- Node was supplied as the official binary rather than the pinned archive.

The pinned Python 3.11.14 runtime, npm and pip packages were downloaded by the
accepted preparation with `--allow-download`. The native CI job
(`mcp-real-filesystem.yml`, native-ubuntu-2404) runs the same qualification
with that job's exact pinned inputs, and its Agent stage reuses the job's
SOU-119 build through the front door. That CI run is the exact-pin evidence;
this document does not replace it.

No paid provider, live model, real secret, private data or publication. The
provider is the existing owned scripted loopback stand-in: host qualification,
not live-model effectiveness or general product readiness.

## Result

`scripts/qualify-pilot-front-door.py`: **passed, 8 cases, 0 skipped**, about
1.5 minutes in total.

| Case | Outcome |
| --- | --- |
| preview, zero effects | exit 0, no missing items; prefix not created; only `python3` and `git` (source identity) executed, no selected program (`agentfw`, `claude`, `node`, `npm`, `bwrap`), no `AF_INET`/`AF_INET6` connect; projects and user Claude configuration unchanged |
| prepare and reuse | `prepare --apply` on owned existing roots (a source tree with hostile project Claude settings, and a supported Git repository): `prepared-not-active`; `prepare --apply --prefix` alone: `reused`, same selection; projects unchanged |
| status before run | `configured-not-running` |
| useful run | exit 0, `completed`, cleanup `owned_processes_stopped_audit_retained`, 21 s; `read_text_file README.md` returned the file; `git_show HEAD` returned the owned commit; `write_file`, `git_reset` and a `Bash` send were refused; no created file, no receiver request, no hostile hook marker; status during the run: `observed-live` with the run ID; all 41 owned descendants stopped |
| status after run | `configured-not-running` |
| stale record | refused `selection_not_current`, no selected program started, operator message printed |
| changed selected policy | refused `selected_artifact_changed`, no selected program started, operator message printed |
| Ctrl-C cancellation | SIGINT to the foreground group while the host was active: exit 1, `pilot_cancelled`, cleanup `owned_processes_stopped_audit_retained`; status during the run `observed-live`; all 36 owned descendants stopped; afterwards `configured-not-running` |

Project and repository snapshots, the user `~/.claude` settings,
`~/.claude.json` and an unrelated file were identical before and after. The
selection file was unchanged.

## Deterministic tests

`python3 -B -m unittest scripts/tests/test_pilot_front_door.py` (17 tests):
prefix rules (absolute, canonical, outside checkout, project and home), both or
neither root, record tampering (missing, other commit, not current, wrong mode,
duplicate keys, other format), dirty checkout, fixed argument list without a
shell, exact non-zero status, signal death reproduced, TERM forwarded while
SIGINT is left to the supervisor, unprepared run starts nothing, status never
reports live without an authenticated answer and never prints tokens, explicit
`--apply`, sanitized failures, and no toolchain auto-install. CI helper tests
and `check_docs` pass.

## Not claimed

No WSL2 run (the flow refuses WSL by design; see the guide). No exact-pin local
build. No live-model effectiveness, readiness certification or new approval
mechanism.
