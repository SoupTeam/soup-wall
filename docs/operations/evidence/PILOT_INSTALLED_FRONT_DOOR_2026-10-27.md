# Installed guided pilot front door: first-use evidence (2026-10-27)

Guide: [PILOT_INSTALLED_FRONT_DOOR.md](../PILOT_INSTALLED_FRONT_DOOR.md).

## Environment and honest limits

| Item | Value |
| --- | --- |
| Platform | hosted Ubuntu 24.04.5 x86_64 container, kernel `6.18.44-fc-v153`; `platform.kind` = `linux` (not WSL2, not a physical host) |
| User | non-root `tester` |
| Base | main `ef6a2c4c` (successor of `3c9cfb08`) |
| Source | the code commit of this change, tree `544db21837b4e45da446b20e41a1e2fd9a0f11f8` (local commit `e61155d6`), clean before and after |
| Component | id `86b7f2ed3bba27d3003972e9996d42288f513720c4ff96294e454648deaa98d8`, archive `755a47caf1cab6f6...`, 47 files, built by `scripts/build-pilot-front-door.py` from that local commit (the id records the commit, so the same tree under another commit has another id) |
| Component interpreter | `/usr/bin/python3.12` CPython 3.12.3, `e50d468e8b0adfb05733f5b87b3cff34829c4a8c1aea50c865aa8bdfe4bb150f` |
| Installed Agent | `agentfw` `c38e34df...` built from this commit; `agentfw-git-sandbox` `f1c3b722...`, sandbox tests `2a0233ce...` |
| Claude Code 2.1.251 | `fd5f10ff0eb58daec04900466b143ea98aab50abf208a422bc008eaec13f61f7` |
| Node 22.22.0 | `1bec56ef...` (official binary, supplied as `--node`/`--npm`) |
| Git 2.51.2 / bubblewrap 0.13.1 | `6b6cfdbc...` / `f56b4f97...` |

This environment's network allowlist blocks `nodejs.org`, `www.kernel.org` and
`static.rust-lang.org`. The Agent executables were therefore built with the
locally installed Rust 1.97.0 (not the pinned 1.94.1), Git from the upstream
`v2.51.2` tag with the pinned flags, and Node supplied as the official binary.
The pinned Python runtime, npm and pip packages were downloaded by the accepted
preparation with `--allow-download`. The native CI job (`mcp-real-filesystem.yml`,
native-ubuntu-2404) runs the same qualification with that job's exact pinned
SOU-119 build and inputs; that run is the exact-pin evidence.

No paid provider, live model, real secret, private data or publication. The
provider is the existing owned scripted loopback stand-in.

## Result

`scripts/qualify-installed-front-door.py`: **passed, 17 cases, 0 skipped**, about
3 minutes. Every `agentfw pilot` call ran from a working directory outside the
checkout that contains hostile `scripts/pilot.py` and `source-identity.json`,
with a hostile `python3`/`python3.12`/`pilot.py` first on `PATH` and hostile
`PYTHONPATH` and `PYTHONSTARTUP` modules; none of them ran.

| Case | Outcome |
| --- | --- |
| component install | `install` into a clean private Agent home, then `verify` ok (component integrity only, no protection claim) |
| preview, zero effects | exit 0, source = the component's clean commit; only `agentfw` (once) and the recorded `python3.12` executed, nothing from the checkout or `PATH`, no selected program, no `AF_INET`/`AF_INET6` connect; prefix not created; projects and user configuration unchanged |
| prepare and reuse | `prepared-not-active`, then `reused` with only `--prefix`; projects unchanged |
| existing selection | a selection prepared by the checkout `scripts/pilot.py` at the same commit: installed `status` reports `configured-not-running` |
| status before run | `configured-not-running` |
| useful run | exit 0, `completed`, cleanup `owned_processes_stopped_audit_retained`, 22 s; `read_text_file README.md` and `git_show HEAD` returned the owned content; `write_file`, `git_reset` and a `Bash` send refused; no created file, receiver request or hostile hook marker; status during the run `observed-live`, the checkout-prepared prefix `configured-not-running` with one unrelated owned run; all 21 owned descendants stopped |
| status after run | `configured-not-running` |
| Ctrl-C | SIGINT to the foreground group: exit 1, `pilot_cancelled`, owned cleanup, all 19 owned descendants stopped; status during the run `observed-live`, afterwards `configured-not-running` |
| tampered helper (bytes, unlisted file, link) | each refused `front_door_component_changed` with the next action; no interpreter started |
| tampered interpreter | a private interpreter copy changed after install: `front_door_interpreter_changed`; no interpreter started |
| interrupted update | the installer was killed (SIGKILL) at its staging rename: `front_door_component_interrupted`, no interpreter started; `recover` cleared journal and staging, the reviewed component stayed selected, status `configured-not-running` |
| failed update | wrong `--sha256` and a damaged archive refused; the previous component stayed selected and verified |
| update and rollback | an update candidate (same tree, other commit) installed; status refused the old selection (`stale_source`, `unavailable`); `rollback` restored the reviewed component and `configured-not-running` |
| owned removal | `remove --component` (unselected), then `remove --all`: only `pilot-front-door/` removed; an unrelated Agent file and both prepared prefixes unchanged; `agentfw pilot` then refuses `front_door_component_not_installed` and starts nothing |

Project and repository snapshots, the user `~/.claude` settings,
`~/.claude.json` and an unrelated file were identical before and after. The
selection file was unchanged.

## Deterministic tests

- `cargo test -p agentfw --lib pilot_component` (4): canonical archive accepted;
  traversal, absolute, empty and `..` paths, duplicates, unlisted and missing
  members, changed bytes, symbolic and hard links, non-canonical and unknown or
  duplicate manifest keys, trailing data, another interpreter requirement, mixed
  source identity and file-also-directory refused; install, tamper (bytes, mode,
  unlisted file, link), interrupted install, recover, update, interpreter
  mismatch, rollback and owned removal on a private home.
- `scripts/tests/test_pilot_front_door_component.py` (6): the listed files cover
  every helper and data reference of the listed scripts (documented exceptions:
  Windows-only and standalone-demo paths); deterministic canonical archive;
  strict source identity; the extracted tree runs `help` and `preview` without a
  checkout and never builds the Agent.
- `scripts/tests/test_pilot_front_door.py` (25) unchanged and passing;
  `cargo clippy -p agentfw --lib --bins --tests -D warnings` (default and
  `--all-features`) and `check_docs` pass.

## Not claimed

No exact-pin local build, no WSL2 run, no other platform, no live-model
effectiveness, readiness certification or kit inclusion (SOU-87 owns the
offline candidate kit).
