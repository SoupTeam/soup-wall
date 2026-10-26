# Linux pilot: installed front door (`agentfw pilot`)

The guided pilot ([`scripts/pilot.py`](PILOT_FRONT_DOOR.md)) can run from the
installed Agent without a repository checkout. Its helper scripts are installed
once as a private, verified **front-door component**; `agentfw pilot` then starts
only those verified bytes with the exact interpreter recorded at install. The
preview, prepare, run and status semantics are unchanged: the installed command
runs the same accepted helpers.

Supported: native Ubuntu 24.04 x86_64, ordinary (non-root) user, CPython 3.11 to
3.13 named by an absolute path. Other platforms refuse.

## 1. Build the component (reviewed checkout)

```bash
repo="$HOME/soup-wall"
test -z "$(git -C "$repo" status --porcelain)"
python3 -B "$repo/scripts/build-pilot-front-door.py" --out "$HOME/pilot-front-door.tar"
```

The builder refuses a dirty checkout. It writes one deterministic archive: a
canonical manifest (schema `sw-pilot-front-door-component/1`) and the complete
transitive runtime files of `scripts/pilot.py` (helper scripts, classifiers,
profile pins), plus `source-identity.json` with the exact clean commit. It prints
`archive_sha256` and the component id (SHA-256 of the manifest).

## 2. Install (private, atomic)

```bash
agentfw pilot-component preview "$HOME/pilot-front-door.tar" --sha256 ARCHIVE_SHA256 --python /usr/bin/python3.12
agentfw pilot-component install "$HOME/pilot-front-door.tar" --sha256 ARCHIVE_SHA256 --python /usr/bin/python3.12
agentfw pilot-component verify
```

`preview` writes nothing. `install` checks the archive digest, every member
(regular files only, listed paths in order, no traversal, duplicates, links,
unlisted or extra data), every size and SHA-256, the canonical manifest, the
source identity and the interpreter (canonical path, CPython version, SHA-256).
It writes a staging directory, verifies it, then selects it with one atomic
rename. Files are mode 0400 and directories 0700 under
`~/.agentfw/pilot-front-door/` (or `--home DIR`).

## 3. Use

```bash
agentfw pilot preview --prefix "$HOME/soup-wall-pilot" --agentfw ... --git-launcher ... --sandbox-tests ... [inputs]
agentfw pilot prepare --apply --prefix "$HOME/soup-wall-pilot" [same inputs]
agentfw pilot run --prefix "$HOME/soup-wall-pilot" --prompt '...'
agentfw pilot status --prefix "$HOME/soup-wall-pilot"
```

Options are those of [the guided pilot](PILOT_FRONT_DOOR.md). Each call first
re-verifies the whole selected component (exact file set, modes, digests) and
the interpreter, then replaces itself with `python -I -B` running the verified
`scripts/pilot.py`; exit status and signals (Ctrl-C) are the helper's own.
Nothing is taken from `PATH`, the working directory, `PYTHONPATH` or a
download. The helpers report the component's recorded commit as their source,
so a selection prepared from that commit (by `agentfw pilot` or by
`scripts/pilot.py` in the reviewed checkout) is used unchanged.

The installed command never builds from source: supply `--agentfw`,
`--git-launcher` and `--sandbox-tests` built from the same commit (for example
with `scripts/build-native-pilot-inputs.py` in the checkout). Native Git and
bubblewrap preparation, Node, Claude Code and the selection step work as in the
checkout. A component install, `verify` or a file hash never reports
protection; only `agentfw pilot status` reports it, with the same meanings.

## 4. Update, roll back, recover, remove

| Command | Effect |
| --- | --- |
| `install` with a new archive | update; the previous component stays installed and selectable |
| `rollback` | select the previous component after verifying it |
| `recover` | clear an interrupted install (journal and staging); the selection is unchanged |
| `inspect` | show selected, previous and installed components |
| `remove --component ID` / `remove --all` | remove an unselected component / all component state |

A failed install (wrong digest, damaged archive, unsupported interpreter) leaves
the selected component unchanged. After an interruption every `agentfw pilot`
call refuses until `recover`. Removal touches only `pilot-front-door/`: prepared
selections, host settings and projects stay. A new component from another commit
does not accept selections prepared from the old commit (`stale_source`); prepare
again or roll back.

## Failures

| `reason` | Next step |
| --- | --- |
| `front_door_component_not_installed` | build and install the component (sections 1 and 2) |
| `front_door_component_interrupted` | `agentfw pilot-component recover`, then `verify` |
| `front_door_component_changed` | a file, mode or the file set changed: `rollback` or install the reviewed archive again |
| `front_door_interpreter_changed` | the recorded interpreter changed or moved: install again with `--python` |
| `unsupported_platform` | use native Ubuntu 24.04 x86_64 |

Each failure prints one JSON line with `reason`, `detail` and `action` and starts
no helper or interpreter. Errors of the guided steps are listed in
[the guided pilot](PILOT_FRONT_DOOR.md#errors).

Limits: the interpreter's own standard library is the operating system's; its
binary identity is pinned. A same-user process that changes component files
between verification and use is outside this boundary; the next call refuses.

Qualification: `scripts/qualify-installed-front-door.py` (native CI job,
`mcp-real-filesystem.yml`). Evidence:
[installed first use, 2026-10-27](evidence/PILOT_INSTALLED_FRONT_DOOR_2026-10-27.md).
