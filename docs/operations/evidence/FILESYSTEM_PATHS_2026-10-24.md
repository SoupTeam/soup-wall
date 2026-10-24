# Filesystem names and errors: Linux evidence (2026-10-24)

Guide: [FILESYSTEM_PATHS_AND_ERRORS.md](../FILESYSTEM_PATHS_AND_ERRORS.md).

## Environment

| Item | Value |
| --- | --- |
| Platform | hosted Linux x86-64 container, kernel `6.18.44-fc-v153`; `platform.kind` = `linux` (not WSL2) |
| User | non-root `tester` |
| Base | main `09c505eacaffcd20804472cdd3c0095dd91a70ee` (descendant of `cdd9d36`) |
| Source | implementation commit of this change, tree `72a47bf928e5125e27af8bf1dc6df145b59f112d` (local commit `8081cd0` before transfer), clean before and after |
| agentfw (debug) | `7bf620822db26d6b585a221cf1f9b603384139526461de671c58fb68c866624d` |
| Node 22.22.0 / bubblewrap 0.13.1 | `1bec56ef...` / `f56b4f97...` |
| Claude Code 2.1.251 | `fd5f10ff0eb58daec04900466b143ea98aab50abf208a422bc008eaec13f61f7` |
| Registry / policy / package lock | `63d12de1...` / `55b0f70c...` / `98afd2e0...` (accepted installer and shipped policy, unchanged) |

No paid provider, live model, real secret, private data or publication. The
provider is the existing owned scripted Messages stand-in; this is host
qualification, not live-model effectiveness.

## Reproduction on main `09c505e`

Exploratory run with the same server, workspace kinds and an enforcing daemon,
non-root, previous build:

| Case | Main | After this change |
| --- | --- | --- |
| spaces, Cyrillic, CJK, emoji, leading dash, dot names, nested, empty, CRLF, quotes, shell-looking names, `%`, `*`, `?` | read exactly | unchanged |
| `/workspace/a:b.txt` (listed by `list_directory` and `search_files`) | refused, `-32602` "MCP arguments violate the selected input profile" | read exactly |
| `/etc/passwd`, `/workspace/../etc/passwd`, `head: -1`, unknown field | all the same `-32602` message | outside, spelling and schema messages differ |
| missing file, `EACCES`, `EISDIR`, `ENOTDIR` | correlated tool errors, session alive | unchanged |
| write and media tools, unknown tool | `-32601`, session alive | unchanged |
| outside symlink | server error, no outside open | unchanged |
| `directory_tree` | `classifier_ask` | unchanged (SOU-97) |

No session ended in any case on main. The defects were the unreadable colon
name and the indistinct refusal messages.

## Result

`scripts/verify-filesystem-paths.py`: **passed, 70 cases, 0 skipped**.

| Group | Cases | Witnessed |
| --- | --- | --- |
| exact list / read / search / allowed directories | 42 | equal to the unprotected direct control; read bytes equal the files; host bytes equal the daemon `content_sha256`; a server open per read |
| file info | 1 | correct size, same as direct control |
| tool errors `ENOENT` x2, `EACCES`, `EISDIR`, `ENOTDIR` | 5 | same text as direct control, correlated, released after inspection |
| outside symlink | 1 | refused by the server; direct control shows the escape (`3.30 KB` size of the host file), sandbox shows `0 B` |
| outside path | 3 | `-32602` outside message, not admitted, not dispatched |
| unsupported spelling | 6 | `-32602` spelling message, not admitted, not dispatched |
| schema | 6 | `-32602` schema message, not admitted, not dispatched |
| unsupported / not installed tool | 3 | `-32601`, not dispatched |
| classifier Ask (`directory_tree`) | 1 | refused before dispatch (SOU-97 boundary) |
| result policy refusal (injection file) | 1 | withheld, rule `filesystem-profile-refuse-result-injection` |
| false positive (64-character hex name) | 1 | listing withheld by the same rule (`injection` low); direct control lists it; the file itself reads exactly (SOU-109 boundary) |

All 27 error and refusal cases are followed by a useful read of `notes.txt`
in the same session. The original server never opened `/etc/passwd` (0
attributed opens; the host-side classifier interpreter's own opens are
excluded by task attribution). Workspace metadata and content unchanged; no
file named `pwned` exists. Collector, original server descendants, direct
control and daemon reaped; `cleanup_verified` true.

Genuine Claude Code 2.1.251 (8 provider requests): list `dir with spaces`,
read the Cyrillic file, a missing file (`ENOENT`, `is_error`), a traversal
(spelling refusal, no argument echo), a Cyrillic glob search, the colon file,
then a useful read. All exact; workspace unchanged; host descendants stopped.

## Deterministic tests

- `cargo test -p agentfw --lib`: 661 passed, including typed path refusals
  and accepted Linux names (`server_profile`) and fixed refusal messages
  without dispatch or echo, with continuation (`real_server::fault_tests`).
- `cargo clippy -p agentfw --all-targets -- -D warnings`, `cargo fmt --check`,
  `check_docs` 0 errors.
- `python3 -B -m unittest scripts/tests/test_filesystem_paths.py`: witness
  spelling and attribution, fixtures, grading.

## Not claimed

No WSL2 run in this environment (command in the guide). No Git-server path
cases, live-model effectiveness, write tools or changes to the classifier,
detectors or policy.
