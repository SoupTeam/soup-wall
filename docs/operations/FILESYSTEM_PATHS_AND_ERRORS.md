# Filesystem paths and errors: user guide

This guide covers everyday work with the selected original filesystem server
(`sw-mcp/filesystem-readonly/1`): which names and paths work, what each error
means and how to continue. The workspace boundary, policy, classifier and
result inspection are unchanged.

## Names and paths

Soup Wall passes path and pattern arguments to the original server exactly as
sent. It does not trim, decode, case-fold or Unicode-normalize them, so two
files whose names differ only by NFC/NFD composition stay two files.

Works (read, list, info and search), qualified with the original server:

- spaces: `/workspace/dir with spaces/file name.txt`
- Cyrillic, CJK and emoji names
- a leading dash: `/workspace/-leading-dash.txt` or the relative `-leading-dash.txt`
- dot files and dot directories: `.hidden`, `.config/settings.json`
- shell-looking names: `rm -rf.txt`, `$(touch pwned).txt`, `; ls.txt`,
  `quote"name.txt`, `it's.txt`, `star*.txt`, `percent%2F.txt`. They are file
  names only: no shell runs and nothing is expanded.
- a colon inside an absolute path: `/workspace/a:b.txt` (new in this change;
  before it was refused although listings showed the file)
- a 255-byte name, nested paths, empty files and directories
- CRLF and UTF-8 content, returned byte for byte; `head` / `tail` line limits
- relative paths, resolved against `/workspace`

Refused before execution (the server never sees the call):

| Path | Error message (code `-32602`) |
| --- | --- |
| absolute path outside `/workspace`, for example `/etc/passwd`, `/workspaces` | `MCP path refused before execution: it is outside the selected workspace /workspace` |
| `..`, `.`, empty or `//` segment, trailing `/`, backslash, leading `~`, control character (such as a tab), a colon in a relative path (`C:/x`, `file:stream`), over 4096 bytes | `MCP path refused before execution: unsupported spelling (...)` |

Messages are fixed text and never repeat the refused argument. A file whose
name contains a backslash or a control character can be listed but not read;
rename it, or read it through a different tool outside this profile.

Symlinks: a link inside the workspace to another workspace file works. A link
to a target outside the workspace fails with the original server's error
(`Parent directory does not exist: /workspace`; the outside target does not
exist inside the sandbox). The server never opens the outside target, and
`list_directory_with_sizes` shows such a link as `0 B`.

## Search

`search_files` uses glob patterns that match the path relative to the search
root, not substrings. Use `**/*файл*` or `**/*file name*` to find a name
anywhere; `файл` alone matches only a top-level entry named exactly `файл`.
`excludePatterns` uses the same syntax, for example `["a/**"]`. Patterns are
literal data: `$(touch pwned)` or `rm -rf` are searched, not run.

## Errors and what to do

Every error below is correlated to its call. The session stays open and the
next useful call works; this is checked after each case.

| What you see | Meaning | What to do |
| --- | --- | --- |
| `ENOENT: no such file or directory, open '/workspace/…'` (tool error) | missing file or directory | check the name with `list_directory` or `search_files` |
| `EACCES: permission denied, open '…'` (tool error) | the file's own permissions forbid reading | fix the file mode outside Soup Wall; Soup Wall never adds permissions |
| `EISDIR` / `ENOTDIR` (tool error) | a directory was read as a file, or a file listed as a directory | use `list_directory` for directories, `read_text_file` for files |
| `-32602` path refusal (see above) | the path is outside the workspace or uses an unsupported spelling | use a path under `/workspace` without `..` |
| `-32602` `MCP arguments violate the selected input profile` | an argument does not match the tool schema: unknown field, wrong type, `head`/`tail` not a positive whole number up to 65536, both `head` and `tail`, invalid `sortBy` | fix the arguments |
| `-32601` `MCP tool is explicitly unsupported in the read-only profile` | a write or media tool (`write_file`, `edit_file`, `create_directory`, `move_file`, `read_media_file`) | not available in this read-only profile |
| `-32601` `MCP tool is not installed in this profile` | the tool does not exist on this server | use an advertised tool |
| `Soup Wall withheld MCP invocation (classifier_ask)` | the accepted classifier is unsure about the call (today: `directory_tree`) | use `list_directory` and `search_files` instead |
| `Soup Wall withheld MCP result (filesystem-profile-refuse-result-injection)` | the result looked like a prompt injection | the content is withheld; see the known false positives below |

Tool errors (`ENOENT`, `EACCES`, ...) are the original server's own text after
normal result inspection. The original call did run.

## Known false positives (reported, not changed here)

The accepted result injection heuristic (owned by SOU-109) refuses ordinary
results that contain:

- a 40-character or longer run of letters, digits, `+` or `/`, for example a
  content-addressed file name such as a 64-character SHA-256 hex name. Listing
  or searching a directory that contains such a name is refused; reading the
  file itself works.
- three or more `---`, `###` or code-fence markers, for example
  `read_multiple_files` with four or more files.
- the words ignore, disregard, override, bypass, forget, reveal, pretend or
  "act as".

`directory_tree` is refused by the accepted classifier (`classifier_ask`,
SOU-97). These boundaries are reported as they are; labels and expectations
were not changed to hide them.

## Qualification

`scripts/verify-filesystem-paths.py` builds an owned public workspace with
the names above, then runs:

1. the same pinned original server unprotected on an identical copy (direct
   control, paths rewritten to `/workspace` for comparison);
2. the enforcing path (daemon, accepted classifier and policy, collector,
   sandboxed original server) with a syscall witness that attributes each open
   to the server's own tasks;
3. genuine Claude Code 2.1.251 with the owned scripted provider: list a
   directory with spaces, read a Cyrillic file, a missing file, a traversal,
   a Cyrillic search, the colon file, then a useful read.

It requires exact equality with the direct control for every supported read,
list and search, a server open for each read, no dispatch for refusals, no
server open of `/etc/passwd`, an unchanged workspace and owned cleanup. It must
run as a non-root user (root ignores file permissions, so the `EACCES` case
would be wrong). Linux command (the filesystem CI job runs the same):

```bash
python3 -B scripts/verify-filesystem-paths.py --run \
  --agentfw "$PWD/target/debug/agentfw" \
  --node /path/to/node-v22.22.0/bin/node --npm /path/to/node-v22.22.0/bin/npm \
  --bwrap /path/to/bubblewrap-0.13.1/bwrap --strace /usr/bin/strace \
  --claude /path/to/claude-host/node_modules/@anthropic-ai/claude-code-linux-x64/claude \
  --expected-commit "$(git rev-parse HEAD)" --output /tmp/filesystem-paths
```

On WSL2 (Ubuntu 24.04), use a Linux-filesystem checkout (not `/mnt/c`), the
same pins as the filesystem CI job and a non-root user. The report's
`platform.kind` is `wsl2` only on a `microsoft-standard-WSL2` kernel.

Evidence: [Linux run, 2026-10-24](evidence/FILESYSTEM_PATHS_2026-10-24.md).
