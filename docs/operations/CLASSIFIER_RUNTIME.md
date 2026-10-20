# Installable rule-classifier runtime (SOU-64, SOU-81)

Internal candidate increment, not a release. Delivers the frozen SOU-14 classifier
(`d2d43d6f…`) and the SOU-34 revision (`d0b4fc02…`) as a **private installed package**
served by a **bounded persistent worker**, selectable behind `InvocationClassifier`.
Nothing here changes either classifier file, enables rev2 by default, or claims
generalization. Two profiles are supported, Linux/Unix (SOU-64) and native Windows x86_64
(SOU-81); every other platform refuses (no weaker fallback).

## Platform scope

| Profile | Demonstrated | Owner / access check | Process ownership |
| --- | --- | --- | --- |
| Linux/Unix | Install, verify, update, rollback, recover, remove; persistent worker; real collector | Owner = current user, mode bits, `O_NOFOLLOW` | Process kill and reap |
| Native Windows x86_64, local NTFS | The same lifecycle and worker, on a real Windows runner and developer machine (see [Windows profile](#windows-profile-sou-81)) | Owner = current user, protected owner-only DACL, no reparse points, handle identity | Job Object with kill-on-close |
| Windows on ARM, macOS, network or ReFS volumes, WSL file systems | Not demonstrated; the package commands refuse or are unsupported | n/a | n/a |

## Package

Deterministic ustar archive with exactly three regular files, in order:
`manifest.json`, `rule_baseline.py` (byte-identical, pinned SHA-256), `worker.py`
(framing only, `rule_baseline/runtime/worker.py`). The manifest (schema
`sw-classifier-package/1`) records classifier name, source path, worker protocol, the
interpreter profile (CPython >= 3.9, isolated) and size + SHA-256 per file. Package id =
SHA-256 of the manifest bytes. The parser refuses links, directories, extra/reordered
members, bad checksums, non-zero padding, trailing data, oversize members, a
non-canonical manifest, any classifier whose digest is not one of the two pinned values,
and any framing code other than the reviewed `worker.py` (its digest is compiled in:
a manifest rebuilt around different framing bytes proves only self-consistency and is
refused by `build`, `parse`, `preview`, `install` and every `verify`). `build` refuses a source file that does not match its pin (e.g. CRLF checkout);
`rule_baseline/runtime/**` is marked `eol=lf` in `.gitattributes`.

## Operator commands

```
agentfw classifier-package build --classifier frozen|rev2 --source <checkout> --out <file>
agentfw classifier-package preview <archive> --python /abs/python3     # writes nothing
agentfw classifier-package install <archive> --python /abs/python3
agentfw classifier-package verify | inspect | rollback | recover
agentfw classifier-package remove --package <id> | --all
```

Nothing is downloaded. `--python` must be an absolute path to a local CPython; its
canonical path and SHA-256 are recorded and re-checked on every worker start.
Selection: `AGENTFW_CLASSIFIER=rule-package` (no script path, no PATH lookup, no
fallback; conflicts with other classifier variables are refused). The classifier's
semantic revision at the `InvocationClassifier` seam is the **verified classifier source
digest** (what resource policies and real-server profiles pin as `classifier_sha256`),
so unchanged frozen bytes satisfy the same pins as the script adapter and a wrong pin is
still refused (`resource_classifier_revision_mismatch`). The package id is a separate
property (`PackagedClassifier::package_id`, `inspect`).

## Installed layout (`~/.agentfw/classifier/`, owner-only)

`packages/<id>/{manifest.json,rule_baseline.py,worker.py}` (files 0400, dirs 0700),
`current.json`, `previous.json`, transient `journal.json` and `staging-*`. Every read
checks regular file, owner = current user, no group/world bits, `O_NOFOLLOW`, size
limit, then digests. A symlinked or redirected profile, an extra file, a wrong mode or
an altered byte makes `verify` fail and the collector refuse to start the worker.

Install writes into a staging directory, renames it into `packages/`, verifies it, then
atomically replaces `current.json` (previous selection kept for `rollback`). A crash
leaves a `journal.json`; `install`/`verify` refuse until `recover` clears leftovers.
Selection never changes except in the final atomic rename. The interrupted-install gate
applies to runtime selection and every worker start (`Store::current`), not only to
`verify`; recovery keeps the last valid selection. `remove` only touches this
directory; unrelated files in `~/.agentfw` are untouched.

## Worker protocol `sw-classifier-worker/1`

One Python process (`-I -u`, empty environment, cwd `/`) per classifier instance. The
bootstrap re-reads and hash-checks the two files from the descriptor it opened, executes
the classifier unchanged under a non-`__main__` name, then runs the framing loop.

```
ready  : {"v","ready":true,"classifier_sha256"}
request: {"v","id","input_sha256","input_json"}     one line, <= 1 MiB input
reply  : {"v","id","input_sha256","result_json"}     one line, <= 64 KiB
```

The reply must echo the request id and the SHA-256 of the exact input bytes, and
`result_json` goes through the same parser as the single-shot adapter. Failure handling
(all fail closed, the process is killed and reaped, the next call starts a fresh
verified process): deadline 1.4 s (below the collector's 2 s), malformed/oversized/
truncated frame, unknown fields, id or digest mismatch, protocol mismatch, worker exit,
classifier technical error. A retired process owns its own channels, so a late frame can
never be read by a later call. Calls on one instance are serialized; each collector
session has its own worker. The worker retains nothing after a reply.

## Evidence

- `eval/evidence/sou64/cli-lifecycle.txt` – clean-directory lifecycle
  (`scripts/classifier-runtime-demo.sh`), repository path absent from the profile.
- `eval/evidence/sou64/latency.json` – worker vs single-shot timings (this container).
- `crates/agentfw/tests/classifier_runtime.rs` – package, tamper, recovery, parity
  (worker output byte-identical to single-shot for both revisions on 9 inputs
  including malformed JSON), crash, hang, restart, concurrent sessions.
- `tests/mcp_admission.rs::sou64_*` – the real collector and daemon classify with the
  installed package and match the script's classification, and the installed package
  satisfies a constrained create profile pinned to the classifier digest while a wrong pin
  is refused.
- The container fixture (`scripts/test-environment.py`, `deploy/Dockerfile.test.dockerignore`)
  carries `rule_baseline/runtime/worker.py` next to the classifier so the real-collector
  test runs unchanged in the Linux fixture baseline.

## Windows profile (SOU-81)

The command set, package format, pins, selection variable, worker protocol, deadlines and
the classifier's semantic revision are identical to the Unix profile. Only the way the
installed objects are protected and the way the worker process tree is owned differ.
Nothing is emulated from Unix: there are no Unix permission bits on Windows, and no
Unix-only code path was removed to make this build.

### Supported on Windows

- Windows x86_64 (`x86_64-pc-windows-msvc`), the installing account's own profile
  (`%USERPROFILE%\.agentfw\classifier\`) on a **local NTFS** volume.
- A local **CPython 3.9 or newer** named by an absolute path to `python.exe`. The path is
  canonicalised (a junction spelling resolves to the real file), recorded with its SHA-256
  and re-checked on every worker start. A Microsoft Store app-execution alias, a reparse
  point as the final file, and a non-CPython interpreter are refused.
- A profile path written with its real long names. A path that contains an 8.3 short name
  such as `C:\Users\RUNNER~1\...` is an alias spelling and is refused with
  `is not on a plain local NTFS path`; set `USERPROFILE` to the long spelling.
- The standard (non-administrator) account that installed the package. The same account
  must run the collector.

### Installed layout and protection

`%USERPROFILE%\.agentfw\classifier\` holds `packages\<id>\{manifest.json,rule_baseline.py,worker.py}`,
`current.json`, `previous.json`, transient `journal.json` and `staging-*`, as on Unix.
Every directory and file the runtime creates is created **already private**: owner is the
current user and the DACL is protected (no inherited entries) with exactly two allow
entries, the current user and `SYSTEM`. Files are created with `CREATE_NEW` and share mode
0 so no other process can hold or swap them during the write.

Every read checks, on the open handle: the object is the expected kind and is not a
reparse point; the owner; the protected DACL and its exact entry set; exactly one link;
not delete-pending; a bounded size; and the file identity (volume serial and 128-bit file
id) before and after the read. Ancestors of the profile are walked without following any
reparse point and revalidated. The result:

- a junction or symbolic link in place of the profile, `packages`, a package directory or a
  file is refused;
- an extra ACL entry, an unprotected (inheriting) DACL or another owner is refused;
- a hard link to an installed file is refused (link count is not 1);
- an edited, missing, extra or replaced file fails digest or identity checks;
- a changed interpreter record or binary blocks the worker until `install` is re-run.

`rollback` verifies the target package with the same checks before the pointer moves.
`recover` and `remove` (both profiles) refuse a classifier directory that is itself a
symbolic link, a junction or another reparse point, so a redirected profile cannot make
cleanup delete anything outside it; below the root they use the standard library's
recursive delete and do not re-verify a damaged profile first. `read_only` has no Windows meaning
and is not used; protection is the ACL.

### Atomic selection and recovery

An install is a staging directory, a rename into `packages\`, verification, and a final
atomic replacement of `current.json` (same-volume `rename` over the old file). A journal
is written first and removed last. If the process dies in between, `journal.json` and a
`staging-*` directory remain: `install`, `verify`, the runtime selection and **every
worker start** refuse until `classifier-package recover` clears the leftovers, and the
last valid selection is kept. A failed or invalid update never changes `current.json`.
A missing or replaced selected file, an invalid ACL, a changed interpreter or an
inconsistent selection (pointer naming a package that is not installed or does not verify)
makes startup refuse; there is no fallback to another classifier or to the script adapter.

### Worker on Windows

One persistent Python process per classifier instance, started with a structured argument
vector (never a shell string): `python.exe -I -u -c <bootstrap> <dir> <classifier sha> <worker sha>`
using the verified interpreter path. The environment is cleared except `SystemRoot`
(required by the interpreter); there is no `PATH`, `PYTHONPATH`, proxy or credential
variable, and the working directory is the Windows directory. Standard streams are binary
safe: the bootstrap reconfigures stdout to UTF-8 with `\n` newlines and opens files in
binary mode, so replies are byte-identical to the single-shot adapter (checked on 66
public cases for both revisions, including non-ASCII input).

The process is created suspended, assigned to a **Job Object** configured to kill on close,
and only then resumed (its primary thread only), so no descendant can exist outside the
job. A launcher that spawns a child interpreter is covered because the whole tree belongs
to the job. On crash, timeout, cancellation, unsolicited or late output, malformed or
oversized frames, or a failed call, the job is terminated and the call fails closed
(no authorization on a technical failure); the next call starts a fresh verified process.
A worker that does not leave its job within two seconds is counted as an unclean
retirement and can be inspected in tests. Every retired process owns its own pipes, so a
late frame cannot be read by a later call.

### Operator runbook (PowerShell)

```powershell
# 1. Build (the only step that reads a checkout; the checkout must have LF endings,
#    which .gitattributes enforces for the classifier files)
agentfw classifier-package build --classifier frozen --source C:\path\to\checkout --out frozen.tar

# 2. Preview writes nothing; then install with an absolute interpreter path
agentfw classifier-package preview frozen.tar --python C:\Python312\python.exe
agentfw classifier-package install frozen.tar --python C:\Python312\python.exe
agentfw classifier-package verify

# 3. Select it for the collector (no script path, no PATH lookup, no fallback)
$env:AGENTFW_CLASSIFIER = 'rule-package'

# Update, roll back, inspect
agentfw classifier-package install rev2.tar --python C:\Python312\python.exe
agentfw classifier-package rollback
agentfw classifier-package inspect

# Recover after an interrupted install (reported by install/verify/inspect)
agentfw classifier-package recover

# Removal touches only %USERPROFILE%\.agentfw\classifier
agentfw classifier-package remove --package <id>
agentfw classifier-package remove --all
```

If `verify` refuses, do not edit files by hand: run `inspect`, then `remove --all` and
install again from a freshly built archive.

### Windows evidence

- `crates/agentfw/tests/classifier_runtime_windows.rs` (19 positive tests that must all
  run on a native Windows runner; there is no skipped positive test) covers build
  determinism from a Windows checkout, the lifecycle, ACLs on every owned object, junction,
  foreign ACL, unprotected inheritance and hard-link attacks, edited, missing, replaced and
  extra files, changed interpreter, interrupted install, invalid update, worker/single-shot
  parity on 9 stress inputs and on the 66 public development/regression cases, reuse,
  crash and hang recovery, restart refusal after tampering, independent sessions and
  Job Object process-tree cleanup.
- `tests/mcp_admission.rs::sou64_*` run on Windows: the real collector classifies with the
  installed package; a missing package is a selection error with no fallback.
- `scripts/classifier-runtime-windows-acceptance.py` runs the production collector and
  daemon from a clean installed directory: a copied executable, a profile that contains
  only the installed package, a minimal environment (no repository sources, no Cargo, no
  `PYTHONPATH`, no provider access). It records the source commit and the executable,
  package, interpreter and classifier identities, then shows repeated calls, independent
  sessions with separate workers, denied calls with zero execution witnesses at the server
  and the receiver, continuation after denials, and recovery after a killed or hung worker.
- `.github/workflows/classifier-runtime-windows.yml` runs all of this on `windows-2022`.
  A missing prerequisite (not Windows x86_64, no CPython, not NTFS, a Store alias, a
  classifier file that does not match its pin) fails the job; the test-count checks fail it
  if any positive test is skipped or filtered.
- `eval/evidence/sou81/windows-latency.json` – cold and warm distributions and the cold-start
  deadline finding (below).

### Latency and the cold-start deadline

Measured on one Windows developer machine (debug build, Python 3.14.5, direct
`PackagedClassifier`, 15 cold starts, 300 warm calls, 20 single-shot calls): worker first
call p50 274 ms, p95 315 ms, max 329 ms (rev2 max 343 ms); warm call p50 0.8 ms, p95 1.1 ms,
max 2.0 ms; single-shot p50 213 ms, p95 230 ms, max 235 ms. The 1.4 s start deadline and the
1.4 s request deadline are **unchanged** and there are no retries: a cold start that exceeds
the deadline fails closed. The slowest observed cold start used about a quarter of the start
budget. The first launch of a freshly installed `python.exe` can be slower when antivirus
scans it; that is exactly the case where the deadline would be exceeded, and the correct
behaviour is a refused call, not a longer deadline. The CI run records the same distribution
on a hosted runner as an artifact.

#### Hosted-runner observations (`windows-2022`)

The hosted runner differs from the developer machine in three ways that matter here, and
none of them changed a deadline or added a retry:

- `TEMP` is spelled with an 8.3 short name (`RUNNER~1`). The store refuses alias
  spellings by design, so the tests create their profiles under the real long path.
- The runner account is the built-in local Administrator. `Get-Acl` prints that SID in
  SDDL as `LA`; the ACL test compares the owner in the form SDDL prints it.
- In one of the hosted runs the very first worker start of a test process did not answer
  within the 1.4 s start deadline (the test took about 2.1 s instead of about 0.8 s) and
  failed closed, as designed. The failure was not captured with its error text, so the
  cold OS file cache of a fresh runner is the likely cause, not a proven one. The tests now
  start the interpreter once before the first profile is created and report the worker
  error text if a call fails. Production code, the start and request deadlines and the
  no-retry rule are unchanged: on a machine where the first launch is that slow, the first
  call is refused and the next call starts a fresh verified worker.

## Limits

The package does not defend against a compromised same-user OS (same limit as SOU-48), and
on Windows not against a process running with the installing account's own token or with
administrator rights: both can change the ACLs or the interpreter. Python itself is outside
the package; only its path and digest are pinned. A swapped interpreter blocks the worker
until `install` is re-run. Windows scope is exactly: x86_64, local NTFS, the installing
standard account, a plain CPython path. Not provided or not demonstrated: Windows on ARM,
network shares, ReFS, redirected profiles, multi-user installs, Microsoft Store Python,
a service account different from the installer, and the SOU-71 installed-Agent self-test.
Latency numbers are from one machine and one run each; they are not a guarantee.
