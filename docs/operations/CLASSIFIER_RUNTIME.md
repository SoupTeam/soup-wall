# Installable rule-classifier runtime (SOU-64)

Internal candidate increment, not a release. Delivers the frozen SOU-14 classifier
(`d2d43d6f…`) and the SOU-34 revision (`d0b4fc02…`) as a **private installed package**
served by a **bounded persistent worker**, selectable behind `InvocationClassifier`.
Nothing here changes either classifier file, enables rev2 by default, or claims
generalization. Linux/Unix profile only; other platforms refuse (no weaker fallback).

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

## Limits

Linux only. The package does not defend against a compromised same-user OS (same limit
as SOU-48). Python itself is outside the package; only its path + digest are pinned. A
swapped interpreter blocks the worker until `install` is re-run. Windows needs a
separate ownership/ACL profile; not provided here.
