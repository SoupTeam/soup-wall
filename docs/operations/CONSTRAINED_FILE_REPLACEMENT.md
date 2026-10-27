# Exact constrained Linux file replacement (SOU-159)

This opt-in native operation replaces one existing direct-child UTF-8 file in
an operator-owned output directory. It is not the original MCP server's
`write_file`, a general project editor, or an extension of create-only authority.
The original discovery child must receive no replacement invocation.

## Concurrency and metadata contract

The host operator, root, and other processes running as the broker's Unix user
are trusted. They must dedicate this directory to Soup output, provision it
before installation, and ensure there are no writable aliases, external writers,
inherited writable descriptors or shared mount namespaces exposing writable
aliases. A configuration assertion records this assumption; it does not discover
or isolate malicious same-user actors. Arbitrary user project directories and an
unprovable exclusive-writer boundary are unsupported. Linux DAC, directory mode
0700, file mode 0600, exact uid/gid, no ACL/xattrs, descriptor-relative no-follow
resolution, and local supported filesystems are independently checked.

Every cooperating Soup replacement uses a nonblocking exclusive `flock` on a
separately opened descriptor of the pinned directory inode. Linux create-only
writers take the conflicting shared lock: their existing parallel, atomic
no-clobber behavior is preserved, while every writer is excluded during a
replacement. Contention refuses rather than waiting or extending any deadline.
The replacement lock is acquired after admission, rechecks the old pinned object and its bounded
complete content, and remains held through publication and directory fsync.
`renameat` under this declared exclusion is the publication linearization point.
The preceding stat/hash is **not** a compare-and-swap against an uncooperative
writer. The directory and its trusted ancestry cannot be moved by an untrusted
actor during execution. Observable substitutions refuse; no race-safety claim
extends beyond the explicit trusted-operator boundary.

Only uid/gid and exact 0600 mode are preserved. The new inode and timestamps are
new. Hardlinks, symlinks, special files, ACLs, xattrs, unexpected owners/modes,
unsupported mounts and byte limits fail closed. Both old and new complete UTF-8
contents are bounded to 4096 bytes. No shell, Git, network or child mutation is
part of this operation.

The output directory supports at most 256 ordinary entries. Enumeration is
descriptor-relative and bounded. A retained `.soup-replace-*` entry blocks new
replacements with `replace_staging_recovery_required`; the broker never sweeps
such entries or assumes their ownership from a filename. An operator must
inspect an interrupted operation and reconcile the actual target before removing
their own confirmed staging state.

## Staging, approval and effects

The default preview only reads bounded metadata/content and returns identities
and digests, never raw contents. It does not grant write authority. Publication
requires a separately installed versioned execution policy, a destructive tool
baseline, and actual native authorization. Existing read and create profiles
remain unchanged. No selector/default, discovery description or installation
manifest grants replacement authority.

Exact arguments include the expected old object identity and old SHA-256. The
native binding includes these, new bytes/digest, root identity, executor,
registry, original call and session/policy context. Ask displays the exact target
and both digests without contents. Grants remain single-use with unchanged TTLs.
After staging, an additional one-use native publication gate verifies the live
session, original call, policy and unchanged invocation outcome. A failed gate
spends the call; cancellation drops staging. A later result refusal never undoes
an already committed replacement.

The publication receipt carries only the remaining original Call and complete
parent-lineage lifetime. The broker anchors it before the gate round trip and
checks the conservative monotonic deadline immediately before rename. The gate
cannot renew a Call, session, parent authority or liveness lease.

The private random stage name, when needed for atomic rename, is created only
after native authorization. Cleanup removes only a still-owned matching inode.
Interruption before rename leaves the old target intact. A process death in the
small named-stage window can leave a private stage requiring operator inspection;
there is no automatic retry or sweep of unknown entries. After rename, errors
report `committed=true`; missing completion after publication intent is
indeterminate. Recovery must inspect actual target identity/content first.

## Qualification

Current status: implementation in progress. Native Ubuntu stdio/daemon effect
witnesses and exact-source evidence are required before declaring qualification.
macOS development checks are not Linux execution evidence.

## Explicit installation and operator use

Provision a dedicated output directory as the broker user with mode 0700 and an
existing owned, single-link 0600 UTF-8 target. Do not select a working project,
shared directory or directory with unreviewed writers. The operator must establish
the sole-writer assumption above; a preview cannot prove it on their behalf.

First obtain a non-executing preview using separately prepared new content:

```sh
agentfw replace-file-preview --workspace /absolute/private-output \
  --target /absolute/private-output/result.txt --content-file /absolute/new.txt
```

It returns the root device/inode, complete old object identity and old/new
SHA-256 digests plus byte length. It prints no content and installs nothing.
Normal read/create profile compilation and installed pilot manifests do not
upgrade themselves to this capability.

Install a separately reviewed native registry tool with a custom name, action
class `destructive`, untrusted result provenance, no egress and one exact path
resource. Its profile has one `/path` selector without aliases, defaults,
optionality or missing-leaf support. Its explicit `execution` is:

```json
{
  "operation": "replace_file",
  "action": "write",
  "executor_profile": "sw-native/replace-file/linux-private-root-child/1",
  "max_content_bytes": 4096,
  "path_selector": "/path",
  "content_selector": "/content",
  "response_contract": "sw-native/response/text/1",
  "replacement": {
    "contract_version": "sw-native/replace-file/binding/1",
    "writer_exclusion": "operator-private-sole-writer+directory-flock/1",
    "root": {"device": 1, "inode": 2},
    "old_sha256_selector": "/old_sha256",
    "old_identity_selector": "/old_identity"
  }
}
```

Replace the illustrative root numbers with the actual preview. Pin the executor
revision to SHA-256 of that exact executor profile string and the classifier to
the installed reviewed classifier. The MCP schema must declare exactly the
selected fields, including all members of the old identity object. Nested custom
selectors are supported when disjoint and fully declared; undeclared branches
refuse. Original MCP names, arguments and host call IDs remain intact.

The call supplies `path`, new `content`, the exact preview's `old_sha256` and
`old_identity`. Only an exact known write classification can proceed to single-use
Ask, while the native destructive baseline and every existing hard Deny remain
authoritative. Explicitly review the applicable policy and its ordering; do not
remove a taint, secret, incomplete-history or other independent refusal to make a
replacement pass. Enable the existing native approval facility and hold timeout
without changing their existing bounds.

Use `agentfw native-approval list`, then `inspect ID`. Replacement inspection
shows the exact target, old identity and both content digests; its raw arguments
are redacted. Decide exactly once with `approve ID --binding DIGEST` or
`reject ID`. Private frozen arguments remain part of grant binding; redaction
changes display only. An approval, an admitted call and a publication permission
each carry their own single-use boundary. None proves the eventual effect or
successful result delivery. Check committed status and the actual file after
any interrupted or withheld completion.
