# SOU-83 — Experimental original filesystem create-only profile

The explicit opt-in profile is `sw-mcp/filesystem-create-only/1`, reusing the
pinned ORIGINAL `@modelcontextprotocol/server-filesystem@2026.8.31` upstream
identity, discovery, schemas and output. The separately selected original
read-only profile remains unchanged. Only original `write_file` has additional
authority. Original `edit_file`, `move_file` and `create_directory` remain
unsupported.

A create request must carry **exactly** `path` and `content`.
`path` is `/workspace/<single-nonhidden-ASCII-leaf>`, content at most 4096
UTF-8 bytes, with no aliases, parents, extra fields, overwrites or append.
At most one create can be queued/running at once. The tool's native registry
entry must explicitly declare `side_effecting`, the exact versioned profile,
untrusted result provenance and no egress. Read-only tools keep read-only
authority. No classifier means fail closed; classifier Ask, Deny, unknown
semantics and unsafe/missing native receipts do **not** publish files.

## Actual create path (opt-in only)

1. Before admission, the collector pins the *actual* owned workspace directory
   inode; substitutions must fail instead of opening the replacement path.
2. The installed read-only server never receives `write_file`. After explicit
   classifier approval, native `call` Allow and a managed-policy lock, one
   fresh pinned ORIGINAL upstream server starts with a writable **private
   temporary staging root only**, read-only package/runtime/library mounts,
   namespace isolation, syscall/network restrictions and no inherited secrets.
3. The private server runs original initialize → pinned tools/list →
   original `write_file`. All framing, runtime and stderr are bounded.
   The sandbox owner and descendants must stop/reap before the stage can be
   inspected. A staged file must be the only entry, owner-private, regular,
   exactly as large as the authorized UTF-8 bytes, and SHA-256 identical.
4. The actual original untrusted result is sent to the authenticated native
   result gate. Denial/uncertainty/cancellation/EOF drop the staged output
   **without publication**. After native result Allow, an anonymous `O_TMPFILE`
   is filled from only those verified bytes under the original pinned workspace
   inode. The policy transition lock remains held until the `linkat` no-clobber
   publication finishes; concurrent targets and root replacement fail.
5. On successful durable publication the host receives the **original**
   upstream result. A post-commit sync failure is explicitly reported as
   potentially committed; the system never claims that late cancellation or
   withholding can undo `linkat`.

## Validation and limits

Linux profile/stage/unit/clippy tests are separate from the accepted read-only
and Git suite. The existing **required Linux original filesystem acceptance**
runs the ignored-in-ordinary-unit `actual_original_write_file_is_confined_to_unpublished_stage`
test using the same pinned installed ORIGINAL server and namespace owner as
SOU-62. A timeout, missing prerequisites, zero tests or a failed assertion
fails that acceptance. Its independent markers show original upstream output
while the *real* workspace and outside marker remain unchanged before release.
The race test rejects replacement of the workspace root after its initial pin.

The required acceptance also installs the actual create-only profile, loads its
full registry through the native daemon, and exercises original-create → read →
verify through the collector and atomic publisher. It checks overwrite,
traversal, extra-field and oversize refusals, spent host IDs, Creating-phase
cancellation, daemon loss before publication and useful read continuation.
The outside sentinel and unrelated workspace entries must remain unchanged;
the independent egress receiver must receive no requests. The final workspace
contains only the deliberately committed successful create.

These controls were independently reviewed on `97db581` (42/42 original
filesystem controls and 15/15 combined real-host controls). They describe that
source's evidence, not a qualification of a later merge candidate. Every new
candidate still needs its own required CI and reviewer acceptance.

Ask remains unsupported and fails closed. The daemon-loss witness is not a
claim of exhaustive worker/process-crash coverage, and read continuation is
not proof of a fresh successful write after every failure. Create-specific
policy-epoch transitions, exhaustive crash/egress injection and measured
performance overhead remain outside the demonstrated increment. Stage/unit
tests alone do not establish those properties.

## Private operator installation (new, opt-in)

Run `python3 scripts/install-sou83-filesystem-create-profile.py --destination /private/new-profile --workspace /private/owned-workspace --node /trusted/node --bwrap /trusted/bwrap` to preview; add `--run` to create a **new** 0700 installation. The script uses the accepted SOU-62 installer and exact pinned ORIGINAL package/runtime/notices, then writes owner-private `profile.json`, `registry.json` and a distinct `policy.yaml`. No existing read-only installation or Agent home is updated. For this opt-in profile, the exact selected original `write_file` is the sole supported side-effecting tool; all other original mutators remain unsupported. The new profile policy removes only the read-only install's general side-effecting deny; it keeps destructive/network/privilege/result-injection denial. Do not share this profile policy with any wider registry.

Binding the installed profile to an authenticated client/native daemon still requires operator review of the new registry/policy hashes and matching source; the installer does not activate any server automatically. Ask cannot be resumed by this profile.

The pinned ORIGINAL server may create an ordinary `0644` file via its default Node umask. This file remains inaccessible to other users under the private `0700` staging root. After child cleanup, the inspector validates a single matching owner-held regular inode, rejects special/execute bits, and normalizes its permissions to `0600` through the pinned descriptor before comparing its approved content. No untrusted file is released or published before that check.

### Create-specific fault evidence (required for release)

The protected real original-filesystem acceptance now exercises a cancelled post-native-Allow `Phase::Creating` call, an independently stopped native daemon during a second `Phase::Creating` call, and a reused already-spent host ID. Each negative case checks that no target was published and that a healthy same-session or restarted-session read still succeeds. Separately, `native_endpoint` now exercises the actual selected original `write_file` native call/result authority, refuses the second identical result (and a tampered replay), and confirms a new distinct call may proceed. These tests are not a replacement for the standard policy-epoch, egress and Ask qualification. Ask remains explicitly unsupported and fails closed.
