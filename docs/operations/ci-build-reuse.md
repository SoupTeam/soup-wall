# Exact-source Linux qualification builds

The first shared tuple is Ubuntu 24.04, x86_64 GNU/Linux, Rust **1.99.1**,
Agent default features and the checked-in dev/test profiles. Its consumers are
`mcp-create-file / linux-create-file` and `mcp-create-file / linux-installed-edit`.
Ubuntu 22.04, the native pilot's Rust 1.94.1, other targets, features and profiles,
Windows and macOS remain separate builds.

## Build and custody

The generated component workflow has one explicit producer dependency for each
selected consumer. The planner selects that producer only when a compatible
consumer is selected; documentation-only plans allocate neither. Edit the source
workflows and regenerate with `python3 -B scripts/ci_components.py`. The producer
registration is declarative; admission scheduling and status writing are unchanged.

`ci-builds / agent-default-ubuntu2404` builds the Agent executable, library test
harness, `native_endpoint` harness and `replace_file` harness. It reuses the
accepted clean-checkout, exact package identity and bounded Cargo process-group
rules. Sources are fetched with `--locked`, compilation is offline in a fresh
private Cargo home/target, and the compiler is already installed at the exact
version. Ambient compiler flags, wrappers, target and profile overrides refuse.

The producer disables incremental compilation explicitly and records its build
environment and actual role profiles, including optimization, debug information,
debug assertions and overflow checks. Other active compilers, compiler/native
flags or Cargo configuration are not accepted implicitly.
Source-mode binaries retain their original target directories and environment;
their bytes are not claimed identical to a separate producer build. The common
tuple records incremental compilation as disabled, and both consumers must pass
their full original tests and witnesses using that exact produced payload.
The producer also records each ELF's actual dynamic library names and requires
the reviewed GNU loader. Unknown dynamic dependencies require a separate review;
the independently checked ABI set includes libc, loader, GCC/C++ runtime, math,
zlib and OpenSSL libraries.

The versioned manifest binds the clean commit, tree, tracked-file digest,
lockfile and toolchain file; compiler/tool hashes; target, profiles, features and
flags; exact hosted image version and selected system ABI libraries; source and
package working-directory paths; producer repository, workflow revision, run and
attempt; and four finite role/path/mode/size/SHA-256 records. Cargo's JSON artifact
records select package/target roles; a similarly named binary cannot substitute.

The producer uploads one raw archive using a pinned official action, with a
run/attempt-specific filename and three-day retention. Its successful `needs`
edge supplies the immutable artifact ID and archive/manifest hashes. Consumers
guard those outputs **before** downloading by ID. No name, pattern, latest-run
search, cross-run download token, extra token scope or secret is used. The
official download action is scoped to the current repository and workflow run,
and digest mismatch is an error.

Each consumer independently checks current source, toolchain, image, ABI and
fixture paths against that protected producer context. A finite parser accepts
only the manifest and four regular files: no extension records, links, traversal,
extra files, special modes or unbounded declared lengths. The initial limits are
256 KiB manifest, 320 MiB compressed archive, 320 MiB per file and 1152 MiB
across the four files. The initial producer refused a 1 GiB aggregate. The
explicit nonincremental tuple measured at `af531a2d` then produced 1,004,034,344
payload bytes (largest file 282,418,024) and 265,384,281 compressed bytes, with
10.473 seconds packing time. These observations set the current refusal limits;
they are size evidence, not a successful multi-consumer qualification claim.
Per-file size observations are retained before copying/packing.

Extraction never overwrites an existing generation or repairs a partial one.
The custody marker is published last. All bytes, modes, finite directory contents
and the marker are rechecked before each harness use; harness execution uses the
verified open descriptor and the original package working directory. Every
original filter executes and must have nonempty successful native tests. Clippy
and formatting remain actual current-source checks in both modes.

Installed-edit keeps the existing read-only source/root, private scratch,
network/PID namespaces, dropped privileges/capabilities, pinned genuine host and
independent runtime witnesses. The shared bundle and local expected-context file
remain outside writable scratch. A CI build archive is **not** runtime
attestation, a release, installation authority or deployment permission.

## Failure and partial reruns

A selected consumer starts even after producer failure and fails its explicit
producer guard. Missing, skipped, cancelled or incomplete producer evidence never
turns a required consumer green. Build/test logs and failed partial generations
are retained; diagnostic artifacts have 30-day retention. No failure triggers a
silent source-build fallback, wider permission, deadline increase or test skip.

A consumer-only rerun may use its retained successful dependency's artifact ID,
hashes and older producer attempt **in the same run**. If the producer actually
reruns, its dependency outputs select its new immutable ID, hashes and attempt.
A future attempt, inconsistent filename, missing ID, changed source, workflow
revision, image or ABI refuses. Do not manually substitute an old ID/hash set or
delete failed evidence to make a retry pass. A new source requires a new run.
Hosted labels can temporarily allocate different image versions during rollout.
The prototype actually refused a `20261025.353.1` consumer for its
`20261023.334.3` producer. Keep that refusal and compare the recorded identities;
a controlled retry must satisfy the original exact-image/ABI contract. The
validator records mismatch fields and the consumer's observed expected context
even on failure, without publishing a usable selection context.

## Focused comparison and evidence

The original `mcp-create-file.yml` manual workflow has explicit modes:

- `build_mode=source`, `comparison_only=true`: execute the two original consumers
  with fresh source targets, including their native tests, clippy and runtime
  witnesses. This path claims no build reuse.
- `build_mode=shared`: a finite local plan invokes the same generated workflow
  for exactly the producer and two selected consumers. It does not run a second
  API planner or the full component matrix. This development dispatch is not
  required PR qualification or admission evidence.

Compare both dispatches at the **same complete source SHA**. Retain run/job/step
timings (including producer, planning, transfer, verification, runtime and
artifact upload), all `sou166-*.json` records, producer manifest/result and the
original useful/safety reports. Count `compiler-artifact` records with
`fresh=false` as observed Cargo compilation outputs, with invocation and job
denominators; they are not a count of OS-level rustc processes. Clippy's own
compiler outputs are counted, including in shared mode. Report incomplete or
failed runs as such, never as zero-cost successful runs.

`python3 -B scripts/ci_build_inventory.py` inventories original declarations
without double-counting generated copies. Matrix declarations, Cargo invocation
declarations and actual compiled outputs are separate quantities. Job execution
seconds and mixed build/test/runtime step seconds are not pure compiler time,
billable minutes or dollar savings. No billing claim follows without actual
billing data. Final current-source CI, all CodeQL and admission remain required;
the shared final qualification and merge remain owned by the technical lead.

The installed-edit driver passes opaque pending IDs after `--`, with approval
options before the separator. URL-safe IDs can start with `-`; treating such an
ID as an option previously produced a CLI parser failure. The real installed
Agent preflight exercises inspect/approve/reject with synthetic hyphenated IDs
and a missing run, requiring domain refusal, zero authority and unchanged
inventory. The original 23 runtime cases and approval semantics remain intact.
