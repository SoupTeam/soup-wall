# Preparation capacity

SOU-151 adds an optional capacity check to the existing Linux preparation commands.
Their normal behavior and verification rules remain unchanged.

## Read-only plan

```sh
python3 -B scripts/build-native-pilot-inputs.py \
  --capacity-plan --output /home/runner/pilot-agent
```

The same option is available in `prepare-native-pilot-prerequisites.py` and
`prepare-installed-pilot.py`. It runs no PATH tools, version probes, network,
compiler, daemon or server. It creates no directories, receipts or selection
markers. The JSON format is `sw-pilot-capacity/1`. A plan exits zero when it
prints its observation; inspect `status` and `admitted` before using it.

## What is counted

| Preparation | Additional generation budget | Other writable locations |
| --- | --- | --- |
| Native Git 2.51.2 and bubblewrap 0.13.1 (SOU-115) | 80 MiB archive caps + 1 GiB extraction caps + declared build allowance | Build logs and temporary files are inside the generation |
| Agent source build (SOU-119) | Existing 8 GiB Cargo generation limit + 512 MiB final-copy allowance | Isolated Cargo cache, target, logs and temporary files are inside the generation |
| Installed profiles (SOU-111) | 256 MiB archive caps + 2 GiB extraction caps + declared installation allowance | npm cache; npm temporary files in `/tmp`; pip temporary files in caller `TMPDIR`, when set |

Archive hashes and versions remain pinned in the preparers and profile metadata.
These sources do not specify exact compressed sizes. Caps are reported separately
from measured supplied-file sizes; neither validates an archive's hash. The Rust
limit is an existing safety cap, not an exact build-size prediction. A caller can
declare a different build allowance, which is labeled accordingly.

Use `--capacity-build-bytes N` for native builds and installed assets. Installed
assets also need `--capacity-cache-bytes N` and `--capacity-temp-bytes N`.
Allow for package installation, its scratch files, logs and metadata. These are
caller estimates, not new enforced storage quotas. A local wheelhouse is an
input; it is not populated by this preparation. No cache tree is walked.

A bounded read of `current.json` reports a selected generation candidate. It does
not establish validity, calculate retained-tree size or grant reuse credit.
Existing retained files already reduce observed free space. The unchanged
preparer performs full reuse verification. Capacity checking conservatively
requires the fresh budget even when that later verification chooses reuse.

## Guarded preparation

Add `--guard-capacity` to the normal, fully provisioned `--prepare` or `--build`
command. For example, after supplying the existing source-build prerequisites:

```sh
python3 -B scripts/build-native-pilot-inputs.py \
  --build --guard-capacity --output /home/runner/pilot-agent \
  --expected-commit "$REVIEWED_COMMIT"
```

The initial check runs before any preparation probes or children. It sums declared
budgets on the same filesystem, uses the lowest observed available balance and
adds the reserve once per filesystem. Separate filesystems cannot borrow space
from each other. `--capacity-reserve-bytes N` defaults to 1 GiB. No storage is
reserved. The check never deletes files or changes permissions to make space.

Linux directory descriptors reject symlink components and unsafe ownership or
writable ancestors. Existing ancestor device/inode identities are checked again
at phase boundaries. New owned descendants are accepted; replacements and mount
changes are refused. This is a point-in-time check, not a lock against all
concurrent path changes. Existing preparation validation and locking still apply.

Rechecks run before native downloads, extraction and builds; Cargo stages and
artifact copying; installed input preparation and each profile installer; and
selection publication. They require the reserve to remain available. They do not
charge the whole initial budget again after it has been partly spent, or predict
remaining work. A successful check cannot guarantee future capacity. Existing
ENOSPC, permission, interruption and atomic-publication handling remains in force.

## Refusal and unknown observations

`insufficient` covers `low_space` and `no_free_inodes`. `refused` covers
`invalid_allowance`, `output_required`, `unsafe_destination`, `destination_changed`, `destination_not_writable`
and `read_only_filesystem`. `unknown` covers `unknown_allowance`, `unknown_capacity`,
`unknown_quota`, `unsupported_platform` and `inaccessible_filesystem`.

On Linux x86-64, read-only `quotactl_fd(Q_GETINFO)` observations cover user, group
and project accounting on ext4/tmpfs. All three must explicitly report inactive
accounting. Active accounting, unavailable queries and other filesystem types
remain unknown; no quota headroom is guessed. See the
[Linux quota interface](https://man7.org/linux/man-pages/man2/quotactl.2.html).
There is no bypass flag. Use a supported environment with an observable capacity
boundary, or retain the existing unguarded workflow and its normal failure rules.

Guarded refusal exits 2. Initial refusal reports `work: not_started` and creates
no failure receipt. A later refusal reports `work: may_have_started`; unpublished
work may remain for the existing recovery path. Prior selected data is retained.

## Controls and local evidence

```sh
python3 -B -m unittest discover -s scripts/tests -p test_pilot_capacity.py
python3 -B scripts/test-pilot-capacity.py
```

The disposable fixture uses a private 16 MiB tmpfs and requests 32 MiB without
filling it. It checks zero admitted work and preservation of prior files. Some
unprivileged user namespaces cannot map root-owned ancestors; this is explicitly
not verified. Where isolated mount setup is authorized, run the driver as root
with `--private-mount --standard-uid UID`: setup occurs in a private mount
namespace, then observations run as that existing standard account. The mount
disappears when the namespace exits. No global mount or quota settings change.

Evidence includes source-file SHA-256 values, observation UID and environment.
A WSL fixture is not native Ubuntu acceptance. An unknown small-budget/quota
observation is retained as unknown, even when the low-space refusal control passes.

For hosted native qualification, dispatch `mcp-real-filesystem.yml` at the PR
branch with only `capacity_only=true`. This reuses the existing Ubuntu 24.04
preparation job. All three real preparers run with the opt-in guard, including
verified reuse and recovery after rejected inputs. Native build and asset
allowances are declared by the workflow; they are not measured size predictions.
The focused mode skips daemon and host scenarios and retains capacity plans,
private-mount observations, test logs and `qualification.json` in the existing
native preparation artifact. It does not change ordinary CI or admission rules.
