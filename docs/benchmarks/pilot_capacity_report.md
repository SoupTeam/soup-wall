# Preparation capacity controls

Task: [SOU-151](https://linear.app/soup-wall/issue/SOU-151/deliver-read-only-preparation-capacity-planning-and-early-low-space).
Base: `a5c6172b0a13232ae586ed5f02dfa6bd03ad4b98`.

| Local control | Result |
| --- | --- |
| Capacity and command boundaries on Linux | 22/22 passed |
| Native prerequisite regression controls | 8/8 passed |
| Source-build regression controls | 16/16 passed |
| Installed-preparation regression controls | 17/17 passed |
| Capacity controls on Windows | 12 passed; 10 Linux-specific skips |
| Private 16 MiB tmpfs; 32 MiB requested | Refused before selected child start |
| Prior selection and unrelated files in that fixture | Unchanged |

Linux tests ran from a Linux Git snapshot of the accepted base plus the changed
files. The mount fixture ran in WSL under standard UID 1000 after isolated root
mount setup. It did not fill host storage or alter global quota settings.
The source-file hashes and observations are retained in
[pilot_capacity_local.json](pilot_capacity_local.json).

The small-budget fixture returned `unknown_quota` and `admitted: false`.
This remains unknown; passing the low-space control does not establish usable
quota headroom. Sufficient-budget dispatch, destination replacement and phase
space loss are covered with mocks. No actual download or compiler build was
performed for this change. Native Ubuntu guarded preparation, real preparation
and reuse, and hosted CI acceptance remain pending.

The guard observes an initial declared budget and rechecks the reserve at phase
boundaries. It does not reserve space or guarantee that remaining work will fit.
Existing storage errors, verification and recovery remain authoritative.
See the [operator guide](../operations/pilot-capacity.md).
