# WSL qualification after current-main integration

[installed-wsl2-6e19343.zip](installed-wsl2-6e19343.zip) records an actual
ordinary-user WSL2 run on clean source
`6e193431b1ecba706c882bc5ee10357c00dcd779`, including main
`d2155ec13e9c10e278ef3e72e1691f4a6613308f`. This integrates native literal
argument handling, verified pilot preparation and Windows onboarding. The
selection diagnostic also rejects non-object JSON without a traceback.

The Agent executables and library-test binary were rebuilt with Rust 1.94.1.
All 32 MCP connection tests and five native literal-argument tests passed.
The WSL, installed-pilot and preparation Python suites passed 42 tests; one
non-WSL-only refusal control was explicitly skipped in WSL and passed on Windows.

The full pilot passed **12/12** required cases and both useful filesystem/Git
workflows, with zero false interruptions. Sandbox calibration, untrusted-input
refusal, independent conversation, parallel cancellation, collector recovery,
daemon fresh-session recovery and invalid-input controls passed. The independent
foreign-port listener survived the expected bind refusal. All owned processes
stopped, the private installation was removed without forced cleanup, and the
unrelated witness survived until its explicit teardown.

Opening observation: `2026-10-22T09:36:27.069094+00:00`. Before/after source
identities matched: tree `b3f2454488a7d0dccde14dcfe5f725bccc4dab1b`, tracked-file
digest `53a4cd8dc8ba03f3ec0d9352b3db665df33b1fe440b915c8ddb720c14dd60b9e`.
Selected runtime hashes and WSL/namespace-setting digests also matched.
The environment was Ubuntu 24.04 WSL2 x86-64, UID 1000, ext4 under `/home`,
kernel `6.18.54.1-microsoft-standard-WSL2`, with Claude Code 2.1.251 and the owned
scripted provider. No host security setting was changed.

[6e19343-manifest.json](6e19343-manifest.json) binds the source and outcome to
the archive: 68 manifest-listed members, **128105 bytes**, SHA-256
`a9c2ed0b3286556d44a4866325da3b70ccdf67298dc3605324f6c37758cca80d`.
The internal `archive-manifest.json` records every retained member's size and
SHA-256 for independent verification.

The earlier attempt on `0b3416025af339f02783c322a71751c843aa10f5` stopped during
preparation because the downloaded Python distribution did not match its pinned
digest. [Its original failed report](python-download-failure-0b34160.zip) is
retained separately: two manifest-listed members, **3771 bytes**, SHA-256
`f7d75eed7e687b241ee011cd2e118e912ed9801e2fab8b66b3eca60be5ba3e09`.
It is not counted as a successful pilot. The later run used the same published
archive digest, acceptance denominators and deadlines without relaxation.

This publication adds only evidence and documentation after the tested source;
it does not claim execution on its later publication commit. Historical
[profile-onboarding qualification](ONBOARDING_REFRESH.md) and all earlier
archives remain intact. Scope remains the original profiles with a scripted
provider; live-model effectiveness and active cgroup budget enforcement are
not measured. See the [reproduction procedure](../../WSL_PILOT.md).
