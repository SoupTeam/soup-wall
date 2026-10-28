# WSL qualification after profile onboarding integration

[installed-wsl2-cb74d94.zip](installed-wsl2-cb74d94.zip) preserves the actual WSL2 run on clean source
`cb74d9458ccb4c15ddd732d3276ea9664825a216`, after integrating main
`4ca347fdda5e9ac3e3ae4565cc186941a0951dd9` and its profile onboarding changes.
The Agent executables and library test binary were rebuilt from that checkout;
all 29 focused Linux MCP connection tests passed before the pilot.
Opening observation: `2026-10-21T20:35:01.039022+00:00`.

All **12/12** required cases passed. Both useful filesystem/Git workflows
completed with zero false interruptions. Sandbox calibration, untrusted-input
refusal, independent conversation, parallel cancellation, collector recovery,
daemon fresh-session recovery, invalid-input controls and final cleanup passed.
The foreign-port control preserved its independent listener. Owned processes
stopped and the private installation was removed without forced cleanup; the
unrelated witness survived until explicit teardown.

Opening and closing source identities matched: tree `fc90131bfd980fd9ba6375d5a18ddca0f0cb6e6d`,
tracked-file digest `30666a0e1c01c2ed3afcbffe00956d1a667ec51a62171c1c56a378d695551088`. The checkout stayed clean. Selected
runtime hashes and guest WSL/namespace-setting digests also matched.

The actual Ubuntu 24.04 WSL2 x86-64 environment ran as UID 1000 on ext4 /home,
using pinned original filesystem/Git MCP profiles and an owned scripted provider.
Guest memory was 7649 MiB. No temporary host setting was needed for this run.
Live-model efficacy and active cgroup resource-budget enforcement were not measured.

[cb74d94-manifest.json](cb74d94-manifest.json) records source, results and archive
identity. The ZIP includes the original report and 68 manifest-listed
sanitized runtime witnesses and logs. Archive size: **128294 bytes**;
SHA-256: `c4b649fec07d828ae42e1306a5c45eabd3d81e9eb526f1c9980abbf493ef67b0`. Its internal `archive-manifest.json` gives each
member's byte length and SHA-256.

```sh
sha256sum docs/operations/evidence/wsl/installed-wsl2-cb74d94.zip
unzip -p docs/operations/evidence/wsl/installed-wsl2-cb74d94.zip report.json
```

The publication adds only documentation/evidence after the tested runtime
commit. It does not claim execution on its later publication commit.
Main subsequently advanced to `e2fa19ce3162aea6a39c821882e369f64dc40e02` with
changes only to `docs/operations/CLASSIFIER_RUNTIME.md` and
`eval/evidence/sou81/README.md`. Integrating that documentation update does not
change the tested runtime, driver, selected profiles or build inputs.
[Earlier main-integration evidence](MAIN_REFRESH.md) and
[historical archives](QUALIFICATION.md) remain intact.
See [reproduction instructions](../../WSL_PILOT.md) for later runtime changes.
