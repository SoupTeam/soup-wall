# WSL qualification after the latest runtime integration

[installed-wsl2-97729f0.zip](installed-wsl2-97729f0.zip) preserves a fresh actual
WSL2 run on clean source `97729f0602516e6d6478e5498de444f4cce2546f`, after
integrating main `731d8c4c3cd921117cdb1934587d5aa97c80d6a7`. Both Agent
executables and the library test binary were rebuilt from that checkout.
Opening observation: `2026-10-21T19:56:26.123858+00:00`.

All **12/12** required cases passed. Both useful workflows completed with zero
false interruptions. Sandbox calibration, untrusted-input refusal, independent
conversation, parallel cancellation, collector recovery, daemon fresh-session
recovery, invalid-input controls and final cleanup passed. The foreign-port
control refused the bind while preserving its independent listener. All owned
processes stopped and the private installation was removed without forced
cleanup; the unrelated witness survived until explicit teardown.

The source tree was `5d2fcc7c9f92ded88604a4b8f209d97b3e9434d2`, tracked-file
digest `9bf86763cbb872b7e4412d518c7faeffbd92f343162464e194a2d7e30a6ede84`.
Opening and closing source identities, selected input hashes and guest
WSL/namespace-setting digests matched. The actual Ubuntu 24.04 WSL2 x86-64
environment ran as UID 1000 on ext4 /home storage, using the pinned original MCP
profiles and an owned scripted provider. Guest memory was 7649 MiB; this run
needed no temporary host setting. No live-model efficacy or active cgroup
resource-budget enforcement is claimed.

[97729f0-manifest.json](97729f0-manifest.json) records exact source, results and
archive identity. The ZIP includes the original report and 68 manifest-listed
sanitized logs/transcripts and runtime witnesses. SHA-256:
`278a39a4833b1f7b35e8d0886dc663ba00885ad33a50424419c5b03a5c24bcd4`;
size **128133 bytes**. Every member has its length and SHA-256 recorded in
`archive-manifest.json`.

```sh
sha256sum docs/operations/evidence/wsl/installed-wsl2-97729f0.zip
unzip -p docs/operations/evidence/wsl/installed-wsl2-97729f0.zip report.json
```

The publication adds only evidence and documentation after the tested commit;
it does not claim that the run executed on its later publication commit.
[The previous refreshed run](CURRENT_RUN.md) and [historical evidence](QUALIFICATION.md)
remain intact. See [reproduction instructions](../../WSL_PILOT.md) for later
runtime changes.
