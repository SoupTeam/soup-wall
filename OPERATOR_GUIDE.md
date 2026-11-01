# Linux Pilot Runtime: Verified Advisory & License Inventory (SOU-130)

## Overview
This document provides an auditable inventory of the explicit Rust, Python, Node, and sandbox inputs for the selected Linux pilot runtime. It verifies specific pinned components (e.g., Git 2.51.2, bubblewrap 0.13.1) and checks their SHA256 digests exactly as defined in the accepted pilot receipt.

## Security Risk & Coverage Summary
- **Receipt Verification:** The script strictly enforces file hash matching. Missing files, missing package lockfiles, or mismatched SHA256 digests will explicitly block integration.
- **Advisory Status:** The environment is scanned using bounded executions of `osv-scanner` and `cargo audit`. See `runtime_inventory.json` for precise timestamps, explicit pass/fail scanner status, and component version ranges.
- **Scan Failures & Missing DBs:** If any underlying scanner tool exits with an unexpected error (e.g., `127 Not Found`), times out, or fails to find packages (e.g., OSV exit `128`), the check explicitly blocks integration (returns exit code `1`). Missing scanners or empty receipts do not generate a false "green" report.
- **Resolved Defects:** 
  * Pinned `ctutils` to `0.4.4` to resolve `RUSTSEC-2026-0385`.
  * Pinned `mcp` to `1.30.0` in the pilot receipt to resolve `CVE-2026-59951` (`GHSA-84m7-p3x7-pcfv`).
  * Updated `certifi` to `2026.10.19` to resolve `PYSEC-2026-4320`.

## License & Notice Inventory
All redistributed runtime components map to their respective licenses.
- **Coverage:** Validated against existing rules via `cargo deny`. All permitted licenses are explicitly logged. Missing coverage or non-passing compliance runs halt the inventory validation.

## Reproducibility
To regenerate the bounded check on the exact machine selection, you must supply the explicit pilot receipt/manifest:

```bash
python3 scripts/generate_inventory.py --receipt profiles/mcp/git-readonly-v1/upstream-identity.json