# MCP schema upgrade review guide

Generated offline by `agentfw mcp-schema-upgrade`. This analyzer accepts nothing. It does not approve or install a schema, grant runtime permission, modify an accepted profile or declaration, launch a server, retrieve references, perform network lookups or classify with a model. Every after-side identity that differs from the before side remains unaccepted until the operator completes the existing review, qualification and admission process.

## Exact inputs

- Before snapshot `discovery.json` raw sha256 `82a8621734d664b7ec948949eb6467e4dff8061c993994de138b3ab86aa55764`, discovery identity `605cbc4776cd1ab1e85ba3ce14ac34d1ec9010c0bada8c1f27bfe742bef0b41a`.
- After snapshot `discovery.json` raw sha256 `82a8621734d664b7ec948949eb6467e4dff8061c993994de138b3ab86aa55764`, discovery identity `605cbc4776cd1ab1e85ba3ce14ac34d1ec9010c0bada8c1f27bfe742bef0b41a`.
- Before identity document: not supplied; the before snapshot was NOT verified.
- Current declarations: `declarations.json` raw sha256 `de304c769a08e64faff87b202ff921eb7e6595c72ac27cf0bb5c8c94eae5e023`.

Outcome `no_drift` (byte_identical); 0 findings; 0 new unaccepted tool identities; coverage complete: false.

## Required operator review before any deployment

1. Confirm the exact before/after snapshot files and identities above match the upstream artifacts under review. Do not rely on names, descriptions or annotations: they are untrusted.
2. Re-read the current operator-owned profile and semantic declarations. A declaration is bound to the before identity and does not cover any new exact identity.
3. Review every finding in `report.json`/`findings.csv`, especially `review_required` and `unsupported` items and the coverage gaps. Inert metadata findings still produce new, unaccepted identities.
4. Review the proposed examples in `review-pack.json`, including `unsupported_case` and `unconstructible` records. They are proposals, not labels, approvals or permission.
5. Author any new declaration through the existing review workflow (`agentfw mcp-profile` or the selected profile's installer review), then run the applicable existing qualification and admission process for the new exact identities. This analyzer performs none of these steps.
