# MCP schema upgrade review guide

Generated offline by `agentfw mcp-schema-upgrade`. This analyzer accepts nothing. It does not approve or install a schema, grant runtime permission, modify an accepted profile or declaration, launch a server, retrieve references, perform network lookups or classify with a model. Every after-side identity that differs from the before side remains unaccepted until the operator completes the existing review, qualification and admission process.

## Exact inputs

- Before snapshot `upstream-tools-list.json` raw sha256 `d9df6889798a48dee9ad78b557dfd638eb618ec580adbd75923af0f64e48f954`, discovery identity `67425ee68375ed484c131989ea3adf3f07a91a04540c100fac0ce61f3ba09c37`.
- After snapshot `fs-destination-controls.json` raw sha256 `eb0095c7b71d19694c2af0ad1d53013c107229f883abb68f7830a6d25d26b881`, discovery identity `2c86a83569d99bc9533f445f0bb9a2793c666107c531a6b849cacbbbabd232f4`.
- Before identity document: not supplied; the before snapshot was NOT verified.
- Current declarations: `fs-control-current.registry.json` raw sha256 `d87b555162420a4e8625682c912065e55c0a0c16fe87b381b3e003554d66e57f`.

Outcome `review_required` (unsupported_present); 11 findings; 2 new unaccepted tool identities; coverage complete: false.

## Required operator review before any deployment

1. Confirm the exact before/after snapshot files and identities above match the upstream artifacts under review. Do not rely on names, descriptions or annotations: they are untrusted.
2. Re-read the current operator-owned profile and semantic declarations. A declaration is bound to the before identity and does not cover any new exact identity.
3. Review every finding in `report.json`/`findings.csv`, especially `review_required` and `unsupported` items and the coverage gaps. Inert metadata findings still produce new, unaccepted identities.
4. Review the proposed examples in `review-pack.json`, including `unsupported_case` and `unconstructible` records. They are proposals, not labels, approvals or permission.
5. Author any new declaration through the existing review workflow (`agentfw mcp-profile` or the selected profile's installer review), then run the applicable existing qualification and admission process for the new exact identities. This analyzer performs none of these steps.
