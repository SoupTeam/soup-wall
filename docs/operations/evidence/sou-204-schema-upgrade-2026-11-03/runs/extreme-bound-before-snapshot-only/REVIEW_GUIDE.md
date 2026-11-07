# MCP schema upgrade review guide

**SNAPSHOT-ONLY MODE: no current operator declarations were supplied. Semantic review is UNAVAILABLE; action, resource and destination effects are unknown. This is not a semantic upgrade review.**

Generated offline by `agentfw mcp-schema-upgrade`. This analyzer accepts nothing. It does not approve or install a schema, grant runtime permission, modify an accepted profile or declaration, launch a server, retrieve references, perform network lookups or classify with a model. Every after-side identity that differs from the before side remains unaccepted until the operator completes the existing review, qualification and admission process.

## Exact inputs

- Before snapshot `git-extreme-bound-before.json` raw sha256 `fa0859610f6639f80fb943e92a56c70d029763480b52a0e3fc2b1887b0eb46b9`, discovery identity `3ff3e9692b6858ddcf0037dcae1e45a0f401b1d899b38d7b44b8ce23a3da3a6b`.
- After snapshot `upstream-tools-list.json` raw sha256 `8819c85d38867065dd429515e612f25300811a304e8f9235a46bed943e02ff9b`, discovery identity `0ebf2d0c147352d483aed19e6988749c8641a11258ac05a16e0a58639163489c`.
- Before identity document: not supplied; the before snapshot was NOT verified.
- Current declarations: not supplied; semantics are unknown.

Outcome `review_required` (review_required); 1 findings; 1 new unaccepted tool identities; coverage complete: false.

## Required operator review before any deployment

1. Confirm the exact before/after snapshot files and identities above match the upstream artifacts under review. Do not rely on names, descriptions or annotations: they are untrusted.
2. Re-read the current operator-owned profile and semantic declarations. A declaration is bound to the before identity and does not cover any new exact identity.
3. Review every finding in `report.json`/`findings.csv`, especially `review_required` and `unsupported` items and the coverage gaps. Inert metadata findings still produce new, unaccepted identities.
4. Review the proposed examples in `review-pack.json`, including `unsupported_case` and `unconstructible` records. They are proposals, not labels, approvals or permission.
5. Author any new declaration through the existing review workflow (`agentfw mcp-profile` or the selected profile's installer review), then run the applicable existing qualification and admission process for the new exact identities. This analyzer performs none of these steps.
