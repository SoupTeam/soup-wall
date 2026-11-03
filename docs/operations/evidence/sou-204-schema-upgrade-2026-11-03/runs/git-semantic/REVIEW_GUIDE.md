# MCP schema upgrade review guide

Generated offline by `agentfw mcp-schema-upgrade`. This analyzer accepts nothing. It does not approve or install a schema, grant runtime permission, modify an accepted profile or declaration, launch a server, retrieve references, perform network lookups or classify with a model. Every after-side identity that differs from the before side remains unaccepted until the operator completes the existing review, qualification and admission process.

## Exact inputs

- Before snapshot `upstream-tools-list.json` raw sha256 `8819c85d38867065dd429515e612f25300811a304e8f9235a46bed943e02ff9b`, discovery identity `0ebf2d0c147352d483aed19e6988749c8641a11258ac05a16e0a58639163489c`.
- After snapshot `git-semantic.json` raw sha256 `9c27adff206eaf6f58f90483c2ef541997976d63bf2daa635b53285ac49c188a`, discovery identity `ce57def326e848c641144288621216f7269931b4c633fd569dcb8a50c4854dd6`.
- Before identity document: `upstream-identity.json` raw sha256 `90fbf2f84db1fee38145914adaf851c35d9b8b3735dc4e78caf7820c507e09e4` (verified).
- Current declarations: `git-readonly-v1.registry.json` raw sha256 `5e22a49a07329335f42f95a48a969c869b5ba84fffcc2739f21a3a70c6437385`.

Outcome `review_required` (unsupported_present); 17 findings; 7 new unaccepted tool identities; coverage complete: false.

## Required operator review before any deployment

1. Confirm the exact before/after snapshot files and identities above match the upstream artifacts under review. Do not rely on names, descriptions or annotations: they are untrusted.
2. Re-read the current operator-owned profile and semantic declarations. A declaration is bound to the before identity and does not cover any new exact identity.
3. Review every finding in `report.json`/`findings.csv`, especially `review_required` and `unsupported` items and the coverage gaps. Inert metadata findings still produce new, unaccepted identities.
4. Review the proposed examples in `review-pack.json`, including `unsupported_case` and `unconstructible` records. They are proposals, not labels, approvals or permission.
5. Author any new declaration through the existing review workflow (`agentfw mcp-profile` or the selected profile's installer review), then run the applicable existing qualification and admission process for the new exact identities. This analyzer performs none of these steps.
