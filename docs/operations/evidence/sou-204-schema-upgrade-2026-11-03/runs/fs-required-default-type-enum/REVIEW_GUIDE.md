# MCP schema upgrade review guide

Generated offline by `agentfw mcp-schema-upgrade`. This analyzer accepts nothing. It does not approve or install a schema, grant runtime permission, modify an accepted profile or declaration, launch a server, retrieve references, perform network lookups or classify with a model. Every after-side identity that differs from the before side remains unaccepted until the operator completes the existing review, qualification and admission process.

## Exact inputs

- Before snapshot `upstream-tools-list.json` raw sha256 `d9df6889798a48dee9ad78b557dfd638eb618ec580adbd75923af0f64e48f954`, discovery identity `67425ee68375ed484c131989ea3adf3f07a91a04540c100fac0ce61f3ba09c37`.
- After snapshot `fs-required-default-type-enum.json` raw sha256 `622913bcc0b319c99aebfd1de0cffc0cbabb99dd831082a6b7d6ee5c7ae4f610`, discovery identity `5fa6482cf5242d4870964993249f2c56fa911cedeaa65d4899a066bb525182db`.
- Before identity document: `upstream-identity.json` raw sha256 `bd2b235f11e4e3ccd31467185b33b26751a626ed23e499ca72392b56dc9849ca` (verified).
- Current declarations: `filesystem-readonly-v1.registry.json` raw sha256 `63d12de143f0f13a7ef63ad0271697ad8d29fcac66b8ccfa7a68ba8f94431de7`.

Outcome `review_required` (unsupported_present); 14 findings; 5 new unaccepted tool identities; coverage complete: false.

## Required operator review before any deployment

1. Confirm the exact before/after snapshot files and identities above match the upstream artifacts under review. Do not rely on names, descriptions or annotations: they are untrusted.
2. Re-read the current operator-owned profile and semantic declarations. A declaration is bound to the before identity and does not cover any new exact identity.
3. Review every finding in `report.json`/`findings.csv`, especially `review_required` and `unsupported` items and the coverage gaps. Inert metadata findings still produce new, unaccepted identities.
4. Review the proposed examples in `review-pack.json`, including `unsupported_case` and `unconstructible` records. They are proposals, not labels, approvals or permission.
5. Author any new declaration through the existing review workflow (`agentfw mcp-profile` or the selected profile's installer review), then run the applicable existing qualification and admission process for the new exact identities. This analyzer performs none of these steps.
