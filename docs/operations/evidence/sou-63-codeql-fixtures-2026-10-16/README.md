# SOU-63 CodeQL test nonce correction

The CodeQL gate on `ea1f6eb` reported 59 hard-coded nonce findings, all in child authority test fixtures or callers passing deterministic labels into the scoped nonce helper. The original annotations are retained in [original-annotations.json](original-annotations.json).

Fixtures now obtain random nonce material from the production token generator. Scoped fixtures append random suffixes to the existing daemon and parent-binding prefixes. Replay witnesses keep reusing the same signed grant; framing witnesses keep the same generated nonce across differing claim layouts, so randomness cannot make an invalid signing implementation pass. Tamper and expiry assertions remain intact. Production cryptographic code and repository scanning rules are unchanged.

Local isolated checks: 312 agentfw library tests and 109 native endpoint tests passed; clippy with `-D warnings` and formatting passed. GitHub CodeQL must independently confirm the correction on the new head.
