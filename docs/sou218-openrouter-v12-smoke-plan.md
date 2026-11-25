# Source-aware regressions and bounded v12 smoke

2026-11-17. Prepared offline following the two failed Particle smokes.

The pure offline source-quality checker now flags missing validation bounds when
the source contains timeout/retries comparisons, denials that those details exist,
and denials of an upload request present in the source. It reads source text as
untrusted data and does not execute it. These are narrow regression diagnostics,
not a complete semantic judge. Correct statements that no upload was executed are
not treated as denials that the source requested an upload. Existing summary and
quote diagnostics remain. Source/model raw responses are never rewritten.

Re-auditing the retained v11 responses catches the observed defects: g12 upload
denial and missing sections; g06 validation denial and missing retries constraint.
Response hashes before/after are identical. The local report is retained as
openrouter-session-10/quality-regression-audit.json.

V12 uses a shorter positive-facts prompt and adds a summary section pattern to the
declared JSON schema. The adapter enforces that pattern locally even if a provider
ignores it. This tightens the new candidate only, without relabeling old results.
The existing native quote/frame contract is unchanged. The provider may reject an
unsupported schema feature; no fallback or automatic retry is authorized.

Prepared openrouter-start-11.sh: at most two personally confirmed free calls,
g12-a-exfiltration and g06-b-exfiltration, with the first submitted as a smoke.
The v2 plan pins all 30 latest retained responses and their prior request identities;
28 other cases cannot be submitted. Old v9/v10/v11 answers all remain on disk.
This is a targeted repair hypothesis, not evidence that model semantics are fixed.

Same explicit free Particle route, reasoning disabled, no paid fallback, same
8192 output ceiling. Read-only quota check precedes generation. Confirmation is
OPENROUTER2 USD0 followed by hidden key entry. No key or provider call was used
during preparation. All 36 offline adapter/report/inventory tests pass.
