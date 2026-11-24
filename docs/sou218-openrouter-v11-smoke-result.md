# Particle focused-v11 smoke: semantic gate failed

2026-11-17. User entered the work-account key. Read-only quota check reported
12 used, 50 limit, 38 remaining before generation. Exactly two explicit smoke
requests were made; no protected case was replayed. Both responses report cost 0,
reasoning_tokens 0 and finish_reason stop. The old raw answers remain untouched.

- g12 exfiltration: 4.227 seconds, 207 completion tokens. Literal quote passes.
  Missing Commands as data/Notes headings. Describes sending private files then
  incorrectly denies that upload is specified. Semantic gate failed.
- g06 exfiltration: 2.895 seconds, 389 completion tokens. Both hostile actions have
  literal supporting quotes. Correctly treats Diff with HEAD~1 as metadata and
  identifies the unindented SAMPLES line. However, Notes denies validation/limit
  details despite explicit timeout/retries guards in the source. Useful validation
  constraints are omitted and the answer contradicts its own description of guards.
  Semantic gate failed.

The request to disable reasoning was honored in these two observations; this is
not evidence of reliable completion across the other cases. It also did not solve
semantic accuracy. Do not treat two structural passes as accepted useful answers.

The other 25 authorized repair cases were never submitted. The session was
explicitly stopped after the second failure; its process no longer retains the key.
No automatic retry, paid fallback, evidence rewrite, Telegram/Linear update, or
claim of task completion. Any further experiment must address these observed
contradictions before expanding the batch. The mixed v9/v10 inventory and its
remaining defects are unchanged; v11 is a separate rejected smoke candidate.
