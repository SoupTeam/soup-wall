# Internal pilot evidence dossier

Status: **NOT_READY**

Candidate: `adefce2a658272e5f23c9c72ef791befe0285648`
Tree: `f23e59fb3bd80e7b0666ef4a9cbdcefeb3267519`

This is evidence reconciliation, not product approval or live-model effectiveness.

| Item | State | Owner | Observations (actual source and denominator) |
| --- | --- | --- | --- |
| install-start | incomplete | SOU-116 | sou116-launch: pass 3/3 at 78e5658128f6fac242a29a222afac5f1d6703164 |
| useful-workflows | fail | SOU-106 | sou106-final: fail 10/12 at ce4f76d823f9f1b5a7ea1dec97a8ff260a5f94dc |
| refusal-zero-effects | incomplete | SOU-106 | sou106-final: pass 8/8 at ce4f76d823f9f1b5a7ea1dec97a8ff260a5f94dc |
| ask | incomplete | SOU-112 | sou112-ask: pass 14/14 at 8e80084e5a682369e4225d6b1bf782244e8ecd99 |
| daemon-loss | incomplete | SOU-116 | sou116-launch: pass 1/1 at 78e5658128f6fac242a29a222afac5f1d6703164 |
| cancellation-cleanup | incomplete | SOU-116 | sou116-launch: pass 2/2 at 78e5658128f6fac242a29a222afac5f1d6703164 |
| linux-platform | incomplete | SOU-115 | No qualified observation |
| wsl-platform | incomplete | TL/platform-owner | No qualified observation |

## Blockers and root-cause references

- `sou106-final` (selected file `docs/operations/evidence/sou106/measured-report.json`): historical_source, expected_environment_unbound, environment_absent_or_mismatched
- `sou106-attempt1` (selected file `docs/operations/evidence/sou106/attempt-1.json`): historical_attempt_not_candidate_evidence
- `sou106-attempt2` (selected file `docs/operations/evidence/sou106/attempt-2.json`): historical_attempt_not_candidate_evidence
- `sou112-ask` (selected file `docs/operations/evidence/sou-112/linux-qualification.json`): historical_source, missing_identity:policy, identity_mismatch:filesystem_profile, identity_mismatch:git_profile, missing_identity:filesystem_classifier, missing_identity:git_classifier, identity_mismatch:agentfw, identity_mismatch:git, identity_mismatch:bwrap, expected_environment_unbound, environment_absent_or_mismatched
- `sou116-launch` (selected file `docs/operations/evidence/sou-116/linux-prepared-run.json`): historical_source, missing_identity:filesystem_profile, missing_identity:git_profile, missing_identity:filesystem_registry, missing_identity:git_registry, identity_mismatch:agentfw, identity_mismatch:git, identity_mismatch:bwrap, expected_environment_unbound, environment_absent_or_mismatched
- install-start: environment_absent_or_mismatched, expected_environment_unbound, historical_source, identity_mismatch:agentfw, identity_mismatch:bwrap, identity_mismatch:git, missing_identity:filesystem_profile, missing_identity:filesystem_registry, missing_identity:git_profile, missing_identity:git_registry
- useful-workflows: environment_absent_or_mismatched, expected_environment_unbound, historical_source
- refusal-zero-effects: environment_absent_or_mismatched, expected_environment_unbound, historical_source
- ask: environment_absent_or_mismatched, expected_environment_unbound, historical_source, identity_mismatch:agentfw, identity_mismatch:bwrap, identity_mismatch:filesystem_profile, identity_mismatch:git, identity_mismatch:git_profile, missing_identity:filesystem_classifier, missing_identity:git_classifier, missing_identity:policy
- daemon-loss: environment_absent_or_mismatched, expected_environment_unbound, historical_source, identity_mismatch:agentfw, identity_mismatch:bwrap, identity_mismatch:git, missing_identity:filesystem_profile, missing_identity:filesystem_registry, missing_identity:git_profile, missing_identity:git_registry
- cancellation-cleanup: environment_absent_or_mismatched, expected_environment_unbound, historical_source, identity_mismatch:agentfw, identity_mismatch:bwrap, identity_mismatch:git, missing_identity:filesystem_profile, missing_identity:filesystem_registry, missing_identity:git_profile, missing_identity:git_registry
- linux-platform: no_exact_bound_linux_runtime_evidence
- wsl-platform: wsl_not_qualified_by_selected_support_index
- sou116-launch / install-start: `{"cases": ["plan", "useful-refusal", "default"]}`
- sou106-final / useful-workflows: `{"failed_cases": ["search-read-status", "search-exclusion"], "false_interruptions": 2}`
- sou106-final / refusal-zero-effects: `{"denied_execution_count": 9, "forbidden_effects": 0, "forbidden_result_delivery_count": 0}`
- sou112-ask / ask: `{"physical_human_presence_proven": false}`
- sou116-launch / daemon-loss: `{"cases": ["daemon-loss"]}`
- sou116-launch / cancellation-cleanup: `{"cases": ["cancel", "timeout"]}`

Historical failed attempts remain selected records; later evidence never overwrites them.
A passing reporter test is not a passing pilot. Missing environment/identity evidence stays incomplete.
Linux evidence does not qualify WSL, Windows or macOS. No paid model or release claim.
