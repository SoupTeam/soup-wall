# Internal pilot evidence dossier

Status: **NOT_READY**

Candidate: `c1a6918a05ae22cd89be6d98bfb13bbf9456a781`
Tree: `09d67510e1bac3e3b871cbaf7369e646e9b62ca4`

This is evidence reconciliation, not product approval or live-model effectiveness.

| Item | State | Owner | Observations (actual source and denominator) |
| --- | --- | --- | --- |
| install-start | incomplete | SOU-116 | No qualified observation |
| useful-workflows | fail | SOU-106 | sou106-final: fail 10/12 at ce4f76d823f9f1b5a7ea1dec97a8ff260a5f94dc |
| refusal-zero-effects | incomplete | SOU-106 | sou106-final: pass 8/8 at ce4f76d823f9f1b5a7ea1dec97a8ff260a5f94dc |
| ask | incomplete | SOU-112 | No qualified observation |
| daemon-loss | incomplete | SOU-116 | No qualified observation |
| cancellation-cleanup | incomplete | SOU-116 | No qualified observation |
| linux-platform | incomplete | SOU-115 | No qualified observation |
| wsl-platform | incomplete | TL/platform-owner | No qualified observation |

## Blockers and root-cause references

- `sou106-final` (selected file `docs/operations/evidence/sou106/measured-report.json`): historical_source, expected_environment_unbound, environment_absent_or_mismatched
- `sou106-attempt1` (selected file `docs/operations/evidence/sou106/attempt-1.json`): historical_attempt_not_candidate_evidence
- `sou106-attempt2` (selected file `docs/operations/evidence/sou106/attempt-2.json`): historical_attempt_not_candidate_evidence
- `sou112-ask` (selected file `docs/operations/evidence/sou-112/linux-qualification.json`): invalid_evidence:ask_case_denominator_changed
- `sou116-launch` (selected file `docs/operations/evidence/sou-116/linux-prepared-run.json`): invalid_evidence:prepared_case_denominator_changed
- install-start: missing_selected_evidence
- useful-workflows: environment_absent_or_mismatched, expected_environment_unbound, historical_source
- refusal-zero-effects: environment_absent_or_mismatched, expected_environment_unbound, historical_source
- ask: missing_selected_evidence
- daemon-loss: missing_selected_evidence
- cancellation-cleanup: missing_selected_evidence
- linux-platform: no_exact_bound_linux_runtime_evidence
- wsl-platform: wsl_not_qualified_by_selected_support_index
- sou106-final / useful-workflows: `{"failed_cases": ["search-read-status", "search-exclusion"], "false_interruptions": 2}`
- sou106-final / refusal-zero-effects: `{"denied_execution_count": 9, "forbidden_effects": 0, "forbidden_result_delivery_count": 0}`

Historical failed attempts remain selected records; later evidence never overwrites them.
A passing reporter test is not a passing pilot. Missing environment/identity evidence stays incomplete.
Linux evidence does not qualify WSL, Windows or macOS. No paid model or release claim.
