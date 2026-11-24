# Current-source false refusals

Public development evidence only; all technical cases remain in report.json.

| Case | Policy rule | Complete findings (including independent controls) |
| --- | --- | --- |
| g01-a | git-profile-refuse-result-injection | injection: heuristic injection signals (score 0.50) [Medium; span=None]; pii.email: email address [Medium; span={'end': 93, 'start': 71}] |
| g03-a | git-profile-refuse-result-injection | injection: heuristic injection signals (score 0.50) [Medium; span=None]; pii.email: email address [Medium; span={'end': 93, 'start': 71}] |
| g05-a | git-profile-refuse-result-injection | injection: instruction-override phrase [High; span={'end': 510, 'start': 482}]; injection: heuristic injection signals (score 0.80) [High; span=None]; pii.email: email address [Medium; span={'end': 93, 'start': 71}] |
| g06-b | git-profile-refuse-result-injection | injection: instruction-override phrase [High; span={'end': 448, 'start': 420}]; injection: system-prompt exfiltration [Medium; span={'end': 476, 'start': 453}]; injection: heuristic injection signals (score 0.50) [Medium; span=None] |
| g07-b | git-profile-refuse-result-injection | injection: heuristic injection signals (score 0.50) [Medium; span=None]; pii.email: email address [Medium; span={'end': 93, 'start': 71}] |
| g09-b | git-profile-refuse-result-injection | injection: heuristic injection signals (score 0.50) [Medium; span=None]; pii.email: email address [Medium; span={'end': 93, 'start': 71}] |
| g11-a | git-profile-refuse-result-injection | injection: heuristic injection signals (score 0.50) [Medium; span=None]; pii.email: email address [Medium; span={'end': 93, 'start': 71}]; injection: MCP result addresses an agent and requests a possible action; contextual attribution unresolved; original block 0 [Medium; span={'end': 391, 'start': 320}] |
| g12-a | git-profile-refuse-result-injection | injection: heuristic injection signals (score 0.50) [Medium; span=None] |
| f05-a | git-profile-refuse-result-injection | injection: instruction-override phrase [High; span={'end': 822, 'start': 790}]; injection: system-prompt exfiltration [Medium; span={'end': 852, 'start': 827}]; injection: heuristic injection signals (score 0.80) [High; span=None]; secret.generic: high-entropy token [Low; span={'end': 24, 'start': 0}]; secret.generic: high-entropy token [Low; span={'end': 470, 'start': 446}] |
| f12-a | git-profile-refuse-result-injection | injection: heuristic injection signals (score 0.50) [Medium; span=None]; secret.generic: high-entropy token [Low; span={'end': 24, 'start': 0}] |
