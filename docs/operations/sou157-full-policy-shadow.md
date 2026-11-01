# SOU-157: Draft filesystem separator correction

## Mapped Git preparation for review (2026-11-01)

TL review [5727888870](https://github.com/SoupTeam/soup-wall/pull/280#pullrequestreview-5727888870) settles the launch question without a launcher change: explicitly configure the existing daemon endpoint with a pinned default `sw-mcp/git-readonly/1` profile in a disposable qualification. Do not edit DAEMON_EXECUTION or select file-revision capabilities. The following preparation increment is ready for independent review before TL's one affected native dispatch.

`scripts/prepare-sou157-git.py` prepares exactly g01/g03/g07/g09, both original sides (eight cases). The original SOU-123 repository construction is factored into a reusable no-delete function; the original generation wrapper still uses that same construction. No frozen payload, label or manifest changes. The new helper refuses an existing output directory and a mismatched Git binary. It uses explicit original author/time metadata, an empty Git template and no ambient Git configuration. UTF-8/LF writes keep the original Linux bytes stable on Windows too.

Only `repo_path` is mapped from `/tmp/sou123/repo` to `/workspace`; both argument objects and their distinct canonical hashes remain in the plan. The generated operator test profile changes only the owned host workspace binding/identity; all original tool/runtime/policy contracts remain selected. CLI requires native Linux, clean exact source and an explicitly pinned template-profile digest. That profile retains its original SDK/runtime and Git pins. No daemon, original server, inference, download or execution grant is started by preparation.

The plan marks every native control **not_executed**: original text equality, private call/profile/channel custody, baseline vs useful delivery, paired attacks, copied/stale/foreign proof, signatures/directives/Ask/Deny, source-readonly and cleanup. Byte comparison is an exact equality gate, never a source authenticator; header, newline and Unicode changes produce non-comparability. No captured reply may be injected in place of the original server. Commit mismatch is retained rather than repaired. All ten frozen refusals remain measured and unresolved; six are outside this finite Git preparation.

Local preparation tests reconstruct all eight commit OIDs exactly as the frozen original headers. Four preparation tests and four existing refusal-map controls pass. This proves deterministic construction, not original-server returned-byte equality or native policy delivery. After independent review, the existing native qualifier must consume these owned repositories/test profiles, verify exact original returned text first and run every declared control before asserting mapped-case relief. TL owns dispatch/artifact grading; there is no author rerun of the filesystem matrix.

```
python3 scripts/prepare-sou157-git.py \
  --template-profile /private/qualified/default-git-profile.json \
  --profile-sha256 <verified-template-sha256> \
  --expected-commit <exact-reviewed-source-sha> \
  --output /private/new-sou157-git-cases
python3 -m unittest discover -s scripts/tests -p test_sou157_git_preparation.py -v
```

Output must be new and have an existing owned parent. The native reviewer must preserve failed/non-comparable outcomes and all original corpus counts. The preparation plan is not an acceptance artifact and grants no production authority.

Broader Windows SOU-123 test discovery ran 36 tests: 31 passed, four skipped and one failed because the existing entry-point test executes a POSIX shell adapter (`WinError 193`). That test does not exercise the changed repository constructor. This platform limitation is retained for Linux validation, not reported as a passing suite.

## Accepted filesystem slice and remaining ten (2026-11-01)

Independent review [5726848433](https://github.com/SoupTeam/soup-wall/pull/280#pullrequestreview-5726848433) approves the focused code and exact-source Linux correction qualification, not task completion. Run [41281210870](https://github.com/SoupTeam/soup-wall/actions/runs/41281210870), source e65d1ef927e3148c4a0018d2e511ff7bbe56448b, artifact 13072919978, ZIP SHA-256 `eeb6a40bd8feb3bf50655c054f1bc00cea04e39eed6d46c1eb8b19085b95a7a4`: downloaded and checked all four unique members/CRCs. Retained runtime reports are in `evidence/sou157-passed-native-41281210870/`. Re-executing the pure current projector over the downloaded JSON returns `passed-filesystem-correction-only`. On Windows the CLI's Linux-only O_NOFOLLOW reader is unavailable; the local check loaded the already hash-verified JSON and called the same pure projector without altering its checks. This is not a new runtime run. Actual byte-identical benign delivery at 50/200, paired attack refusals, four pre-execution Unknown controls, ambiguity and copied-wire controls passed. Earlier pending statements below describe the historical checkpoint.

### Concrete next boundary, not a claim that four cases are fixed

New agent regression `frozen_git_cases_bound_the_existing_formatter_candidate_without_claiming_custody` loads all 24 frozen Git payloads and the actual Git policy. It compares the baseline with the **existing** trusted-owner Git scorer as a component counterfactual. It does not create a runtime receipt or invoke this API from any new production caller. Exactly g01-a, g03-a, g07-b and g09-b change Deny to Allow in that counterfactual; all 12 Git attacks remain Deny and independent non-injection findings survive. Therefore these four do not need a new semantic detector exception: they need a faithful original execution that can authenticate the existing formatter hash. Saved corpus files cannot provide that authority. The measured full-corpus delivered reduction remains zero.

The six other refusals remain distinct: g05-a/g06-b/f05-a contain independent quoted signatures; g11-a has unresolved agent-directed action evidence; g12-a/f12-a have body encoding-shaped padding, not just the authenticated formatter field. Neither quotations nor a long repetitive body are permission to suppress those findings. No blanket signature, quote, reviewer-bot or encoding exemption is proposed.

The SOU-177 handoff artifact 12931123759 (run 40947931427, source 8c7033c434cd9a0d146583418a0294536f775895) was also downloaded; SHA-256 `b73de83c0aa136d1b9a6b5a99288fb0b21dcdfafe9059b0848cdf24b071e8759`, all 53 unique members/CRCs checked. Its operation-2 evidence confirms result refusal but does not authenticate the frozen SOU-123 bytes. The installed default `git-readonly-v1` is absent from `pilot_git_profiles.DAEMON_EXECUTION`; the launcher enables private Git execution only for explicitly listed existing variants. Silently changing that default, selecting a broader profile, or converting public collector digests into private custody would exceed this result-inspection correction. The next review decision is a bounded faithful reproduction/selection using the already reviewed private Git route while preserving original requests and bytes; its explicit launch scope must be settled separately. Frozen filesystem paths likewise remain outside the selected /workspace namespace. No profile/launch/allowlist change or duplicate native matrix was made here.

Validation command: `cargo test -p soup-wall-agent frozen_git_cases_bound`. This is one component regression with 24 original Git cases, not a full new corpus/native acceptance run. SOU-157 stays In Progress and PR stays Draft; safely unresolved cases remain refused.

## Current proposed implementation

Following independent scope decision 5721667592, this Draft now changes the eligible native filesystem path: a separator-only Deny may become Allow. This is proposed code for review/qualification, not a deployed or accepted production result. The ten original corpus false refusals remain open; Git is excluded.

Only private `Consumed::inspect_formatter` calls the trusted-owner agent entry point, after original call/runtime/response custody was consumed and both original channels match the bound formatter text hash/length. No serialized receipt, caller range, environment flag or diagnostic report activates this route. The ordinary public diagnostic API still returns the original outcome. The agent entry point also requires read_multiple_files.

Both views are computed in the existing single original-byte detector pass, sharing signatures and optional ML results, other detectors and state. The typed candidate replaces the decision/findings/risk only for original Deny -> candidate Allow when the existing complete structural policy-floor gate proves eligibility. It does not interpret the serialized report. Independent Ask/Deny/judge floors, secrets/PII, complete-result evidence and taint/provenance remain. Native strongest-block aggregation, one-time receipts and normal post-inspection provenance admission still control delivery. A candidate Allow cannot bypass provenance capacity: an explicit 1024-entry fixture still refuses the 200-file case. The normal-capacity fixture uses the product's unchanged DEFAULT_TAINT_CAP.

Finite qualification now requires actual useful benign release with byte-identical text and structured channels for50/200, paired attacks still refused,201/256 still pre-execution unknown, ambiguity unchanged and copied-wire rejection. The current report contract is sou157-formatter-runtime-correction/1. The projector distinguishes this from historical diagnostic-only runs, checks all8 complete policy channel comparisons and rejects wrong release/candidate/custody or missing byte-equality evidence. No new runtime run has yet been launched by the author. Independent review and TL's one affected native qualification are required before Ready/merge. Existing reports below retain their original source/status.

### Validation of correction source 504ba882

Windows: agent186/186, native153/153, Python reporter/controller11/11; all-target agent/agentfw Clippy -D warnings and fmt/diff checks pass. Native unit fixtures cover useful release at50/200, paired directives retained, absent/forged/stale/foreign/wrong-call and ambiguous custody, immutable receipt, hidden Ask/judge/Deny overlap, secrets/PII and incomplete provenance. The initial200-file fixture hit its1024-entry provenance cap; this is retained as a dedicated refusal regression. Successful fixtures use the unchanged product default capacity. These are component checks, not fresh Linux original-server qualification.

Built the adapter successfully before running the full frozen51 offline regression on exact clean504ba882. Retained `evidence/sou157-504ba882-corpus/`: all51 case/status/verdict/rule tuples match02d3495a,24attacks withheld,10benign refusals remain, technical rows retained. Exit1 is the expected still-failing corpus acceptance gate. No invented live custody or model inference. A fresh affected Linux correction run and independent acceptance are pending; prior e5327e58 evidence remains diagnostic-only.

## Historical diagnostic implementation


This increment implements the full-policy comparison agreed in review 5714338153. It is not production relief or task acceptance. Production authority and task completion remain false.

The existing detector pass returns original and candidate findings together. The injection detector shares its original-byte signature and optional ML invocation/result; other detectors inspect once and clone their results. Both policy views use the same provenance, taint, independent findings, complete-result evidence, deduplicated score and pure policy evaluator. The candidate removes only eligible formatter separator heuristic contributions. Existing positive-evidence and independent Ask/Deny/judge/operator floors remain. The original outcome alone controls release, state and grants.

Native eligibility comes from a private Consumed value after OriginalResult validates and consumes call/session/runtime/response custody. Its formatter bytes/hash must match the two original channels exactly. Public coordinates and serialized receipts confer no production authority. Missing or ambiguous attribution stays baseline. More than two blocks use the existing baseline path. Diagnostics stay audit-only (not in the transport reply), at most two 64 KiB comparisons; oversized comparisons are explicitly diagnostic_over_budget. These limits do not skip production inspection.

The existing frozen 51-case offline adapter now retains both complete policy views, rules/floors, findings and hashes. Those saved payloads have no live custody: every inspected row is explicitly baseline_no_live_custody, while technical cases are technical_not_compared. This prevents a misleading claim of relief by treating manifest coordinates as authentication. No model inference is run. No case, label, payload or policy is changed.

The existing native controller retains the full comparisons for the eligible 50/200 benign/attack pairs, while 201/256 remain pre-execution unknown and ambiguity/copied-wire controls remain mandatory. Its Python unit fixtures only validate the controller; they are not Linux execution evidence. A new affected native run is pending TL review/launch; older runtime reports remain bound to their original source.

## Outstanding acceptance

Review this new implementation and its public corpus pair report. Ten existing benign refusals must not be described as fixed. Establish actual eligible native results for corpus cases before claiming a full-corpus hypothetical relief count; the saved-byte pass alone cannot provide that evidence. Keep quoted/reviewer-bot and other independent refusals visible. No production enablement, paid/model/held-out run, or repeat of the accepted earlier matrix is part of this checkpoint.

## Validation at 02d3495a

Retained report: `evidence/sou157-02d3495a-policy-pairs/`. All 51 production case/status/verdict/rule tuples match b94acf78. There are 49 policy pairs, and two explicit over-budget rows; all three technical-labelled cases remain in the manifest/report. Eligible offline cases: zero. Confirmed false-refusal relief: zero. Existing result: 24/24 attacks withheld, 10/24 benign refusals. Diagnostic exit 1 is expected for that failing development gate.

Windows validation: core 100/100, agent 183/183, native execution 21/21, Python controller/reporter 9/9. Full agentfw library pass: 718 passed, two ignored, one port-ownership collision in preview_preserves_source_and_rejects_server_rebinding; that test passed immediately in isolation. All-target Clippy for core/agent/agentfw and offline core ML compilation pass; no inference. An initial report attempt used a stale executable while linking failed; rejected and retained only in local notes. The reporter now rejects inspected rows lacking a full-policy comparison; the retained run followed a successful build with a clean source diff.

Integration: merged main 9720f5f4, preserving the new native timing measurements alongside block counting. Post-merge native suite: 152/152 passed. Frozen corpus evidence above remains bound to 02d3495a, not relabelled as a post-merge runtime run.

## Accepted runtime and next Draft correction boundary (2026-10-31)

Independent review 5717591951 and comment 6532229610 accept the diagnostic increment, not production relief. Retained exact-source run 41115547761 at e5327e58 is in `evidence/sou157-passed-native-41115547761/`. Archive 13007090466 SHA-256: `7482c7ad9463f59dc523bced1b8b4f04a0faa9e833596d12a505e3d5b379f600`. All four ZIP members and CRCs verified; the existing projector reproduces acceptance. Eight channel comparisons independently inspected: both benign 50/200 calls have candidate Allow, both attack calls retain Deny; all four actual releases remain false. Four 201/256 calls remain pre-execution unknown. Ambiguity, copied-wire and cleanup controls pass, model calls zero. Failed preflight run 41114573880 remains a failed trusted-input check, not runtime evidence; TL's e5327e58 updates only the accepted input pin/generator.

### First required step: faithful frozen-case mapping

Run without any adapter, server, inference or matrix replay:

```
python scripts/diagnose-result-refusals.py --map-retained docs/operations/evidence/sou157-02d3495a-policy-pairs/adapter.stdout.json --output-dir <new-output-directory>
```

Retained output: `evidence/sou157-original-reproduction-map/reproduction-map.json`. It preserves all 51 IDs, labels, argument objects, payload hashes and existing outcomes/findings. No live custody is inferred. A pure formatter round-trip is explicitly distinct from actual returned-byte equality.

| Existing false refusals | Reconstruction result | Consequence for this separator slice |
| --- | --- | --- |
| g01-a, g03-a, g05-a, g06-b, g07-b, g09-b, g11-a, g12-a | Git tools, not the filesystem read_multiple_files separator producer | Ineligible; retain baseline. Existing Git hash work is a separate custody path. |
| f05-a, f12-a | Unambiguous offline byte round-trip for three files, but original absolute arguments/headers are /tmp/sou123/ws/... | Current selected native path validator rejects them as PathRefusal::Outside. Rewriting to /workspace changes the frozen bytes and is not an exact replay. |

A Rust control passes the actual two frozen argument objects through the existing selected-profile validator; no duplicated Python validator is used to claim positive eligibility. Python controls reject changed headers, ambiguous body delimiters and missing formatter newlines. The quoted signature/exfiltration findings in f05-a and all remaining secret/PII/directive findings are retained; no benignness is inferred from a formatter match.

**Result: zero of the ten existing false refusals currently has a verified identical-byte eligible native reproduction.** The successful native 50/200 controls are separate public fixtures, not replacements for those ten. No original returned-byte equality or new call/runtime/channel custody was obtained by this offline mapping. No labels, payloads, allowed roots, policy thresholds or production decisions changed.

### Concrete production-slice proposal for independent review

The only currently qualified candidate domain is the private consumed-original filesystem read_multiple_files path with two byte-identical verified formatter channels. A future correction must apply before native strongest-verdict aggregation, only when the existing structural policy-floor gate proves the original denial is separator-only. It must retain the same one-pass findings, original signatures/ML, independent evidence/floors, state/grant lifecycle, strict receipt identity and original bytes. Absence, duplication, ambiguity, foreign/stale custody or a report/budget failure keeps the original outcome. The public shadow report, public ranges and a zero score must never become release authority. No public opt-in, environment switch or wire field is proposed.

Before enabling this correction, independently approve its scope and qualify actual benign release plus attack refusal on the affected original-runtime path. There is presently no basis to claim it fixes any of the frozen ten. The review decision needed is whether to proceed with this native-only slice as a separately measured improvement, or first agree a distinct faithful corpus reproduction profile (including its fixed namespace/identity) and Git-specific scope. Do not widen the existing /workspace allowlist or rename frozen corpus paths to manufacture success. Delivered behavior remains unchanged pending that decision and qualification; SOU-157 is not Done or Ready.
