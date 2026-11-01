# Local PR feedback (SOU-206)

Use the committed source you intend to push. Supply both the reviewed base and
your local head explicitly. The base must be an ancestor of the head; rebase
locally if it is not. This command neither creates a merge candidate nor
qualifies one for GitHub admission.

```bash
python3 -B scripts/local_pr_verify.py plan --base origin/main --head HEAD
python3 -B scripts/local_pr_verify.py run --base origin/main --head HEAD \
  --step-seconds 120 --total-seconds 600 \
  --report-json "$HOME/local-pr-feedback.json"
```

Python 3.11+ and Git are required. `plan` reads committed Git objects and runs
the accepted `scripts/ci_impact.py` selector from the explicit base commit in
memory; it never imports a dirty or head-modified selector. The report binds
the selector and its activation dependencies by SHA-256. It makes no scratch checkout and
does not write a report. `run` checks an exact-head detached worktree in a
private system temporary directory. Pre-existing staged, unstaged and
untracked contributor changes are excluded from the checked source and left
untouched. The report states when such changes were excluded. The command
refuses if the base/head refs or the contributor's dirty contents change during
the run, or if a check changes its scratch source.

The source contract records exact base/head commits, changed paths, the pinned
`rust-toolchain.toml` channel and digest, `Cargo.lock` digest, local Python
version and resolved executables. Floating Rust channels are refused. Rust
checks require the pinned toolchain and locally available offline dependencies;
missing prerequisites are `unavailable`, never passed. Cargo runs with
`--locked --offline`, `RUSTUP_AUTO_INSTALL=0`, two build jobs and a scratch
target directory. The command installs nothing, downloads nothing and makes no
GitHub, paid-provider or model API call. It does not push, modify global Git
configuration or post a status.

| Local check | When selected | Feedback, not a substitute for |
| --- | --- | --- |
| Patch whitespace | Every committed change | GitHub source and admission checks |
| Documentation unit and local links | Selector includes documentation | Hosted documentation job |
| Python syntax | Changed Python files still present in head | Broader Python/runtime suites |
| CI contracts | CI-sensitive or unknown/full path | Trusted planner/admission |
| Rust format, offline Clippy, offline test compilation | Rust or unknown/full path | Native tests, platform matrix, CodeQL |

Unknown paths retain the accepted selector's full remote plan. The report lists
every selected remote workflow job and all required CodeQL languages as
`not-run` remote obligations. Native provider, IdP, platform and protection
qualification remain remote or separately owned even when every local check
passes. `local_checks_passed` is **only local feedback**; `full_qualification`,
`trusted_admission` and `github_status_posted` are always false.

Checks run sequentially. Each check subprocess has a 1–300 second limit
(default 120), the selected-check phase a 1–900 second limit (default 600),
and Git preparation/cleanup have separate finite timeouts. Retained output is capped
at 64 KiB per check with a 2 KiB excerpt. Cancellation and limits stop the
owned process group; later checks become `not-run`. Result states are
`passed`, `failed`, `skipped`, `unavailable`, `not-run` and `incomplete`, with
separate selected/executed/pass denominators, commands, exit codes and
durations. A missing toolchain or timed-out check makes the local result
unsuccessful. Temporary check logs and build outputs are removed. An optional
JSON report is created exclusively as a private file outside the repository;
an existing file or symlink is refused, so stale cached success cannot be
reused. Keep report excerpts private because a failing local tool can print
local paths or input data.

The focused process regressions use owned synthetic Git projects, including a
public Python/docs change, an actual failing syntax check, missing Rust,
unknown paths, concurrent source mutation, cancellation with a child process,
oversized output and a forged existing report. These are local verifier
controls, not observed provider protection or measured CI savings. Exact
source and measured feedback from the Draft PR are recorded in its description;
no reduction in hosted runner usage is claimed without paired CI data.

One Windows synthetic public Python/docs fixture measured 0.688 s for `plan`
and 2.406 s wall time for `run` (1.219 s inside checks), with 4/4 selected
local checks passed and four unselected checks skipped. Its private fixture
base/head were `1f57d785c3f95715b12157c98dccf315fd7fb3ca` and
`5325fc5bb5ec21755b2f91bc80a7c1af57046962`. This is one local sample,
not a native or hosted CI measurement.
