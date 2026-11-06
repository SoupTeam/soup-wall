# Exact-source infrastructure retry (SOU-240)

This command plans a **single failed leaf job** retry from a clean checkout of
the PR's current base. Planning is read-only. It does not grant candidate
admission, replace a failed test, or reuse a prior admission result. GitHub's
job rerun API can also rerun dependent jobs, so jobs with any dependent in the
trusted workflow graph are refused.

## Supported causes

| Category | Required evidence | Result |
| --- | --- | --- |
| `hosted_runner_allocation` | Completed failed job, static hosted runner, no runner or steps, and one matching GitHub check-run failure annotation | Plan one leaf rerun |
| `package_mirror_500`, `_502`, `_503`, `_504` | Completed failed reviewed Ubuntu installation step and a timestamped matching Ubuntu mirror error in bounded job logs | Plan one leaf rerun |
| Assertion/test failure, unknown cause, canceled job/run, missing or conflicting evidence | None of the above | Refuse; investigate manually |

Only registered component jobs and the reviewed installation steps in
`scripts/ci_infrastructure_retry.py` are eligible. The planner rejects changed
workflow sources, renamed/deleted or incomplete PR files, changed base/head/merge parents, newer
runs or attempts, duplicate selected jobs, another failed job, and any other
selected job that has not succeeded. The aggregate `Components` wrapper may
reflect the one failed component leaf. A missing API page or inaccessible log is a refusal, not a
successful plan. A previously rerun attempt is outside this one-shot action.

## Operator procedure

Use an Actions-read token for planning. Start from a clean, trusted checkout
of the PR's exact current base. The command checks `git status` and HEAD.

```sh
read -rs -p 'GitHub token: ' GITHUB_TOKEN; echo; export GITHUB_TOKEN
python3 scripts/ci_infrastructure_retry.py --pr 123 --job-id 456
```

The JSON plan names the PR, base/head/merge, run/attempt/job, cause category,
evidence SHA-256 and successful-job lineage. It contains no log body, signed
URL or credential. Review the plan and failed job in GitHub. To send the
single request, use an Actions-write token and an existing, owner-private
directory on a native Linux host:

```sh
install -d -m 700 "$HOME/.local/state/soup-wall/retry-journal"
python3 scripts/ci_infrastructure_retry.py --pr 123 --job-id 456 \
  --execute --plan-id '<plan_id_from_read_only_plan>' \
  --journal-dir "$HOME/.local/state/soup-wall/retry-journal"
```

Execution re-reads all evidence before and after atomically reserving a
create-new `0600` journal. After the final log read it checks current
base/head/merge, job and run attempt again immediately before dispatch. It
writes `attempted` before the POST. An
acknowledged `201` is recorded as `acknowledged`; a lost response or HTTP
failure is `uncertain` and **must not be blindly retried**. Inspect the run
and journal manually. A second operator using the same plan ID is refused.
Keep this private journal across process restarts. Do not remove entries to
force another request.

GitHub emits the existing workflow completion event when the rerun finishes.
The trusted SOU-91 admission workflow then recomputes current base/head/merge,
selected jobs, attempts and all five CodeQL results. The retry command never
posts a check/status and does not enable SOU-160 admission reuse. Inspect the
new job attempt, artifacts and trusted admission separately. Preserve the
original failed attempt and logs in the incident record.

## Source-bound observation and limits

At accepted main `8003fac2d271156e2229c8c15c6eddb98ee2da8e`, PR #359
run `41855378981` had three unsuccessful macOS allocation attempts. Attempt
three's job `126718007400` was `cancelled`, with `runner_id=0`, no steps and
no matching check-run annotation. The central workflow also retained
dependent jobs. This is **not** an eligible positive retry witness. No live
rerun was requested for it. The synthetic controls cover the positive mirror
and allocation classifications, changed source, real failures, uncertain
responses and duplicate operators; they do not claim hosted-runner allocation
success or current-source Ready qualification.

The local journal protects one operator-controlled directory. It does not
coordinate separate machines or recover a GitHub response lost after the
server accepted the request. Such an outcome remains `uncertain` and requires
manual inspection. Final Ready/security/admission and merge remain with the
team lead.
