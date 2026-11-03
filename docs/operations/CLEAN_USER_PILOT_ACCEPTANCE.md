# Current installed Linux pilot: clean-user acceptance (SOU-216)

## Selected path and current decision

**Not yet measured.** No first-use, performance or product GO follows from local
Python checks. This report will retain both fresh ordinary-user runs, including
failed and incomplete observations. The checkpoint is November 4 and delivery
deadline is November 5, 2026.

The product is accepted source
`9a3c5b38e56ebc6ebbeedfda98805f6a327cb371`, not the newer measurement-driver
commit. The existing native prerequisite and Agent builders run from a separate
clean checkout of that source. Their receipt binds the tracked source, reviewed
compiler inputs and each selected binary. The front-door component is built
from the same accepted checkout. Driver, product, binary, profile, policy,
selection and original child-report identities remain separate.

Supported measurement path: native Ubuntu 24.04 x86_64, ordinary non-root user
with no effective capabilities, CPython 3.12 and the current pinned original
Claude Code, filesystem and Git packages. Two separately dispatched GitHub-hosted
jobs provide fresh disposable user environments; each starts with empty private
Agent/home/preparation state. Run ID and hashed kernel boot identity distinguish
the environments. Cache state and build durations are observations; this is not
a claim that every compiler/download cache was cold.

Ubuntu's namespace permission is an explicit administrator prerequisite. This
uses the unchanged job-scoped exact-binary provisioning procedure documented in
[native prerequisites](PILOT_NATIVE_PREREQUISITES.md). It changes no global sysctl,
global AppArmor profile, setuid bit or product policy. The new measurement mode
does not run the older isolated-account cleanup fixture or create OS accounts.
A successful run cannot establish unassisted stock-host installation.

## Reproduce

From a clean measurement-driver checkout, use the existing
[installed producer](PILOT_INSTALLED_FRONT_DOOR.md). Supply inputs emitted by the
accepted native builders and retain the original build receipt:

```sh
python3 -B scripts/qualify-installed-front-door.py --run --clean-user-only \
  --runtime-source /absolute/accepted-source \
  --source-build-receipt /private/agent-build/generations/ID/receipt.json \
  --expected-commit FULL_MEASUREMENT_DRIVER_COMMIT \
  --output /private/new-clean-user-result \
  --component-python /usr/bin/python3.12 --strace /usr/bin/strace \
  --agentfw /private/agent-build/generations/ID/bin/agentfw \
  --git-launcher /private/agent-build/generations/ID/bin/git_launcher \
  --sandbox-tests /private/agent-build/generations/ID/bin/sandbox_tests \
  --git /private/native/git --bwrap /approved/exact/bubblewrap \
  --node-archive /private/assets/node.tar.xz \
  --claude /private/assets/claude/node_modules/@anthropic-ai/claude-code-linux-x64/claude \
  --python /usr/bin/python3.12 --allow-download
```

The existing `mcp-real-filesystem.yml` workflow adds the explicit
`installed_focus=clean-user`, `native_preparation_only=true` selection. Leave
every other flag false, optional comparison inputs empty and stability off.
Dispatch twice at the same driver commit for two fresh environments. Acquisition
and compilation precede installed execution; no protected server downloads its
own implementation at startup. Only pinned public inputs and owned synthetic
projects are used.

## Fixed useful work and independent witnesses

Both environments use two new projects, distinct from historical SOU-145 inputs:

| Project | Fixed developer tasks |
| --- | --- |
| Catalog service | Read the API contract exactly; inspect the complete pending configuration diff; trace both local commits; inspect the latest commit |
| Release ledger | Read the release-review contract exactly; inspect the complete pending retention diff; trace both local commits; inspect the latest commit |

Expected source bytes, Git commit IDs, messages and complete pending diffs are
recorded before any provider or host is started. Each task uses the genuine
pinned host and original servers through `agentfw pilot`, outside both source
checkouts. Error flags, missing/partial replies and unconfirmed process cleanup
cannot count as useful work. A failed useful task remains in its four-task
denominator; later independent tasks proceed only after confirmed cleanup.

Denied original writes/resets and an unavailable host shell have independent
original-dispatch, receiver, marker-file and complete source/index/object
preservation witnesses, followed by a useful read. The receiver is positively
calibrated first. An unsupported tool or profile refusal is not relabeled a
native policy Deny.

The unchanged [quickstart walkthrough](PILOT_QUICKSTART.md) runs its complete
inventory on a separately generated demo selection: useful operations, Ask,
cancellation, timeout, daemon loss, fresh recovery and cleanup. The accepted
two-profile Ask approval smoke additionally checks exact inspection, one-use
redemption, replay rejection and independent effects. Its two-case correctness
scope is not the full fifteen-case Ask inventory or performance acceptance.
Original child reports retain their formats and hashes.

The same installed component then exercises an identity-only synthetic update,
stale-selection refusal, rollback and removal. New project bytes, Git state,
prepared selections and synthetic user files must survive. No classifier,
result-inspection or original Git implementation is changed here. Failures in
those owned areas retain exact task/tool/result hashes and reproduce against the
fixed accepted source for SOU-97/157/177.

## Bounds and report interpretation

The existing host, broker, pending-call and walkthrough limits are unchanged.
Task wall time includes host startup and cleanup; it is not a per-tool p95.
The existing five-second first-pending correctness observation is reused.
General useful-task/installation latency thresholds remain **unapproved**.

`report.json` reuses `sw-installed-front-door-qualification/1`. Its separate
`clean_user` inventory records every attempted, failed and incomplete case;
ordinary installed producers and SOU-145/176/190 contracts are not replaced or
backfilled. Child walkthrough/Ask reports are retained separately. Raw syscall
traces stay private; bounded summaries include hashes and independent witnesses.

GO can cover only the exact measured, preprovisioned read-only path. Any failed
or incomplete required observation is NO-GO for this scope. Scripted-provider
results are not live-model attack efficacy, novice-human evidence, WSL evidence,
license/advisory clearance, public release or full-product acceptance.
