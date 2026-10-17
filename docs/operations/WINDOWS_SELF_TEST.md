# Native Windows Agent self-test

Run the installed Agent from a normal, non-elevated Windows terminal. The
self-test uses the existing command, fixture tools and report schema
`sw-self-test/1`. Its platform profile is
`windows-stdio-mcp-admission-v1`.

## Prerequisites

Select an installed Agent executable, a local Python 3 interpreter and the
reviewed `rule_baseline.py` source with its expected SHA-256. Keep these assets
outside the source checkout. The operator command needs no compiler, Docker,
WSL, administrator rights, provider account or downloads.

Use local NTFS directories owned by the current account for the report and
temporary workspace. Existing reports, junctions, symlinks, reparse components,
path aliases and foreign-owned parent directories are refused. The self-test
does not change the permissions of an existing operator directory.
Parents that grant an untrusted account write or delete access are refused.

## Run

Set the paths and the classifier digest to the installed revision you reviewed:

```powershell
$agent = 'C:\SoupWall\agentfw.exe'
$python = 'C:\Python312\python.exe'
$classifier = 'C:\SoupWall\classifier\rule_baseline.py'
$expectedHash = '<reviewed SHA-256>'
& $agent self-test --agent $agent --classifier rule-baseline `
    --classifier-script $classifier --classifier-sha256 $expectedHash `
    --classifier-python $python --report .\self-test.json
```

The report path must be new. Optional flags and exit codes follow the
[shared self-test contract](SELF_TEST.md#exit-codes).
`--work-parent` selects an existing owned parent directory.
`--keep-workspace` retains only this run's synthetic workspace for inspection.

## Evidence

The five scenarios check exact allowed-read bytes, withholding of an injected
result, refusal of a synthetic-key send before execution and delivery, another
useful read, and actual daemon loss with no bypass. Ask has no approval channel
and remains a refusal.

The JSON report records binary, classifier, policy, registry and fixture hashes;
classification and native-audit receipts; execution and receiver counts;
latency; and cleanup. Configuration and health appear separately from these
witnesses. A final check reads the whole execution journal after all owned
processes stop, so a late unexpected call also fails the run.

The receiver binds numeric loopback only. Its positive delivery control is
included in final counts: a complete run has three fixture executions and one
direct receiver delivery. None of the protected sends should open a receiver
connection.

## Isolation and cleanup

Each run creates a private home, Agent profile, policy, registry and notes.
New objects receive a restricted DACL and the current user as owner. Existing
files are never repaired or overwritten.

Processes start suspended, enter an unnamed kill-on-close Windows Job and then
resume. Descendants remain in that job. Cleanup terminates the owned jobs,
reaps their leaders and verifies zero active members. It does not search by
process name or terminate unrelated processes.

Ctrl+C, Ctrl+Break, startup failure and the run deadline trigger cleanup.
Output lines, channels, log writes and receiver traffic have explicit bounds.
Cleanup failure produces exit 4 and retains the workspace location in the
terminal output. JSON reports omit user paths, account identifiers and
synthetic sensitive content.

A passing result covers the scripted MCP path and bundled fixtures. It does
not establish live-model effectiveness or complete Phase 4.

## Native acceptance

From an existing non-elevated Windows account:

```powershell
python -B scripts/test-windows-self-test.py `
    --agent C:\SoupWall\agentfw.exe `
    --baseline C:\SoupWall\classifier\rule_baseline.py `
    --out .\windows-self-test-evidence
```

The driver stages the executable and classifier outside the checkout and runs
positive and negative controls. It checks missing assets, a wrong classifier
revision, existing reports, reparse paths, a foreign owner, an occupied foreign
port, interrupted descendants, failed cleanup and unrelated sentinel data.

The focused [Windows workflow](../../.github/workflows/agent-windows-self-test.yml)
builds the candidate and runs it under a disposable standard account. Account
provisioning is restricted to ephemeral GitHub Actions runners. The normal
Windows regression workflow remains required.

Retained results are in the [Windows verification record](evidence/SOU71_WINDOWS_SELF_TEST_2026-10-17.md).
