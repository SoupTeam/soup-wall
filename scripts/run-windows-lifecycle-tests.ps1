# SPDX-License-Identifier: Apache-2.0
# Child of ci-windows-lifecycle.ps1; all paths and credentials are disposable.
param([Parameter(Mandatory = $true)][string]$Root)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$report = [ordered]@{ status = 'error'; user_sid = $null; is_administrator = $null; profile_owner_sid = $null
    agent_sha256 = $null; test_sha256 = $null; passed = 0; failed = 0; ignored = 0; error = $null }
$exitCode = 1
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    $report.user_sid = $identity.User.Value
    $report.is_administrator = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if ($report.is_administrator) { throw 'Lifecycle acceptance must run as a standard user' }
    $temporary = Join-Path $rootPath 'owned-temp'
    [IO.Directory]::CreateDirectory($temporary) | Out-Null
    $report.profile_owner_sid = (Get-Acl -LiteralPath $temporary).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($report.profile_owner_sid -ne $report.user_sid) { throw 'Temporary profile is not owned by the test user' }
    $env:TEMP = $temporary
    $env:TMP = $temporary
    $env:AGENTFW_LIFECYCLE_TEST_BINARY = Join-Path $rootPath 'agentfw.exe'
    $tests = Join-Path $rootPath 'lifecycle-tests.exe'
    $report.agent_sha256 = (Get-FileHash -LiteralPath $env:AGENTFW_LIFECYCLE_TEST_BINARY -Algorithm SHA256).Hash.ToLowerInvariant()
    $report.test_sha256 = (Get-FileHash -LiteralPath $tests -Algorithm SHA256).Hash.ToLowerInvariant()
    & $tests --ignored --nocapture --test-threads=1 *> (Join-Path $rootPath 'lifecycle.log')
    $testExit = $LASTEXITCODE
    $log = Get-Content -LiteralPath (Join-Path $rootPath 'lifecycle.log') -Raw
    if ($log -match 'test result: (?:ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;') {
        $report.passed = [int]$Matches[1]
        $report.failed = [int]$Matches[2]
        $report.ignored = [int]$Matches[3]
    }
    if ($testExit -ne 0 -or $report.passed -ne 5 -or $report.failed -ne 0 -or $report.ignored -ne 0) {
        throw "Lifecycle tests did not complete all five cases (exit=$testExit)"
    }
    $report.status = 'pass'
    $exitCode = 0
} catch {
    $report.error = $_.Exception.Message
} finally {
    $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $rootPath 'result.json') -Encoding utf8
}
exit $exitCode
