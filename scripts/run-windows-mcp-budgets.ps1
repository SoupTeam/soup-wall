# SPDX-License-Identifier: Apache-2.0
# Runs only inside the caller-owned private acceptance staging directory.
param(
    [Parameter(Mandatory = $true)][string]$Root,
    [Parameter(Mandatory = $true)][string]$Python,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$Commit
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$rootPath = (Resolve-Path -LiteralPath $Root).Path
$out = Join-Path $rootPath 'evidence'
$exitCode = 1
$report = [ordered]@{ format = 'sou96-windows-budget-standard-user/1'; status = 'incomplete'; error = $null; phase = 'standard_user_check'; exception_type = $null; hresult = $null }
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'standard_user_required' }
    Set-Location -LiteralPath $rootPath
    $env:TEMP = $rootPath
    $env:TMP = $rootPath
    $report.phase = 'python_invocation'
    & $Python -I -B (Join-Path $rootPath 'verify-windows-mcp-budgets.py') --run `
        --agentfw (Join-Path $rootPath 'agentfw.exe') --source-commit $Commit `
        --source-manifest (Join-Path $rootPath 'source-manifest.json') --output $out
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) { throw 'native_acceptance_failed' }
    $report.phase = 'complete'
    $report.status = 'pass'
} catch {
    $report.status = 'fail'
    $report.error = 'standard_user_acceptance_failed'
    $report.exception_type = $_.Exception.GetType().Name
    $report.hresult = $_.Exception.HResult
    $exitCode = 1
} finally {
    [IO.Directory]::CreateDirectory($out) | Out-Null
    $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'launcher.json') -Encoding utf8NoBOM
}
exit $exitCode
