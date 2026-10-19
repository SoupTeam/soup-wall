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
$report = [ordered]@{ format = 'sou96-windows-budget-standard-user/1'; status = 'incomplete'; error = $null; phase = 'standard_user_check'; exception_type = $null; hresult = $null; native_exit_code = $null; python_error_types = @(); python_trace_lines = @() }
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'standard_user_required' }
    Set-Location -LiteralPath $rootPath
    $env:TEMP = $rootPath
    $env:TMP = $rootPath
    $report.phase = 'python_invocation'
    # Bootstrap can fail before Python writes results.json (runtime/import/ACL).
    # Capture at most 32 KiB privately; publish only exception classes and line
    # numbers in this reviewed public harness, never raw source/path/arguments.
    $diagnostic = [Text.StringBuilder]::new()
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $Python -I -B (Join-Path $rootPath 'verify-windows-mcp-budgets.py') --run `
            --agentfw (Join-Path $rootPath 'agentfw.exe') --source-commit $Commit `
            --native-test-binary (Join-Path $rootPath 'native-tests.exe') `
            --source-manifest (Join-Path $rootPath 'source-manifest.json') --output $out 2>&1 |
            ForEach-Object {
                $line = $_.ToString()
                $remaining = 32768 - $diagnostic.Length
                if ($remaining -gt 0) { [void]$diagnostic.Append($line.Substring(0, [Math]::Min($line.Length, $remaining))) }
                if ($diagnostic.Length -lt 32768) { [void]$diagnostic.AppendLine() }
            }
        $exitCode = $LASTEXITCODE
    } finally { $ErrorActionPreference = $savedPreference }
    $report.native_exit_code = $exitCode
    $report.python_error_types = @([regex]::Matches($diagnostic.ToString(), '\b[A-Za-z][A-Za-z0-9]*(?:Error|Exception)(?=:)') |
        ForEach-Object Value | Select-Object -Unique -First 8)
    $report.python_trace_lines = @([regex]::Matches($diagnostic.ToString(), 'verify-windows-mcp-budgets\.py", line (\d+)') |
        ForEach-Object { [int]$_.Groups[1].Value } | Select-Object -First 8)
    [void]$diagnostic.Clear()
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
