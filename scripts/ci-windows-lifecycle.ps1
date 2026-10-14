# SPDX-License-Identifier: Apache-2.0
# Disposable hosted-runner account only. For a workstation, run the Rust tests
# directly as a standard user; do not provision another account with this script.
param(
    [Parameter(Mandatory = $true)][string]$AgentBinary,
    [Parameter(Mandatory = $true)][string]$TestBinary,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$Commit
)
$ErrorActionPreference = 'Stop'
if (!$IsWindows -or $env:GITHUB_ACTIONS -ne 'true') {
    throw 'Account provisioning is limited to an ephemeral Windows GitHub Actions runner'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The CI launcher needs an administrator token to create its disposable standard user'
}
$agent = (Resolve-Path -LiteralPath $AgentBinary).Path
$tests = (Resolve-Path -LiteralPath $TestBinary).Path
$out = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $out) { throw 'Refusing to overwrite lifecycle evidence' }
[IO.Directory]::CreateDirectory($out) | Out-Null
$name = 'swlc' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$stage = Join-Path ([IO.Path]::GetTempPath()) $name
$user = $null
$process = $null
$exitCode = 1
$report = [ordered]@{
    schema_version = 'sou18-windows-lifecycle/1'; status = 'error'; source_commit = $Commit
    observed_at = [DateTime]::UtcNow.ToString('o'); test_exit_code = $null
    os_version = [Environment]::OSVersion.VersionString
    architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    powershell_version = $PSVersionTable.PSVersion.ToString()
    agent_sha256 = (Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash.ToLowerInvariant()
    test_sha256 = (Get-FileHash -LiteralPath $tests -Algorithm SHA256).Hash.ToLowerInvariant()
    timeout_seconds = 600; timed_out = $false; account_removed = $false; staging_removed = $false
    error = $null; cleanup_error = $null; child = $null
}
try {
    $password = ConvertTo-SecureString ('Aa1!' + [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')) -AsPlainText -Force
    $user = New-LocalUser -Name $name -Password $password -Description 'Disposable Soup Wall lifecycle CI fixture'
    $group = Get-LocalGroup -SID 'S-1-5-32-545'
    Add-LocalGroupMember -Group $group -Member $user
    $credential = [Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$name", $password)
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    & icacls $stage /inheritance:r /grant:r "*$($identity.User.Value):(OI)(CI)F" "*$($user.SID.Value):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict fixture staging permissions' }
    Copy-Item -LiteralPath $agent -Destination (Join-Path $stage 'agentfw.exe')
    Copy-Item -LiteralPath $tests -Destination (Join-Path $stage 'lifecycle-tests.exe')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'run-windows-lifecycle-tests.ps1') -Destination $stage
    $script = Join-Path $stage 'run-windows-lifecycle-tests.ps1'
    $arguments = "-NoLogo -NoProfile -NonInteractive -File `"$script`" -Root `"$stage`""
    $process = Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') -ArgumentList $arguments -Credential $credential -LoadUserProfile -WorkingDirectory $stage -PassThru
    if (!$process.WaitForExit(600000)) {
        $report.timed_out = $true
        $process.Kill($true)
        $process.WaitForExit(10000) | Out-Null
        throw 'Standard-user lifecycle tests exceeded the 600-second deadline'
    }
    $report.test_exit_code = $process.ExitCode
    $childPath = Join-Path $stage 'result.json'
    if (!(Test-Path -LiteralPath $childPath)) { throw 'Standard-user result is missing' }
    $child = Get-Content -LiteralPath $childPath -Raw | ConvertFrom-Json
    $report.child = $child
    if ($process.ExitCode -ne 0 -or $child.status -ne 'pass' -or $child.is_administrator -ne $false -or
        $child.user_sid -ne $user.SID.Value -or $child.profile_owner_sid -ne $user.SID.Value -or
        $child.agent_sha256 -ne $report.agent_sha256 -or $child.test_sha256 -ne $report.test_sha256 -or
        $child.passed -ne 5 -or $child.failed -ne 0 -or $child.ignored -ne 0) {
        throw 'Standard-user lifecycle evidence did not satisfy all required checks'
    }
    $report.status = 'pass'
    $exitCode = 0
} catch {
    $report.error = $_.Exception.Message
    Write-Warning $report.error
} finally {
    try {
        if (Test-Path -LiteralPath (Join-Path $stage 'lifecycle.log')) {
            Copy-Item -LiteralPath (Join-Path $stage 'lifecycle.log') -Destination (Join-Path $out 'lifecycle.log')
            Get-Content -LiteralPath (Join-Path $out 'lifecycle.log')
        }
        if (Test-Path -LiteralPath (Join-Path $stage 'result.json')) {
            Copy-Item -LiteralPath (Join-Path $stage 'result.json') -Destination (Join-Path $out 'standard-user.json')
        }
    } catch {
        $report.error = "Could not retain lifecycle evidence: $($_.Exception.Message)"
        $report.status = 'error'
        $exitCode = 1
    }
    try {
        if ($user) {
            # Clean up only processes owned by the unique disposable account,
            # including an orphan daemon after a failed or timed-out test.
            foreach ($candidate in Get-CimInstance Win32_Process) {
                $owner = Invoke-CimMethod -InputObject $candidate -MethodName GetOwnerSid -ErrorAction SilentlyContinue
                if ($owner -and $owner.Sid -eq $user.SID.Value) {
                    Stop-Process -Id $candidate.ProcessId -Force -ErrorAction SilentlyContinue
                }
            }
            $ownedProfile = Get-CimInstance Win32_UserProfile -Filter "SID='$($user.SID.Value)'"
            if ($ownedProfile) { $ownedProfile | Remove-CimInstance }
            Remove-LocalUser -SID $user.SID
        }
        $report.account_removed = $true
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
        $report.staging_removed = $true
    } catch {
        $report.cleanup_error = $_.Exception.Message
        $report.status = 'error'
        $exitCode = 1
    }
    if ($process) { $process.Dispose() }
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out 'results.json') -Encoding utf8
}
Write-Output "Standard-user Windows lifecycle: $($report.status). Evidence: $out"
exit $exitCode
