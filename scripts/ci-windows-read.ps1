# SPDX-License-Identifier: Apache-2.0
# Disposable hosted-runner standard account. Workstations run the Python driver
# directly from their existing standard account instead of provisioning users.
param(
    [Parameter(Mandatory = $true)][string]$AgentBinary,
    [Parameter(Mandatory = $true)][string]$TestBinary,
    [Parameter(Mandatory = $true)][string]$PythonBinary,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$Commit
)
$ErrorActionPreference = 'Stop'
if (!$IsWindows -or $env:GITHUB_ACTIONS -ne 'true') {
    throw 'Account provisioning is limited to an ephemeral native Windows GitHub Actions runner'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The CI launcher requires an administrator token to create its disposable standard user'
}
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$agent = (Resolve-Path -LiteralPath $AgentBinary).Path
$tests = (Resolve-Path -LiteralPath $TestBinary).Path
$python = (Resolve-Path -LiteralPath $PythonBinary).Path
$out = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $out) { throw 'Refusing to overwrite Windows read evidence' }
[IO.Directory]::CreateDirectory($out) | Out-Null
$name = 'swrd' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$stage = Join-Path ([IO.Path]::GetTempPath()) $name
$user = $null
$process = $null
$exitCode = 1
$report = [ordered]@{
    schema_version = 'sou58-windows-standard-user-launcher/1'; status = 'incomplete'; source_commit = $Commit
    observed_at = [DateTime]::UtcNow.ToString('o'); child_exit_code = $null
    os_version = [Environment]::OSVersion.VersionString
    architecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    powershell_version = $PSVersionTable.PSVersion.ToString()
    agent_sha256 = (Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash.ToLowerInvariant()
    native_test_sha256 = (Get-FileHash -LiteralPath $tests -Algorithm SHA256).Hash.ToLowerInvariant()
    python_sha256 = (Get-FileHash -LiteralPath $python -Algorithm SHA256).Hash.ToLowerInvariant()
    timeout_seconds = 1200; timed_out = $false; account_removed = $false; staging_removed = $false
    error = $null; cleanup_error = $null; child = $null
}
try {
    $password = ConvertTo-SecureString ('Aa1!' + [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')) -AsPlainText -Force
    $user = New-LocalUser -Name $name -Password $password -Description 'Disposable Soup Wall native Windows read acceptance'
    Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545') -Member $user
    $credential = [Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$name", $password)
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    & icacls $stage /inheritance:r /grant:r "*$($identity.User.Value):(OI)(CI)F" "*$($user.SID.Value):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict standard-user fixture staging permissions' }
    # Clone rather than copy a live worktree, and disable newline rewriting so
    # this exact clean source has the same script bytes as the built candidate.
    $source = Join-Path $stage 'source'
    & git -c core.autocrlf=false clone --no-hardlinks --no-checkout --quiet $repo $source
    if ($LASTEXITCODE -ne 0) { throw 'Could not stage the exact source repository' }
    & git -C $source -c core.autocrlf=false checkout --quiet --detach $Commit
    if ($LASTEXITCODE -ne 0) { throw 'Could not check out the exact candidate source' }
    $observed = (& git -C $source rev-parse HEAD).Trim()
    if ($observed -ne $Commit -or (& git -C $source status --porcelain --untracked-files=no)) {
        throw 'Staged source is not the exact clean candidate'
    }
    Copy-Item -LiteralPath $agent -Destination (Join-Path $stage 'agentfw.exe')
    Copy-Item -LiteralPath $tests -Destination (Join-Path $stage 'native-tests.exe')
    # The hosted toolcache is not assumed accessible to the new account. A
    # private full runtime copy also avoids launching another user's Python.
    Copy-Item -LiteralPath (Split-Path -Parent $python) -Destination (Join-Path $stage 'python') -Recurse
    $childScript = Join-Path $stage 'run.ps1'
    @'
param([string]$Root, [string]$ExpectedCommit)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Standard user required' }
$temporary = Join-Path $Root 'owned-temp'
[IO.Directory]::CreateDirectory($temporary) | Out-Null
$owner = (Get-Acl -LiteralPath $temporary).GetOwner([Security.Principal.SecurityIdentifier]).Value
if ($owner -ne $identity.User.Value) { throw 'Fixture temporary directory must be owned by the standard user' }
$env:TEMP = $temporary
$env:TMP = $temporary
$env:PYTHONDONTWRITEBYTECODE = '1'
$python = Join-Path $Root 'python/python.exe'
$source = Join-Path $Root 'source'
$output = Join-Path $Root 'acceptance.json'
& $python -B (Join-Path $source 'scripts/verify-sou58-windows-read.py') --run --repo $source `
    --agentfw (Join-Path $Root 'agentfw.exe') --native-test-binary (Join-Path $Root 'native-tests.exe') `
    --expected-commit $ExpectedCommit --output $output *> (Join-Path $Root 'driver.log')
$code = $LASTEXITCODE
[ordered]@{ user_sid = $identity.User.Value; profile_owner_sid = $owner; exit_code = $code } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'identity.json') -Encoding utf8
exit $code
'@ | Set-Content -LiteralPath $childScript -Encoding utf8
    $arguments = "-NoLogo -NoProfile -NonInteractive -File `"$childScript`" -Root `"$stage`" -ExpectedCommit $Commit"
    $process = Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') -ArgumentList $arguments -Credential $credential `
        -LoadUserProfile -WorkingDirectory $stage -PassThru
    if (!$process.WaitForExit(1200000)) {
        $report.timed_out = $true
        $process.Kill($true)
        $process.WaitForExit(10000) | Out-Null
        throw 'Standard-user native Windows read acceptance exceeded the 1200-second deadline'
    }
    $report.child_exit_code = $process.ExitCode
    $child = Get-Content -LiteralPath (Join-Path $stage 'acceptance.json') -Raw | ConvertFrom-Json
    $childIdentity = Get-Content -LiteralPath (Join-Path $stage 'identity.json') -Raw | ConvertFrom-Json
    $report.child = [ordered]@{ status = $child.status; acceptance_passed = $child.acceptance_passed; summary = $child.summary
        standard_user = $child.standard_user; profile_owner_sid = $childIdentity.profile_owner_sid }
    if ($process.ExitCode -ne 0 -or $child.status -ne 'pass' -or $child.acceptance_passed -ne $true -or
        $child.standard_user.is_administrator -ne $false -or $child.standard_user.administrator_group_present -ne $false -or
        $child.standard_user.sid -ne $user.SID.Value -or $childIdentity.user_sid -ne $user.SID.Value -or
        $childIdentity.profile_owner_sid -ne $user.SID.Value -or
        $child.binary_sha256 -ne $report.agent_sha256 -or $child.native_test_binary_sha256 -ne $report.native_test_sha256 -or
        $child.source_before.commit -ne $Commit -or $child.source_before.tracked_dirty -ne $false -or
        $child.source_before.untracked_present -ne $false -or
        $child.source_binary_stable -ne $true -or $child.summary.skips -ne 0 -or $child.summary.failed -ne 0 -or
        $child.summary.observed -ne $child.summary.expected) {
        throw 'Standard-user native Windows evidence did not satisfy all required checks'
    }
    $report.status = 'pass'
    $exitCode = 0
} catch {
    $report.error = $_.Exception.Message
    Write-Warning $report.error
} finally {
    try {
        foreach ($file in @('acceptance.json', 'identity.json', 'driver.log')) {
            $path = Join-Path $stage $file
            if (Test-Path -LiteralPath $path) { Copy-Item -LiteralPath $path -Destination (Join-Path $out $file) }
        }
        if (Test-Path -LiteralPath (Join-Path $out 'driver.log')) { Get-Content -LiteralPath (Join-Path $out 'driver.log') }
        $acceptancePath = Join-Path $out 'acceptance.json'
        if ($report.status -ne 'pass' -and (Test-Path -LiteralPath $acceptancePath)) {
            $failure = Get-Content -LiteralPath $acceptancePath -Raw | ConvertFrom-Json
            Write-Output "Native Windows acceptance failure: $($failure.status); $($failure.error)"
            foreach ($stream in @('stdout', 'stderr')) {
                $text = [string]$failure.native_tests.$stream
                if ($text) {
                    Write-Output "Owned native tests $stream (maximum 32768 characters):"
                    if ($text.Length -gt 32768) {
                        Write-Output $text.Substring(0, 32768)
                        Write-Output '[TRUNCATED: native test diagnostics exceeded 32768 characters; complete bytes retained in acceptance.json]'
                    } else { Write-Output $text }
                }
            }
        }
    } catch {
        $report.error = "Could not retain read acceptance evidence: $($_.Exception.Message)"
        $report.status = 'incomplete'
        $exitCode = 1
    }
    try {
        if ($user) {
            # Only the unique disposable account is eligible for orphan cleanup.
            foreach ($candidate in Get-CimInstance Win32_Process) {
                $owner = Invoke-CimMethod -InputObject $candidate -MethodName GetOwnerSid -ErrorAction SilentlyContinue
                if ($owner -and $owner.Sid -eq $user.SID.Value) {
                    Stop-Process -Id $candidate.ProcessId -Force -ErrorAction SilentlyContinue
                }
            }
            $profile = Get-CimInstance Win32_UserProfile -Filter "SID='$($user.SID.Value)'"
            if ($profile) { $profile | Remove-CimInstance }
            Remove-LocalUser -SID $user.SID
        }
        $report.account_removed = $true
        if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
        $report.staging_removed = $true
    } catch {
        $report.cleanup_error = $_.Exception.Message
        $report.status = 'incomplete'
        $exitCode = 1
    }
    if ($process) { $process.Dispose() }
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out 'launcher.json') -Encoding utf8
}
Write-Output "Standard-user native Windows read: $($report.status). Evidence: $out"
exit $exitCode
