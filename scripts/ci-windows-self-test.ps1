# SPDX-License-Identifier: Apache-2.0
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
if (Test-Path -LiteralPath $out) { throw 'Refusing to overwrite Windows self-test evidence' }
[IO.Directory]::CreateDirectory($out) | Out-Null
$name = 'swst' + [guid]::NewGuid().ToString('N').Substring(0, 12)
$stageParent = [Environment]::GetFolderPath([System.Environment+SpecialFolder]::CommonApplicationData)
if ([string]::IsNullOrWhiteSpace($stageParent)) { throw 'CommonApplicationData staging parent is unavailable' }
$stage = Join-Path $stageParent $name
$user = $null
$process = $null
$exitCode = 1
$report = [ordered]@{
    schema_version = 'sou71-windows-standard-user-launcher/1'; status = 'incomplete'; source_commit = $Commit
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
    $user = New-LocalUser -Name $name -Password $password -Description 'Disposable Soup Wall Windows self-test CI'
    Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545') -Member $user
    $credential = [Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$name", $password)
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    & icacls $stage /inheritance:r /grant:r "*$($identity.User.Value):(OI)(CI)F" "*$($user.SID.Value):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict standard-user fixture staging permissions' }
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
& icacls $temporary /inheritance:r /grant:r "*$($identity.User.Value):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not restrict the fresh standard-user temporary directory' }
$env:TEMP = $temporary
$env:TMP = $temporary
$env:PYTHONDONTWRITEBYTECODE = '1'
$python = Join-Path $Root 'python/python.exe'
$source = Join-Path $Root 'source'
$output = Join-Path $Root 'acceptance.json'
$env:SELF_TEST_PYTHON = $python
& (Join-Path $Root 'native-tests.exe') 'self_test::' --test-threads=1 *> (Join-Path $Root 'native-tests.log')
if ($LASTEXITCODE -ne 0) { throw 'Self-test unit regressions failed' }
& $python -B (Join-Path $source 'scripts/test-windows-self-test.py') `
    --agent (Join-Path $Root 'agentfw.exe') --baseline (Join-Path $source 'rule_baseline/rule_baseline.py') `
    --out (Join-Path $Root 'results') *> (Join-Path $Root 'driver.log')
$driverCode = $LASTEXITCODE
Copy-Item -LiteralPath (Join-Path $Root 'results/acceptance.json') -Destination $output
$global:LASTEXITCODE = $driverCode
$code = $LASTEXITCODE
[ordered]@{ user_sid = $identity.User.Value; profile_owner_sid = $owner; exit_code = $code } |
    ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Root 'identity.json') -Encoding utf8
exit $code
'@ | Set-Content -LiteralPath $childScript -Encoding utf8
    $arguments = "-NoLogo -NoProfile -NonInteractive -File `"$childScript`" -Root `"$stage`" -ExpectedCommit $Commit"
    $process = Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') -ArgumentList $arguments -Credential $credential `
        -LoadUserProfile -WorkingDirectory $stage -PassThru -WindowStyle Hidden
    if (!$process.WaitForExit(1200000)) {
        $report.timed_out = $true
        $process.Kill($true)
        $process.WaitForExit(10000) | Out-Null
        throw 'Standard-user native Windows self-test acceptance exceeded the 1200-second deadline'
    }
    $report.child_exit_code = $process.ExitCode
    $child = Get-Content -LiteralPath (Join-Path $stage 'acceptance.json') -Raw | ConvertFrom-Json
    $childIdentity = Get-Content -LiteralPath (Join-Path $stage 'identity.json') -Raw | ConvertFrom-Json
    $report.child = [ordered]@{ status = $child.status; passed = $child.passed; failed = $child.failed
        current_user_owns_temporary = $childIdentity.user_sid -eq $childIdentity.profile_owner_sid }
    if ($process.ExitCode -ne 0 -or $child.status -ne 'passed' -or $child.failed -ne 0 -or
        $child.native_windows -ne $true -or $child.elevated -ne $false -or $child.administrator_group_present -ne $false -or
        $childIdentity.user_sid -ne $user.SID.Value -or $childIdentity.profile_owner_sid -ne $user.SID.Value -or
        $child.agent_sha256 -ne $report.agent_sha256 -or $child.passed -ne 19) {
        throw 'Native standard-user self-test acceptance did not satisfy all required checks'
    }
    $report.status = 'pass'
    $exitCode = 0
} catch {
    $report.error = $_.Exception.Message
    Write-Warning $report.error
} finally {
    try {
        foreach ($file in @('acceptance.json', 'identity.json', 'driver.log', 'native-tests.log')) {
            $path = Join-Path $stage $file
            if (Test-Path -LiteralPath $path) { Copy-Item -LiteralPath $path -Destination (Join-Path $out $file) }
        }
        $results = Join-Path $stage 'results'
        if (Test-Path -LiteralPath $results) { Copy-Item -LiteralPath $results -Destination (Join-Path $out 'results') -Recurse }
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
        $resolvedStage = [IO.Path]::GetFullPath($stage)
        if ($name -notmatch '^swst[0-9a-f]{12}$' -or $resolvedStage -ne [IO.Path]::GetFullPath((Join-Path $stageParent $name)) -or
            [IO.Path]::GetDirectoryName($resolvedStage) -ne [IO.Path]::GetFullPath($stageParent).TrimEnd('\')) {
            throw 'Refusing cleanup outside disposable CI staging'
        }
        if (Test-Path -LiteralPath $resolvedStage) { Remove-Item -LiteralPath $resolvedStage -Recurse -Force }
        $report.staging_removed = $true
    } catch {
        $report.cleanup_error = $_.Exception.Message
        $report.status = 'incomplete'
        $exitCode = 1
    }
    if ($process) { $process.Dispose() }
    $report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $out 'launcher.json') -Encoding utf8
}
Write-Output "Standard-user native Windows self-test: $($report.status). Evidence: $out"
exit $exitCode
