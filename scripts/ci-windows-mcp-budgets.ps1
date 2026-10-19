# SPDX-License-Identifier: Apache-2.0
# Account provisioning is limited to an ephemeral hosted CI runner. Workstation
# operators run verify-windows-mcp-budgets.py directly as a standard user.
param(
    [Parameter(Mandatory = $true)][string]$AgentBinary,
    [Parameter(Mandatory = $true)][string]$NativeTestBinary,
    [Parameter(Mandatory = $true)][string]$OutputDirectory,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$Commit
)
$ErrorActionPreference = 'Stop'
if (!$IsWindows -or $env:GITHUB_ACTIONS -ne 'true') { throw 'Hosted Windows CI runner required' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (!$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The CI launcher needs an administrator token to provision its disposable standard user'
}
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$agent = (Resolve-Path -LiteralPath $AgentBinary).Path
$nativeTests = (Resolve-Path -LiteralPath $NativeTestBinary).Path
$out = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $out) { throw 'Refusing to overwrite budget evidence' }
[IO.Directory]::CreateDirectory($out) | Out-Null
$name = 'swb' + [guid]::NewGuid().ToString('N').Substring(0, 12)
# runner TEMP can have non-traversable/listable parent ACLs for the disposable
# user. Keep the unique stage outside the checkout under ProgramData, with the
# same protected user/SYSTEM/runner-only ACL on the stage itself.
$stage = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) $name
$user = $null
$process = $null
$stageCreated = $false
$exitCode = 1
$report = [ordered]@{
    format = 'sou96-windows-mcp-budget-launcher/1'; status = 'incomplete'; source_commit = $Commit
    binary_sha256 = (Get-FileHash -LiteralPath $agent -Algorithm SHA256).Hash.ToLowerInvariant()
    native_test_binary_sha256 = (Get-FileHash -LiteralPath $nativeTests -Algorithm SHA256).Hash.ToLowerInvariant()
    python_binary_sha256 = $null
    python_runtime_manifest_sha256 = $null
    source_manifest_sha256 = $null; child_exit_code = $null
    timeout_seconds = 240; timed_out = $false; account_removed = $false; staging_removed = $false
    error = $null; phase = 'source_snapshot'; exception_type = $null; hresult = $null; failure_line = $null
}
try {
    $head = (& git -C $repo rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -ne $Commit) { throw 'source_identity_mismatch' }
    $dirty = & git -C $repo status --porcelain --untracked-files=no
    if ($LASTEXITCODE -ne 0 -or $dirty) { throw 'source_not_clean' }
    $files = [ordered]@{}
    foreach ($path in (& git -C $repo ls-files)) {
        $files[$path] = (Get-FileHash -LiteralPath (Join-Path $repo $path) -Algorithm SHA256).Hash.ToLowerInvariant()
    }
    if ($LASTEXITCODE -ne 0 -or $files.Count -eq 0) { throw 'source_manifest_missing' }
    $manifest = [ordered]@{ commit = $Commit; files = $files }
    $manifestPath = Join-Path $out 'source-manifest.json'
    $manifest | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifestPath -Encoding utf8NoBOM
    $report.source_manifest_sha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $report.phase = 'python_runtime_probe'
    $pythonCommand = (Get-Command python -CommandType Application).Source
    $runtimeText = & $pythonCommand -I -B -c 'import json,sys,struct; print(json.dumps({"prefix":sys.base_prefix,"bits":struct.calcsize("P")*8}))'
    if ($LASTEXITCODE -ne 0) { throw 'python_runtime_probe_failed' }
    $runtimeInfo = $runtimeText | ConvertFrom-Json
    if ($runtimeInfo.bits -ne 64) { throw 'native_64bit_python_required' }
    $runtimeSource = [IO.Path]::GetFullPath($runtimeInfo.prefix)
    $sourcePython = Join-Path $runtimeSource 'python.exe'
    if (!(Test-Path -LiteralPath $sourcePython -PathType Leaf) -or
        !(Test-Path -LiteralPath (Join-Path $runtimeSource 'Lib/encodings') -PathType Container) -or
        !(Test-Path -LiteralPath (Join-Path $runtimeSource 'DLLs') -PathType Container)) {
        throw 'standard_cpython_layout_required'
    }
    $report.python_binary_sha256 = (Get-FileHash -LiteralPath $sourcePython -Algorithm SHA256).Hash.ToLowerInvariant()
    $report.phase = 'private_stage'
    $password = ConvertTo-SecureString ('Aa1!' + [guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')) -AsPlainText -Force
    $user = New-LocalUser -Name $name -Password $password -Description 'Disposable MCP resource budget acceptance'
    Add-LocalGroupMember -Group (Get-LocalGroup -SID 'S-1-5-32-545') -Member $user
    $credential = [Management.Automation.PSCredential]::new("$env:COMPUTERNAME\$name", $password)
    if (Test-Path -LiteralPath $stage) { throw 'staging_directory_already_exists' }
    [IO.Directory]::CreateDirectory($stage) | Out-Null
    $stageCreated = $true
    & icacls $stage /inheritance:r /grant:r "*$($identity.User.Value):(OI)(CI)F" "*$($user.SID.Value):(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'staging_acl_setup_failed' }
    # The runner's command may be a user-only shim/runtime. Copy the actual
    # reviewed image CPython runtime into the same private fixture; never grant
    # the disposable account access to runner profiles or source directories.
    $runtime = Join-Path $stage 'python-runtime'
    [IO.Directory]::CreateDirectory($runtime) | Out-Null
    $report.phase = 'python_runtime_copy'
    $runtimeFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $runtimeFiles.Add((Get-Item -LiteralPath $sourcePython))
    foreach ($file in (Get-ChildItem -LiteralPath $runtimeSource -File)) {
        if ($file.Extension -in @('.dll', '.zip') -or $file.Name -eq 'LICENSE.txt') { $runtimeFiles.Add($file) }
    }
    $pending = [System.Collections.Generic.Stack[System.IO.DirectoryInfo]]::new()
    foreach ($subdirectoryName in @('DLLs', 'Lib')) { $pending.Push((Get-Item -LiteralPath (Join-Path $runtimeSource $subdirectoryName))) }
    $directories = 0
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        $directories++
        if ($directories -gt 2048 -or ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'python_runtime_directory_bound_or_reparse'
        }
        foreach ($item in (Get-ChildItem -LiteralPath $directory.FullName -Force)) {
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'python_runtime_reparse_refused' }
            if ($item.PSIsContainer) {
                if ($item.Name -notin @('site-packages', '__pycache__', 'test')) { $pending.Push($item) }
            } else { $runtimeFiles.Add($item) }
            if ($runtimeFiles.Count -gt 8192 -or $pending.Count -gt 2048) { throw 'python_runtime_entry_bound' }
        }
    }
    if (($runtimeFiles | Measure-Object Length -Sum).Sum -gt 256MB) { throw 'python_runtime_copy_bound' }
    $runtimeManifest = [ordered]@{}
    foreach ($file in $runtimeFiles) {
        if (($file.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'python_runtime_reparse_refused' }
        $relative = [IO.Path]::GetRelativePath($runtimeSource, $file.FullName)
        if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)') { throw 'python_runtime_path_invalid' }
        $destination = Join-Path $runtime $relative
        [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($destination)) | Out-Null
        Copy-Item -LiteralPath $file.FullName -Destination $destination
        $digest = (Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($digest -ne (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()) {
            throw 'python_runtime_copy_mismatch'
        }
        $runtimeManifest[$relative.Replace('\', '/')] = $digest
    }
    $runtimeManifestPath = Join-Path $out 'python-runtime-manifest.json'
    $runtimeManifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $runtimeManifestPath -Encoding utf8NoBOM
    $report.python_runtime_manifest_sha256 = (Get-FileHash -LiteralPath $runtimeManifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $python = Join-Path $runtime 'python.exe'
    if ((Get-FileHash -LiteralPath $python -Algorithm SHA256).Hash.ToLowerInvariant() -ne $report.python_binary_sha256) {
        throw 'python_executable_identity_mismatch'
    }
    Copy-Item -LiteralPath $agent -Destination (Join-Path $stage 'agentfw.exe')
    Copy-Item -LiteralPath $nativeTests -Destination (Join-Path $stage 'native-tests.exe')
    Copy-Item -LiteralPath $manifestPath -Destination (Join-Path $stage 'source-manifest.json')
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'verify-windows-mcp-budgets.py') -Destination $stage
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'run-windows-mcp-budgets.ps1') -Destination $stage
    $arguments = "-NoLogo -NoProfile -NonInteractive -File `"$(Join-Path $stage 'run-windows-mcp-budgets.ps1')`" -Root `"$stage`" -Python `"$python`" -Commit $Commit"
    $report.phase = 'standard_user_process'
    $process = Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') -ArgumentList $arguments -Credential $credential -LoadUserProfile -WorkingDirectory $stage -PassThru
    if (!$process.WaitForExit(240000)) {
        $report.timed_out = $true
        $process.Kill($true)
        $process.WaitForExit(10000) | Out-Null
        throw 'standard_user_deadline'
    }
    $report.child_exit_code = $process.ExitCode
    $report.phase = 'native_report_validation'
    $resultPath = Join-Path $stage 'evidence/results.json'
    if (!(Test-Path -LiteralPath $resultPath)) { throw 'native_evidence_missing' }
    $child = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
    if ($process.ExitCode -ne 0 -or $child.status -ne 'pass' -or $child.standard_user -ne $true -or
        $child.administrator_group_present -ne $false -or $child.source_commit -ne $Commit -or
        $child.binary_sha256 -ne $report.binary_sha256 -or
        $child.native_test_binary_sha256 -ne $report.native_test_binary_sha256 -or
        $child.python_binary_sha256 -ne $report.python_binary_sha256 -or
        $child.atomic_launch_controls.Count -ne 2 -or
        @($child.atomic_launch_controls | Where-Object { $_.exit_code -ne 0 -or !$_.exact_one_passed }).Count -ne 0 -or
        $child.source_manifest_sha256 -ne $report.source_manifest_sha256 -or
        $child.cases.Count -ne 20 -or @($child.cases | Where-Object { !$_.passed -or !$_.sibling_useful }).Count -ne 0) {
        throw 'native_qualification_incomplete'
    }
    $report.phase = 'source_verification'
    foreach ($path in $files.Keys) {
        if ((Get-FileHash -LiteralPath (Join-Path $repo $path) -Algorithm SHA256).Hash.ToLowerInvariant() -ne $files[$path]) {
            throw 'source_changed_during_acceptance'
        }
    }
    $report.status = 'pass'
    $exitCode = 0
} catch {
    # Do not publish exception strings that can embed usernames or local paths.
    $report.status = 'fail'
    $report.error = 'windows_budget_qualification_failed'
    $report.exception_type = $_.Exception.GetType().Name
    $report.hresult = $_.Exception.HResult
    $report.failure_line = $_.InvocationInfo.ScriptLineNumber
} finally {
    try {
        foreach ($name in @('results.json', 'launcher.json', 'bootstrap.json')) {
            $source = Join-Path $stage "evidence/$name"
            if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination (Join-Path $out $name) }
        }
        if ($user) {
            # Only the unique disposable acceptance account; never production
            # process enumeration or cleanup authority.
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
        if ($stageCreated -and (Test-Path -LiteralPath $stage)) { Remove-Item -LiteralPath $stage -Recurse -Force }
        $report.staging_removed = $true
    } catch {
        $report.status = 'fail'
        $report.error = 'evidence_retention_or_disposable_cleanup_failed'
        $exitCode = 1
    }
    if ($process) { $process.Dispose() }
    $report | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $out 'ci-launcher.json') -Encoding utf8NoBOM
}
Write-Output "Windows MCP resource budget acceptance: $($report.status)"
exit $exitCode
