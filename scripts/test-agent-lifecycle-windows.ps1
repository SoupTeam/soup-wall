param(
    [Parameter(Mandatory = $true)]
    [string]$AgentBinary
)

$ErrorActionPreference = 'Stop'
$agent = (Resolve-Path -LiteralPath $AgentBinary).Path
$profileRoot = Join-Path ([IO.Path]::GetTempPath()) ("agentfw-lifecycle-" + [guid]::NewGuid().ToString('N'))
$agentHome = Join-Path $profileRoot '.agentfw'
$originalProfile = $env:USERPROFILE
$count = 0

function Invoke-Agent {
    param(
        [string[]]$Arguments,
        [bool]$ShouldSucceed = $true
    )
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $agent
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.ArgumentList.Add('lifecycle')
    foreach ($argument in $Arguments) { $start.ArgumentList.Add($argument) }
    $capture = $Arguments[0] -eq 'status'
    $start.RedirectStandardOutput = $capture
    $start.RedirectStandardError = $capture
    $process = [Diagnostics.Process]::Start($start)
    try {
        $output = if ($capture) { $process.StandardOutput.ReadToEnd() } else { '' }
        $errors = if ($capture) { $process.StandardError.ReadToEnd() } else { '' }
        $process.WaitForExit()
        $succeeded = $process.ExitCode -eq 0
    } finally {
        $process.Dispose()
    }
    if ($succeeded -ne $ShouldSucceed) {
        throw "Unexpected exit for $($Arguments -join ' '): $output $errors"
    }
    $script:count++
    return $output
}

function Get-Status {
    return (Invoke-Agent -Arguments @('status') | ConvertFrom-Json)
}

try {
    [IO.Directory]::CreateDirectory($agentHome) | Out-Null
    $env:USERPROFILE = $profileRoot
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    [IO.File]::WriteAllText((Join-Path $agentHome 'config.yaml'), "port: $port`n")
    [IO.File]::WriteAllText((Join-Path $agentHome 'foreign.txt'), 'keep')

    $first = Join-Path $profileRoot 'candidate-one.exe'
    $second = Join-Path $profileRoot 'candidate-two.exe'
    $failed = Join-Path $profileRoot 'invalid.exe'
    [IO.File]::Copy($agent, $first)
    [IO.File]::Copy($agent, $second)
    $stream = [IO.File]::OpenWrite($second)
    try {
        $stream.Seek(0, [IO.SeekOrigin]::End) | Out-Null
        $bytes = [Text.Encoding]::ASCII.GetBytes("second-version")
        $stream.Write($bytes, 0, $bytes.Length)
    } finally {
        $stream.Dispose()
    }
    [IO.File]::WriteAllText($failed, 'not an executable')
    $oneHash = (Get-FileHash -LiteralPath $first -Algorithm SHA256).Hash.ToLowerInvariant()
    $twoHash = (Get-FileHash -LiteralPath $second -Algorithm SHA256).Hash.ToLowerInvariant()
    $failedHash = (Get-FileHash -LiteralPath $failed -Algorithm SHA256).Hash.ToLowerInvariant()

    Invoke-Agent -Arguments @('install', 'one', $first, '--sha256', ('0' * 64)) -ShouldSucceed $false | Out-Null
    if ((Get-Status).active) { throw 'Mismatched digest activated a candidate' }
    Invoke-Agent -Arguments @('install', 'one', $first, '--sha256', $oneHash) | Out-Null
    Invoke-Agent -Arguments @('start') | Out-Null
    if (!(Get-Status).running) { throw 'Managed Agent did not start' }
    Invoke-Agent -Arguments @('upgrade', 'two', $second, '--sha256', $twoHash) | Out-Null
    $updated = Get-Status
    if (!$updated.running -or $updated.active.version -ne 'two') { throw 'Upgrade was not healthy' }
    Invoke-Agent -Arguments @('rollback') | Out-Null
    $restored = Get-Status
    if (!$restored.running -or $restored.active.version -ne 'one') { throw 'Rollback did not restore Agent' }
    Invoke-Agent -Arguments @('upgrade', 'broken', $failed, '--sha256', $failedHash) -ShouldSucceed $false | Out-Null
    $afterFailure = Get-Status
    if (!$afterFailure.running -or $afterFailure.active.version -ne 'one' -or $afterFailure.interrupted) {
        throw 'Failed upgrade did not restore the working Agent'
    }
    Invoke-Agent -Arguments @('stop') | Out-Null
    if ((Get-Status).running) { throw 'Agent is still running after stop' }
    Invoke-Agent -Arguments @('start') | Out-Null
    Invoke-Agent -Arguments @('restart') | Out-Null
    if (!(Get-Status).running) { throw 'Agent did not restart' }
    Invoke-Agent -Arguments @('remove') | Out-Null
    if ((Get-Status).active) { throw 'Agent is still installed after removal' }
    if (!(Test-Path -LiteralPath (Join-Path $agentHome 'config.yaml'))) { throw 'Configuration was removed' }
    if (!(Test-Path -LiteralPath (Join-Path $agentHome 'token'))) { throw 'Token was removed' }
    if (!(Test-Path -LiteralPath (Join-Path $agentHome 'audit.jsonl'))) { throw 'Audit log was removed' }
    if (!(Test-Path -LiteralPath (Join-Path $agentHome 'foreign.txt'))) { throw 'Foreign file was removed' }
    foreach ($version in @('one', 'two', 'broken')) {
        if (Test-Path -LiteralPath (Join-Path $agentHome "versions/agentfw-$version.exe")) {
            throw "Managed version $version remains after removal"
        }
    }
    Write-Output "Windows lifecycle: PASS ($count commands, port $port)"
} finally {
    try {
        $current = Get-Status
        if ($current.process) { Invoke-Agent -Arguments @('stop') | Out-Null }
    } catch {}
    $env:USERPROFILE = $originalProfile
    if (Test-Path -LiteralPath $profileRoot) {
        $resolved = [IO.Path]::GetFullPath($profileRoot)
        $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if (!$resolved.StartsWith($tempRoot, [StringComparison]::OrdinalIgnoreCase) -or
            !(Split-Path -Leaf $resolved).StartsWith('agentfw-lifecycle-')) {
            throw "Refusing to remove unexpected path: $resolved"
        }
        Remove-Item -LiteralPath $resolved -Recurse -Force
    }
}
