# CI-owned Linux userland on the persistent Windows VPS. Machine WSL support is
# enabled by the operator, not this script. Never adopts another user's distro.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('prepare', 'syntax', 'dev', 'libc', 'checksum', 'manifest', 'stop')]
    [string]$Check
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function ConvertFrom-CiWslBytes([byte[]]$Bytes) {
    if (-not $Bytes.Length) { return '' }
    # WSL's Windows CLI can emit UTF-16; Linux commands emit UTF-8. Decode each
    # stream, rather than deleting NULs and corrupting non-ASCII diagnostics.
    if (($Bytes.Length -ge 2 -and $Bytes[0] -eq 255 -and $Bytes[1] -eq 254) -or
        ($Bytes.Length -ge 2 -and $Bytes[1] -eq 0)) {
        return [Text.Encoding]::Unicode.GetString($Bytes).TrimStart([char]0xFEFF)
    }
    return [Text.Encoding]::UTF8.GetString($Bytes).TrimStart([char]0xFEFF)
}

function Invoke-CiWsl(
    [string[]]$Arguments,
    [string]$InputText = '',
    [int]$TimeoutSeconds = 120,
    [int[]]$AllowedExitCodes = @(0)
) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $wsl.Source
    $info.UseShellExecute = $false
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.RedirectStandardInput = $true
    $info.StandardInputEncoding = [Text.UTF8Encoding]::new($false)
    foreach ($argument in $Arguments) { $info.ArgumentList.Add($argument) }
    $process = [Diagnostics.Process]::Start($info)
    $outBuffer = [IO.MemoryStream]::new()
    $errBuffer = [IO.MemoryStream]::new()
    try {
        $outTask = $process.StandardOutput.BaseStream.CopyToAsync($outBuffer)
        $errTask = $process.StandardError.BaseStream.CopyToAsync($errBuffer)
        # .ps1 checkout is CRLF; Linux stdin must remain LF, without a BOM.
        $process.StandardInput.Write($InputText.Replace("`r`n", "`n"))
        $process.StandardInput.Close()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw 'Owned WSL command timed out; cleanup must terminate only the CI distro.'
        }
        # Runtime generic Task<VoidTaskResult> may otherwise leak a value into
        # PowerShell's success pipeline alongside the structured process result.
        [void]$outTask.GetAwaiter().GetResult()
        [void]$errTask.GetAwaiter().GetResult()
        $output = ConvertFrom-CiWslBytes $outBuffer.ToArray()
        $errorText = ConvertFrom-CiWslBytes $errBuffer.ToArray()
        if ($process.ExitCode -notin $AllowedExitCodes) {
            throw "WSL exit $($process.ExitCode): $output $errorText"
        }
        return [pscustomobject]@{ ExitCode = $process.ExitCode; Output = $output; ErrorText = $errorText }
    } finally {
        $process.Dispose()
        $outBuffer.Dispose()
        $errBuffer.Dispose()
    }
}

function Show-CiWsl([string[]]$Arguments, [string]$InputText = '', [int]$TimeoutSeconds = 120) {
    $result = Invoke-CiWsl -Arguments $Arguments -InputText $InputText -TimeoutSeconds $TimeoutSeconds
    if ($result.Output) { Write-Host $result.Output }
    if ($result.ErrorText) { Write-Host $result.ErrorText }
}

function Get-CiWslDistributions([switch]$RunningOnly) {
    $arguments = @('--list', '--quiet')
    if ($RunningOnly) { $arguments += '--running' }
    $result = Invoke-CiWsl -Arguments $arguments -TimeoutSeconds 30 -AllowedExitCodes @(0, 1, -1)
    $text = $result.Output + $result.ErrorText
    if ($result.ExitCode -ne 0) {
        if ($text -match 'has no installed distributions|WSL_E_DEFAULT_DISTRO_NOT_FOUND') { return }
        throw "Cannot enumerate service-owned WSL distributions: $text (exit $($result.ExitCode))"
    }
    $result.Output.Split("`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

function Assert-CiLinuxPath([string]$Path) {
    if ((Test-Path -LiteralPath $Path) -and
        ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "Refusing a linked CI Linux path: $Path"
    }
}

function Read-CiLinuxOwner {
    Assert-CiLinuxPath $ownerFile
    $owner = Get-Content -LiteralPath $ownerFile -Raw | ConvertFrom-Json
    if ($owner.packageId -ne $packageId -or $owner.distro -ne $distro -or
        $owner.rootfsSha256 -ne $rootfsHash -or $owner.ciRoot -ne $ciRoot -or $owner.ready -isnot [bool]) {
        throw 'Foreign or changed Linux ownership marker; refusing to adopt or replace it.'
    }
    return $owner
}

function Save-CiLinuxOwner($Owner) {
    $temporary = $ownerFile + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    [IO.File]::WriteAllText($temporary, ($Owner | ConvertTo-Json), [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($temporary, $ownerFile, $true)
}

function Assert-CiLinuxArchive([string]$Path, [string]$ExpectedHash) {
    Assert-CiLinuxPath $Path
    if ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ine $ExpectedHash) {
        throw 'Ubuntu Base SHA-256 mismatch; archive not imported.'
    }
}

if ($PSVersionTable.PSVersion.Major -lt 7 -or $env:OS -ne 'Windows_NT') { throw 'Use native Windows PowerShell 7.' }
if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-20') {
    throw 'Use the registered NETWORK SERVICE runner, not an administrator distro.'
}
Write-Host 'WSL owner: runner service SID S-1-5-20 (NETWORK SERVICE).'
if (-not $env:SOUPZERO_CI_ROOT) { throw 'CI root is missing.' }
$ciRoot = [IO.Path]::GetFullPath($env:SOUPZERO_CI_ROOT).TrimEnd('\')
Assert-CiLinuxPath $ciRoot
$hostOwner = Get-Content -LiteralPath (Join-Path $ciRoot '.soupzero-ci-host.json') -Raw | ConvertFrom-Json
if ($hostOwner.packageId -ne 'soupzero-ci-host-v1' -or $hostOwner.state -ne 'installed') { throw 'Unrecognized CI host.' }
$wsl = Get-Command wsl.exe -ErrorAction Stop
$distro = 'SoupZero-CI-Linux'
$directory = Join-Path $ciRoot 'cache\wsl-linux'
$ownerFile = Join-Path $directory 'owner.json'
$rootfsName = 'ubuntu-base-24.04.4-base-amd64.tar.gz'
# Official release/SHA256SUMS from cdimage.ubuntu.com; never accept an override.
$rootfsHash = 'c1e67ef7b17a6300e136118bd1dc04725009cb376c1aad10abcf8cd453628d58'
$packageId = 'soupzero-ci-wsl-v1'
foreach ($path in @((Join-Path $ciRoot 'cache'), $directory, (Join-Path $directory 'rootfs'))) {
    Assert-CiLinuxPath $path
}

if ($Check -eq 'stop') {
    if (Test-Path -LiteralPath $ownerFile -PathType Leaf) {
        $null = Read-CiLinuxOwner
        if (@(Get-CiWslDistributions -RunningOnly) -contains $distro) {
            Show-CiWsl -Arguments @('--terminate', $distro) -TimeoutSeconds 30
        }
        if (@(Get-CiWslDistributions -RunningOnly) -contains $distro) { throw 'Owned Linux distro is still running.' }
        Write-Host 'CI Linux distro is stopped; its registration/cache and other distros are retained.'
    }
    return
}

if ($Check -eq 'prepare') {
    Show-CiWsl -Arguments @('--version') -TimeoutSeconds 30
    Show-CiWsl -Arguments @('--status') -TimeoutSeconds 30
    $registered = @(Get-CiWslDistributions) -contains $distro
    if (-not (Test-Path -LiteralPath $ownerFile -PathType Leaf)) {
        if ($registered -or (Test-Path -LiteralPath $directory)) { throw 'Existing unowned CI Linux path/distribution; refusing to adopt or replace it.' }
        New-Item -ItemType Directory -Path $directory | Out-Null
        Save-CiLinuxOwner ([ordered]@{ packageId = $packageId; distro = $distro; rootfsSha256 = $rootfsHash; ciRoot = $ciRoot; ready = $false })
    }
    $owner = Read-CiLinuxOwner
    if (-not $registered) {
        $archive = Join-Path $directory $rootfsName
        if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
            $partial = $archive + '.' + [guid]::NewGuid().ToString('N') + '.partial'
            Invoke-WebRequest -Uri ('https://cdimage.ubuntu.com/ubuntu-base/releases/24.04/release/' + $rootfsName) -OutFile $partial -TimeoutSec 300
            Assert-CiLinuxArchive $partial $rootfsHash
            Move-Item -LiteralPath $partial -Destination $archive
        }
        Assert-CiLinuxArchive $archive $rootfsHash
        Write-Host "Verified Ubuntu Base rootfs SHA-256: $rootfsHash"
        $installPath = Join-Path $directory 'rootfs'
        if (Test-Path -LiteralPath $installPath) { throw 'Incomplete import retained; inspect its owned root before another import.' }
        Show-CiWsl -Arguments @('--import', $distro, $installPath, $archive, '--version', '2') -TimeoutSeconds 180
        $owner.ready = $false
        Save-CiLinuxOwner $owner
    }
    if (-not $owner.ready) {
        $bootstrap = @'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive
dpkg --configure -a
apt-get update
apt-get install --no-install-recommends -y bash coreutils curl ca-certificates python3 file tar gzip xz-utils passwd
if ! id soupzero-ci >/dev/null 2>&1; then useradd --create-home --shell /bin/bash soupzero-ci; fi
printf '%s\n' "soupzero-ci-wsl-v1 $1" > /etc/soupzero-ci-owner
chmod 0644 /etc/soupzero-ci-owner
'@
        Show-CiWsl -Arguments @('--distribution', $distro, '--user', 'root', '--exec', '/bin/bash', '-s', '--', $rootfsHash) -InputText $bootstrap -TimeoutSeconds 600
        $owner.ready = $true
        Save-CiLinuxOwner $owner
    } else { Write-Host 'Reusing the owned CI Linux registration; no rootfs download or package installation.' }
    Show-CiWsl -Arguments @('--list', '--verbose') -TimeoutSeconds 30
    Show-CiWsl -Arguments @('--distribution', $distro, '--user', 'soupzero-ci', '--exec', '/bin/bash', '-c', 'set -eu; test "$(uname -s)" = Linux; cat /etc/os-release; uname -a; id; /usr/bin/python3 --version')
    return
}

$owner = Read-CiLinuxOwner
if (-not $owner.ready) { throw 'CI Linux bootstrap has not completed.' }
if (-not $env:GITHUB_WORKSPACE) { throw 'Recorded checkout is missing.' }
Write-Host "Recorded Windows checkout: $env:GITHUB_WORKSPACE; check: $Check"
$payload = @'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PYTHON=/usr/bin/python3
test "$(uname -s)" = Linux
test "$(id -u)" -ne 0
test "$(cat /etc/soupzero-ci-owner)" = "soupzero-ci-wsl-v1 $2"
printf 'Linux execution: %s; check: %s; workspace: %s\n' "$(uname -a)" "$1" "$PWD"
case "$1" in
  syntax) for script in scripts/*.sh scripts/tests/*.sh; do bash -n "$script"; done ;;
  dev) bash scripts/tests/test-dev.sh ;;
  libc) bash scripts/tests/test-fetch-uv.sh ;;
  checksum) bash scripts/tests/test-fetch-uv-checksum.sh ;;
  manifest) bash scripts/tests/test-updater-manifest.sh ;;
  *) exit 2 ;;
esac
'@
# --cd accepts an absolute Windows path; no distro-specific wslpath dependency.
Show-CiWsl -Arguments @('--distribution', $distro, '--user', 'soupzero-ci', '--cd', $env:GITHUB_WORKSPACE, '--exec', '/bin/bash', '-s', '--', $Check, $rootfsHash) -InputText $payload
