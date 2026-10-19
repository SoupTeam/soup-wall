# Uses the same service-owned distro/transport/ownership guards as main's shell CI.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Source,
    [Parameter(Mandatory = $true)][string]$Output,
    [Parameter(Mandatory = $true)][ValidatePattern('\A[0-9a-f]{40}\z')][string]$SourceSha
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$linuxControl = Join-Path $PSScriptRoot 'run-wsl-shell-checks.ps1'
try {
    # Dot-source the existing tested transport after its normal ownership checks.
    . $linuxControl -Check prepare
    $packages = @'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export DEBIAN_FRONTEND=noninteractive
test "$(uname -s)" = Linux
test "$(cat /etc/soupzero-ci-owner)" = "soupzero-ci-wsl-v1 $1"
missing=0
for package in git python3-venv openssl; do
  if ! dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -qx 'install ok installed'; then missing=1; fi
done
if [ "$missing" = 1 ]; then
  apt-get update
  apt-get install --no-install-recommends -y git python3-venv openssl
fi
'@
    Show-CiWsl -Arguments @('--distribution', $distro, '--user', 'root', '--exec', '/bin/bash', '-s', '--', $rootfsHash) -InputText $packages -TimeoutSeconds 600
    $helper = Join-Path $PSScriptRoot 'wall_python_linux.py'
    $payload = @'
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
test "$(uname -s)" = Linux
test "$(id -u)" -ne 0
test "$(cat /etc/soupzero-ci-owner)" = "soupzero-ci-wsl-v1 $5"
exec /usr/bin/python3 "$(wslpath -u "$3")" --source "$(wslpath -u "$1")" --output "$(wslpath -u "$2")" --source-sha "$4"
'@
    Show-CiWsl -Arguments @('--distribution', $distro, '--user', 'soupzero-ci', '--exec', '/bin/bash', '-s', '--',
        ([IO.Path]::GetFullPath($Source)), ([IO.Path]::GetFullPath($Output)), $helper, $SourceSha, $rootfsHash) -InputText $payload -TimeoutSeconds 1800
} finally {
    # Never stop another user's distro or issue a global WSL shutdown.
    & $linuxControl -Check stop
}
