<#
.SYNOPSIS
    Build the full Sentinel AV product on Windows (drivers + engine + UI).

.DESCRIPTION
    Orchestrates the Windows build:
      1. Kernel drivers + ELAM via MSBuild against the WDK.
      2. The user-mode engine via CMake (MSVC).
      3. The C# dashboard and tray via the .NET SDK.
    Test-signs the drivers for VM testing when -TestSign is set. Never ships a
    test-signed driver to real users (see build/signing/README.md).

    The portable engine + tests build on any platform with CMake; see the repo
    README for the Linux/CI invocation.

.PARAMETER Configuration
    Debug (default) or Release.

.PARAMETER TestSign
    Test-sign the built drivers with the development certificate for VM use.

.EXAMPLE
    pwsh build/build.ps1 -Configuration Debug -TestSign
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [switch]$TestSign,
    [switch]$SkipDrivers,
    [switch]$SkipUi
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Write-Host "Sentinel AV build — $Configuration" -ForegroundColor Cyan

function Invoke-Checked([string]$exe, [string[]]$args) {
    Write-Host ">> $exe $($args -join ' ')" -ForegroundColor DarkGray
    & $exe @args
    if ($LASTEXITCODE -ne 0) { throw "$exe failed ($LASTEXITCODE)" }
}

# 1. User-mode engine (CMake + MSVC).
$engineOut = Join-Path $root "out/engine-win"
Invoke-Checked 'cmake' @('-S', (Join-Path $root 'engine'), '-B', $engineOut,
    '-DSENTINEL_BUILD_TESTS=ON', "-DCMAKE_BUILD_TYPE=$Configuration")
Invoke-Checked 'cmake' @('--build', $engineOut, '--config', $Configuration)
Invoke-Checked 'ctest' @('--test-dir', $engineOut, '--output-on-failure', '-C', $Configuration)

# 2. Kernel drivers + ELAM (MSBuild + WDK).
if (-not $SkipDrivers) {
    $sln = Join-Path $root 'sentinel.sln'
    foreach ($proj in @(
        'drivers/fsfilter/fsfilter.vcxproj',
        'drivers/procmon/procmon.vcxproj',
        'drivers/netfilter/netfilter.vcxproj',
        'drivers/shadowfs/shadowfs.vcxproj',
        'drivers/elam/elam.vcxproj')) {
        Invoke-Checked 'msbuild' @((Join-Path $root $proj),
            "/p:Configuration=$Configuration", '/p:Platform=x64')
    }

    if ($TestSign) {
        & (Join-Path $PSScriptRoot 'signing/test-sign.ps1') -Configuration $Configuration
    }
}

# 3. C# UI + tray (.NET SDK).
if (-not $SkipUi) {
    Invoke-Checked 'dotnet' @('build', (Join-Path $root 'ui/Sentinel.UI/Sentinel.UI.csproj'),
        '-c', $Configuration)
    Invoke-Checked 'dotnet' @('build', (Join-Path $root 'ui/Sentinel.Tray/Sentinel.Tray.csproj'),
        '-c', $Configuration)
}

Write-Host "Build complete." -ForegroundColor Green
