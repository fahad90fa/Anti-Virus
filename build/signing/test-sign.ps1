<#
.SYNOPSIS
    Test-sign built Sentinel drivers for use on a disposable test VM.
.DESCRIPTION
    Signs each .sys with the development certificate (CN=Sentinel-Dev) using
    signtool, and creates catalog files. FOR VM TESTING ONLY — a test-signed
    driver loads only with test-signing enabled and must never reach real users.
    Requires the WDK/SDK signtool and inf2cat on PATH.
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Debug',
    [string]$CertSubject = 'Sentinel-Dev'
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)

$drivers = @(
    "drivers/fsfilter/x64/$Configuration/fsfilter.sys",
    "drivers/procmon/x64/$Configuration/procmon.sys",
    "drivers/netfilter/x64/$Configuration/netfilter.sys",
    "drivers/shadowfs/x64/$Configuration/shadowfs.sys",
    "drivers/elam/x64/$Configuration/elam.sys"
)

foreach ($rel in $drivers) {
    $path = Join-Path $root $rel
    if (-not (Test-Path $path)) {
        Write-Warning "skip (not built): $rel"
        continue
    }
    Write-Host "Test-signing $rel" -ForegroundColor Cyan
    & signtool sign /v /s PrivateCertStore /n $CertSubject `
        /fd SHA256 /t http://timestamp.digicert.com $path
    if ($LASTEXITCODE -ne 0) { throw "signtool failed for $rel" }
}
Write-Host "Test-signing complete (VM use only)." -ForegroundColor Green
