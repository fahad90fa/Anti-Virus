<#
.SYNOPSIS
    Provision a disposable Hyper-V VM for Sentinel AV kernel-driver testing.
.DESCRIPTION
    Creates an isolated, snapshot-based test VM with NO bridged networking, ready
    for test-signed driver loads and WinDbg kernel debugging. Run on the HOST.
    This never touches your development machine's own OS.
#>
[CmdletBinding()]
param(
    [string]$VmName = 'Sentinel-Test',
    [Parameter(Mandatory = $true)][string]$IsoPath,
    [int64]$MemoryBytes = 4GB,
    [int64]$DiskBytes = 60GB,
    [string]$SwitchName = 'Sentinel-HostOnly'
)
$ErrorActionPreference = 'Stop'

# Host-only switch so test malware / samples cannot reach a real network.
if (-not (Get-VMSwitch -Name $SwitchName -ErrorAction SilentlyContinue)) {
    New-VMSwitch -Name $SwitchName -SwitchType Internal | Out-Null
    Write-Host "Created host-only switch $SwitchName" -ForegroundColor Green
}

$vhd = Join-Path (Split-Path (Get-VMHost).VirtualHardDiskPath) "$VmName.vhdx"
New-VM -Name $VmName -MemoryStartupBytes $MemoryBytes -Generation 2 `
    -NewVHDPath $vhd -NewVHDSizeBytes $DiskBytes -SwitchName $SwitchName | Out-Null
Set-VM -Name $VmName -AutomaticCheckpointsEnabled $false
Add-VMDvdDrive -VMName $VmName -Path $IsoPath

Write-Host "VM '$VmName' created (host-only, no bridged network)." -ForegroundColor Green
Write-Host "After installing Windows, inside the VM run:" -ForegroundColor Yellow
Write-Host "  bcdedit /set testsigning on" -ForegroundColor Yellow
Write-Host "  bcdedit /debug on   (see vm/kd-config.md for the transport)" -ForegroundColor Yellow
Write-Host "Then take a clean snapshot:  Checkpoint-VM -Name $VmName -SnapshotName Clean" -ForegroundColor Yellow
