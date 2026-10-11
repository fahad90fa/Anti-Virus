<#
.SYNOPSIS
    Create a one-time self-signed development certificate for test-signing.
.DESCRIPTION
    Creates CN=Sentinel-Dev in a private cert store on the TEST VM. This cert is
    for test-signing on a disposable VM only. It is never exported to the repo
    and never used for production signing (that requires an EV cert + Microsoft
    attestation — see README.md).
#>
[CmdletBinding()]
param([string]$Subject = 'Sentinel-Dev')
$ErrorActionPreference = 'Stop'

$cert = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject "CN=$Subject" `
    -CertStoreLocation 'Cert:\CurrentUser\My' `
    -KeyUsage DigitalSignature `
    -KeyExportPolicy NonExportable `
    -NotAfter (Get-Date).AddYears(2)

Write-Host "Created dev cert: $($cert.Thumbprint)" -ForegroundColor Green
Write-Host "Enable test-signing on this VM: bcdedit /set testsigning on (reboot)" -ForegroundColor Yellow
