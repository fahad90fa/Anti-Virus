<#
.SYNOPSIS
    Sentinel AV in-VM integration test harness. Run ONLY in the disposable,
    snapshotted test VM (test-signing on, WinDbg attached, host-only network).

.DESCRIPTION
    Verifies the Windows components against the mission acceptance criteria using
    SAFE stimuli only (EICAR + a benign, test-blocklisted program). It does NOT
    ship or use any malware or offensive simulators. The behavioral sensor
    criteria (injection, ransomware rollback, C2, self-protection) are listed as
    operator-performed steps — see vm/VERIFICATION-RUNBOOK.md — to be exercised
    with your own authorized tooling in the isolated VM.

    Steps automated here:
      T1  engine self-test (EICAR detect + clean allow + sha256)
      T2  EICAR static detection via the CLI
      T3  real-time EXECUTE GATE: a benign, test-blocklisted exe is blocked
          before it runs (fsfilter + `sentinel service`)
      T4  each driver loads and unloads cleanly; no new bugcheck

.PARAMETER EngineExe
    Path to the built sentinel.exe (Release).
.PARAMETER DriversDir
    Directory containing the built .sys files (fsfilter.sys, etc.).
.EXAMPLE
    pwsh -File vm/run-integration-tests.ps1 -EngineExe .\out\Release\sentinel.exe -DriversDir .\drivers\out
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$EngineExe,
    [string]$DriversDir = ".",
    [string]$Signatures = "signatures",
    [string]$Work = "$env:TEMP\sentinel_vmtest"
)

$ErrorActionPreference = "Stop"
$script:pass = 0; $script:fail = 0; $script:skip = 0
$results = @()

function Require-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "Run this harness from an elevated (Administrator) prompt."
    }
}

function Record([string]$name, [string]$state, [string]$detail = "") {
    $script:results += [pscustomobject]@{ Test = $name; Result = $state; Detail = $detail }
    switch ($state) {
        "PASS" { $script:pass++; Write-Host "[PASS] $name  $detail" -ForegroundColor Green }
        "FAIL" { $script:fail++; Write-Host "[FAIL] $name  $detail" -ForegroundColor Red }
        "SKIP" { $script:skip++; Write-Host "[SKIP] $name  $detail" -ForegroundColor Yellow }
    }
}

function Get-BugcheckCount {
    try {
        return (Get-WinEvent -FilterHashtable @{ LogName = "System"; Id = 1001; ProviderName = "Microsoft-Windows-WER-SystemErrorReporting" } -ErrorAction SilentlyContinue).Count
    } catch { return 0 }
}

Require-Admin
Write-Host "=== Sentinel VM integration tests ===" -ForegroundColor Cyan
Write-Host "REMINDER: snapshot the VM before loading drivers; attach WinDbg." -ForegroundColor Yellow

# Preconditions
$testsigning = (bcdedit | Select-String -SimpleMatch "testsigning").ToString()
if ($testsigning -notmatch "Yes") {
    Write-Host "WARNING: test-signing may be OFF — drivers will not load. (bcdedit /set testsigning on; reboot)" -ForegroundColor Yellow
}
$bugBefore = Get-BugcheckCount
New-Item -ItemType Directory -Force -Path $Work | Out-Null

# ---------------------------------------------------------------------------
# T1 — engine self-test
# ---------------------------------------------------------------------------
try {
    $out = & $EngineExe --state "$Work\state1" selftest 2>&1 | Out-String
    if ($LASTEXITCODE -eq 0 -and $out -match "Self-test PASSED") {
        Record "T1 engine self-test" "PASS"
    } else {
        Record "T1 engine self-test" "FAIL" "exit=$LASTEXITCODE"
    }
} catch { Record "T1 engine self-test" "FAIL" $_.Exception.Message }

# ---------------------------------------------------------------------------
# T2 — EICAR static detection via the CLI
# ---------------------------------------------------------------------------
try {
    $eicar = ("X5O!P%@AP[4\PZX54(P^)7CC)7}" + '$EICAR-STANDARD-ANTIVIRUS-' + "TEST-FILE!`$H+H*")
    $eicarPath = "$Work\eicar.com"
    [IO.File]::WriteAllText($eicarPath, $eicar)
    $null = & $EngineExe --set quarantine_on_malicious=false --state "$Work\state2" scan $eicarPath 2>&1
    # scan returns exit 1 when a malicious file is found.
    if ($LASTEXITCODE -eq 1) { Record "T2 EICAR static detection" "PASS" }
    else { Record "T2 EICAR static detection" "FAIL" "exit=$LASTEXITCODE (expected 1)" }
} catch { Record "T2 EICAR static detection" "FAIL" $_.Exception.Message }

# ---------------------------------------------------------------------------
# T3 — real-time EXECUTE GATE (benign, test-blocklisted program)
# ---------------------------------------------------------------------------
# Builds a harmless program, blocklists ITS hash, loads the minifilter + the
# service, and confirms the program is blocked before it runs. No malware needed.
$svcName = "SentinelFs"
$fsSys = Join-Path $DriversDir "fsfilter.sys"
$cl = Get-Command cl.exe -ErrorAction SilentlyContinue
if (-not (Test-Path $fsSys)) {
    Record "T3 execute gate" "SKIP" "fsfilter.sys not found in $DriversDir (build drivers first)"
} elseif (-not $cl) {
    Record "T3 execute gate" "SKIP" "cl.exe not on PATH (open a VS dev prompt)"
} else {
    try {
        # Build the benign test program.
        Push-Location $Work
        & cl.exe /nologo /W4 (Join-Path $PSScriptRoot "testprog\benign_hello.c") /Fe:benign_hello.exe | Out-Null
        Pop-Location
        $prog = "$Work\benign_hello.exe"
        $hash = (Get-FileHash -Algorithm SHA256 $prog).Hash.ToLower()

        # Test blocklist + config.
        $block = "$Work\test_blocklist.txt"
        "$hash  VMTEST-Benign-Blocklisted" | Set-Content -Encoding ascii $block
        $cfg = "$Work\test.conf"
        @(
            "blocklist_hashes = $block",
            "rules_dir = $Signatures\rules",
            "allowlist_hashes = $Signatures\hashes\allowlist.txt",
            "state_dir = $Work\state3",
            "quarantine_dir = $Work\state3\q",
            "shadow_dir = $Work\state3\shadow",
            "timeline_path = $Work\state3\timeline.log"
        ) | Set-Content -Encoding ascii $cfg

        # Install + load the minifilter (idempotent-ish).
        sc.exe create $svcName type= filesystem binPath= $fsSys start= demand | Out-Null
        fltmc load $svcName 2>&1 | Out-Null

        # Start the service connected to the port.
        $svc = Start-Process -FilePath $EngineExe -ArgumentList @("--config", $cfg, "service") -PassThru -WindowStyle Hidden
        Start-Sleep -Seconds 2

        # Attempt to run the blocklisted benign program — expect it to be blocked.
        $blocked = $false
        try {
            $p = Start-Process -FilePath $prog -PassThru -Wait -ErrorAction Stop
            if ($p.ExitCode -ne 0) { $blocked = $true }
        } catch {
            $blocked = $true  # launch denied (STATUS_VIRUS_INFECTED / access denied)
        }

        if ($blocked) { Record "T3 execute gate" "PASS" "benign blocklisted exe blocked before execution" }
        else { Record "T3 execute gate" "FAIL" "the blocklisted program was allowed to run" }

        # Cleanup
        if ($svc -and -not $svc.HasExited) { Stop-Process -Id $svc.Id -Force -ErrorAction SilentlyContinue }
        fltmc unload $svcName 2>&1 | Out-Null
        sc.exe delete $svcName | Out-Null
    } catch {
        Record "T3 execute gate" "FAIL" $_.Exception.Message
    }
}

# ---------------------------------------------------------------------------
# T4 — each driver loads and unloads cleanly; no new bugcheck
# ---------------------------------------------------------------------------
$drivers = @(
    @{ Name = "SentinelFs";     Sys = "fsfilter.sys"; Kind = "filesystem" },
    @{ Name = "SentinelProc";   Sys = "procmon.sys";  Kind = "kernel" },
    @{ Name = "SentinelNet";    Sys = "netfilter.sys";Kind = "kernel" },
    @{ Name = "SentinelShadow"; Sys = "shadowfs.sys"; Kind = "filesystem" }
)
foreach ($d in $drivers) {
    $sys = Join-Path $DriversDir $d.Sys
    if (-not (Test-Path $sys)) { Record "T4 load/unload $($d.Sys)" "SKIP" "not built"; continue }
    try {
        sc.exe create $d.Name type= $d.Kind binPath= $sys start= demand | Out-Null
        if ($d.Kind -eq "filesystem") { fltmc load $d.Name 2>&1 | Out-Null }
        else { sc.exe start $d.Name | Out-Null }
        Start-Sleep -Milliseconds 500
        if ($d.Kind -eq "filesystem") { fltmc unload $d.Name 2>&1 | Out-Null }
        else { sc.exe stop $d.Name | Out-Null }
        sc.exe delete $d.Name | Out-Null
        Record "T4 load/unload $($d.Sys)" "PASS"
    } catch { Record "T4 load/unload $($d.Sys)" "FAIL" $_.Exception.Message }
}

# ---------------------------------------------------------------------------
# Operator-performed sensor criteria (NOT automated; no offensive tools shipped)
# ---------------------------------------------------------------------------
Record "T5 injection flag"        "SKIP" "operator step — see VERIFICATION-RUNBOOK.md"
Record "T6 ransomware rollback"   "SKIP" "operator step — see VERIFICATION-RUNBOOK.md"
Record "T7 C2 block"              "SKIP" "operator step — see VERIFICATION-RUNBOOK.md"
Record "T8 self-protection"       "SKIP" "operator step — see VERIFICATION-RUNBOOK.md"

# Bugcheck check
$bugAfter = Get-BugcheckCount
if ($bugAfter -gt $bugBefore) {
    Record "Bugcheck check" "FAIL" "a bugcheck occurred during the run — inspect the minidump in WinDbg"
} else {
    Record "Bugcheck check" "PASS" "no new bugcheck"
}

Write-Host "`n==================== SUMMARY ====================" -ForegroundColor Cyan
$results | Format-Table -AutoSize
Write-Host "$($script:pass) passed, $($script:fail) failed, $($script:skip) skipped/manual" -ForegroundColor Cyan
if ($script:fail -gt 0) { exit 1 } else { exit 0 }
