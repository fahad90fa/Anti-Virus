# Sentinel AV — VM verification runbook

How to take the Windows components from **CI-build-verified** to **VM-runtime-
verified**, mapping each mission acceptance criterion (AC) to a concrete step.

Run everything here in a **disposable, snapshotted VM** with test-signing on,
WinDbg attached, and host-only networking. Never on a host; never with live
malware. The only stimuli used are the EICAR test string, a benign
test-blocklisted program, and — for the behavioral sensors — your own authorized
test tooling.

## 0. Prerequisites (once per VM)

```powershell
bcdedit /set testsigning on
bcdedit /debug on
# configure the kernel debug transport, then reboot (see vm/kd-config.md)
Checkpoint-VM -Name Sentinel-Test -SnapshotName Clean   # on the host
```

Install VS 2022 + the matching WDK/SDK and .NET 8. Build everything:

```powershell
pwsh build/build.ps1 -Configuration Release -TestSign
```

The portable engine + 71 tests also build/run cross-platform; CI
(`.github/workflows/ci.yml`) already proves the engine (Linux + MSVC) and the
.NET UI compile, and attempts the WDK driver build.

## 1. Solution builds clean (Task 1 AC)

- CI `engine-windows` (MSVC `/W4 /WX`) and `ui-windows` (.NET 8) must be green.
- CI `drivers-windows` builds the `.sys` set with the WDK; if the hosted runner
  cannot provide the WDK VS integration, build the drivers in the VM with
  `build/build.ps1` and confirm a clean Release.
- **Verify:** no warnings-as-errors, no stubs in any Windows code path.

## 2. Kernel⇄user comms round-trip (Task 2 AC)

1. Snapshot. Load the minifilter: `fltmc load SentinelFs`.
2. Start the engine service: `sentinel --config <cfg> service`.
3. The service logs `connected to minifilter port`. Open a file under a watched
   path; WinDbg (`!fltkd.filters`) shows the message/verdict round-trip.
4. **Version mismatch:** temporarily build the service with a bumped
   `SENTINEL_PROTOCOL_VERSION` and confirm the service logs a rejection and the
   kernel applies its fail-safe (no hang).

## 3. File execute gate (Task 3 AC) — automated by the harness

```powershell
pwsh -File vm/run-integration-tests.ps1 -EngineExe .\out\Release\sentinel.exe -DriversDir .\drivers\out
```

- **T2** confirms EICAR static detection.
- **T3** builds a benign program, blocklists its hash, loads `fsfilter` + the
  service, and confirms the program is **blocked before it runs** (no malware
  used). Measure added latency with `tools/benchmark` and compare to the
  < 1 ms cached-path budget and the few-to-low-tens-of-ms cache-miss budget.
- **Fail-safe:** stop the service and confirm the machine keeps working (the
  gate fails open by default; `service --fail-closed` denies unknowns instead).
  There must be no deadlock and no hard-block of the OS.

## 4. Process/thread/image/registry callbacks (Task 4 AC) — operator step

Use your own authorized test tooling in the isolated VM to produce:
- the allocate→write→remote-thread **injection chain** → the thread callback
  reports a remote thread and the behavioral engine flags it;
- a **malicious test launch** (a benign exe whose hash you blocklisted) → the
  process-create callback vetoes it;
- a **Run-key persistence** write → the registry callback reports it.

Confirm each via the engine timeline (`sentinel` logs / the sealed timeline) and
WinDbg. The detection logic itself is already unit-tested on the engine side;
this step verifies the kernel sensors forward the events.

## 5. Object-callback self-protection (Task 5 AC) — operator step

From an elevated prompt, attempt `OpenProcess(PROCESS_TERMINATE | PROCESS_VM_WRITE)`
on the Sentinel service and try to terminate/inject it. Expect `ACCESS_DENIED`
(the object callback strips those rights). Confirm Sentinel's own processes are
protected and that **no other** security product or OS process is affected.

## 6. WFP network callout (Task 6 AC) — operator step

Point a benign connector at a VM-local sink whose IP you added to the network
blocklist. Confirm the connection is blocked and attributed to the right PID
(the callout logs the per-process attribution). Metadata only — no TLS
interception.

## 7. Shadow copy-on-write rollback (Task 7 AC) — operator step

In a scratch directory only, run your authorized mass-write test as a gated
(unknown) process. Confirm:
- while gated, writes land in the shadow layer (the real files are unchanged);
- on a malicious verdict the layer is **discarded** and the originals are
  byte-for-byte intact;
- on a clean verdict the staged writes **commit** exactly.

The engine-side rollback gate (stage/commit/discard + side-effect boundary) is
already unit-tested (`tests/unit/test_rollback.cpp`); this verifies the kernel
staging driver.

## 8. ELAM + BYOVD (Task 8 AC) — operator step

1. Register the ELAM driver and reboot; confirm it loads before other boot
   drivers (`!elam` / the boot log).
2. Put a known-vulnerable **test** driver's hash on the BYOVD blocklist and
   confirm its load is refused (image-load path + ELAM classify).

## 9. Service transport + ETW-TI (Task 9 AC)

- `sentinel service` connects the filter port (Task 2) and routes events into
  the engine (confirmed in steps 3–4).
- Run the service as the ELAM-backed PPL anti-malware process and confirm it
  consumes the Microsoft-Windows-Threat-Intelligence provider (ETW-TI is gated
  to PPL AM processes). See `docs/ppl-signing.md`.

## 10. WPF dashboard + tray (Task 10 AC)

Launch `Sentinel.UI.exe`. Trigger a detection (step 3) and confirm it appears
end to end (driver → engine → UI). Quarantine an item and restore it from the
UI; confirm the file returns byte-for-byte.

## 11. VTL1 trustlet (Task 11 AC) — requires VBS/HVCI enabled

Enable VBS/HVCI in the VM. Confirm keys are sealed in the VTL1 enclave and that a
tampered sealed blob fails verification (the software store remains the dev
fallback when VBS is off). See `docs/ppl-signing.md`.

## 12. No bugcheck

The harness records the bugcheck count before/after and fails if any occurred.
Keep WinDbg attached for the whole suite; triage any bugcheck with
`!analyze -v` and revert to the `Clean` snapshot between runs.

## What is gated on paperwork, not code

ELAM load on a non-test machine, PPL anti-malware level, and Security Center
registration require the **Microsoft Virus Initiative**, an **EV code-signing
certificate**, and **attestation/WHQL** signing. These are organizational, not
code, blockers — see `docs/ppl-signing.md` for the exact steps.
