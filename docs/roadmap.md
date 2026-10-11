# Build roadmap (phases)

Each phase ends in a **gate**: something that works and is tested before moving
on. The order deliberately starts in user mode (safe, no blue screens) and
descends into the kernel only once the fundamentals are proven. Start at Phase 0;
do not jump to the kernel first.

| Phase | Scope | Gate | Status in this repo |
| --- | --- | --- | --- |
| 0 | **User-mode foundation.** A service that enumerates processes, watches folders for new files, hashes them, checks against a blocklist/allowlist, a basic YARA-style scanner, and a quarantine folder. | Detects and quarantines the EICAR test file in real time. No drivers. | **Implemented** — `engine/` + `sentinel-cli`, EICAR self-test green |
| 1 | **File minifilter.** First kernel driver: intercept file opens, send to the engine over a communication port, block on a bad verdict. | A flagged executable is blocked *before* it runs, with acceptable latency. | Driver source in `drivers/fsfilter` (build in the VM) |
| 2 | **Behavior & process callbacks.** Process/thread/image/registry callbacks; action graph; first behavioral heuristics (injection chain, ransomware pattern, canary files). | A simulated ransomware script is caught by behavior, not signature, and stopped. | Engine behavioral layer implemented; driver in `drivers/procmon` |
| 3 | **Network layer.** WFP callout for per-process connection filtering and C2/beacon heuristics. | A test process's connection to a blocklisted endpoint is blocked and attributed to the right app. | Driver source in `drivers/netfilter` |
| 4 | **Shadow-commit rollback gate.** Copy-on-write staging for gated processes, commit/discard driven by the live verdict, first side-effect boundary. | Simulated ransomware encrypts only shadow copies; discard leaves originals intact. | Engine `rollback/` implemented; driver in `drivers/shadowfs` |
| 5 | **Boot & rootkit tier.** ELAM driver, PPL self-protection, watchdog, cross-view rootkit detection. Signing + MVI eligibility become mandatory. | ELAM loads at boot and classifies drivers; the service cannot be killed by an admin-level test. | Driver source in `drivers/elam` + `driverblock` |
| 6 | **Hardening, UI & updates.** C# dashboard, signed incremental update pipeline, performance tuning against the latency budget, false-positive reduction, evaluation on a real test corpus. | Measured performance meets targets; false-positive rate on clean software is acceptably low. | UI in `ui/`, updater in `signatures/updater`, benchmarks in `tools/` |
| 7 | **Memory & exploit protection + sandbox.** In-memory scan, exploit-technique detection, CET, LSASS guard; unpacking emulator + micro-sandbox. | Injected/reflective code is found in RAM; a packed sample is unpacked and judged in the sandbox. | Engine `memory/` + `sandbox/` implemented |
| 8 | **EDR + fileless defense.** Forensic timeline, auto-containment, tamper-evident logging; AMSI provider + ETW-TI consumer. | An abused PowerShell one-liner is decoded and convicted; the kill chain is reconstructable and sealed. | Engine `edr/` + `script/` + `amsi/` implemented |
| 9 | **Advanced isolation & deception.** VBS/HVCI trustlet, deception grid, device control. Depend on the same signing/MVI eligibility as the boot tier. | Honeytoken access fires with zero false positives; keys live in the VTL1 enclave. | Engine `trustlet/` + `deception/` + `devicecontrol/` implemented |

A realistic solo or small-team pace reaches a genuinely useful Phase 0–2 product
well before the Phase 5 boot tier, which is the slowest and most gated part.

## What runs today (this repository)

The **user-mode engine is complete and portable**: it builds and its full test
suite passes on Linux (CI) and Windows. The CLI (`sentinel-cli`) exercises every
Phase 0 capability — scan a file or tree, watch a folder, EICAR self-test, manage
the quarantine vault, print verdicts — plus the higher-layer engine logic
(behavioral scoring, script-intent analysis, sandbox detonation of synthetic
samples, rollback staging, sealed timeline). The **kernel drivers, ELAM,
trustlet, and C# UI** are complete source targeting Windows and are built with
the WDK / .NET in the disposable VM (`vm/`).
