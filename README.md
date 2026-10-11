# Sentinel AV — Real-Time Protection Antivirus

Sentinel is a layered, defense-in-depth Windows antivirus built from scratch on
the supported Windows kernel frameworks (Filter Manager, WFP, ELAM). It follows
the *Real-Time Protection Antivirus — Engineering Blueprint*: many independent
protections stacked so that what one layer misses, the next catches. The
realistic promise is not "nothing ever gets in" but "nothing gets in **and
stays**, and nothing does lasting damage."

> **Honest scope.** No antivirus protects against *everything*. This project
> targets layered defense, a reversible shadow-commit gate, and fail-safe
> containment. A firmware implant below the OS, or a signed-but-malicious
> driver abusing a legitimate signature, can still be extremely hard to stop.

## Threats in scope

| Threat | Defending layer | Mechanism |
| --- | --- | --- |
| File virus / trojan / worm | Minifilter + static engine | Scan on execute: hash, YARA-style rules, PE heuristics |
| Dropper / downloader | Minifilter + network | Block the payload file and the download connection |
| Ransomware | Behavioral + rollback gate | Mass-encrypt heuristic, canary files, kill + discard shadow writes |
| Fileless / malicious script | Behavioral + script analysis | Judge intent of obfuscated PowerShell and LOLBins |
| Code injection / hollowing | Process & thread callbacks | Veto remote threads; detect allocate-write-execute chain |
| Credential / handle theft | Object callbacks | Deny illicit handles to protected processes |
| Persistence (Run keys, services) | Registry callbacks + remediation | Flag or deny boot-persistence writes; undo on cleanup |
| C2 / data exfiltration | Network (WFP) | Reputation + beacon pattern + per-process rules |
| Rootkit (kernel hiding) | Kernel callbacks + cross-view | Detect hooking and unlinking; compare API vs raw view |
| Bootkit (pre-OS) | ELAM + Secure Boot | Classify boot drivers before load; rely on verified boot |
| AV tampering / kill | Self-protection (PPL, watchdog) | Protected process, mutual watchdog, integrity checks |
| In-memory / fileless code | Memory scan + AMSI + ETW-TI | Scan RAM for injected or unpacked code; read de-obfuscated scripts |
| Exploits (ROP, heap spray) | Memory & exploit protection | Detect techniques live; enforce CET shadow stacks |
| Credential theft (LSASS dump) | Memory protection + object callbacks | Block illicit reads of LSASS memory |
| BYOVD (vulnerable driver) | Image-load + ELAM blocklist | Refuse known-abusable signed drivers |
| Packed / obfuscated malware | Unpacking + sandbox emulation | Unpack and detonate in isolation before execution |
| Firmware / UEFI implant | Firmware integrity checks | Verify Secure Boot, TPM measured boot, UEFI vars |
| Lateral movement / spread | EDR auto-containment | Isolate the machine on a strong detection |
| Malicious USB / removable media | Device control | Policy and scan-on-insert for removable media |
| Log / forensics tampering | Tamper-evident logging | Append-only hash-chained records |

## Architecture

Six layers, one real-time loop. Kernel sensors feed one user-mode engine that
decides allow, block, or roll back.

```
Protected apps and the user
Interface — dashboard and tray (C#)
User-mode engine (C++)  — static scan · behavioral engine · verdict fusion
                           script analysis · shadow-commit gate · quarantine
   ^ events                              | verdicts
Kernel drivers (C/C++)  — file minifilter · process/thread/image callbacks
                           registry/object callbacks · WFP network filter
Boot tier — ELAM driver + Secure Boot
Windows OS and hardware
```

Every file, process, and packet is intercepted by a kernel sensor, scored by
the user-mode engine, then allowed, blocked, or rolled back.

## Repository layout

```
docs/          design docs, specs, architecture decision records
build/          build + signing scripts (no secrets committed)
drivers/        ALL kernel-mode C/C++ (built with the WDK)
  common/         kernel <-> user message protocol
  fsfilter/       file-system minifilter, real-time file scan      [Phase 1]
  procmon/        process/thread/image/registry/object callbacks   [Phase 2]
  netfilter/      WFP callout driver, network                      [Phase 3]
  shadowfs/       copy-on-write shadow layer, rollback gate         [Phase 4]
  elam/           Early Launch Anti-Malware boot driver             [Phase 5]
engine/         user-mode service + detection engine (C++)
  core/           shared types, logging, hashing, config
  platform/       OS abstraction (file watch, process enum)
  service/        always-on service (orchestrator, PPL, watchdog)
  scan/           static scanning (hash, YARA-style, PE, cache)
  behavior/       behavioral/heuristic engine, verdict fusion
  script/         on-device script-intent analysis
  amsi/           AMSI provider                                     [Phase 8]
  memory/         in-memory scan + exploit-technique detection      [Phase 7]
  sandbox/        unpacking emulator + micro-sandbox detonation     [Phase 7]
  rollback/       shadow-commit control (commit/discard)            [Phase 4]
  edr/            forensic timeline, auto-containment, sealed logs  [Phase 8]
  deception/      honeytokens, decoys, canary management            [Phase 9]
  devicecontrol/  removable-media policy + DLP signals              [Phase 9]
  trustlet/       VBS/HVCI isolated enclave (VTL1)                  [Phase 9]
  quarantine/     encrypted vault + remediation / cleanup
  lowlevel/       intrinsics + self-code integrity checks
ui/             C# dashboard + tray (.NET)
ipc/            the contract between engine (C++) and UI (C#)
signatures/     the rule / signature database + update pipeline
tests/          unit, integration, and SAFE samples only (EICAR, sims)
tools/          dev utilities (log viewer, rule compiler, benchmarks)
vm/             disposable test-VM setup + kernel-debug config
```

Two rules baked into the layout:

- **`drivers/` never runs on your main PC.** Build and test only in the
  disposable VM under `vm/`, with kernel debugging attached.
- **`tests/samples/` holds safe material only** — the EICAR test string and
  synthetic behavior simulators, never live malware. Real samples are never
  committed.

## Build

The **user-mode engine** is portable C++17 and builds on Linux (for CI and the
test suite) and Windows (for the shipping product). The **kernel drivers**,
**ELAM**, **trustlet**, and the **C# UI** target Windows and are built with the
WDK and .NET respectively.

```sh
# Engine + tests (Linux / macOS / Windows with a C++17 compiler + CMake)
cmake -S engine -B out/engine -DSENTINEL_BUILD_TESTS=ON
cmake --build out/engine
ctest --test-dir out/engine --output-on-failure

# Full Windows product (drivers + engine + UI), on Windows with VS + WDK:
pwsh build/build.ps1 -Configuration Debug
```

The CLI front end (`sentinel-cli`) exposes every Phase 0 capability — scan a
file or tree, watch a folder, run the EICAR self-test, manage the quarantine
vault, and print verdicts — so the engine is exercisable without any driver.

See `docs/blueprint.md` for the full engineering blueprint and `docs/roadmap.md`
for the phase-by-phase build plan.

## Safety, legal & ethics

Building defensive software is fine, and testing it responsibly is essential.
Use malware samples only in isolated labs, comply with local law on handling
malicious code, and never test on systems or networks you do not own. This
repository ships **no live malware** — only the standard EICAR test string and
synthetic simulators.

## License

See [LICENSE](LICENSE).
