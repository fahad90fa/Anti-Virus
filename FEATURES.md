# Sentinel AV — completed features

Status of every capability in the *Real-Time Protection Antivirus — Engineering
Blueprint*, as implemented in this repository.

**Legend**
- ✅ **Done + verified** — implemented and exercised (builds, and covered by the
  passing test suite / CLI run).
- ⚙️ **CI-build-verified on Windows** — compiles clean on a real Windows runner
  in GitHub Actions. User-mode code (engine, UI) builds via
  `.github/workflows/ci.yml`; the kernel drivers build via
  `.github/workflows/drivers.yml` on the real WDK kernel toolchain
  (`WindowsKernelModeDriver10.0`, `/kernel`, KMDF 1.15) — they compile, link, and
  pass the Universal-driver `ApiValidator`, all `/W4 /WX`. INF stamping and
  verification, catalog generation, driver signing, loading, and runtime
  behavior are **not** covered by CI; those remain pending the disposable VM
  (`vm/run-integration-tests.ps1`, `vm/VERIFICATION-RUNBOOK.md`).
- 🪟 **Source complete (Windows-target)** — complete, structurally correct source
  that builds with the WDK / .NET on Windows; runtime-verified only in the VM.

Verification baseline (from CI, commit-current):
- `engine-linux` ✅ — engine builds `-Werror`; **71/71 tests pass**.
- `engine-windows` ✅ — engine (incl. the Windows FltMgr filter-service) builds
  MSVC `/W4 /WX` Release; 71 tests pass.
- `ui-windows` ✅ — WPF dashboard + tray build with .NET 8.
- `drivers-windows` ⚙️ — **all five kernel drivers build green on the WDK kernel
  toolchain** (required): the `fsfilter` and `shadowfs` minifilters, the `elam`
  boot driver, and the `procmon` + `netfilter` sensor drivers each compile, link,
  and pass `ApiValidator` as Universal drivers (`/W4 /WX`, `/kernel`, KMDF 1.15).
  The minifilters use the FltMgr comms (`comms.c`); `procmon`/`netfilter` use the
  control-device IOCTL comms (`sensor_comms.c`). INF stamping/verification,
  catalog, signing, loading and runtime behavior are VM-gated and **not** covered
  here.
- No `TODO`/stub markers in any Windows code path.

**No acceptance criterion is marked VM-verified here**, because this work was
done in a Linux container with no Windows VM / WinDbg. The runtime criteria are
turnkey via the VM kit; see the final report and the runbook.

---

## Core design principles
- ✅ Built from scratch — own detection logic, rule engine, PE parser, emulator,
  crypto (SHA-256); no third-party AV SDK.
- ✅ Real-time with near-zero overhead — verdict cache (cache hit ≈ 0.0007 ms,
  under the 1 ms budget), fast path for known-good.
- ✅ Defense in depth — independent file / process / behavior / network / boot /
  memory layers feeding one fusion stage.
- ✅ Fail-safe & reversible — shadow-commit rollback gate; reversible responses.
- ✅ Least privilege per app — per-process rules + behavioral baselining.
- ✅ Self-protecting — object-callback anti-tamper, mutual watchdog, integrity
  checks, PPL design.

## Static scanning engine (`engine/scan`) — ✅
- ✅ Layer 1: SHA-256 hash lookup against allowlist + blocklist (fast path).
- ✅ Layer 2: own YARA-style rule engine — text strings (`nocase`, `wide`), hex
  byte patterns with `??` wildcards, conditions (`any of them`, `all of them`,
  `N of them`, `and`/`or`/`not`/parentheses), `//` and `/* */` comments.
- ✅ Layer 3: PE structure heuristics — packed/high-entropy sections,
  dynamic-only imports, missing signature, W^X sections, future timestamp.
- ✅ Verdict cache keyed on file hash (LRU, thread-safe, hit/miss stats).
- ✅ EICAR detection via both the hash and rule layers.
- ✅ Signature database: rule sets (EICAR, generic malware, fileless/script),
  hash allow/blocklist, BYOVD driver blocklist.

## Behavioral & heuristic engine (`engine/behavior`) — ✅
- ✅ Per-process action graph (files, threads, injection, registry, network).
- ✅ Ransomware heuristic — mass-encrypt pattern + canary-file tripwire.
- ✅ Injection/hollowing heuristic — allocate → write → remote-thread chain.
- ✅ Corroborating ML model — transparent logistic scorer over static + behavioral
  features (capped so it never convicts alone; loadable weights).
- ✅ Verdict fusion — noisy-OR with per-level weights, allow/block short-circuit,
  threshold → action mapping (allow / monitor / hold-in-shadow / block / kill).

## Fileless & script defense (`engine/script`, `engine/amsi`) — ✅
- ✅ Deobfuscator — base64, PowerShell `-EncodedCommand` (UTF-16LE), layer peeling.
- ✅ Intent classifier — download-execute, in-memory execution, AMSI bypass,
  encoded command, LOLBin abuse.
- ✅ AMSI provider core — scans decoded content, maps to the AMSI result codes.

## Memory & exploit protection (`engine/memory`) — ✅
- ✅ In-memory scan — private RWX / injected / reflective (non-image-backed) code,
  shellcode byte patterns.
- ✅ Exploit-technique guard — ROP chains, stack pivots, heap spray, W^X execution,
  CET violation.
- ✅ LSASS credential-theft guard — denies illicit reads of protected processes.

## Unpacking & sandbox (`engine/sandbox`) — ✅
- ✅ SENTVM unpacking emulator — safe synthetic VM + two-pass assembler; reveals
  unpacked payloads with full bounds checking (no native code runs).
- ✅ Detonator — maps synthetic syscalls onto the action graph and scores them
  (detects the injection chain under detonation).

## Shadow-commit rollback gate (`engine/rollback`) — ✅
- ✅ Copy-on-write per-process staging; commit (writes reach disk) / discard
  (perfect rollback, originals untouched).
- ✅ Side-effect boundary — network buffered, inter-process injection denied while
  gated.

## Self-protection, quarantine & recovery (`engine/quarantine`, `engine/lowlevel`) — ✅
- ✅ Encrypted quarantine vault — neutralize (keystream), metadata, restore (with
  integrity check) / purge; round-trip recovers exact bytes.
- ✅ Remediator — plan + execute cleanup (dropped files, persistence, shadow,
  quarantine) from the action graph.
- ✅ Self-integrity — enroll known-good hashes, detect tampering.
- ✅ CPU intrinsics — CPUID feature detection (CET shadow stacks), timestamp
  counter.

## EDR layer (`engine/edr`) — ✅
- ✅ Tamper-evident sealed log — append-only SHA-256 hash chain; detects any
  alteration at open or verify.
- ✅ Forensic kill-chain timeline — per-pid reconstruction, sealed backing.
- ✅ Auto-containment — network isolation on strong verdicts only, via a hook.

## Advanced isolation & deception (`engine/trustlet`, `engine/deception`, `engine/devicecontrol`) — ✅
- ✅ Deception grid — honeytokens / canary files; access fires a near-certain
  detection.
- ✅ Device control & DLP — removable-media policy (block / read-only / allow),
  scan-on-insert, exfiltration signal.
- ✅ Trustlet interface — seal/unseal + sign/verify + trust anchor; software store
  (dev fallback), with the VTL1 enclave as the Windows backend.

## Service, CLI & IPC (`engine/service`, `ipc`) — ✅
- ✅ `sentinel-cli` — scan file/tree, real-time folder watch, EICAR self-test,
  script analysis, quarantine list/restore, config, version.
- ✅ Always-on service orchestrator + mutual watchdog.
- ✅ Engine ⇄ UI IPC protocol (named pipe / loopback, JSON) documented.
- ⚙️ `sentinel service` — Windows FltMgr filter-service: connects the minifilter
  port, validates the versioned protocol, answers the execute-gate with an engine
  verdict (fail-open default, `--fail-closed`), feeds events into the action
  graph. Builds clean on Windows CI; stub off Windows.
- 🪟 ETW-TI consumer (runs under the anti-malware PPL process in the VM).

## Kernel-mode core (`drivers/`) — ⚙️ (all five build green in CI)
- ⚙️ File-system minifilter (`fsfilter`) — intercept execute/create/write,
  synchronous verdict gate, async behavioral events. Builds green on the WDK
  kernel toolchain in CI (compile + link + `ApiValidator`).
- ⚙️ Process / thread / image / registry callbacks (`procmon`) — with
  process-launch veto and remote-thread (injection) detection. Builds green in CI.
- ⚙️ Object-callback self-protection (`procmon`, `selfprotect.c`) — strips
  dangerous access to protected processes. Builds green in CI.
- ⚙️ WFP network callout (`netfilter`) — per-process connection filtering +
  C2/beacon events. Builds green in CI.
- ⚙️ Shadow COW minifilter (`shadowfs`) — kernel half of the rollback gate.
  Builds green on the WDK kernel toolchain in CI (compile + link + `ApiValidator`).
- ⚙️ Kernel ⇄ user comms — two transports: the FltMgr communication port
  (`comms.c`, used by the minifilters) and the control-device IOCTL inverted-call
  transport (`sensor_comms.c`, used by `procmon`/`netfilter` — secured device,
  cancel-safe `IO_CSQ`, bounded event ring, sequence-matched sync verdicts). Both
  carry the same versioned `shared_defs.h` wire messages and compile clean in CI.

## Boot-time & rootkit/bootkit defense (`drivers/elam`) — ⚙️
- ⚙️ ELAM boot driver (`elam`) — classifies boot drivers good/bad/unknown before
  load. Builds green on the WDK kernel toolchain in CI (compile + link +
  `ApiValidator`).
- ⚙️ BYOVD vulnerable-driver blocklist (`driverblock.c`) — constant-time hash
  lookup, updatable; compiles clean into the ELAM driver in CI.
- ✅ (Design) Secure Boot / TPM / PPL / cross-view relied on and documented.

## Interface (`ui/`) — ⚙️ (builds on Windows CI with .NET 8)
- ⚙️ WPF dashboard — protection banner, live stats, scan box, detections +
  quarantine lists, engine IPC client (MVVM). Compiles clean on Windows CI.
- ⚙️ System-tray app — status icon, toasts, dashboard launch. Compiles clean on
  Windows CI.

## Signatures & updates (`signatures/`) — ✅
- ✅ Rule / hash / driver-block databases.
- ✅ Signed incremental update pipeline — builder + fail-closed verifier
  (per-file + manifest digest + pinned-key signature), schema, docs.

## Tooling, tests & docs — ✅
- ✅ Dev tools — rule compiler, latency benchmark, sealed-log viewer.
- ✅ Dependency-free test harness — 71 unit + integration tests, all passing.
- ✅ Docs — blueprint, architecture, roadmap, glossary, SENTVM spec, 3 ADRs.
- ✅ Build & signing scripts, disposable test-VM setup, Visual Studio solution,
  EICAR generator + synthetic (non-malicious) samples.

---

## Build roadmap coverage

| Phase | Scope | Status |
| --- | --- | --- |
| 0 | User-mode foundation | ✅ built + tested (engine, CLI, EICAR self-test) |
| 1 | File minifilter | ⚙️ `fsfilter` builds on WDK CI |
| 2 | Behavior & process callbacks | ✅ engine · ⚙️ `procmon` builds on WDK CI |
| 3 | Network layer (WFP) | ⚙️ `netfilter` builds on WDK CI |
| 4 | Shadow-commit rollback gate | ✅ engine · ⚙️ `shadowfs` builds on WDK CI |
| 5 | Boot & rootkit tier (ELAM, PPL, BYOVD) | ⚙️ `elam`+BYOVD build on WDK CI · PPL design |
| 6 | Hardening, UI, updates | ✅ engine/updater/tools · 🪟 UI |
| 7 | Memory & exploit protection + sandbox | ✅ |
| 8 | EDR + AMSI/ETW-TI fileless defense | ✅ (ETW-TI transport is Windows-only) |
| 9 | Advanced isolation & deception | ✅ engine · 🪟 VTL1 trustlet backend |

**Safety:** ships no live malware — only the EICAR test string and synthetic
simulators, per the blueprint.
