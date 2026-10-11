# Real-Time Protection Antivirus — Engineering Blueprint

This is the engineering blueprint Sentinel AV implements. It maps each threat to
the concrete layer that defends against it.

## Vision & honest scope

The goal is a Windows antivirus that gives continuous, real-time protection:
watching the system 24/7, catching a threat the instant it acts, and keeping the
PC safe even when the user accidentally runs a malicious file.

One honest correction up front, because it shapes every design choice: **no
antivirus protects against everything.** Microsoft Defender, Kaspersky, and
CrowdStrike do not claim 100%, because a novel zero-day, a kernel-level rootkit,
or a user who approves the wrong prompt can defeat any single check. Chasing
"block everything" produces a bloated, slow, false-positive-ridden product that
users end up disabling, which protects nothing.

What *is* achievable is **layered defense (defense in depth)**: many independent
protections stacked so that what one layer misses, the next catches. The
realistic promise is not "nothing ever gets in" but "nothing gets in **and
stays**, and nothing does lasting damage."

Threats in scope, from easiest to hardest to stop: file-based malware,
ransomware, fileless/script malware, injection & process hollowing, rootkits,
and bootkits.

## Core design principles

1. **Built from scratch, no third-party AV SDKs.** The detection logic, drivers,
   and engine are our own code. We build *on* the official Windows kernel
   frameworks (Filter Manager, WFP, ELAM) because those are the supported,
   documented ways to run in the kernel.
2. **Real-time with near-zero overhead.** Protection runs inline, before an
   action completes, not on a schedule. Aggressive caching and a fast path for
   anything already known-good.
3. **Defense in depth.** Independent layers (file, process, registry, network,
   boot) each catch what the others miss.
4. **Fail-safe and reversible.** When unsure, lean toward containment that can be
   undone (hold, sandbox, snapshot) rather than an irreversible kill. The idea
   behind the rollback gate.
5. **Least privilege, learned per app.** A PDF reader that suddenly tries to spawn
   a command shell is denied by default.
6. **Self-protecting.** The engine resists being killed, unloaded, or having its
   files, settings, and quarantine tampered with.

## System architecture

Six layers, one real-time loop. See `docs/architecture.md` for the component
diagram and the data flow. Every file, process, and packet is intercepted by a
kernel sensor, scored by the user-mode engine, then allowed, blocked, or rolled
back.

## Kernel-mode core components

Real-time protection lives in the kernel because that is the only place that sees
every action as it happens and can block it *before* it completes.

- **File-system minifilter** (`drivers/fsfilter`). Registered with the Filter
  Manager, it intercepts file operations as I/O passes through the stack. On an
  executable open it can pause the operation, get a verdict, then allow, block,
  or quarantine. The front line against file-based malware.
- **Process/thread creation callbacks** (`drivers/procmon`).
  `PsSetCreateProcessNotifyRoutineEx` and `PsSetCreateThreadNotifyRoutine` — the
  driver is told of every new process and thread, with the power to veto a
  launch. Catches malicious child processes and, crucially, remote threads
  created inside another process (the signature of injection/hollowing).
- **Image-load callbacks.** `PsSetLoadImageNotifyRoutine` fires when a DLL or
  driver is mapped — side-loaded DLLs, unsigned drivers (an early rootkit
  warning).
- **Registry callbacks.** `CmRegisterCallbackEx` watches and can block registry
  changes — Run keys, services, boot entries (persistence).
- **Object callbacks (self-protection).** `ObRegisterCallbacks` intercepts
  attempts to open a handle to another process/thread. Used defensively, it stops
  malware from acquiring the access it needs to kill the antivirus.
- **ETW Threat-Intelligence (ETW-TI).** A hook-free stream of sensitive events
  (remote memory allocation, handle opens, driver loads), gated by Windows to
  anti-malware processes. The backbone for the memory and fileless layers.

## Network protection layer (WFP)

A Windows Filtering Platform callout driver (`drivers/netfilter`) inspects
connections and packets: block outbound to known-malicious endpoints, detect C2
beacons (regular small periodic connections), an exfiltration guard, and
per-process rules. It does not decrypt TLS; it works on metadata and endpoint
reputation.

## Boot-time & rootkit/bootkit defense

- **ELAM** (`drivers/elam`). A certified Early Launch Anti-Malware driver loads
  before every other boot-start driver and classifies each as good/bad/unknown.
- **Secure Boot and Trusted Boot** — relied on, not rebuilt.
- **Protected Process Light (PPL)** — the service runs as a PPL anti-malware
  process; self-protection and a rootkit countermeasure.
- **Runtime rootkit detection** — cross-view detection: compare what the normal
  API reports against a low-level enumeration; a mismatch reveals a hider.
- **BYOVD defense** — a vulnerable-driver blocklist (`signatures/driverblock`)
  refuses known-abusable signed drivers through image-load and ELAM.
- **Firmware/UEFI integrity** — verify and report on Secure Boot state, TPM
  measured boot, and UEFI variable integrity.

## Static scanning engine (`engine/scan`)

Inspects a file *without running it* and returns a fast verdict. Layer 1: hash
lookup (allow/block SHA-256 sets). Layer 2: YARA-style signature/pattern
matching (our own rule set and engine). Layer 3: PE structure heuristics. Backed
by a verdict cache keyed on the file hash. Signatures update as signed,
incremental, pinned-key-verified packages.

## Behavioral & heuristic engine (`engine/behavior`)

Asks "is this process behaving like malware right now?" It keeps an **action
graph** per process and judges sequence and combination. Ransomware heuristic
(mass-encrypt + canary files), injection/hollowing heuristic (allocate-write-
execute chain), rootkit-hiding heuristic, and a corroborating ML model. All feed
**verdict fusion**, which combines every layer's signals into one risk level and
action: allow, monitor-closely, hold-in-shadow, block, or kill-and-roll-back.

## On-device script analysis (`engine/script`, `engine/amsi`)

A deobfuscator + intent classifier reads obfuscated PowerShell/JScript/shell and
judges intent ("this decodes a base64 blob and executes it in memory"). Wired to
an AMSI provider so the engine sees the real, decoded script at the moment of
execution. Closes the fileless gap without sending anything to the cloud.

## Shadow-commit rollback gate (`engine/rollback`)

The feature that makes the engine uniquely safe. A risky process's changes are
reversible by construction: trusted writes go straight to disk; unknown/
suspicious writes are redirected into a per-process copy-on-write shadow layer.
If the live verdict stays clean, the shadow is committed atomically; if it turns
malicious, the whole shadow layer is discarded — perfect rollback, no data loss.
The hard part is the side-effect boundary: irreversible actions (network sends,
inter-process injection) are held/throttled/denied while gated.

## Self-protection, quarantine & recovery (`engine/quarantine`, `engine/lowlevel`)

PPL anti-malware process, signed/verified driver, mutual watchdog, integrity-
checked config and signatures. Convicted files go to an **encrypted quarantine
vault** (neutralized, metadata recorded, tamper-protected), restorable in one
click for false positives. Remediation walks the action graph and undoes dropped
files, persistence, and settings.

## Memory & exploit protection (`engine/memory`)

In-memory scanning for injected/reflective/unpacked code; exploit-technique
detection (ROP, heap spray, stack pivots, W^X violations); CET shadow-stack
enforcement where available; LSASS credential-theft protection via the object
callbacks.

## Fileless & script defense (AMSI + ETW-TI)

AMSI provider sees decoded scripts at execution; ETW-TI supplies the surrounding
context (which process spawned the interpreter, what it touched). Together they
turn "a legitimate tool ran" into "this legitimate tool is being abused."

## Unpacking & sandbox emulation (`engine/sandbox`)

A lightweight emulator fast-forwards an unpacking stub so the decrypted payload
appears in emulator memory for inspection. A micro-sandbox detonates higher-risk
unknowns to observe behavior before granting real execution. Pairs with the
rollback gate: detonate, judge, then allow real writes.

## EDR layer (`engine/edr`)

Forensic kill-chain timeline (durable, sealed), auto-containment on strong
detections (isolate from the network except the management path), and
tamper-evident, hash-chained append-only logging.

## Advanced isolation & deception (`engine/trustlet`, `engine/deception`, `engine/devicecontrol`)

VBS/HVCI trustlet (VTL1) for the crown-jewel keys and integrity anchor; a
deception grid (honeytokens, decoys) as near-zero-false-positive tripwires;
device control and DLP for removable media.

## Technology stack

C/C++ for everything in the kernel and at boot (non-negotiable), C++ (or Rust)
for the user-mode engine, C# for the interface. See `docs/architecture.md` and
the ADRs in `docs/adr/`.

## Build roadmap

See `docs/roadmap.md` for the phase-by-phase plan (Phase 0 user-mode foundation
through Phase 9 advanced isolation & deception), each phase ending in a tested
gate.

## Hard realities, prerequisites & risks

- **Driver code-signing.** Windows will not load an unsigned kernel driver. To
  ship one you need an EV code-signing certificate plus Microsoft attestation
  signing (and WHQL for broad distribution). Test-signing is for a VM only.
- **Microsoft Virus Initiative (MVI) and ELAM.** The boot tier and anti-malware
  privileges (ELAM, PPL, Security Center registration) are gated behind MVI, with
  real requirements (established company, third-party lab certification).
- **A safe test environment.** Isolated, disposable VMs with snapshots and kernel
  debugging; strict isolation so test malware never touches a real network/data.
- **Risks:** false positives, performance regressions, a driver bug bricking
  machines, becoming an attack surface, and the arms race — each with its
  mitigation (allowlist + fusion + reversible responses; cache + fast path;
  staged rollout + watchdog + safe-mode disable; least privilege + memory-safe
  code + signed updates; frequent rule/model updates + behavioral detection).

## Legal & ethical

Building defensive software is fine, and testing it responsibly is essential: use
malware samples only in isolated labs, comply with local law, and never test on
systems or networks you do not own.

See `docs/glossary.md` for terminology.
