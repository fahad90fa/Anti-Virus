# Architecture

Kernel sensors feed one user-mode engine that decides allow, block, or roll back.

```
┌───────────────────────────────────────────────────────────────┐
│  Protected apps and the user                                   │
├───────────────────────────────────────────────────────────────┤
│  Interface — dashboard and tray (C#)          ui/              │
├───────────────────────────────────────────────────────────────┤
│  User-mode engine (C++)                       engine/          │
│    static scan · behavioral engine · verdict fusion            │
│    script analysis · shadow-commit gate · quarantine · EDR     │
│          ▲ events                     │ verdicts               │
├──────────┼────────────────────────────┼───────────────────────┤
│  Kernel drivers (C/C++)               ▼       drivers/         │
│    file minifilter · process/thread/image callbacks            │
│    registry/object callbacks · WFP network filter · shadow COW │
├───────────────────────────────────────────────────────────────┤
│  Boot tier — ELAM driver + Secure Boot        drivers/elam/    │
├───────────────────────────────────────────────────────────────┤
│  Windows OS and hardware                                       │
└───────────────────────────────────────────────────────────────┘
```

## The real-time loop

1. A kernel sensor intercepts an action (file execute, process start, packet).
2. For a synchronous gate (image execute), the driver pauses the operation and
   sends a request to the engine over the FltMgr communication port
   (`drivers/common/shared_defs.h`), with file content in a shared section.
3. The engine scores it: static scan (hash → rules → PE), and for a running
   process, behavioral signals from the action graph.
4. **Verdict fusion** combines all signals into one `RiskLevel` + `Action`.
5. The driver enforces the verdict: allow, block, hold-in-shadow, or
   kill-and-roll-back. Ordinary reads/writes of already-cleared files are handled
   asynchronously with minimal inline cost.

## Kernel ⇄ engine protocol

Defined in `drivers/common/shared_defs.h`. Fixed-width, C-compatible structs; no
pointers cross the boundary; file content travels via a shared section referenced
by offset. The numeric `SENTINEL_ACTION`/`SENTINEL_RISK` values match the engine
enums `sentinel::Action` / `sentinel::RiskLevel` so verdicts round-trip without
re-mapping. See `drivers/common/comms.h` for the port helpers.

## Engine ⇄ UI protocol

Defined in `ipc/protocol.md`. Newline-delimited JSON over a secured named pipe
(TCP loopback in the dev build). The UI is read-mostly; destructive actions are
re-authorized by the service.

## User-mode engine composition

`sentinel::Engine` (`engine/include/sentinel/engine.h`) composes:

| Subsystem | Directory | Responsibility |
| --- | --- | --- |
| Core | `engine/core` | types, Result/Status, SHA-256, entropy, logging, config, fs |
| Platform | `engine/platform` | process enumeration, folder watcher (OS abstraction) |
| Static scan | `engine/scan` | hash store, YARA-style rules, PE heuristics, cache |
| Behavioral | `engine/behavior` | action graph, ransomware/injection heuristics, model, fusion |
| Script | `engine/script`, `engine/amsi` | deobfuscation, intent classification, AMSI provider |
| Memory | `engine/memory` | in-memory scan, exploit guard, LSASS guard |
| Sandbox | `engine/sandbox` | unpacking emulator (SENTVM) + detonator |
| Rollback | `engine/rollback` | copy-on-write shadow gate, commit/discard |
| Quarantine | `engine/quarantine` | encrypted vault + remediation |
| EDR | `engine/edr` | sealed hash-chained log, timeline, auto-containment |
| Deception | `engine/deception` | honeytokens / canaries |
| Device control | `engine/devicecontrol` | removable-media policy + DLP signals |
| Trustlet | `engine/trustlet` | VTL1 enclave interface (software fallback in dev) |
| Low-level | `engine/lowlevel` | CPU intrinsics (CET detection), self-integrity |
| Service | `engine/service` | always-on orchestrator, CLI, port client, watchdog |

## Threading & performance

- The kernel driver stays small and fast (intercept, apply cached policy,
  escalate). Heavy logic (parsing, rules, model, fusion) lives in the user-mode
  service.
- Verdict caching: a file's hash maps to a cached verdict; unchanged known-good
  files clear instantly. Cache invalidates when the hash changes.
- Scanning runs in parallel across cores; one slow file never blocks unrelated
  ones. Synchronous only where required (a new image about to execute).

## Latency budget (design targets)

| Path | Target |
| --- | --- |
| Cached known-good open | under 1 ms (effectively unmeasurable) |
| Cache-miss static scan of a typical executable | a few to low tens of ms |
| Behavioral tracking | continuous and lightweight, off the critical path |

These are targets to validate with benchmarks (`tools/benchmark`), not
guarantees.
