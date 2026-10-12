# Sentinel AV kernel drivers

All kernel-mode C, built with the WDK. **Build and load ONLY in the disposable,
snapshotted test VM** (test-signing on, WinDbg attached) — never on a host. These
are **sensors + enforcement**; every detection decision is made by the user-mode
engine (`engine/`), never duplicated in the kernel.

CI (`.github/workflows/ci.yml`, `drivers-windows`) attempts a WDK build on a
hosted runner; the authoritative build is `build/build.ps1 -TestSign` in the VM.
Runtime verification is `vm/run-integration-tests.ps1` + `vm/VERIFICATION-RUNBOOK.md`.

## Shared protocol — `common/`

`shared_defs.h` is the versioned kernel⇄user wire format (C-compatible,
fixed-width, no pointers across the boundary). `comms.h` / `comms.c` implement
the FltMgr communication-port server; the user side is `engine/service/port_client.cpp`
(`sentinel service`). Bump `SENTINEL_PROTOCOL_VERSION` when extending; the service
rejects a mismatched version and the kernel applies its fail-safe.

## `fsfilter/` — file-system minifilter  [Phase 1]

Intercepts create/open/write and the execute-map (image section create). The
**execute gate is synchronous**: the op is held, the engine is asked, and the
image is allowed or blocked (`STATUS_VIRUS_INFECTED`). Writes are reported
asynchronously for the behavioral engine. **Fail-safe:** if the engine is not
connected or times out, the gate fails **open** by default (the machine keeps
working); `sentinel service --fail-closed` makes it deny unknowns instead. Load:
`fltmc load SentinelFs`.

## `procmon/` — process/thread/image/registry + object callbacks  [Phase 2]

`callbacks.c`: `PsSetCreateProcessNotifyRoutineEx` (with launch veto),
`PsSetCreateThreadNotifyRoutine` (flags **remote** threads — the injection tail),
`PsSetLoadImageNotifyRoutine`, and `CmRegisterCallbackEx` (persistence writes).
All feed the engine's action graph via the port. `selfprotect.c`:
`ObRegisterCallbacks` strips terminate/inject rights to the Sentinel service +
driver only — defensive anti-tamper that never touches other products or the OS.

## `netfilter/` — WFP network callout  [Phase 3]

ALE connect-layer callout for per-process connection filtering and C2/beacon
event emission. Metadata only — no TLS interception. Blocklist + reputation
enforcement with per-PID attribution. Links `fwpkclnt.lib` + `ndis.lib`.

## `shadowfs/` — copy-on-write shadow / rollback gate (kernel half)  [Phase 4]

For a gated (unknown/suspicious) process, write redirection into the per-process
shadow layer; commit/discard is driven by the engine verdict. Enforces the
side-effect boundary (buffer network, deny cross-process injection from a gated
process). The authoritative staging store + commit/discard live in
`engine/rollback`.

## `elam/` — Early Launch Anti-Malware + BYOVD  [Phase 5]

`elam.c`: boot-driver callback classifying each boot driver good/bad/unknown
before load (never classifies an unverified driver as good). `driverblock.c`:
constant-time BYOVD vulnerable-driver hash lookup from the updatable blocklist in
`signatures/driverblock`. Requires an ELAM certificate + the Microsoft Virus
Initiative to load on a real machine — see `docs/ppl-signing.md`.

## Kernel hygiene checklist (enforced across these drivers)

- Every field parsed from a port message / untrusted input is bounds-checked
  (path lengths clamped to `SENTINEL_MAX_PATH`, no unchecked user pointers).
- Synchronous requests always get a reply or a fail-safe default — the kernel is
  never left waiting (no deadlock, no TOCTOU in the gate: the op is held while the
  verdict is fetched).
- Allocations and references are released on every path; callbacks unregister on
  unload; ports close on teardown.
- Built `/W4`; the WDK's code-analysis (SDV/CodeQL) is part of the VM build.
