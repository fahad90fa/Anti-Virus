# Sentinel AV kernel drivers

All kernel-mode C, built with the WDK. **Build and load ONLY in the disposable,
snapshotted test VM** (test-signing on, WinDbg attached) — never on a host. These
are **sensors + enforcement**; every detection decision is made by the user-mode
engine (`engine/`), never duplicated in the kernel.

CI (`.github/workflows/drivers.yml`, `drivers-windows`) builds all five drivers
on a hosted Windows runner — each compiles, links, and passes `ApiValidator` as a
Universal driver (`/W4 /WX`, `/kernel`, KMDF 1.15); this step is **required**.
Signing and INF verification are skipped in CI (no cert; the runner's WDK ships a
broken InfVerif) — the authoritative, fully-packaged build is `build/build.ps1
-TestSign` in the VM, and runtime verification is `vm/run-integration-tests.ps1` +
`vm/VERIFICATION-RUNBOOK.md`. Loading, signing, and runtime behavior are **only**
verified in the VM, never in CI.

## Shared protocol — `common/`

`shared_defs.h` is the versioned kernel⇄user wire format (C-compatible,
fixed-width, no pointers across the boundary). There are **two transports** that
carry the same messages:

- `comms.h` / `comms.c` — the **FltMgr communication-port** server, used by the
  minifilters (`fsfilter`, `shadowfs`). User side: `engine/service/port_client.cpp`.
- `sensor_comms.h` / `sensor_comms.c` — the **control-device IOCTL** transport
  (inverted-call model: a secured control device + symlink, cancel-safe `IO_CSQ`
  for the async event stream, a bounded drop-oldest event ring, and a
  sequence-matched waiter table for synchronous verdicts), used by the
  non-minifilter sensor drivers (`procmon`, `netfilter`), which have no
  `PFLT_FILTER`. The control device's SDDL restricts access to SYSTEM +
  Administrators, a single trusted client connects, and every IOCTL input length
  is validated — it is not an attack surface.

Bump `SENTINEL_PROTOCOL_VERSION` when changing the wire messages; both the FltMgr
connect and the `IOCTL_SENTINEL_CONNECT` handshake reject a mismatched version and
the kernel applies its fail-safe.

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
All feed the engine's action graph via the control-device IOCTL transport
(`sensor_comms.c`). `selfprotect.c`:
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
