# ADR 0001 — Language and toolchain split

**Status:** Accepted

## Context

Sentinel spans kernel drivers, a boot-start driver, a heavy user-mode detection
engine, and a desktop UI. These have very different constraints.

## Decision

- **C/C++ for everything in the kernel and at boot** (minifilter, process/
  registry/object callbacks, WFP callout, shadow COW, ELAM). This is
  non-negotiable: only C/C++ can run at boot-driver level and these are the
  supported WDK models.
- **C++ (C++17) for the user-mode engine**, portable so it builds and is tested
  on Linux (CI) and Windows (product). Rust is a valid choice for *new* user-mode
  components (memory safety on a high-value target); the interface boundaries are
  kept clean so a module can be reimplemented in Rust without disturbing callers.
- **C# (.NET/WPF) for the dashboard and tray** — fast, native-looking Windows UI
  with no kernel risk.
- **Build & debug:** Visual Studio + WDK + WinDbg + HLK for the Windows product;
  CMake + a C++17 compiler for the portable engine and its test suite.

## Consequences

- One codebase, three toolchains. The portable engine can be developed and
  tested without a Windows kernel-debug setup, which keeps the inner loop fast and
  blue-screen-free (Phase 0 discipline).
- The kernel ⇄ engine and engine ⇄ UI boundaries are explicit, versioned
  protocols (`drivers/common/shared_defs.h`, `ipc/protocol.md`) so each side can
  evolve independently.
- Rust adoption is incremental, not a rewrite.
