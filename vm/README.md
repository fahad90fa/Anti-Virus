# Disposable test VM

**`drivers/` never runs on your main PC.** Kernel development means blue screens;
malware testing means live threats. You need isolated, disposable virtual
machines with snapshots, kernel debugging set up (WinDbg over a debug
connection), and strict isolation so test malware never touches a real network or
real data.

## What this folder provides

- `setup-test-vm.ps1` — provisions a fresh Windows VM for Sentinel driver
  testing: enables test-signing, configures a kernel-debug transport, installs
  the WDK runtime bits, creates a clean snapshot, and disables outbound network
  (host-only) so samples cannot call home.
- `kd-config.md` — the WinDbg kernel-debugging setup (network or serial).

## Golden rules

1. **Snapshot before every test.** Revert after. Treat the VM as burnable.
2. **No bridged networking.** Host-only or fully isolated. The engine's own tests
   use only the EICAR string and synthetic SENTVM samples — never live malware.
3. **Never develop drivers on your host.** A driver bug bricks the machine it
   runs on; that machine must be the disposable VM.
4. **Kernel debugger attached** when loading a new driver build, so a bug surfaces
   in WinDbg instead of a bare bugcheck.

## Quick start

```powershell
# On the host (Hyper-V), create and configure the test VM:
pwsh vm/setup-test-vm.ps1 -VmName Sentinel-Test -IsoPath C:\iso\Win11.iso

# Inside the VM, once:
bcdedit /set testsigning on
bcdedit /debug on
# then reboot, attach WinDbg (see kd-config.md), and load a driver:
sc create SentinelFs type= filesystem binPath= C:\sentinel\fsfilter.sys
fltmc load SentinelFs
```
