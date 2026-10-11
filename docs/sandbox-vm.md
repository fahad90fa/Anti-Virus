# SENTVM — the sandbox unpacking emulator

The unpacking emulator (`engine/sandbox/emulator`) interprets a small, safe,
synthetic instruction set called **SENTVM** rather than native x86. This lets the
unpack-and-observe pipeline run end to end — reveal a packed payload, record the
"syscalls" a sample attempts — **without ever executing untrusted native code**.
Real malware is never run here; synthetic samples (`tests/samples`) are SENTVM
programs that model packer and injector behavior.

The native-code path (running a real suspicious PE in an instrumented,
hardware-isolated micro-sandbox) is a Windows-only, VM-only capability layered on
top of this model; the SENTVM emulator is the portable, testable core of the
same idea.

## Machine model

- **Registers:** `R0`–`R7`, 64-bit.
- **VM memory:** a bounded, zero-initialized buffer (default 64 KiB). All memory
  access is bounds-checked; an out-of-range access halts the VM.
- **Program:** a byte stream of instructions plus an embedded data section. A
  packer stub typically decrypts bytes from the data section into VM memory and
  the decrypted region becomes the revealed payload.
- **Execution limit:** `max_instructions` bounds runtime to defeat decompression
  bombs and infinite stubs.

## Instruction set (conceptual)

The exact opcode encoding is documented in `engine/sandbox/emulator.cpp`. The
assembler (`Emulator::Assemble`) accepts a line-based textual form; `;` begins a
comment and `label:` defines a jump target.

| Mnemonic | Meaning |
| --- | --- |
| `NOP` | no-op |
| `MOV reg, imm` | load an immediate into a register |
| `LOADK reg, addr` | load a byte from the program data section into VM memory / a register |
| `XORK reg, imm` | XOR a register (decryption primitive) |
| `WRITE addr, reg` | store a register's low byte into VM memory at `addr` |
| `SYSCALL id` | record an observed synthetic syscall (see below) |
| `JMP addr` | unconditional jump |
| `JNZ reg, addr` | jump if a register is non-zero |
| `HALT` | stop execution |

## Synthetic syscalls

`SYSCALL id` records an `EmulatedSyscall`. The detonator (`engine/sandbox/detonator`)
maps these onto the behavioral action-graph model so the same heuristics that
score live processes also score detonated samples:

| Syscall | Maps to action |
| --- | --- |
| `VirtualAlloc` | `MemoryAllocRemote` |
| `WriteProcessMemory` | `MemoryWriteRemote` |
| `CreateRemoteThread` | `RemoteThreadCreate` |
| `WriteFile` | `FileWrite` |
| `Connect` | `NetworkConnect` |
| `RegSetValue` | `RegistryWrite` |

A sample that allocates, writes, and creates a remote thread reproduces the
injection chain and is scored Malicious by the injection heuristic — exactly as a
real injector would be, but entirely in a synthetic, memory-safe interpreter.

## Example (illustrative)

```
; decrypt an embedded blob and "inject" it
    MOV   R0, 0        ; index
loop:
    LOADK R1, R0       ; load encrypted byte
    XORK  R1, 0x5A     ; decrypt
    WRITE R0, R1       ; store decrypted byte into VM memory
    MOV   R2, R0
    JNZ   R2, loop     ; (bounded by max_instructions)
    SYSCALL VirtualAlloc
    SYSCALL WriteProcessMemory
    SYSCALL CreateRemoteThread
    HALT
```
