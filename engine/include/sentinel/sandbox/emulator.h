// Lightweight unpacking emulator. Because most malware is packed, inspecting the
// file as-is reveals little. This emulator executes a suspicious file's code in a
// controlled, synthetic environment, fast-forwarding the unpacking stub so the
// decrypted payload appears in the emulator's memory, where the static and
// behavioral engines can inspect it. No real system resources are touched.
//
// To keep this real, testable, and safe, the emulator interprets a small,
// well-defined synthetic instruction set (SENTVM) rather than native x86. A
// packed "sample" is a SENTVM program whose stub decrypts an embedded blob into
// VM memory and jumps to it; the emulator reveals the unpacked payload and
// records the synthetic "syscalls" it attempts. This demonstrates the unpack +
// observe pipeline end to end without executing untrusted native code.
#ifndef SENTINEL_SANDBOX_EMULATOR_H
#define SENTINEL_SANDBOX_EMULATOR_H

#include <cstdint>
#include <string>
#include <vector>

#include "sentinel/core/bytes.h"
#include "sentinel/core/result.h"

namespace sentinel {

// A synthetic syscall the emulated program attempted.
struct EmulatedSyscall {
    std::string name;      // e.g. "WriteFile", "VirtualAlloc", "Connect"
    std::string argument;  // best-effort decoded argument
    std::uint64_t value = 0;
};

struct EmulationResult {
    bool completed = false;
    int instructions_executed = 0;
    Bytes unpacked_payload;                  // revealed payload bytes
    std::vector<EmulatedSyscall> syscalls;   // observed behavior
    std::string halt_reason;
};

// SENTVM opcodes (documented in docs/sandbox-vm.md).
class Emulator {
public:
    // Execute a SENTVM program. `max_instructions` bounds runtime to defeat
    // decompression bombs / infinite stubs.
    EmulationResult Run(const Bytes& program, int max_instructions = 100000) const;

    // Assemble a tiny SENTVM program from a textual form (used by tests and the
    // synthetic-sample generator). Returns ParseError on bad input.
    static Result<Bytes> Assemble(const std::string& source);
};

}  // namespace sentinel

#endif  // SENTINEL_SANDBOX_EMULATOR_H
