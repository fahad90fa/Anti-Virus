// The small low-level layer. Thin wrappers over CPU intrinsics used by the
// exploit-protection and self-integrity code: CPUID feature detection (does the
// CPU support CET shadow stacks?), a high-resolution timestamp counter for the
// latency budget, and cache-line helpers. Guarded so the engine still builds on
// platforms/compilers without the intrinsics.
#ifndef SENTINEL_LOWLEVEL_INTRINSICS_H
#define SENTINEL_LOWLEVEL_INTRINSICS_H

#include <cstdint>
#include <string>

namespace sentinel {
namespace lowlevel {

struct CpuFeatures {
    bool cet_shadow_stack = false;  // CET SHSTK (ROP defense)
    bool cet_ibt = false;           // CET indirect-branch tracking
    bool smep = false;
    bool smap = false;
    bool rdrand = false;
    std::string vendor;
    std::string brand;
};

// Detect CPU features via CPUID where available; fields are false/empty when
// CPUID is not accessible.
CpuFeatures DetectCpuFeatures();

// High-resolution cycle counter (rdtsc). Falls back to a steady clock in ns on
// platforms without the intrinsic. Monotonic within a run; used for benchmarks
// and the latency budget, not for security decisions.
std::uint64_t ReadTimestampCounter();

// True if CET shadow stacks are available on this CPU.
bool HasShadowStackSupport();

}  // namespace lowlevel
}  // namespace sentinel

#endif  // SENTINEL_LOWLEVEL_INTRINSICS_H
