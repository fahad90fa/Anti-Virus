#include "sentinel/lowlevel/intrinsics.h"

#include <chrono>
#include <cstddef>
#include <cstdint>

// Decide once whether we are on an x86 family target with CPUID/RDTSC. Every
// intrinsic below is guarded by this so the engine still builds (with honest
// all-false results) on ARM, RISC-V, and anywhere the intrinsics are absent.
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || \
    defined(_M_IX86)
#  define SENTINEL_X86 1
#  if defined(_MSC_VER)
#    include <intrin.h>  // __cpuidex, __rdtsc
#  else
#    include <cpuid.h>   // __get_cpuid_count
#  endif
#else
#  define SENTINEL_X86 0
#endif

namespace sentinel {
namespace lowlevel {
namespace {

#if SENTINEL_X86
struct Regs {
    std::uint32_t eax = 0;
    std::uint32_t ebx = 0;
    std::uint32_t ecx = 0;
    std::uint32_t edx = 0;
};

// Portable CPUID wrapper. Returns false when the requested leaf is beyond what
// the CPU reports, so callers never act on garbage register contents. The
// subleaf matters for leaf 7 (structured extended features).
bool CpuId(std::uint32_t leaf, std::uint32_t subleaf, Regs& r) {
#  if defined(_MSC_VER)
    int regs[4] = {0, 0, 0, 0};
    __cpuidex(regs, static_cast<int>(leaf), static_cast<int>(subleaf));
    r.eax = static_cast<std::uint32_t>(regs[0]);
    r.ebx = static_cast<std::uint32_t>(regs[1]);
    r.ecx = static_cast<std::uint32_t>(regs[2]);
    r.edx = static_cast<std::uint32_t>(regs[3]);
    return true;
#  else
    unsigned int a = 0, b = 0, c = 0, d = 0;
    // __get_cpuid_count validates leaf against the basic/extended max itself.
    if (__get_cpuid_count(leaf, subleaf, &a, &b, &c, &d) == 0) return false;
    r.eax = a;
    r.ebx = b;
    r.ecx = c;
    r.edx = d;
    return true;
#  endif
}

// Append the four little-endian bytes of a register to a string, stopping at a
// NUL. CPUID packs the vendor/brand characters into registers in this order.
void AppendRegChars(std::string& out, std::uint32_t reg) {
    for (int i = 0; i < 4; ++i) {
        const char c = static_cast<char>((reg >> (8 * i)) & 0xFF);
        if (c == '\0') return;
        out.push_back(c);
    }
}

// Trim ASCII spaces from both ends; Intel pads the brand string with them.
std::string Trim(const std::string& s) {
    std::size_t b = 0;
    std::size_t e = s.size();
    while (b < e && s[b] == ' ') ++b;
    while (e > b && s[e - 1] == ' ') --e;
    return s.substr(b, e - b);
}
#endif  // SENTINEL_X86

}  // namespace

CpuFeatures DetectCpuFeatures() {
    CpuFeatures f;

#if SENTINEL_X86
    Regs r;

    // Leaf 0: vendor string is EBX, EDX, ECX (note the EDX/ECX order).
    if (CpuId(0, 0, r)) {
        AppendRegChars(f.vendor, r.ebx);
        AppendRegChars(f.vendor, r.edx);
        AppendRegChars(f.vendor, r.ecx);
    }

    // Leaf 1: basic feature flags. ECX bit 30 = RDRAND.
    if (CpuId(1, 0, r)) {
        f.rdrand = (r.ecx & (1u << 30)) != 0;
    }

    // Leaf 7 subleaf 0: structured extended features.
    //   EBX bit 7  = SMEP      EBX bit 20 = SMAP
    //   ECX bit 7  = CET_SS    EDX bit 20 = CET_IBT
    if (CpuId(7, 0, r)) {
        f.smep = (r.ebx & (1u << 7)) != 0;
        f.smap = (r.ebx & (1u << 20)) != 0;
        f.cet_shadow_stack = (r.ecx & (1u << 7)) != 0;
        f.cet_ibt = (r.edx & (1u << 20)) != 0;
    }

    // Brand string from extended leaves 0x80000002..0x80000004 (48 bytes). Only
    // read it when the extended range advertises those leaves.
    Regs ext;
    if (CpuId(0x80000000u, 0, ext) && ext.eax >= 0x80000004u) {
        std::string brand;
        for (std::uint32_t leaf = 0x80000002u; leaf <= 0x80000004u; ++leaf) {
            Regs b;
            if (!CpuId(leaf, 0, b)) break;
            AppendRegChars(brand, b.eax);
            AppendRegChars(brand, b.ebx);
            AppendRegChars(brand, b.ecx);
            AppendRegChars(brand, b.edx);
        }
        f.brand = Trim(brand);
    }
#else
    // No CPUID on this architecture: report honest, conservative defaults.
    f.vendor = "unknown";
#endif

    return f;
}

std::uint64_t ReadTimestampCounter() {
#if SENTINEL_X86
#  if defined(_MSC_VER)
    return static_cast<std::uint64_t>(__rdtsc());
#  else
    // Compiler builtin; needs no extra header and emits a bare RDTSC.
    return static_cast<std::uint64_t>(__builtin_ia32_rdtsc());
#  endif
#else
    // Portable fallback: a monotonic nanosecond clock. Not a cycle count, but
    // monotonic within a run — all this counter is used for (benchmarks, the
    // latency budget), never a security decision.
    const auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
#endif
}

bool HasShadowStackSupport() { return DetectCpuFeatures().cet_shadow_stack; }

}  // namespace lowlevel
}  // namespace sentinel
