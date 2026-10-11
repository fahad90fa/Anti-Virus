#include "sentinel/memory/mem_scan.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <iterator>
#include <string>

#include "sentinel/core/bytes.h"
#include "sentinel/core/types.h"
#include "sentinel/scan/rule_engine.h"

namespace sentinel {
namespace {

// Clamp a probability/confidence into [0,1]. Matches the house helper used by
// the static scanner and verdict fusion so scores compose consistently.
double Clamp01(double v) {
    if (v < 0.0) return 0.0;
    if (v > 1.0) return 1.0;
    return v;
}

// Combine independent signal confidences with a noisy-OR: each signal lowers
// the "nothing is wrong" probability, so weak corroborating signals accumulate
// while no single one saturates the score.
double NoisyOr(const std::vector<Signal>& signals) {
    double inv = 1.0;
    for (const auto& s : signals) {
        inv *= (1.0 - Clamp01(s.confidence));
    }
    return 1.0 - inv;
}

// Map a rule's textual severity to a RiskLevel for the emitted Signal. Mirrors
// the static scanner's mapping so a rule means the same thing in either path.
RiskLevel SeverityToLevel(const std::string& sev) {
    std::string s;
    s.reserve(sev.size());
    for (char c : sev) {
        s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    if (s == "high" || s == "critical") return RiskLevel::Malicious;
    if (s == "medium" || s == "moderate") return RiskLevel::Suspicious;
    if (s == "low") return RiskLevel::LowRisk;
    return RiskLevel::Suspicious;  // sensible default for unrecognized severity
}

// Lowercase hex of a 64-bit address, trimmed to its significant nibbles, for
// human-readable region addresses in signal detail strings.
std::string HexU64(std::uint64_t v) {
    static const char* kHex = "0123456789abcdef";
    char buf[16];
    for (int i = 15; i >= 0; --i) {
        buf[i] = kHex[v & 0xF];
        v >>= 4;
    }
    std::size_t start = 0;
    while (start < 15 && buf[start] == '0') ++start;  // keep at least one digit
    return std::string(buf + start, buf + 16);
}

// Longest run of a single byte value, e.g. a NOP sled of 0x90. O(len), no
// allocation, fully bounded by the buffer.
std::size_t LongestByteRun(const std::uint8_t* data, std::size_t len,
                           std::uint8_t value) {
    std::size_t best = 0;
    std::size_t run = 0;
    for (std::size_t i = 0; i < len; ++i) {
        if (data[i] == value) {
            ++run;
            if (run > best) best = run;
        } else {
            run = 0;
        }
    }
    return best;
}

// Known position-independent shellcode prologues: GetPC stubs, PEB walks, and
// egg-hunter kernels. A hit is a strong indicator of hand-written shellcode
// (legitimate compiled code does not resolve its own address this way). All
// searches are bounded linear scans of the captured bytes.
bool ContainsAnyShellcodeStub(const std::uint8_t* data, std::size_t len) {
    // Each pattern is a short, well-known byte signature.
    static const std::array<Bytes, 6> kStubs = {{
        // call $+5 ; the classic GetPC (call over zero displacement).
        {0xE8, 0x00, 0x00, 0x00, 0x00},
        // fnstenv [esp-0x0c] ; GetPC via the saved FPU instruction pointer.
        {0xD9, 0x74, 0x24, 0xF4},
        // fldz ; fnstenv ... ; the fldz-primed fnstenv GetPC variant.
        {0xD9, 0xEE, 0xD9, 0x74, 0x24},
        // mov eax, fs:[0x30] ; 32-bit PEB walk (process environment block).
        {0x64, 0xA1, 0x30, 0x00, 0x00, 0x00},
        // mov rax, gs:[0x60] ; 64-bit PEB walk.
        {0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00},
        // or dx, 0x0fff ; page-align loop body of the skape egg-hunter.
        {0x66, 0x81, 0xCA, 0xFF, 0x0F},
    }};
    for (const auto& pat : kStubs) {
        if (pat.empty() || pat.size() > len) continue;  // bounds guard
        if (std::search(data, data + len, pat.begin(), pat.end()) != data + len) {
            return true;
        }
    }
    return false;
}

// Fraction of bytes that are common x86/x64 opcode bytes (calls, jumps, the
// push/pop register range, frequent mov forms). A region that should hold data
// but is dense with these is weak evidence of staged machine code.
double CodeByteDensity(const std::uint8_t* data, std::size_t len) {
    if (len == 0) return 0.0;
    static const std::array<bool, 256> kCodeByte = [] {
        std::array<bool, 256> t{};
        const std::uint8_t common[] = {
            0xE8, 0xE9, 0xEB,              // call / jmp near / jmp short
            0xFF,                          // call/jmp/push/inc group
            0x55, 0x89, 0x8B, 0x83, 0xC3,  // push ebp / mov / add / ret
            0x68, 0x6A,                    // push imm32 / imm8
        };
        for (std::uint8_t b : common) t[b] = true;
        for (int b = 0x50; b <= 0x5F; ++b) t[b] = true;  // push/pop reg
        return t;
    }();
    std::size_t hits = 0;
    for (std::size_t i = 0; i < len; ++i) {
        if (kCodeByte[data[i]]) ++hits;
    }
    return static_cast<double>(hits) / static_cast<double>(len);
}

constexpr std::size_t kNopSledThreshold = 16;    // bytes of 0x90 before we flag
constexpr double kCodeDensityThreshold = 0.30;   // fraction of common opcodes

}  // namespace

MemoryScanResult MemoryScanner::ScanRegion(std::uint32_t pid,
                                           const MemoryRegion& region) const {
    MemoryScanResult result;
    const std::string where = "pid " + std::to_string(pid) + " region 0x" +
                              HexU64(region.base);

    // --- Structural signals from the region's protection/backing ---
    if (region.private_commit && region.writable && region.executable) {
        // Private, committed RWX memory: no legitimate image loader maps code
        // writable-and-executable. The hallmark of shellcode run in place.
        result.signals.emplace_back(
            SignalSource::MemoryScan, RiskLevel::Malicious, 0.90,
            where + ": private committed RWX memory (injected/self-modifying code)",
            "mem.rwx_private");
    } else if (region.executable && !region.image_backed) {
        // Executable memory not backed by a file on disk => code that was never
        // loaded as a module: reflectively loaded DLL, manual map, or injection.
        result.signals.emplace_back(
            SignalSource::MemoryScan, RiskLevel::Suspicious, 0.75,
            where + ": executable non-image-backed memory (reflective/injected code)",
            "mem.exec_not_image");
    }

    // --- Content heuristics (bounded, read-only over the captured sample) ---
    const std::uint8_t* data = region.contents.data();
    const std::size_t len = region.contents.size();
    if (len > 0) {
        // NOP sled: a long run of 0x90 is a classic landing pad ahead of a
        // payload. Confidence scales with the sled length, capped.
        const std::size_t nop_run = LongestByteRun(data, len, 0x90);
        if (nop_run >= kNopSledThreshold) {
            const double conf = Clamp01(0.4 + 0.01 * static_cast<double>(nop_run));
            result.signals.emplace_back(
                SignalSource::MemoryScan, RiskLevel::Suspicious, conf,
                where + ": NOP sled of " + std::to_string(nop_run) + " bytes",
                "mem.nop_sled");
        }

        // Position-independent shellcode prologue (GetPC / PEB walk / egg hunter).
        if (ContainsAnyShellcodeStub(data, len)) {
            result.signals.emplace_back(
                SignalSource::MemoryScan, RiskLevel::Malicious, 0.70,
                where + ": position-independent shellcode stub (GetPC/PEB-walk/egg-hunter)",
                "mem.shellcode_stub");
        }

        // Dense common-opcode content is weak corroboration of staged code.
        const double density = CodeByteDensity(data, len);
        if (density >= kCodeDensityThreshold) {
            // Scale confidence by how far past the threshold we are, kept low so
            // it only ever corroborates a stronger signal.
            const double conf = Clamp01((density - kCodeDensityThreshold) * 1.5);
            if (conf > 0.0) {
                result.signals.emplace_back(
                    SignalSource::MemoryScan, RiskLevel::LowRisk, conf,
                    where + ": high executable-byte density", "mem.code_density");
            }
        }
    }

    // --- Rule matches against the captured bytes, if a rule set was supplied ---
    if (rules_ != nullptr && len > 0) {
        rules_->Match(data, len, result.matches);
        for (const auto& m : result.matches) {
            std::string detail = where + ": memory rule match " + m.rule_id;
            if (!m.description.empty()) detail += " (" + m.description + ")";
            result.signals.emplace_back(SignalSource::MemoryScan,
                                        SeverityToLevel(m.severity),
                                        Clamp01(m.weight), detail, m.rule_id);
        }
    }

    // Fuse this region's evidence with a noisy-OR.
    result.score = NoisyOr(result.signals);
    return result;
}

MemoryScanResult MemoryScanner::ScanProcess(
    std::uint32_t pid, const std::vector<MemoryRegion>& regions) const {
    MemoryScanResult fused;
    for (const auto& region : regions) {
        MemoryScanResult r = ScanRegion(pid, region);
        // Gather every region's signals and rule matches into the process view.
        fused.signals.insert(fused.signals.end(),
                             std::make_move_iterator(r.signals.begin()),
                             std::make_move_iterator(r.signals.end()));
        fused.matches.insert(fused.matches.end(),
                             std::make_move_iterator(r.matches.begin()),
                             std::make_move_iterator(r.matches.end()));
    }
    // Fuse across all regions with the same noisy-OR, so one convicting region
    // drives the process score while weak signals from several regions add up.
    fused.score = NoisyOr(fused.signals);
    return fused;
}

}  // namespace sentinel
