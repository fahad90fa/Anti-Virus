// In-memory scanning. File- and behavior-based layers can miss code that only
// ever lives in RAM. This scans a captured region of process memory for code
// that never touched disk: injected shellcode, reflectively loaded DLLs, and
// payloads unpacked in RAM. It is triggered by the suspicious-allocation and
// injection signals from the kernel sensors, so it scans at the right moment.
#ifndef SENTINEL_MEMORY_MEM_SCAN_H
#define SENTINEL_MEMORY_MEM_SCAN_H

#include <cstdint>
#include <string>
#include <vector>

#include "sentinel/core/bytes.h"
#include "sentinel/core/types.h"
#include "sentinel/scan/rule_engine.h"

namespace sentinel {

// Describes a region of a process's memory handed to the scanner.
struct MemoryRegion {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    bool executable = false;
    bool writable = false;
    bool image_backed = false;  // backed by a file on disk (a loaded module)
    bool private_commit = false;
    Bytes contents;             // captured bytes (may be a sample of the region)
};

struct MemoryScanResult {
    std::vector<Signal> signals;
    std::vector<RuleMatch> matches;
    double score = 0.0;
};

class MemoryScanner {
public:
    // Rules are optional; if provided they are matched against region contents.
    explicit MemoryScanner(const RuleSet* rules = nullptr) : rules_(rules) {}

    // Scan one region. Flags private + RWX, executable-but-not-image-backed
    // (classic injected/reflective code), shellcode byte patterns, and rule hits.
    MemoryScanResult ScanRegion(std::uint32_t pid, const MemoryRegion& region) const;

    // Scan a set of regions for a process, fusing per-region findings.
    MemoryScanResult ScanProcess(std::uint32_t pid,
                                 const std::vector<MemoryRegion>& regions) const;

private:
    const RuleSet* rules_;
};

}  // namespace sentinel

#endif  // SENTINEL_MEMORY_MEM_SCAN_H
