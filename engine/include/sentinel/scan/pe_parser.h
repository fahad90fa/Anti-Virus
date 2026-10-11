// PE structure heuristics — Layer 3 of static scanning. Parse the Portable
// Executable (Windows .exe/.dll) and score structural red flags: a tiny code
// section beside a huge high-entropy blob (a packed/encrypted payload); imports
// consisting only of LoadLibrary/GetProcAddress (runtime API resolution to hide
// intent); a missing/mismatched signature; sections both writable and
// executable; a timestamp from the future. No single flag convicts; the
// weighted sum raises or lowers suspicion.
#ifndef SENTINEL_SCAN_PE_PARSER_H
#define SENTINEL_SCAN_PE_PARSER_H

#include <cstdint>
#include <string>
#include <vector>

#include "sentinel/core/bytes.h"
#include "sentinel/core/result.h"

namespace sentinel {

struct PeSection {
    std::string name;
    std::uint32_t virtual_size = 0;
    std::uint32_t raw_size = 0;
    std::uint32_t characteristics = 0;
    double entropy = 0.0;
    bool executable = false;
    bool writable = false;
    bool readable = false;
};

struct PeInfo {
    bool is_pe = false;
    bool is_64bit = false;
    bool is_dll = false;
    std::uint32_t timestamp = 0;             // PE header TimeDateStamp
    std::uint32_t entry_point_rva = 0;
    std::uint16_t section_count = 0;
    std::vector<PeSection> sections;
    std::vector<std::string> imported_dlls;
    std::vector<std::string> imported_functions;
    bool has_import_table = false;
    bool has_certificate = false;            // security directory present
    std::string entry_section;               // section containing the entry point
};

// A PE heuristic finding and the overall structural score.
struct PeHeuristicResult {
    PeInfo info;
    double score = 0.0;                      // [0,1] structural suspicion
    std::vector<std::string> flags;          // human-readable red flags
};

class PeParser {
public:
    // Parse the PE headers from a buffer. Returns Unsupported if not a PE.
    static Result<PeInfo> Parse(const std::uint8_t* data, std::size_t len);
    static Result<PeInfo> Parse(const Bytes& b) { return Parse(b.data(), b.size()); }

    // Parse and score structural heuristics. `high_entropy_threshold` controls
    // the packed-section flag (default 7.2 bits/byte).
    static PeHeuristicResult Analyze(const Bytes& b,
                                     double high_entropy_threshold = 7.2);
};

}  // namespace sentinel

#endif  // SENTINEL_SCAN_PE_PARSER_H
