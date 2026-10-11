#include "sentinel/scan/pe_parser.h"

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "sentinel/core/bytes.h"
#include "sentinel/core/result.h"

namespace sentinel {
namespace {

// Bounds-checked little-endian readers. Every PE field access goes through
// these so a truncated or crafted buffer can never be read out of range.
bool Rd16(const std::uint8_t* d, std::size_t len, std::size_t off,
          std::uint16_t& out) {
    if (off + 2 > len) return false;
    out = static_cast<std::uint16_t>(d[off] |
                                     (static_cast<std::uint16_t>(d[off + 1]) << 8));
    return true;
}

bool Rd32(const std::uint8_t* d, std::size_t len, std::size_t off,
          std::uint32_t& out) {
    if (off + 4 > len) return false;
    out = static_cast<std::uint32_t>(d[off]) |
          (static_cast<std::uint32_t>(d[off + 1]) << 8) |
          (static_cast<std::uint32_t>(d[off + 2]) << 16) |
          (static_cast<std::uint32_t>(d[off + 3]) << 24);
    return true;
}

std::string Fmt2(double v) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.2f", v);
    return std::string(buf);
}

bool StartsWith(const std::string& s, const char* prefix) {
    const std::size_t n = std::char_traits<char>::length(prefix);
    return s.size() >= n && s.compare(0, n, prefix) == 0;
}

// Section address map used to translate RVAs to file offsets.
struct SecMap {
    std::uint32_t vaddr = 0;
    std::uint32_t vsize = 0;
    std::uint32_t praw = 0;
    std::uint32_t rsize = 0;
};

// Translate an RVA to a file offset using the section map. Returns false when
// the RVA falls outside any section's on-disk range (so we never read OOB).
bool RvaToOffset(const std::vector<SecMap>& maps, std::size_t len,
                 std::uint32_t rva, std::size_t& off) {
    for (const auto& m : maps) {
        const std::uint32_t vsz = m.vsize ? m.vsize : m.rsize;
        if (vsz == 0) continue;
        if (rva >= m.vaddr && rva < static_cast<std::uint64_t>(m.vaddr) + vsz) {
            const std::uint32_t delta = rva - m.vaddr;
            if (delta >= m.rsize) return false;  // in virtual-only tail
            const std::size_t o = static_cast<std::size_t>(m.praw) + delta;
            if (o >= len) return false;
            off = o;
            return true;
        }
    }
    return false;
}

// Read a bounded, NUL-terminated ASCII string starting at a file offset.
std::string ReadCStr(const std::uint8_t* d, std::size_t len, std::size_t off,
                     std::size_t max_chars) {
    std::string out;
    for (std::size_t k = 0; k < max_chars && off + k < len; ++k) {
        const char ch = static_cast<char>(d[off + k]);
        if (ch == '\0') break;
        out.push_back(ch);
    }
    return out;
}

}  // namespace

Result<PeInfo> PeParser::Parse(const std::uint8_t* data, std::size_t len) {
    PeInfo info;

    // DOS header: "MZ" magic + e_lfanew at 0x3C.
    if (!data || len < 0x40) {
        return Status::Error(ErrorCode::Unsupported, "not a PE: too small");
    }
    if (data[0] != 'M' || data[1] != 'Z') {
        return Status::Error(ErrorCode::Unsupported, "not a PE: missing MZ");
    }
    std::uint32_t e_lfanew = 0;
    Rd32(data, len, 0x3C, e_lfanew);
    // Need room for PE signature (4) + COFF header (20).
    if (static_cast<std::uint64_t>(e_lfanew) + 24 > len) {
        return Status::Error(ErrorCode::Unsupported,
                             "not a PE: e_lfanew out of range");
    }
    if (!(data[e_lfanew] == 'P' && data[e_lfanew + 1] == 'E' &&
          data[e_lfanew + 2] == 0 && data[e_lfanew + 3] == 0)) {
        return Status::Error(ErrorCode::Unsupported,
                             "not a PE: missing PE signature");
    }
    info.is_pe = true;

    // COFF file header.
    const std::size_t coff = static_cast<std::size_t>(e_lfanew) + 4;
    std::uint16_t machine = 0, num_sections = 0, size_opt = 0, characteristics = 0;
    std::uint32_t timestamp = 0;
    Rd16(data, len, coff + 0, machine);
    Rd16(data, len, coff + 2, num_sections);
    Rd32(data, len, coff + 4, timestamp);
    Rd16(data, len, coff + 16, size_opt);
    Rd16(data, len, coff + 18, characteristics);
    (void)machine;
    info.timestamp = timestamp;
    info.is_dll = (characteristics & 0x2000u) != 0;  // IMAGE_FILE_DLL
    info.section_count = num_sections;

    // Optional header.
    const std::size_t opt = coff + 20;
    std::uint16_t magic = 0;
    if (!Rd16(data, len, opt, magic)) {
        return Status::Error(ErrorCode::Unsupported,
                             "not a PE: truncated optional header");
    }
    info.is_64bit = (magic == 0x20b);  // 0x10b=PE32, 0x20b=PE32+

    std::uint32_t entry = 0;
    Rd32(data, len, opt + 16, entry);  // AddressOfEntryPoint
    info.entry_point_rva = entry;

    // Data directory layout differs between PE32 and PE32+.
    std::size_t dd_off = 0;
    std::uint32_t num_rva = 0;
    if (info.is_64bit) {
        Rd32(data, len, opt + 108, num_rva);
        dd_off = opt + 112;
    } else {
        Rd32(data, len, opt + 92, num_rva);
        dd_off = opt + 96;
    }
    std::uint32_t import_rva = 0, import_size = 0, sec_rva = 0, sec_size = 0;
    if (num_rva > 1) {  // index 1 = import table
        Rd32(data, len, dd_off + 1 * 8 + 0, import_rva);
        Rd32(data, len, dd_off + 1 * 8 + 4, import_size);
    }
    if (num_rva > 4) {  // index 4 = certificate / security table
        Rd32(data, len, dd_off + 4 * 8 + 0, sec_rva);
        Rd32(data, len, dd_off + 4 * 8 + 4, sec_size);
    }
    (void)import_size;
    (void)sec_rva;
    info.has_import_table = (import_rva != 0);
    info.has_certificate = (sec_size > 0);

    // Section headers (40 bytes each), starting right after the optional header.
    const std::size_t sec_table = opt + size_opt;
    std::vector<SecMap> maps;
    maps.reserve(num_sections);
    for (std::uint16_t i = 0; i < num_sections; ++i) {
        const std::size_t so =
            sec_table + static_cast<std::size_t>(i) * 40;
        if (so + 40 > len) break;  // truncated section table — stop safely

        PeSection sec;
        // Section name: up to 8 bytes, not necessarily NUL-terminated.
        std::size_t nl = 0;
        while (nl < 8 && data[so + nl] != 0) ++nl;
        sec.name.assign(reinterpret_cast<const char*>(data + so), nl);

        std::uint32_t vsize = 0, vaddr = 0, rsize = 0, praw = 0, chars = 0;
        Rd32(data, len, so + 8, vsize);
        Rd32(data, len, so + 12, vaddr);
        Rd32(data, len, so + 16, rsize);
        Rd32(data, len, so + 20, praw);
        Rd32(data, len, so + 36, chars);

        sec.virtual_size = vsize;
        sec.raw_size = rsize;
        sec.characteristics = chars;
        sec.executable = (chars & 0x20000000u) != 0;  // MEM_EXECUTE
        sec.writable = (chars & 0x80000000u) != 0;     // MEM_WRITE
        sec.readable = (chars & 0x40000000u) != 0;     // MEM_READ

        // Per-section entropy over its on-disk bytes, clamped to the buffer.
        if (rsize > 0 && praw < len) {
            const std::size_t avail =
                std::min(static_cast<std::size_t>(rsize), len - praw);
            sec.entropy = ShannonEntropy(data + praw, avail);
        }

        maps.push_back(SecMap{vaddr, vsize, praw, rsize});
        info.sections.push_back(std::move(sec));
    }

    // Identify the section containing the entry point (by RVA range).
    for (std::size_t i = 0; i < maps.size(); ++i) {
        const std::uint32_t vsz = maps[i].vsize ? maps[i].vsize : maps[i].rsize;
        if (vsz == 0) continue;
        if (info.entry_point_rva >= maps[i].vaddr &&
            info.entry_point_rva <
                static_cast<std::uint64_t>(maps[i].vaddr) + vsz) {
            info.entry_section = info.sections[i].name;
            break;
        }
    }

    // Best-effort import table walk. Every access is bounds-checked and the
    // loops are capped so a hostile or truncated table cannot hang or over-read.
    if (info.has_import_table) {
        std::size_t imp_off = 0;
        if (RvaToOffset(maps, len, import_rva, imp_off)) {
            const std::size_t kMaxDesc = 4096;
            for (std::size_t d = 0; d < kMaxDesc; ++d) {
                const std::size_t desc = imp_off + d * 20;
                if (desc + 20 > len) break;
                std::uint32_t oft = 0, name_rva = 0, ft = 0;
                Rd32(data, len, desc + 0, oft);   // OriginalFirstThunk (ILT)
                Rd32(data, len, desc + 12, name_rva);
                Rd32(data, len, desc + 16, ft);   // FirstThunk (IAT)
                if (oft == 0 && name_rva == 0 && ft == 0) break;  // terminator

                std::size_t noff = 0;
                if (name_rva != 0 && RvaToOffset(maps, len, name_rva, noff)) {
                    const std::string dll = ReadCStr(data, len, noff, 256);
                    if (!dll.empty()) info.imported_dlls.push_back(dll);
                }

                // Prefer the import lookup table; fall back to the IAT.
                const std::uint32_t thunk_rva = oft ? oft : ft;
                if (thunk_rva == 0) continue;
                std::size_t toff = 0;
                if (!RvaToOffset(maps, len, thunk_rva, toff)) continue;

                const std::size_t entry_sz = info.is_64bit ? 8 : 4;
                const std::size_t kMaxThunks = 8192;
                for (std::size_t t = 0; t < kMaxThunks; ++t) {
                    const std::size_t te = toff + t * entry_sz;
                    std::uint64_t val = 0;
                    if (info.is_64bit) {
                        std::uint32_t lo = 0, hi = 0;
                        if (!Rd32(data, len, te, lo) ||
                            !Rd32(data, len, te + 4, hi)) {
                            break;
                        }
                        val = (static_cast<std::uint64_t>(hi) << 32) | lo;
                    } else {
                        std::uint32_t lo = 0;
                        if (!Rd32(data, len, te, lo)) break;
                        val = lo;
                    }
                    if (val == 0) break;  // end of this DLL's thunk list

                    const bool by_ordinal =
                        info.is_64bit
                            ? (val & 0x8000000000000000ull) != 0
                            : (val & 0x80000000u) != 0;
                    if (by_ordinal) continue;  // no name to collect

                    const std::uint32_t hint_name_rva =
                        static_cast<std::uint32_t>(val & 0x7fffffffu);
                    std::size_t hnoff = 0;
                    if (!RvaToOffset(maps, len, hint_name_rva, hnoff)) continue;
                    // IMAGE_IMPORT_BY_NAME: 2-byte hint, then the ASCII name.
                    const std::string func =
                        ReadCStr(data, len, hnoff + 2, 256);
                    if (!func.empty() &&
                        info.imported_functions.size() < 65536) {
                        info.imported_functions.push_back(func);
                    }
                }
            }
        }
    }

    return info;
}

PeHeuristicResult PeParser::Analyze(const Bytes& b,
                                    double high_entropy_threshold) {
    PeHeuristicResult res;
    auto parsed = Parse(b.data(), b.size());
    if (!parsed) {
        return res;  // not a PE: empty info, score 0
    }
    res.info = std::move(parsed.value());
    const PeInfo& pe = res.info;
    double score = 0.0;

    // Flag: a tiny code section beside a much larger high-entropy section is a
    // classic packer/encrypted-payload layout.
    const PeSection* code = nullptr;     // smallest executable section
    const PeSection* big_he = nullptr;   // largest high-entropy section
    std::uint32_t max_raw = 0;
    for (const auto& s : pe.sections) {
        if (s.executable && (code == nullptr || s.raw_size < code->raw_size)) {
            code = &s;
        }
    }
    for (const auto& s : pe.sections) {
        if (s.entropy > high_entropy_threshold && s.raw_size >= max_raw) {
            max_raw = s.raw_size;
            big_he = &s;
        }
    }
    if (code && big_he && code != big_he && code->raw_size > 0 &&
        static_cast<std::uint64_t>(big_he->raw_size) >=
            static_cast<std::uint64_t>(code->raw_size) * 4) {
        score += 0.35;
        res.flags.push_back(
            "tiny code section beside large high-entropy section '" +
            big_he->name + "' (entropy " + Fmt2(big_he->entropy) +
            ", likely packed)");
    } else if (big_he) {
        score += 0.10;
        res.flags.push_back("high-entropy section '" + big_he->name +
                            "' (entropy " + Fmt2(big_he->entropy) + ")");
    }

    // Flag: imports consist ONLY of dynamic API resolution primitives, a way to
    // hide real intent from static import analysis.
    if (!pe.imported_functions.empty()) {
        bool only_dynamic_resolution = true;
        for (const auto& f : pe.imported_functions) {
            if (!(StartsWith(f, "LoadLibrary") || f == "GetProcAddress")) {
                only_dynamic_resolution = false;
                break;
            }
        }
        if (only_dynamic_resolution) {
            score += 0.30;
            res.flags.push_back(
                "imports only runtime API resolution "
                "(LoadLibrary*/GetProcAddress)");
        }
    }

    // Flag: no embedded code-signing certificate (weak on its own — lots of
    // legitimate software is unsigned — so it carries little weight).
    if (!pe.has_certificate) {
        score += 0.10;
        res.flags.push_back("no embedded code-signing certificate");
    }

    // Flag: any section that is both writable and executable (self-modifying /
    // unpacking stub).
    for (const auto& s : pe.sections) {
        if (s.writable && s.executable) {
            score += 0.25;
            res.flags.push_back("section '" + s.name +
                                "' is both writable and executable");
            break;
        }
    }

    // Flag: a build timestamp in the far future (bogus header). ~2100-01-01.
    const std::uint32_t kYear2100Epoch = 4102444800u;
    if (pe.timestamp > kYear2100Epoch) {
        score += 0.10;
        res.flags.push_back("PE timestamp is implausibly far in the future");
    }

    if (score < 0.0) score = 0.0;
    if (score > 1.0) score = 1.0;
    res.score = score;
    return res;
}

}  // namespace sentinel
