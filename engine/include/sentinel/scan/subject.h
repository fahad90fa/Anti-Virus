// A Subject is the thing being evaluated — most often a file. It carries the
// content (or a capped head of it), the computed hash, size, and derived
// features so that each scan layer does not re-read or re-hash.
#ifndef SENTINEL_SCAN_SUBJECT_H
#define SENTINEL_SCAN_SUBJECT_H

#include <cstdint>
#include <string>

#include "sentinel/core/bytes.h"
#include "sentinel/core/result.h"
#include "sentinel/core/types.h"

namespace sentinel {

struct FileSubject {
    std::string path;        // original path (may be empty for in-memory buffers)
    std::string display_name;// name shown in UI / timeline
    Bytes content;           // file bytes (possibly capped — see content_truncated)
    std::uint64_t size = 0;  // true size on disk
    bool content_truncated = false;
    std::string sha256;      // hex digest of the FULL file (streamed), may be empty
    std::string extension;   // lowercased, includes dot

    // Load a file into a FileSubject. Reads up to `max_content` bytes into
    // `content` (0 = whole file) and always streams the full file to compute
    // the exact sha256.
    static Result<FileSubject> FromFile(const std::string& path,
                                        std::size_t max_content = 16 * 1024 * 1024);

    // Build a subject from an in-memory buffer (e.g. unpacked payload, script).
    static FileSubject FromBuffer(Bytes bytes, std::string name);

    double Entropy() const { return ShannonEntropy(content); }
    bool LooksLikePe() const {  // "MZ" magic
        return content.size() >= 2 && content[0] == 'M' && content[1] == 'Z';
    }
};

}  // namespace sentinel

#endif  // SENTINEL_SCAN_SUBJECT_H
