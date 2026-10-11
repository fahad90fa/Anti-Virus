#include "sentinel/scan/subject.h"

#include <utility>

#include "sentinel/core/fs.h"
#include "sentinel/core/sha256.h"

namespace sentinel {

Result<FileSubject> FileSubject::FromFile(const std::string& path,
                                          std::size_t max_content) {
    // Capped content read for cheap feature extraction (PE headers, string
    // scanning). max_content == 0 means "whole file".
    auto content = ReadFile(path, max_content);
    if (!content) {
        return content.status();
    }
    // True on-disk size, independent of the (possibly capped) read.
    auto size = FileSize(path);
    if (!size) {
        return size.status();
    }
    // Exact full-file hash is streamed from disk so the cache key and the
    // allow/block lookup are correct even when `content` was truncated.
    auto hash = HashFile(path);
    if (!hash) {
        return hash.status();
    }

    FileSubject s;
    s.path = path;
    s.display_name = FileName(path);
    s.content = std::move(content.value());
    s.size = size.value();
    // Truncated iff the file is larger than what we actually loaded.
    s.content_truncated = s.size > s.content.size();
    s.sha256 = std::move(hash.value());
    s.extension = Extension(path);
    return s;
}

FileSubject FileSubject::FromBuffer(Bytes bytes, std::string name) {
    FileSubject s;
    s.display_name = std::move(name);
    s.size = bytes.size();
    s.content_truncated = false;  // the buffer IS the whole subject
    // Hash the buffer directly before it is moved into `content`.
    s.sha256 = Sha256::HexDigest(bytes);
    s.extension = Extension(s.display_name);
    s.content = std::move(bytes);
    return s;
}

}  // namespace sentinel
