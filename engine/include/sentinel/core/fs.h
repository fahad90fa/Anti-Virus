// Filesystem helpers built on <filesystem> (C++17). Reading file contents,
// walking directory trees, and safe size-capped reads for the scanner.
#ifndef SENTINEL_CORE_FS_H
#define SENTINEL_CORE_FS_H

#include <cstdint>
#include <functional>
#include <string>

#include "sentinel/core/bytes.h"
#include "sentinel/core/result.h"

namespace sentinel {

// Read an entire file into memory. `max_bytes` caps the read (0 = unlimited);
// files larger than the cap return only the first max_bytes (enough for
// hashing the head and PE parsing). Use ReadFileFull for exact hashing.
Result<Bytes> ReadFile(const std::string& path, std::size_t max_bytes = 0);

// Hash a file streaming from disk (no full load), returning the hex SHA-256.
Result<std::string> HashFile(const std::string& path);

// File size in bytes, or an error if it cannot be stat'd.
Result<std::uint64_t> FileSize(const std::string& path);

bool PathExists(const std::string& path);
bool IsRegularFile(const std::string& path);
bool IsDirectory(const std::string& path);
bool MakeDirs(const std::string& path);

// Walk a directory tree, invoking `visit` for every regular file. If
// `recursive` is false, only the immediate directory is scanned.
Status WalkFiles(const std::string& root, bool recursive,
                 const std::function<void(const std::string&)>& visit);

// Atomic-ish write: write to a temp file then rename over the destination.
Status WriteFileAtomic(const std::string& path, const Bytes& data);
Status WriteFileAtomic(const std::string& path, const std::string& data);

std::string FileName(const std::string& path);
std::string Extension(const std::string& path);  // lowercased, includes dot
std::string ParentDir(const std::string& path);
std::string JoinPath(const std::string& a, const std::string& b);

}  // namespace sentinel

#endif  // SENTINEL_CORE_FS_H
