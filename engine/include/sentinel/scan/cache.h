// Verdict cache. The expensive work is done once per file: a file's hash maps
// to a cached verdict, so an unchanged, already-scanned, known-good file is
// cleared instantly on every future open. Entries are invalidated when the
// file changes (its hash changes, so a stale entry is simply never hit).
//
// Thread-safe. Bounded by capacity with simple LRU eviction.
#ifndef SENTINEL_SCAN_CACHE_H
#define SENTINEL_SCAN_CACHE_H

#include <atomic>
#include <cstddef>
#include <list>
#include <mutex>
#include <string>
#include <unordered_map>

#include "sentinel/core/types.h"

namespace sentinel {

class VerdictCache {
public:
    explicit VerdictCache(std::size_t capacity = 100000) : capacity_(capacity) {}

    // Look up a verdict by file hash. Returns true and fills `out` on a hit.
    bool Get(const std::string& sha256_hex, Verdict& out);

    // Insert or update a verdict for a hash.
    void Put(const std::string& sha256_hex, const Verdict& verdict);

    void Invalidate(const std::string& sha256_hex);
    void Clear();

    std::size_t size() const;
    std::size_t hits() const { return hits_.load(); }
    std::size_t misses() const { return misses_.load(); }

private:
    struct Entry {
        std::string key;
        Verdict verdict;
    };
    void Touch(std::list<Entry>::iterator it);

    mutable std::mutex mutex_;
    std::size_t capacity_;
    std::list<Entry> lru_;  // front = most recently used
    std::unordered_map<std::string, std::list<Entry>::iterator> index_;
    std::atomic<std::size_t> hits_{0};
    std::atomic<std::size_t> misses_{0};
};

}  // namespace sentinel

#endif  // SENTINEL_SCAN_CACHE_H
