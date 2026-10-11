#include "sentinel/scan/cache.h"

#include <iterator>
#include <utility>

namespace sentinel {

void VerdictCache::Touch(std::list<Entry>::iterator it) {
    // Move the entry to the front (most-recently-used). splice keeps `it`
    // valid and does not invalidate the iterator stored in index_.
    lru_.splice(lru_.begin(), lru_, it);
}

bool VerdictCache::Get(const std::string& sha256_hex, Verdict& out) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = index_.find(sha256_hex);
    if (it == index_.end()) {
        misses_.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    Touch(it->second);
    out = it->second->verdict;
    hits_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

void VerdictCache::Put(const std::string& sha256_hex, const Verdict& verdict) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = index_.find(sha256_hex);
    if (it != index_.end()) {
        // Update in place and refresh recency.
        it->second->verdict = verdict;
        Touch(it->second);
        return;
    }
    lru_.push_front(Entry{sha256_hex, verdict});
    index_[sha256_hex] = lru_.begin();

    // Evict the least-recently-used entries until we are within capacity.
    while (index_.size() > capacity_ && !lru_.empty()) {
        auto last = std::prev(lru_.end());
        index_.erase(last->key);
        lru_.pop_back();
    }
}

void VerdictCache::Invalidate(const std::string& sha256_hex) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = index_.find(sha256_hex);
    if (it == index_.end()) return;
    lru_.erase(it->second);
    index_.erase(it);
}

void VerdictCache::Clear() {
    std::lock_guard<std::mutex> lock(mutex_);
    lru_.clear();
    index_.clear();
}

std::size_t VerdictCache::size() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return index_.size();
}

}  // namespace sentinel
