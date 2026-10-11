// Hash lookup — Layer 1 of static scanning (the fast path). A SHA-256 blocklist
// of known-malware hashes and an allowlist of known-good hashes. A hit on
// either ends the scan immediately: allowlist => Trusted, blocklist => Malicious.
#ifndef SENTINEL_SCAN_HASH_STORE_H
#define SENTINEL_SCAN_HASH_STORE_H

#include <string>
#include <unordered_map>
#include <unordered_set>

#include "sentinel/core/result.h"

namespace sentinel {

enum class HashVerdict { Unknown, Allowed, Blocked };

class HashStore {
public:
    // Load allowlist and blocklist from text files. Each line is a hex SHA-256,
    // optionally followed by whitespace and a label/comment. Lines starting with
    // '#' are comments. Missing files are not an error (empty set).
    Status LoadAllowlist(const std::string& path);
    Status LoadBlocklist(const std::string& path);

    // In-memory additions (tests, dynamic updates).
    void AddAllowed(const std::string& sha256_hex, std::string label = {});
    void AddBlocked(const std::string& sha256_hex, std::string label = {});

    HashVerdict Lookup(const std::string& sha256_hex) const;

    // If the hash is blocked, returns its label (malware family), else "".
    std::string BlockedLabel(const std::string& sha256_hex) const;

    std::size_t allowed_count() const { return allowed_.size(); }
    std::size_t blocked_count() const { return blocked_.size(); }

private:
    static std::string Normalize(const std::string& hex);
    std::unordered_set<std::string> allowed_;
    std::unordered_map<std::string, std::string> blocked_;  // hash -> label
};

}  // namespace sentinel

#endif  // SENTINEL_SCAN_HASH_STORE_H
