// Self-code integrity checks. Part of self-protection: the engine verifies that
// its own on-disk modules and its configuration/signature store have not been
// tampered with, so malware cannot silently weaken settings or poison rules.
// Known-good hashes are recorded at install/update time (sealed by the trustlet
// in production) and verified at startup and periodically.
#ifndef SENTINEL_LOWLEVEL_INTEGRITY_H
#define SENTINEL_LOWLEVEL_INTEGRITY_H

#include <map>
#include <string>
#include <vector>

#include "sentinel/core/result.h"

namespace sentinel {

struct IntegrityViolation {
    std::string path;
    std::string expected_hash;
    std::string actual_hash;  // "" if the file is missing
    std::string reason;
};

class SelfIntegrity {
public:
    // Record (or update) the known-good hash for a protected file by hashing it
    // now. Call at install/update time.
    Status Enroll(const std::string& path);

    // Load/save the manifest of protected files and their known-good hashes.
    Status LoadManifest(const std::string& manifest_path);
    Status SaveManifest(const std::string& manifest_path) const;

    // Verify all enrolled files. Returns the list of violations (empty = intact).
    std::vector<IntegrityViolation> Verify() const;

    void AddExpected(const std::string& path, const std::string& hash) {
        expected_[path] = hash;
    }
    std::size_t protected_count() const { return expected_.size(); }

private:
    std::map<std::string, std::string> expected_;  // path -> known-good sha256
};

}  // namespace sentinel

#endif  // SENTINEL_LOWLEVEL_INTEGRITY_H
