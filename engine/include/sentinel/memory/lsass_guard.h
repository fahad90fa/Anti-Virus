// Credential-theft protection. Guard high-value targets, especially LSASS (the
// process holding Windows credentials), from memory-dumping tools of the
// Mimikatz family. Illicit attempts to read LSASS memory are blocked through the
// object callbacks and raised as a severe signal. This module holds the policy;
// the kernel object-callback driver enforces it.
#ifndef SENTINEL_MEMORY_LSASS_GUARD_H
#define SENTINEL_MEMORY_LSASS_GUARD_H

#include <cstdint>
#include <string>
#include <unordered_set>

#include "sentinel/core/types.h"

namespace sentinel {

// A requested handle open to a protected process, as seen by the object
// callback. The guard decides allow/deny and the resulting signal.
struct HandleRequest {
    std::uint32_t source_pid = 0;
    std::string source_image;        // requester image path
    std::uint32_t target_pid = 0;
    std::string target_image;        // e.g. "lsass.exe"
    std::uint32_t desired_access = 0;// requested access mask
};

struct HandleDecision {
    bool deny = false;
    std::uint32_t stripped_access = 0;  // access bits removed if not denied
    Signal signal;
};

class LsassGuard {
public:
    LsassGuard();

    // Register image names that are allowed to read protected processes
    // (e.g. known AV/EDR, the OS itself). Matching is case-insensitive basename.
    void AllowReader(const std::string& image_basename);

    // Mark a process image as a protected credential store (default: lsass.exe).
    void ProtectImage(const std::string& image_basename);

    HandleDecision Evaluate(const HandleRequest& req) const;

private:
    std::unordered_set<std::string> protected_images_;
    std::unordered_set<std::string> allowed_readers_;
};

}  // namespace sentinel

#endif  // SENTINEL_MEMORY_LSASS_GUARD_H
