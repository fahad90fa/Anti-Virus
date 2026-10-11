// Forensic kill-chain timeline. Every significant event (process launches, file
// and registry changes, network connections, injections, detections) is recorded
// into a durable, sealed local timeline. When a threat is confirmed, the full
// attack chain is reconstructable: the entry point, what it did, and where it
// tried to go. This is both the user's explanation and what data remediation
// acts on.
#ifndef SENTINEL_EDR_TIMELINE_H
#define SENTINEL_EDR_TIMELINE_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "sentinel/core/result.h"
#include "sentinel/core/types.h"
#include "sentinel/edr/secure_log.h"

namespace sentinel {

struct TimelineEvent {
    std::uint64_t timestamp_ms = 0;
    std::uint32_t pid = 0;
    std::string actor;       // image path / name
    std::string category;    // "process", "file", "registry", "network", "detection"
    std::string description; // human-readable
    RiskLevel severity = RiskLevel::Unknown;
};

class Timeline {
public:
    Timeline();
    ~Timeline();

    // Back the timeline with a sealed log file (optional but recommended).
    Status Open(const std::string& sealed_log_path);

    void Record(const TimelineEvent& event);

    // Record a confirmed detection and mark the contributing events.
    void RecordDetection(std::uint32_t pid, const std::string& actor,
                         const Verdict& verdict, std::uint64_t timestamp_ms);

    // Reconstruct the chain for a given pid (its events, newest last).
    std::vector<TimelineEvent> ChainForPid(std::uint32_t pid) const;

    std::vector<TimelineEvent> All() const;

    // Verify the sealed log backing the timeline.
    Status VerifyIntegrity() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace sentinel

#endif  // SENTINEL_EDR_TIMELINE_H
