// Ransomware heuristic. The defining pattern is rapid, broad file modification:
// one process opening many files across user folders in quick succession,
// reading then overwriting them, with output of high entropy (encryption). Add
// canary files (hidden decoys): a process that touches them is almost certainly
// ransomware. On that signal the engine kills the process and triggers rollback
// of its staged writes.
#ifndef SENTINEL_BEHAVIOR_RANSOMWARE_H
#define SENTINEL_BEHAVIOR_RANSOMWARE_H

#include <string>
#include <unordered_set>

#include "sentinel/behavior/action_graph.h"
#include "sentinel/core/config.h"
#include "sentinel/core/types.h"

namespace sentinel {

class RansomwareHeuristic {
public:
    explicit RansomwareHeuristic(const Config& config) : config_(config) {}

    // Register canary/decoy file paths. Any touch is a near-certain detection.
    void AddCanary(const std::string& path);
    bool IsCanary(const std::string& path) const;

    // Evaluate a process node's recent activity. Returns a Signal with
    // confidence scaled by how strongly the pattern matches; level Malicious
    // when a canary is touched or the mass-encrypt threshold is crossed.
    Signal Evaluate(const ProcessNode& node) const;

private:
    Config config_;
    std::unordered_set<std::string> canaries_;
};

}  // namespace sentinel

#endif  // SENTINEL_BEHAVIOR_RANSOMWARE_H
