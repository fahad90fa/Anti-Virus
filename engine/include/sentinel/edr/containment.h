// Auto-containment. On a high-confidence serious detection, the machine can
// automatically isolate itself from the network — except the management path —
// to stop lateral movement and data exfiltration while remediation runs. The
// threshold is tuned so only strong verdicts trigger it. This module holds the
// decision logic and an apply hook; the network driver enforces the isolation.
#ifndef SENTINEL_EDR_CONTAINMENT_H
#define SENTINEL_EDR_CONTAINMENT_H

#include <functional>
#include <string>
#include <vector>

#include "sentinel/core/config.h"
#include "sentinel/core/types.h"

namespace sentinel {

enum class ContainmentState { Normal, Isolated };

struct ContainmentDecision {
    bool isolate = false;
    std::string reason;
};

// A platform hook that actually applies/removes network isolation. Injected so
// the logic is testable without touching the real firewall. Returns true on
// success.
using IsolationApplier = std::function<bool(bool isolate)>;

class Containment {
public:
    explicit Containment(const Config& config) : config_(config) {}

    void SetApplier(IsolationApplier applier) { applier_ = std::move(applier); }

    // Hosts/paths that must stay reachable even when isolated (management path).
    void AddManagementAllow(const std::string& host) { management_allow_.push_back(host); }
    const std::vector<std::string>& management_allow() const { return management_allow_; }

    // Decide whether a verdict warrants isolation (only strong verdicts do).
    ContainmentDecision Decide(const Verdict& verdict) const;

    // Apply/lift isolation through the hook. No-ops if already in that state.
    bool Isolate(const std::string& reason);
    bool Release();

    ContainmentState state() const { return state_; }

private:
    Config config_;
    IsolationApplier applier_;
    std::vector<std::string> management_allow_;
    ContainmentState state_ = ContainmentState::Normal;
};

}  // namespace sentinel

#endif  // SENTINEL_EDR_CONTAINMENT_H
