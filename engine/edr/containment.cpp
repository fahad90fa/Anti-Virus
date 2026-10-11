// Auto-containment decision logic. Only a strong, blocking, malicious verdict
// trips network isolation; the actual firewall change is delegated to an
// injected applier so this logic is testable. See containment.h for the contract.
#include "sentinel/edr/containment.h"

#include <sstream>
#include <string>

#include "sentinel/core/logging.h"

namespace sentinel {

ContainmentDecision Containment::Decide(const Verdict& verdict) const {
    ContainmentDecision decision;
    // Isolate only when the verdict is unambiguous: convicted as Malicious, the
    // fused score clears the block threshold, and the chosen action actually
    // blocks execution. The threshold keeps routine/weak detections from
    // severing the network.
    if (verdict.level == RiskLevel::Malicious &&
        verdict.score >= config_.block_threshold &&
        verdict.BlocksExecution()) {
        decision.isolate = true;
        std::ostringstream os;
        os << "malicious verdict (score=" << verdict.score
           << " >= block_threshold=" << config_.block_threshold << ")";
        if (!verdict.summary.empty()) os << ": " << verdict.summary;
        decision.reason = os.str();
    } else {
        decision.isolate = false;
    }
    return decision;
}

bool Containment::Isolate(const std::string& reason) {
    if (state_ == ContainmentState::Isolated) {
        return true;  // already isolated; idempotent no-op
    }
    // Enforce through the platform hook first. If enforcement fails, stay Normal
    // so state_ never claims an isolation the driver did not apply.
    if (applier_ && !applier_(true)) {
        SENTINEL_LOG(Error) << "containment: isolation applier failed: " << reason;
        return false;
    }
    state_ = ContainmentState::Isolated;
    SENTINEL_LOG(Warn) << "containment: network isolation engaged: " << reason;
    return true;
}

bool Containment::Release() {
    if (state_ == ContainmentState::Normal) {
        return true;  // already connected; idempotent no-op
    }
    if (applier_ && !applier_(false)) {
        SENTINEL_LOG(Error) << "containment: release applier failed";
        return false;
    }
    state_ = ContainmentState::Normal;
    SENTINEL_LOG(Info) << "containment: network isolation lifted";
    return true;
}

}  // namespace sentinel
