#include "sentinel/behavior/ransomware.h"

#include <algorithm>
#include <string>

namespace sentinel {

void RansomwareHeuristic::AddCanary(const std::string& path) {
    canaries_.insert(path);
}

bool RansomwareHeuristic::IsCanary(const std::string& path) const {
    return canaries_.find(path) != canaries_.end();
}

Signal RansomwareHeuristic::Evaluate(const ProcessNode& node) const {
    // 1) Canary/decoy touch is a near-certain detection. Trust the fast counter
    //    first, then fall back to scanning recorded action targets so a decoy
    //    hit is caught even if the counter was not pre-incremented.
    bool canary_hit = node.canary_touches > 0;
    if (!canary_hit) {
        for (const auto& a : node.actions) {
            if (IsCanary(a.target)) {
                canary_hit = true;
                break;
            }
        }
    }
    if (canary_hit) {
        return Signal(SignalSource::Ransomware, RiskLevel::Malicious, 0.97,
                      "process touched a ransomware canary/decoy file",
                      "ransomware.canary");
    }

    // 2) Mass-encrypt pattern: rapid, broad file modification with encrypted-
    //    looking (high-entropy) output. Everything is scored relative to the
    //    configured file window; guard against a zero/negative window.
    const int window_cfg = config_.ransomware_file_window > 0
                               ? config_.ransomware_file_window
                               : 20;
    const double window = static_cast<double>(window_cfg);
    const std::uint32_t he = node.high_entropy_writes;
    const std::uint32_t writes = node.files_written;
    const std::uint32_t renames = node.files_renamed;

    // Hard trip: enough high-entropy writes to fill the window on their own.
    if (he >= static_cast<std::uint32_t>(window_cfg)) {
        // Start at ~0.90 and climb toward 0.99 as the count exceeds the window.
        const double over = (static_cast<double>(he) - window) / window;
        const double confidence = std::min(0.99, 0.90 + 0.09 * std::min(1.0, over));
        return Signal(SignalSource::Ransomware, RiskLevel::Malicious, confidence,
                      "mass high-entropy file rewrite (" + std::to_string(he) +
                          " encrypted-looking writes)",
                      "ransomware.mass_encrypt");
    }

    // Composite activity: high-entropy writes count double since encryption is
    // the defining trait. Normalized so ~2 windows of weighted activity => 1.0.
    const double activity = static_cast<double>(writes) +
                            static_cast<double>(renames) +
                            2.0 * static_cast<double>(he);
    const double ratio = std::min(1.0, activity / (2.0 * window));

    if (ratio >= 0.75) {
        // Strong but short of canary/hard-trip certainty.
        const double confidence = std::min(0.89, 0.80 + 0.09 * (ratio - 0.75) / 0.25);
        return Signal(SignalSource::Ransomware, RiskLevel::Malicious, confidence,
                      "rapid broad file modification consistent with ransomware",
                      "ransomware.mass_encrypt");
    }
    if (ratio >= 0.40) {
        // Mid band: corroborating, not convicting on its own.
        const double confidence = 0.30 + 0.40 * (ratio - 0.40) / 0.35;
        return Signal(SignalSource::Ransomware, RiskLevel::Suspicious, confidence,
                      "elevated file-modification activity",
                      "ransomware.activity");
    }

    // Below the mid band: no ransomware pattern. Emit a clean, zero-confidence
    // signal so fusion/aggregation is never nudged by background file I/O.
    return Signal(SignalSource::Ransomware, RiskLevel::Unknown, 0.0,
                  "no ransomware pattern", "ransomware.none");
}

}  // namespace sentinel
