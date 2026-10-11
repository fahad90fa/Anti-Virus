// Verdict fusion. Every layer (static score, behavioral score, network signals,
// reputation, model) feeds one verdict engine that combines them into a single
// risk level and an action: allow, monitor-closely, hold-in-shadow, block, or
// kill-and-roll-back. Fusion lets weak-but-corroborating signals convict
// together, while no single noisy signal causes a false positive on its own.
//
// Model: a definitive allowlist hit short-circuits to Trusted/Allow. A
// definitive blocklist hit or any Malicious-level signal with high confidence
// short-circuits to Malicious. Otherwise, signal confidences are combined with
// a noisy-OR so that several independent weak signals accumulate, and the fused
// score is mapped to an Action via the configured thresholds.
#ifndef SENTINEL_BEHAVIOR_VERDICT_FUSION_H
#define SENTINEL_BEHAVIOR_VERDICT_FUSION_H

#include <vector>

#include "sentinel/core/config.h"
#include "sentinel/core/types.h"

namespace sentinel {

class VerdictFusion {
public:
    explicit VerdictFusion(const Config& config) : config_(config) {}

    // Fuse a set of signals into a single Verdict. `allowlisted` / `blocklisted`
    // carry the definitive hash-set outcomes that short-circuit fusion.
    Verdict Fuse(const std::vector<Signal>& signals, bool allowlisted = false,
                 bool blocklisted = false) const;

    // Map a fused score in [0,1] to an Action using the configured thresholds.
    Action ActionForScore(double score) const;
    RiskLevel LevelForScore(double score) const;

    void SetConfig(const Config& config) { config_ = config; }

private:
    Config config_;
};

}  // namespace sentinel

#endif  // SENTINEL_BEHAVIOR_VERDICT_FUSION_H
