#include "sentinel/behavior/verdict_fusion.h"

#include <algorithm>
#include <sstream>
#include <string>

namespace sentinel {
namespace {

double Clamp01(double v) {
    if (v < 0.0) return 0.0;
    if (v > 1.0) return 1.0;
    return v;
}

// Per-level weight applied to a signal's confidence before the noisy-OR.
// Higher-risk levels contribute more; a Trusted-level signal is evidence of
// benignity and is returned negative so it pulls the fused score down.
double LevelWeight(RiskLevel level) {
    switch (level) {
        case RiskLevel::Trusted: return -1.0;
        case RiskLevel::Unknown: return 0.15;
        case RiskLevel::LowRisk: return 0.45;
        case RiskLevel::Suspicious: return 0.80;
        case RiskLevel::Malicious: return 1.00;
    }
    return 0.15;
}

std::string FormatScore(double v) {
    std::ostringstream oss;
    oss.setf(std::ios::fixed);
    oss.precision(2);
    oss << v;
    return oss.str();
}

}  // namespace

Verdict VerdictFusion::Fuse(const std::vector<Signal>& signals, bool allowlisted,
                            bool blocklisted) const {
    Verdict v;
    v.signals = signals;  // keep every signal in the verdict for explainability

    // Definitive hash-set outcomes short-circuit all fusion math.
    if (allowlisted) {
        v.level = RiskLevel::Trusted;
        v.action = Action::Allow;
        v.score = 0.0;
        v.summary = "allowlisted: known-good hash, fusion short-circuited";
        return v;
    }
    if (blocklisted) {
        v.level = RiskLevel::Malicious;
        v.action = Action::KillAndRollback;
        v.score = 1.0;
        v.summary = "blocklisted: known-malicious hash, fusion short-circuited";
        return v;
    }

    if (signals.empty()) {
        v.level = RiskLevel::Unknown;
        v.action = Action::Allow;
        v.score = 0.0;
        v.summary = "no signals";
        return v;
    }

    // Noisy-OR over positive contributors: the probability that at least one
    // independent signal is a true positive is 1 - prod(1 - p_i), where
    // p_i = clamp(confidence_i * levelWeight_i). Several weak-but-corroborating
    // signals thus accumulate, while no single noisy one dominates on its own.
    // Trusted signals carry negative weight and are folded in as a separate
    // multiplicative discount so benign evidence lowers the final score.
    double positive_product = 1.0;
    double trust_product = 1.0;
    bool short_circuit = false;
    const Signal* top = nullptr;
    double top_contrib = -1.0;

    for (const auto& s : signals) {
        // Any high-confidence Malicious-level signal convicts regardless of the
        // fusion arithmetic (a strong, deterministic layer fired).
        if (s.level == RiskLevel::Malicious && s.confidence >= 0.9) {
            short_circuit = true;
        }

        const double weight = LevelWeight(s.level);
        const double conf = Clamp01(s.confidence);
        if (weight >= 0.0) {
            const double p = Clamp01(conf * weight);
            positive_product *= (1.0 - p);
            if (p > top_contrib) {
                top_contrib = p;
                top = &s;
            }
        } else {
            // Trusted: discount by the strength of the benign evidence.
            const double t = Clamp01(conf * (-weight));
            trust_product *= (1.0 - t);
        }
    }

    double score = (1.0 - positive_product) * trust_product;
    score = Clamp01(score);

    if (short_circuit) {
        // Force at least the block threshold so the action maps to kill/rollback
        // even if the arithmetic alone fell short.
        score = std::max(score, config_.block_threshold);
        v.level = RiskLevel::Malicious;
    } else {
        v.level = LevelForScore(score);
    }
    v.score = score;
    v.action = ActionForScore(score);

    // One-line summary naming the top contributing signal.
    if (top != nullptr) {
        std::string detail = top->detail.empty() ? std::string(ToString(top->source))
                                                  : top->detail;
        v.summary = std::string(ToString(top->source)) + ": " + detail +
                    " (score " + FormatScore(score) + ")";
    } else {
        // All signals were Trusted (no positive contributor).
        v.summary = "benign evidence only (score " + FormatScore(score) + ")";
    }
    return v;
}

Action VerdictFusion::ActionForScore(double score) const {
    if (score >= config_.block_threshold) return Action::KillAndRollback;
    if (score >= config_.shadow_threshold) return Action::HoldInShadow;
    if (score >= config_.monitor_threshold) return Action::MonitorClosely;
    return Action::Allow;
}

RiskLevel VerdictFusion::LevelForScore(double score) const {
    if (score >= config_.block_threshold) return RiskLevel::Malicious;
    if (score >= config_.shadow_threshold) return RiskLevel::Suspicious;
    if (score >= config_.monitor_threshold) return RiskLevel::LowRisk;
    return RiskLevel::Unknown;
}

}  // namespace sentinel
