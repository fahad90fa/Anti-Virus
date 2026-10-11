// The behavioral/heuristic engine. Consumes the live event stream (actions),
// maintains the action graph, and scores every process continuously by running
// the ransomware, injection, and model heuristics plus a rootkit/persistence
// check. It emits behavioral Signals that feed verdict fusion. This is the layer
// that catches what signatures cannot: zero-days, fileless attacks, novelty.
#ifndef SENTINEL_BEHAVIOR_BEHAVIORAL_ENGINE_H
#define SENTINEL_BEHAVIOR_BEHAVIORAL_ENGINE_H

#include <memory>
#include <vector>

#include "sentinel/behavior/action_graph.h"
#include "sentinel/behavior/injection.h"
#include "sentinel/behavior/ml_model.h"
#include "sentinel/behavior/ransomware.h"
#include "sentinel/core/config.h"
#include "sentinel/core/types.h"

namespace sentinel {

// Result of scoring one process.
struct BehavioralAssessment {
    std::uint32_t pid = 0;
    std::vector<Signal> signals;
    double behavioral_score = 0.0;  // aggregate [0,1]
};

class BehavioralEngine {
public:
    explicit BehavioralEngine(const Config& config);
    ~BehavioralEngine();

    ActionGraph& graph() { return *graph_; }
    RansomwareHeuristic& ransomware() { return *ransomware_; }

    // Feed one observed action for a process; updates the graph.
    void Observe(std::uint32_t pid, std::uint32_t ppid,
                 const std::string& image_path, const ActivityEvent& action);

    // Score a single process from its current graph node.
    BehavioralAssessment Assess(std::uint32_t pid) const;

    // Score every tracked process; useful for periodic sweeps.
    std::vector<BehavioralAssessment> AssessAll() const;

    // Build the feature vector for the model from a process node (exposed for
    // tests and for the sandbox detonation path).
    FeatureVector ExtractFeatures(const ProcessNode& node) const;

private:
    Config config_;
    std::unique_ptr<ActionGraph> graph_;
    std::unique_ptr<RansomwareHeuristic> ransomware_;
    std::unique_ptr<InjectionHeuristic> injection_;
    std::unique_ptr<MlModel> model_;
};

}  // namespace sentinel

#endif  // SENTINEL_BEHAVIOR_BEHAVIORAL_ENGINE_H
