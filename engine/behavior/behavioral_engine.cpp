#include "sentinel/behavior/behavioral_engine.h"

#include <utility>
#include <vector>

namespace sentinel {
namespace {

// Noisy-OR aggregation of signal confidences: independent weak signals
// accumulate while any single strong one dominates. Confidences are clamped so
// a malformed signal can neither exceed 1 nor subtract from the score.
double NoisyOr(const std::vector<Signal>& signals) {
    double product = 1.0;
    for (const auto& s : signals) {
        double c = s.confidence;
        if (c < 0.0) c = 0.0;
        else if (c > 1.0) c = 1.0;
        product *= (1.0 - c);
    }
    return 1.0 - product;
}

}  // namespace

BehavioralEngine::BehavioralEngine(const Config& config)
    : config_(config),
      graph_(std::make_unique<ActionGraph>()),
      ransomware_(std::make_unique<RansomwareHeuristic>(config)),
      injection_(std::make_unique<InjectionHeuristic>()),
      model_(std::make_unique<MlModel>()) {}

// Out-of-line destructor so unique_ptr<T> members can hold forward/complete
// types defined via the included headers without issue.
BehavioralEngine::~BehavioralEngine() = default;

void BehavioralEngine::Observe(std::uint32_t pid, std::uint32_t ppid,
                               const std::string& image_path,
                               const ActivityEvent& action) {
    // Ensure the node exists with its identity filled in, then append the event
    // and update the rolling counters the heuristics read.
    graph_->AddProcess(pid, ppid, image_path);
    graph_->Record(pid, action);
}

FeatureVector BehavioralEngine::ExtractFeatures(const ProcessNode& node) const {
    FeatureVector fv;
    // Translate the node's rolling counters into the model's named behavioral
    // features. The PE/static features (entropy, rwx_section, pe_packed, ...)
    // are supplied by the static-scan path and simply default to 0 here.
    fv.Set("high_entropy_writes", static_cast<double>(node.high_entropy_writes));
    fv.Set("remote_thread", node.remote_threads > 0 ? 1.0 : 0.0);
    fv.Set("remote_alloc_write",
           (node.remote_allocs > 0 && node.remote_writes > 0) ? 1.0 : 0.0);
    fv.Set("persistence", node.persistence_writes > 0 ? 1.0 : 0.0);
    fv.Set("canary_touch", node.canary_touches > 0 ? 1.0 : 0.0);
    return fv;
}

BehavioralAssessment BehavioralEngine::Assess(std::uint32_t pid) const {
    BehavioralAssessment result;
    result.pid = pid;

    const ProcessNode* node = graph_->Get(pid);
    if (node == nullptr) {
        // Unknown pid: nothing observed yet, empty assessment with score 0.
        return result;
    }

    // Gather the corroborating behavioral signals for this node.
    result.signals.reserve(3);
    result.signals.push_back(ransomware_->Evaluate(*node));
    result.signals.push_back(injection_->Evaluate(*node));
    result.signals.push_back(model_->Evaluate(ExtractFeatures(*node)));

    result.behavioral_score = NoisyOr(result.signals);
    return result;
}

std::vector<BehavioralAssessment> BehavioralEngine::AssessAll() const {
    // Snapshot the graph once so scoring doesn't hold the graph lock across the
    // whole sweep and isn't disturbed by concurrent event recording.
    const std::vector<ProcessNode> nodes = graph_->Snapshot();
    std::vector<BehavioralAssessment> out;
    out.reserve(nodes.size());

    for (const auto& node : nodes) {
        BehavioralAssessment a;
        a.pid = node.pid;
        a.signals.reserve(3);
        a.signals.push_back(ransomware_->Evaluate(node));
        a.signals.push_back(injection_->Evaluate(node));
        a.signals.push_back(model_->Evaluate(ExtractFeatures(node)));
        a.behavioral_score = NoisyOr(a.signals);
        out.push_back(std::move(a));
    }
    return out;
}

}  // namespace sentinel
