#include "sentinel/amsi/amsi_provider.h"

#include <string>
#include <vector>

#include "sentinel/behavior/verdict_fusion.h"
#include "sentinel/core/logging.h"

namespace sentinel {

Verdict AmsiProvider::ScanString(const std::string& content,
                                 const std::string& content_name,
                                 AmsiResult* amsi_result) const {
    // The scripting engine hands us the de-obfuscated content at execution
    // time; run it through the script-intent analysis and fuse the resulting
    // signal into a single verdict.
    const ScriptAnalysis analysis = analyzer_.Analyze(content);
    const VerdictFusion fusion(config_);
    Verdict verdict = fusion.Fuse({analysis.signal});

    // Tag the summary with the AMSI content identity for the timeline/UI.
    if (!content_name.empty()) {
        verdict.summary = content_name + ": " + verdict.summary;
    }

    if (amsi_result != nullptr) {
        *amsi_result = ToAmsiResult(verdict);
    }

    SENTINEL_LOG(Debug) << "AMSI scan of "
                        << (content_name.empty() ? std::string("<script>")
                                                 : content_name)
                        << " => " << ToString(verdict.level) << " (score "
                        << verdict.score << ")";
    return verdict;
}

AmsiResult AmsiProvider::ToAmsiResult(const Verdict& verdict) {
    switch (verdict.level) {
        case RiskLevel::Malicious:
            return AmsiResult::Detected;
        case RiskLevel::Suspicious:
        case RiskLevel::LowRisk:
            // Only trip the AMSI gate when the fused action actually blocks
            // execution; otherwise let the engine monitor without a hard stop.
            return verdict.BlocksExecution() ? AmsiResult::Detected
                                             : AmsiResult::NotDetected;
        case RiskLevel::Trusted:
            return AmsiResult::Clean;
        case RiskLevel::Unknown:
        default:
            return AmsiResult::NotDetected;
    }
}

}  // namespace sentinel
