#include "sentinel/script/script_analyzer.h"

#include <cstddef>
#include <ios>
#include <sstream>
#include <string>

namespace sentinel {

ScriptAnalysis ScriptAnalyzer::Analyze(const std::string& script) const {
    ScriptAnalysis out;

    // 1) Reduce the script toward its real intent, 2) classify that intent,
    // feeding the obfuscation-layer count into the density signal.
    out.deob = deob_.Deobfuscate(script);
    out.intent = classifier_.Classify(out.deob.normalized, out.deob.layers_peeled);

    // Map the intent score onto a risk level for fusion. These cutoffs mirror
    // the fusion level bands; the configured action thresholds are applied
    // later by VerdictFusion, so here we only produce an honest level.
    const double s = out.intent.score;
    RiskLevel level;
    if (s >= 0.80) {
        level = RiskLevel::Malicious;
    } else if (s >= 0.50) {
        level = RiskLevel::Suspicious;
    } else if (s >= 0.25) {
        level = RiskLevel::LowRisk;
    } else {
        level = RiskLevel::Unknown;
    }

    // Confidence tracks the intent score directly (already clamped to [0,1]).
    const double confidence = s;

    // Build a one-line detail naming the top indicators that fired.
    std::ostringstream oss;
    oss.setf(std::ios::fixed);
    oss.precision(2);
    if (out.intent.indicators.empty()) {
        oss << "no script-intent indicators";
    } else {
        oss << "script intent: ";
        const std::size_t cap =
            out.intent.indicators.size() < 4 ? out.intent.indicators.size() : 4;
        for (std::size_t i = 0; i < cap; ++i) {
            if (i != 0) oss << ", ";
            oss << out.intent.indicators[i];
        }
        if (out.intent.indicators.size() > cap) oss << ", ...";
    }
    oss << " (score " << s << ")";

    out.signal = Signal(SignalSource::ScriptIntent, level, confidence, oss.str(),
                        "script.intent");
    return out;
}

}  // namespace sentinel
