// Script analyzer: de-obfuscate, classify intent, and emit a ScriptIntent
// Signal for verdict fusion. This is the engine side of the AMSI provider and
// the fileless/script defense layer.
#ifndef SENTINEL_SCRIPT_SCRIPT_ANALYZER_H
#define SENTINEL_SCRIPT_SCRIPT_ANALYZER_H

#include <string>

#include "sentinel/core/types.h"
#include "sentinel/script/classifier.h"
#include "sentinel/script/deobfuscator.h"

namespace sentinel {

struct ScriptAnalysis {
    DeobfuscationResult deob;
    ScriptIntent intent;
    Signal signal;
};

class ScriptAnalyzer {
public:
    ScriptAnalysis Analyze(const std::string& script) const;

private:
    Deobfuscator deob_;
    ScriptClassifier classifier_;
};

}  // namespace sentinel

#endif  // SENTINEL_SCRIPT_SCRIPT_ANALYZER_H
