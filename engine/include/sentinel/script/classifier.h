// Script-intent classifier. Judges intent ("this decodes a base64 blob and
// executes it in memory") rather than matching raw strings an attacker can
// trivially mutate. Works on the de-obfuscated text: weighs indicators like
// download-and-execute, in-memory execution, AMSI bypass, encoded commands,
// LOLBin invocation, and obfuscation density.
#ifndef SENTINEL_SCRIPT_CLASSIFIER_H
#define SENTINEL_SCRIPT_CLASSIFIER_H

#include <string>
#include <vector>

#include "sentinel/core/types.h"

namespace sentinel {

struct ScriptIntent {
    double score = 0.0;                 // malice intent [0,1]
    std::vector<std::string> indicators;// which intent signals fired
    bool download_execute = false;
    bool in_memory_execution = false;
    bool amsi_bypass = false;
    bool encoded_command = false;
    bool lolbin = false;
};

class ScriptClassifier {
public:
    // Classify already-de-obfuscated script text. `obfuscation_layers` from the
    // deobfuscator feeds the obfuscation-density signal.
    ScriptIntent Classify(const std::string& normalized_text,
                          int obfuscation_layers = 0) const;
};

}  // namespace sentinel

#endif  // SENTINEL_SCRIPT_CLASSIFIER_H
