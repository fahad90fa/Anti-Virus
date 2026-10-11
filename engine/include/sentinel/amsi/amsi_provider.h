// AMSI provider. The Antimalware Scan Interface is the Windows hook where
// scripting engines hand their content to a registered scanner, crucially AFTER
// de-obfuscation, at the moment of execution. Registering as an AMSI provider
// lets the engine see the real, decoded PowerShell or macro rather than the
// obfuscated wrapper, and pass it to the script-intent analysis for a verdict.
//
// On Windows this class is wrapped by a COM provider (see amsi_provider_com.cpp,
// Windows-only). The portable core here takes a string/buffer and returns a
// Verdict via the ScriptAnalyzer, so the logic is testable off-Windows.
#ifndef SENTINEL_AMSI_AMSI_PROVIDER_H
#define SENTINEL_AMSI_AMSI_PROVIDER_H

#include <string>

#include "sentinel/core/config.h"
#include "sentinel/core/types.h"
#include "sentinel/script/script_analyzer.h"

namespace sentinel {

enum class AmsiResult {
    Clean = 0,          // AMSI_RESULT_CLEAN
    NotDetected = 1,    // AMSI_RESULT_NOT_DETECTED
    Detected = 32768,   // AMSI_RESULT_DETECTED
};

class AmsiProvider {
public:
    explicit AmsiProvider(const Config& config) : config_(config) {}

    // Scan content handed over by a scripting engine. `content_name` is the
    // app/script identity (e.g. "PowerShell"). Returns a full Verdict plus the
    // AMSI-native result code.
    Verdict ScanString(const std::string& content, const std::string& content_name,
                       AmsiResult* amsi_result = nullptr) const;

    // Map a fused Verdict to the AMSI result enum Windows expects.
    static AmsiResult ToAmsiResult(const Verdict& verdict);

private:
    Config config_;
    ScriptAnalyzer analyzer_;
};

}  // namespace sentinel

#endif  // SENTINEL_AMSI_AMSI_PROVIDER_H
