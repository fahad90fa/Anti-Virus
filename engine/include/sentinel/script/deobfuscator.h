// On-device script de-obfuscation. Reads obfuscated PowerShell, JScript, and
// shell commands and reduces them toward their real intent: decode base64
// blobs (including PowerShell -EncodedCommand UTF-16LE), undo simple string
// concatenation and char-code arrays, strip ticks/escapes. This closes the
// fileless gap without sending anything to the cloud.
#ifndef SENTINEL_SCRIPT_DEOBFUSCATOR_H
#define SENTINEL_SCRIPT_DEOBFUSCATOR_H

#include <string>
#include <vector>

namespace sentinel {

struct DeobfuscationResult {
    std::string normalized;                 // best-effort decoded/normalized text
    std::vector<std::string> decoded_layers;// each decode step's output
    int layers_peeled = 0;                  // how many obfuscation layers removed
    bool found_encoded_command = false;     // -enc / FromBase64String / etc.
};

class Deobfuscator {
public:
    // Decode a script to its most-revealed form. Idempotent and bounded
    // (max_layers) to avoid pathological loops.
    DeobfuscationResult Deobfuscate(const std::string& script,
                                    int max_layers = 6) const;

    // Standalone base64 decode helper (returns empty on invalid input).
    static std::string Base64Decode(const std::string& in);
    // Decode a UTF-16LE byte string (as PowerShell -EncodedCommand uses) to
    // ASCII/UTF-8 best effort.
    static std::string Utf16LeToUtf8(const std::string& bytes);
};

}  // namespace sentinel

#endif  // SENTINEL_SCRIPT_DEOBFUSCATOR_H
