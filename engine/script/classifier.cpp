#include "sentinel/script/classifier.h"

#include <cctype>
#include <cstddef>
#include <string>

namespace sentinel {
namespace {

std::string ToLower(const std::string& s) {
    std::string out(s.size(), '\0');
    for (std::size_t i = 0; i < s.size(); ++i) {
        out[i] = static_cast<char>(std::tolower(static_cast<unsigned char>(s[i])));
    }
    return out;
}

// Plain case-insensitive substring test (input already lowercased).
bool Has(const std::string& hay, const char* needle) {
    return hay.find(needle) != std::string::npos;
}

bool IsTokChar(unsigned char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

// Substring test that requires token boundaries on both sides, for short names
// that are otherwise substrings of innocent identifiers (e.g. "iex" inside
// "iexplore", "cmd" inside "cmdlet").
bool HasWord(const std::string& hay, const std::string& w) {
    std::size_t pos = 0;
    while ((pos = hay.find(w, pos)) != std::string::npos) {
        const bool lb = (pos == 0) || !IsTokChar(static_cast<unsigned char>(hay[pos - 1]));
        const std::size_t after = pos + w.size();
        const bool rb =
            (after >= hay.size()) || !IsTokChar(static_cast<unsigned char>(hay[after]));
        if (lb && rb) return true;
        ++pos;
    }
    return false;
}

// PowerShell -EncodedCommand accepts any unambiguous prefix down to -e. Match a
// standalone "-<prefix>" flag so we fire on -enc/-e but not on -ExecutionPolicy.
bool HasEncFlag(const std::string& lower) {
    static const std::string kEnc = "encodedcommand";
    for (std::size_t i = 0; i + 1 < lower.size(); ++i) {
        if (lower[i] != '-') continue;
        if (i > 0 && !std::isspace(static_cast<unsigned char>(lower[i - 1]))) continue;
        std::size_t a = i + 1;
        std::string flag;
        while (a < lower.size() && lower[a] >= 'a' && lower[a] <= 'z') {
            flag.push_back(lower[a]);
            ++a;
        }
        if (flag.empty() || flag.size() > kEnc.size()) continue;
        if (kEnc.compare(0, flag.size(), flag) != 0) continue;
        // The flag name must be followed by a boundary (space or end of text).
        if (a >= lower.size() || std::isspace(static_cast<unsigned char>(lower[a]))) {
            return true;
        }
    }
    return false;
}

}  // namespace

ScriptIntent ScriptClassifier::Classify(const std::string& normalized_text,
                                        int obfuscation_layers) const {
    ScriptIntent intent;
    const std::string t = ToLower(normalized_text);

    // Fetch-a-payload primitives vs. run-it-now primitives. We judge intent on
    // the combination rather than any single mutable string.
    const bool has_download =
        Has(t, "downloadstring") || Has(t, "downloadfile") ||
        Has(t, "downloaddata") || Has(t, "invoke-webrequest") ||
        Has(t, "net.webclient") || Has(t, "start-bitstransfer") ||
        HasWord(t, "iwr") || HasWord(t, "wget") || HasWord(t, "curl");
    const bool has_iex = HasWord(t, "iex") || Has(t, "invoke-expression");

    double score = 0.0;

    // download-and-execute: fetch a remote payload AND run it.
    if (has_download && has_iex) {
        intent.download_execute = true;
        intent.indicators.push_back("download_execute");
        score += 0.50;
    }

    // In-memory execution: run code without ever touching disk.
    if (has_iex || Has(t, "[reflection.assembly]::load") ||
        Has(t, "reflection.assembly") || Has(t, "virtualalloc")) {
        intent.in_memory_execution = true;
        intent.indicators.push_back("in_memory_execution");
        score += 0.35;
    }

    // AMSI tamper / bypass.
    if (Has(t, "amsiinitfailed") || Has(t, "amsiscanbuffer") ||
        Has(t, "amsiutils")) {
        intent.amsi_bypass = true;
        intent.indicators.push_back("amsi_bypass");
        score += 0.45;
    }

    // Encoded-command wrapper.
    if (HasEncFlag(t) || Has(t, "frombase64string")) {
        intent.encoded_command = true;
        intent.indicators.push_back("encoded_command");
        score += 0.25;
    }

    // Living-off-the-land binaries. "cmd" is boundary-checked to avoid matching
    // "cmdlet"; the rest are distinctive enough for a plain substring test.
    static const char* kLolbins[] = {"powershell", "wscript",  "cscript",
                                     "mshta",      "rundll32", "regsvr32",
                                     "certutil",   "bitsadmin"};
    bool any_lolbin = false;
    for (const char* b : kLolbins) {
        if (Has(t, b)) {
            intent.indicators.push_back(std::string("lolbin:") + b);
            any_lolbin = true;
        }
    }
    if (HasWord(t, "cmd")) {
        intent.indicators.push_back("lolbin:cmd");
        any_lolbin = true;
    }
    if (any_lolbin) {
        intent.lolbin = true;
        score += 0.15;  // one weight for the whole LOLBin signal
    }

    // Obfuscation density: benign scripts are rarely multiply-encoded, so the
    // number of layers the deobfuscator peeled is itself evidence.
    if (obfuscation_layers > 0) {
        double density = 0.10 * static_cast<double>(obfuscation_layers);
        if (density > 0.30) density = 0.30;  // cap the density contribution
        score += density;
        intent.indicators.push_back("obfuscation_density:" +
                                    std::to_string(obfuscation_layers));
    }

    if (score < 0.0) score = 0.0;
    if (score > 1.0) score = 1.0;
    intent.score = score;
    return intent;
}

}  // namespace sentinel
