// Engine configuration. Loaded from a simple key=value file (and overridable
// from the CLI). Kept deliberately small and dependency-free — no YAML/JSON
// parser pulled in just for config.
#ifndef SENTINEL_CORE_CONFIG_H
#define SENTINEL_CORE_CONFIG_H

#include <map>
#include <string>
#include <vector>

#include "sentinel/core/logging.h"
#include "sentinel/core/types.h"

namespace sentinel {

struct Config {
    // Paths to the signature database components.
    std::string signatures_dir = "signatures";
    std::string blocklist_hashes = "signatures/hashes/blocklist.txt";
    std::string allowlist_hashes = "signatures/hashes/allowlist.txt";
    std::string rules_dir = "signatures/rules";
    std::string driverblock = "signatures/driverblock/blocklist.txt";

    // Runtime state.
    std::string quarantine_dir = "runtime/quarantine";
    std::string shadow_dir = "runtime/shadow";
    std::string timeline_path = "runtime/timeline.log";
    std::string state_dir = "runtime";

    // Behavior thresholds (fusion). Scores are in [0,1].
    double block_threshold = 0.85;      // >= this => Block/Kill
    double shadow_threshold = 0.45;     // >= this => HoldInShadow (gated)
    double monitor_threshold = 0.20;    // >= this => MonitorClosely

    // Static heuristic knobs.
    double high_entropy_threshold = 7.2;  // packed/encrypted indicator

    // Ransomware heuristic knobs.
    int ransomware_file_window = 20;       // files touched to trip the heuristic
    int ransomware_window_ms = 2000;       // within this many ms
    double ransomware_entropy_min = 7.0;   // output entropy that looks encrypted

    // Feature toggles.
    bool enable_behavioral = true;
    bool enable_script_analysis = true;
    bool enable_memory_scan = true;
    bool enable_deception = true;
    bool quarantine_on_malicious = true;

    LogLevel log_level = LogLevel::Info;

    // Load key=value pairs from a file, overriding defaults. Unknown keys are
    // ignored (logged at debug). Returns false only on a read error.
    bool LoadFromFile(const std::string& path);
    // Apply a single "key=value" override (from CLI --set key=value).
    bool Set(const std::string& key, const std::string& value);

    // All current values as a flat map (for diagnostics / the UI).
    std::map<std::string, std::string> AsMap() const;
};

}  // namespace sentinel

#endif  // SENTINEL_CORE_CONFIG_H
