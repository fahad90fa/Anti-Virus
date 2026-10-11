// The static scanning engine: inspects a file WITHOUT running it and returns a
// fast verdict. It is the cheapest layer, so it runs first and resolves the
// vast majority of files instantly.
//
//   Layer 1 — hash lookup (allow/block sets)  -> instant allow or block
//   Layer 2 — YARA-style rule matching        -> known families / techniques
//   Layer 3 — PE structure heuristics         -> packing, suspicious imports
//   + verdict cache keyed on the file hash     -> skip rescans of unchanged files
//
// StaticScanner produces a set of Signals (not a final Action); the verdict
// fusion stage combines these with behavioral and network signals. A standalone
// Scan() convenience is provided that applies the configured thresholds so the
// CLI can scan a file without the full orchestrator.
#ifndef SENTINEL_SCAN_STATIC_SCANNER_H
#define SENTINEL_SCAN_STATIC_SCANNER_H

#include <memory>
#include <string>
#include <vector>

#include "sentinel/core/config.h"
#include "sentinel/core/types.h"
#include "sentinel/scan/cache.h"
#include "sentinel/scan/hash_store.h"
#include "sentinel/scan/pe_parser.h"
#include "sentinel/scan/rule_engine.h"
#include "sentinel/scan/subject.h"

namespace sentinel {

struct StaticScanReport {
    std::vector<Signal> signals;
    bool allowlisted = false;       // hash on the allowlist (definitive good)
    bool blocklisted = false;       // hash on the blocklist (definitive bad)
    bool cache_hit = false;
    PeHeuristicResult pe;           // populated if the subject is a PE
    std::vector<RuleMatch> matches; // rule hits
    double static_score = 0.0;      // aggregate static malice score [0,1]
};

class StaticScanner {
public:
    explicit StaticScanner(const Config& config);
    ~StaticScanner();

    // Load the signature database (hash sets + rules) from the configured paths.
    // Safe to call again to hot-reload after an update.
    Status LoadSignatures();

    // Direct access for tests / dynamic updates.
    HashStore& hashes() { return *hashes_; }
    RuleSet& rules() { return *rules_; }
    VerdictCache& cache() { return *cache_; }

    // Scan a subject, producing static signals (no final action decision).
    StaticScanReport Analyze(const FileSubject& subject);

    // Convenience: scan and fuse to a standalone Verdict using Config
    // thresholds. Used by the CLI and the one-shot scan path.
    Verdict Scan(const FileSubject& subject);
    Verdict ScanFile(const std::string& path);

private:
    Config config_;
    std::unique_ptr<HashStore> hashes_;
    std::unique_ptr<RuleSet> rules_;
    std::unique_ptr<VerdictCache> cache_;
};

}  // namespace sentinel

#endif  // SENTINEL_SCAN_STATIC_SCANNER_H
