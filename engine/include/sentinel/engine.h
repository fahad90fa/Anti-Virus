// The Sentinel engine facade. Composes every user-mode layer into one API that
// the service, the CLI, and the IPC port all call:
//
//   static scan  ->  behavioral  ->  verdict fusion  ->  rollback gate / quarantine
//
// It owns the signature database, the verdict cache, the behavioral engine, the
// script analyzer, the shadow-commit gate, the quarantine vault, the EDR
// timeline, auto-containment, and the deception grid. The kernel drivers (when
// present) feed events in through Observe*(); in Phase 0 the user-mode file
// watcher and process enumerator drive the same path.
#ifndef SENTINEL_ENGINE_H
#define SENTINEL_ENGINE_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "sentinel/amsi/amsi_provider.h"
#include "sentinel/behavior/behavioral_engine.h"
#include "sentinel/behavior/verdict_fusion.h"
#include "sentinel/core/config.h"
#include "sentinel/core/result.h"
#include "sentinel/core/types.h"
#include "sentinel/deception/honeytokens.h"
#include "sentinel/edr/containment.h"
#include "sentinel/edr/timeline.h"
#include "sentinel/quarantine/remediator.h"
#include "sentinel/quarantine/vault.h"
#include "sentinel/rollback/shadow_gate.h"
#include "sentinel/scan/static_scanner.h"
#include "sentinel/scan/subject.h"
#include "sentinel/script/script_analyzer.h"

namespace sentinel {

// Outcome of evaluating a file through the engine.
struct FileScanResult {
    std::string path;
    std::string sha256;
    Verdict verdict;
    bool quarantined = false;
    std::string quarantine_id;
    StaticScanReport static_report;
};

// Aggregate report for scanning a tree.
struct TreeScanResult {
    int files_scanned = 0;
    int malicious = 0;
    int suspicious = 0;
    int quarantined = 0;
    std::vector<FileScanResult> detections;  // suspicious+ only
};

class Engine {
public:
    explicit Engine(const Config& config);
    ~Engine();

    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;

    // Load signatures, open the vault/timeline, plant deception, etc. Must be
    // called before scanning. Returns the first fatal error (missing vault dir
    // and the like); missing signature files are non-fatal (logged).
    Status Initialize();

    // --- Static / on-access file path ---------------------------------------
    FileScanResult ScanFile(const std::string& path);
    FileScanResult ScanSubject(const FileSubject& subject);
    TreeScanResult ScanTree(const std::string& root, bool recursive = true);

    // --- Script / AMSI path --------------------------------------------------
    Verdict ScanScript(const std::string& content, const std::string& origin);

    // --- Behavioral event path (fed by kernel sensors or the Phase 0 sim) ----
    // Observe one action for a process; returns the current fused verdict for
    // that process so the caller (driver) can act (allow / gate / kill).
    Verdict ObserveProcessAction(std::uint32_t pid, std::uint32_t ppid,
                                 const std::string& image_path,
                                 const ActivityEvent& action);

    // --- Response actions ----------------------------------------------------
    Result<QuarantineEntry> QuarantineFile(const std::string& path,
                                           const std::string& reason);
    Status RestoreQuarantined(const std::string& id, const std::string& dest = "");
    Result<std::vector<QuarantineEntry>> ListQuarantine() const;

    // Build and (optionally) execute a remediation plan for a convicted process.
    RemediationPlan PlanRemediation(std::uint32_t pid) const;

    // --- Self-test -----------------------------------------------------------
    // Writes the EICAR test file into a temp dir, scans it (expects Malicious),
    // and reports whether detection worked. Cleans up afterwards.
    struct SelfTestResult {
        bool eicar_detected = false;
        bool sha256_ok = false;
        bool clean_file_allowed = false;
        std::string detail;
        bool Passed() const { return eicar_detected && sha256_ok && clean_file_allowed; }
    };
    SelfTestResult SelfTest();

    // --- Accessors for the service / UI / tests ------------------------------
    const Config& config() const { return config_; }
    StaticScanner& scanner() { return *scanner_; }
    BehavioralEngine& behavior() { return *behavior_; }
    VerdictFusion& fusion() { return *fusion_; }
    QuarantineVault& vault() { return *vault_; }
    ShadowGate& shadow() { return *shadow_; }
    Timeline& timeline() { return *timeline_; }
    Containment& containment() { return *containment_; }
    HoneytokenManager& deception() { return *deception_; }

    std::uint64_t NowMs() const;

private:
    // Decide the action for a fused verdict and carry it out (quarantine on
    // malicious, record to timeline, maybe trigger containment).
    void ApplyResponse(FileScanResult& result);

    Config config_;
    bool initialized_ = false;

    std::unique_ptr<StaticScanner> scanner_;
    std::unique_ptr<BehavioralEngine> behavior_;
    std::unique_ptr<VerdictFusion> fusion_;
    std::unique_ptr<ScriptAnalyzer> script_;
    std::unique_ptr<AmsiProvider> amsi_;
    std::unique_ptr<QuarantineVault> vault_;
    std::unique_ptr<ShadowGate> shadow_;
    std::unique_ptr<Timeline> timeline_;
    std::unique_ptr<Containment> containment_;
    std::unique_ptr<HoneytokenManager> deception_;
    std::unique_ptr<Remediator> remediator_;
};

}  // namespace sentinel

#endif  // SENTINEL_ENGINE_H
