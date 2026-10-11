// The Sentinel engine facade implementation. Composes every user-mode layer and
// drives the allow / quarantine / contain response.
#include "sentinel/engine.h"

#include <chrono>
#include <string>

#include "sentinel/core/fs.h"
#include "sentinel/core/logging.h"
#include "sentinel/core/sha256.h"

namespace sentinel {

Engine::Engine(const Config& config)
    : config_(config),
      scanner_(std::make_unique<StaticScanner>(config)),
      behavior_(std::make_unique<BehavioralEngine>(config)),
      fusion_(std::make_unique<VerdictFusion>(config)),
      script_(std::make_unique<ScriptAnalyzer>()),
      amsi_(std::make_unique<AmsiProvider>(config)),
      vault_(std::make_unique<QuarantineVault>()),
      shadow_(std::make_unique<ShadowGate>(config.shadow_dir)),
      timeline_(std::make_unique<Timeline>()),
      containment_(std::make_unique<Containment>(config)),
      deception_(std::make_unique<HoneytokenManager>()),
      remediator_(std::make_unique<Remediator>()) {}

Engine::~Engine() = default;

std::uint64_t Engine::NowMs() const {
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch())
            .count());
}

Status Engine::Initialize() {
    scanner_->LoadSignatures();

    MakeDirs(config_.state_dir);

    // The quarantine vault is the one component whose failure is fatal: without
    // it we cannot safely neutralize a convicted file.
    if (!MakeDirs(config_.quarantine_dir)) {
        return Status::Error(ErrorCode::IoError,
                             "cannot create quarantine dir: " + config_.quarantine_dir);
    }
    Status v = vault_->Open(config_.quarantine_dir);
    if (!v.ok()) {
        return Status::Error(ErrorCode::IoError,
                             "vault open failed: " + v.message());
    }

    // The sealed timeline is best-effort; log but tolerate a failure.
    Status t = timeline_->Open(config_.timeline_path);
    if (!t.ok()) {
        SENTINEL_LOG(Warn) << "timeline open (" << config_.timeline_path
                           << "): " << t.message();
    }

    // Deception grid: plant canary files and teach the ransomware heuristic to
    // treat any touch of them as a near-certain detection.
    if (config_.enable_deception) {
        const std::string canary_dir = JoinPath(config_.state_dir, "canaries");
        auto planted = deception_->PlantCanaryFiles(canary_dir, 3);
        if (planted.ok()) {
            for (const auto& p : planted.value()) {
                behavior_->ransomware().AddCanary(p);
            }
            SENTINEL_LOG(Info) << "deception: planted " << planted.value().size()
                               << " canary files";
        } else {
            SENTINEL_LOG(Warn) << "deception: canary plant failed: "
                               << planted.status().message();
        }
    }

    initialized_ = true;
    SENTINEL_LOG(Info) << "Sentinel engine initialized";
    return Status::Ok();
}

void Engine::ApplyResponse(FileScanResult& result) {
    const Verdict& v = result.verdict;
    const bool convict = v.IsMalicious() || v.BlocksExecution();

    // Record every suspicious-or-worse outcome to the sealed timeline.
    if (convict || v.level == RiskLevel::Suspicious) {
        timeline_->RecordDetection(0, result.path, v, NowMs());
    }

    if (convict && config_.quarantine_on_malicious && !result.path.empty() &&
        IsRegularFile(result.path)) {
        auto q = vault_->Quarantine(result.path, v.summary, NowMs());
        if (q.ok()) {
            result.quarantined = true;
            result.quarantine_id = q.value().id;
        } else {
            SENTINEL_LOG(Warn) << "quarantine failed for " << result.path << ": "
                               << q.status().message();
        }
    }

    // Auto-containment on a strong verdict.
    if (containment_->Decide(v).isolate) {
        containment_->Isolate("strong detection: " + v.summary);
    }
}

FileScanResult Engine::ScanSubject(const FileSubject& subject) {
    FileScanResult result;
    result.path = subject.path;
    result.sha256 = subject.sha256;
    result.static_report = scanner_->Analyze(subject);
    result.verdict = scanner_->Scan(subject);
    ApplyResponse(result);
    return result;
}

FileScanResult Engine::ScanFile(const std::string& path) {
    auto subject = FileSubject::FromFile(path);
    if (!subject) {
        FileScanResult result;
        result.path = path;
        result.verdict.level = RiskLevel::Unknown;
        result.verdict.action = Action::Allow;
        result.verdict.summary =
            "could not read '" + path + "': " + subject.status().message();
        return result;
    }
    return ScanSubject(subject.value());
}

TreeScanResult Engine::ScanTree(const std::string& root, bool recursive) {
    TreeScanResult tree;
    WalkFiles(root, recursive, [&](const std::string& path) {
        FileScanResult r = ScanFile(path);
        tree.files_scanned++;
        if (r.verdict.IsMalicious()) tree.malicious++;
        else if (r.verdict.level == RiskLevel::Suspicious) tree.suspicious++;
        if (r.quarantined) tree.quarantined++;
        if (r.verdict.IsMalicious() || r.verdict.level == RiskLevel::Suspicious) {
            tree.detections.push_back(std::move(r));
        }
    });
    return tree;
}

Verdict Engine::ScanScript(const std::string& content, const std::string& origin) {
    AmsiResult amsi_result = AmsiResult::NotDetected;
    Verdict v = amsi_->ScanString(content, origin, &amsi_result);
    if (v.BlocksExecution() || v.level == RiskLevel::Suspicious) {
        timeline_->RecordDetection(0, "script:" + origin, v, NowMs());
    }
    return v;
}

Verdict Engine::ObserveProcessAction(std::uint32_t pid, std::uint32_t ppid,
                                     const std::string& image_path,
                                     const ActivityEvent& action) {
    behavior_->Observe(pid, ppid, image_path, action);
    BehavioralAssessment a = behavior_->Assess(pid);
    Verdict v = fusion_->Fuse(a.signals);
    if (v.BlocksExecution()) {
        timeline_->RecordDetection(pid, image_path, v, NowMs());
        if (containment_->Decide(v).isolate) {
            containment_->Isolate("process behavior: " + v.summary);
        }
    }
    return v;
}

Result<QuarantineEntry> Engine::QuarantineFile(const std::string& path,
                                               const std::string& reason) {
    auto e = vault_->Quarantine(path, reason, NowMs());
    if (e.ok()) {
        Verdict v;
        v.level = RiskLevel::Malicious;
        v.action = Action::Block;
        v.summary = reason;
        timeline_->RecordDetection(0, path, v, NowMs());
    }
    return e;
}

Status Engine::RestoreQuarantined(const std::string& id, const std::string& dest) {
    return vault_->Restore(id, dest);
}

Result<std::vector<QuarantineEntry>> Engine::ListQuarantine() const {
    return vault_->List();
}

RemediationPlan Engine::PlanRemediation(std::uint32_t pid) const {
    const ProcessNode* node = behavior_->graph().Get(pid);
    if (node == nullptr) {
        RemediationPlan empty;
        empty.pid = pid;
        return empty;
    }
    return remediator_->Plan(*node);
}

Engine::SelfTestResult Engine::SelfTest() {
    SelfTestResult r;

    // Build the EICAR string at runtime from pieces (not stored verbatim).
    const std::string eicar =
        std::string("X5O!P%@AP[4\\PZX54(P^)7CC)7}") +
        "$EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*";

    // Scan the EICAR content directly through the scanner (no quarantine side
    // effects during a self-test).
    FileSubject eicar_subj = FileSubject::FromBuffer(
        Bytes(eicar.begin(), eicar.end()), "eicar.com");
    Verdict ev = scanner_->Scan(eicar_subj);
    r.eicar_detected = ev.IsMalicious();

    // A plainly benign buffer must be allowed.
    const std::string clean = "An ordinary, harmless document. Nothing to see here.";
    FileSubject clean_subj = FileSubject::FromBuffer(
        Bytes(clean.begin(), clean.end()), "clean.txt");
    Verdict cv = scanner_->Scan(clean_subj);
    r.clean_file_allowed = !cv.IsMalicious();

    // SHA-256 known-answer self-check.
    r.sha256_ok =
        Sha256::HexDigest(std::string("abc")) ==
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    r.detail = std::string("eicar=") + (r.eicar_detected ? "detected" : "MISSED") +
               ", clean=" + (r.clean_file_allowed ? "allowed" : "FLAGGED") +
               ", sha256=" + (r.sha256_ok ? "ok" : "BAD") +
               "; eicar verdict: " + ToString(ev.level);
    return r;
}

}  // namespace sentinel
