#include "sentinel/scan/static_scanner.h"

#include <algorithm>
#include <cctype>
#include <memory>
#include <string>
#include <utility>

#include "sentinel/behavior/verdict_fusion.h"
#include "sentinel/core/fs.h"
#include "sentinel/core/logging.h"

namespace sentinel {
namespace {

// Map a rule's textual severity to a RiskLevel for the emitted Signal.
RiskLevel SeverityToLevel(const std::string& sev) {
    std::string s;
    s.reserve(sev.size());
    for (char c : sev) {
        s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    if (s == "high" || s == "critical") return RiskLevel::Malicious;
    if (s == "medium" || s == "moderate") return RiskLevel::Suspicious;
    if (s == "low") return RiskLevel::LowRisk;
    return RiskLevel::Suspicious;  // sensible default for unrecognized severity
}

double Clamp01(double v) {
    if (v < 0.0) return 0.0;
    if (v > 1.0) return 1.0;
    return v;
}

// A short human-readable summary when fusion did not supply one.
std::string BuildSummary(const FileSubject& subject,
                         const StaticScanReport& report, const Verdict& v) {
    std::string name = subject.display_name.empty() ? std::string("<buffer>")
                                                    : subject.display_name;
    std::string s = name + ": " + ToString(v.level) + " / " + ToString(v.action);
    if (report.blocklisted) {
        s += " (blocklisted hash)";
    } else if (report.allowlisted) {
        s += " (allowlisted hash)";
    } else if (!report.matches.empty()) {
        s += " (" + std::to_string(report.matches.size()) + " rule match" +
             (report.matches.size() == 1 ? ")" : "es)");
    }
    return s;
}

}  // namespace

StaticScanner::StaticScanner(const Config& config)
    : config_(config),
      hashes_(std::make_unique<HashStore>()),
      rules_(std::make_unique<RuleSet>()),
      cache_(std::make_unique<VerdictCache>()) {}

StaticScanner::~StaticScanner() = default;

Status StaticScanner::LoadSignatures() {
    // Each component is optional: a fresh install may ship without some files.
    // Missing pieces are logged, never fatal, so the engine still runs.
    const Status a = hashes_->LoadAllowlist(config_.allowlist_hashes);
    if (!a.ok()) {
        SENTINEL_LOG(Warn) << "allowlist load (" << config_.allowlist_hashes
                           << "): " << a.message();
    }
    const Status b = hashes_->LoadBlocklist(config_.blocklist_hashes);
    if (!b.ok()) {
        SENTINEL_LOG(Warn) << "blocklist load (" << config_.blocklist_hashes
                           << "): " << b.message();
    }
    std::size_t rule_count = 0;
    const Status r = rules_->LoadDirectory(config_.rules_dir, &rule_count);
    if (!r.ok()) {
        SENTINEL_LOG(Warn) << "rules load (" << config_.rules_dir
                           << "): " << r.message();
    }
    SENTINEL_LOG(Info) << "signatures loaded: " << hashes_->allowed_count()
                       << " allow, " << hashes_->blocked_count() << " block, "
                       << rules_->rule_count() << " rules";
    return Status::Ok();
}

StaticScanReport StaticScanner::Analyze(const FileSubject& subject) {
    StaticScanReport report;

    // --- Layer 1: hash lookup (definitive, short-circuits the score) ---
    if (!subject.sha256.empty()) {
        const HashVerdict hv = hashes_->Lookup(subject.sha256);
        if (hv == HashVerdict::Allowed) {
            report.allowlisted = true;
            report.signals.emplace_back(SignalSource::HashLookup,
                                        RiskLevel::Trusted, 1.0,
                                        "hash on allowlist (known good)",
                                        subject.sha256);
        } else if (hv == HashVerdict::Blocked) {
            report.blocklisted = true;
            const std::string label = hashes_->BlockedLabel(subject.sha256);
            report.signals.emplace_back(
                SignalSource::HashLookup, RiskLevel::Malicious, 1.0,
                label.empty() ? std::string("hash on blocklist (known malware)")
                              : ("known malware: " + label),
                subject.sha256);
        }
    }

    // --- Layer 2: YARA-style rule matching ---
    rules_->Match(subject.content, report.matches);
    for (const auto& m : report.matches) {
        const RiskLevel level = SeverityToLevel(m.severity);
        const double conf = Clamp01(m.weight);
        report.signals.emplace_back(
            SignalSource::YaraRule, level, conf,
            m.description.empty() ? ("rule " + m.rule_id) : m.description,
            m.rule_id);
    }

    // --- Layer 3: PE structural heuristics (only for PE files) ---
    if (subject.LooksLikePe()) {
        report.pe = PeParser::Analyze(subject.content,
                                      config_.high_entropy_threshold);
        if (report.pe.score > 0.0) {
            // PE heuristics never convict alone; cap their standalone level.
            const RiskLevel level = report.pe.score >= 0.5
                                        ? RiskLevel::Suspicious
                                        : RiskLevel::LowRisk;
            std::string detail = "PE heuristics";
            if (!report.pe.flags.empty()) {
                detail += ": " + report.pe.flags.front();
                if (report.pe.flags.size() > 1) {
                    detail += " (+" +
                              std::to_string(report.pe.flags.size() - 1) +
                              " more)";
                }
            }
            report.signals.emplace_back(SignalSource::PeHeuristic, level,
                                        Clamp01(report.pe.score), detail,
                                        "pe_heuristic");
        }
    }

    // --- Aggregate static score ---
    // Definitive hash outcomes pin the score; otherwise combine the signal
    // confidences with a noisy-OR so independent weak signals accumulate while
    // no single one saturates.
    if (report.allowlisted) {
        report.static_score = 0.0;
    } else if (report.blocklisted) {
        report.static_score = 1.0;
    } else {
        double inv = 1.0;
        for (const auto& sig : report.signals) {
            inv *= (1.0 - Clamp01(sig.confidence));
        }
        report.static_score = 1.0 - inv;
    }
    return report;
}

Verdict StaticScanner::Scan(const FileSubject& subject) {
    // Verdict cache keyed on the full-file hash: an unchanged, already-scanned
    // file is resolved instantly. A changed file has a new hash, so a stale
    // entry is simply never hit.
    if (!subject.sha256.empty()) {
        Verdict cached;
        if (cache_->Get(subject.sha256, cached)) {
            return cached;
        }
    }

    const StaticScanReport report = Analyze(subject);
    VerdictFusion fusion(config_);
    Verdict v = fusion.Fuse(report.signals, report.allowlisted,
                            report.blocklisted);
    if (v.summary.empty()) {
        v.summary = BuildSummary(subject, report, v);
    }

    if (!subject.sha256.empty()) {
        cache_->Put(subject.sha256, v);
    }
    return v;
}

Verdict StaticScanner::ScanFile(const std::string& path) {
    auto subject = FileSubject::FromFile(path);
    if (!subject) {
        // Unreadable file: fail open with a benign verdict and an explanation
        // rather than blocking the user over an I/O error.
        Verdict v;
        v.level = RiskLevel::Unknown;
        v.action = Action::Allow;
        v.score = 0.0;
        v.summary =
            "could not read '" + path + "': " + subject.status().message();
        return v;
    }
    return Scan(subject.value());
}

}  // namespace sentinel
