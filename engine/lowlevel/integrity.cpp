#include "sentinel/lowlevel/integrity.h"

#include <fstream>
#include <string>
#include <utility>

#include "sentinel/core/fs.h"
#include "sentinel/core/logging.h"

namespace sentinel {

Status SelfIntegrity::Enroll(const std::string& path) {
    // Record the current on-disk hash as known-good. Streams from disk so large
    // modules do not have to be fully resident.
    auto r = HashFile(path);
    if (!r) return r.status();
    expected_[path] = r.value();
    SENTINEL_LOG(Debug) << "integrity: enrolled " << path << " -> "
                        << r.value();
    return Status::Ok();
}

Status SelfIntegrity::LoadManifest(const std::string& manifest_path) {
    if (!PathExists(manifest_path)) {
        return Status::Error(ErrorCode::NotFound,
                             "manifest not found: " + manifest_path);
    }

    std::ifstream in(manifest_path, std::ios::binary);
    if (!in) {
        return Status::Error(ErrorCode::IoError,
                             "cannot read manifest: " + manifest_path);
    }

    // Merge into expected_ (do not clear), so an enrolled set and a saved
    // manifest can be combined; a fresh object loads the manifest verbatim.
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        // Format: path<TAB>hash. The path itself may not contain a tab, so a
        // single split on the first tab is unambiguous. Skip malformed lines
        // rather than trusting a partially-corrupt record.
        const std::size_t tab = line.find('\t');
        if (tab == std::string::npos) {
            SENTINEL_LOG(Warn) << "integrity: skipping malformed manifest line";
            continue;
        }
        std::string path = line.substr(0, tab);
        std::string hash = line.substr(tab + 1);
        if (path.empty() || hash.empty()) continue;

        expected_[std::move(path)] = std::move(hash);
    }

    SENTINEL_LOG(Debug) << "integrity: loaded manifest " << manifest_path
                        << " (" << expected_.size() << " protected files)";
    return Status::Ok();
}

Status SelfIntegrity::SaveManifest(const std::string& manifest_path) const {
    // std::map iterates in sorted key order, so the manifest is deterministic.
    std::string content;
    for (const auto& kv : expected_) {
        content += kv.first;   // path
        content += '\t';
        content += kv.second;  // known-good sha256
        content += '\n';
    }
    const Status st = WriteFileAtomic(manifest_path, content);
    if (!st) return st;
    SENTINEL_LOG(Debug) << "integrity: saved manifest " << manifest_path;
    return Status::Ok();
}

std::vector<IntegrityViolation> SelfIntegrity::Verify() const {
    std::vector<IntegrityViolation> violations;

    for (const auto& kv : expected_) {
        const std::string& path = kv.first;
        const std::string& expected_hash = kv.second;

        // Missing (or no longer a regular file) is itself a violation: a
        // protected module should never vanish out from under us.
        if (!IsRegularFile(path)) {
            IntegrityViolation v;
            v.path = path;
            v.expected_hash = expected_hash;
            v.actual_hash = "";  // absent
            v.reason = "protected file is missing";
            violations.push_back(std::move(v));
            continue;
        }

        auto r = HashFile(path);
        if (!r) {
            // Readable-but-unhashable (e.g. permission revoked mid-run) is
            // treated as a violation so it cannot be used to hide tampering.
            IntegrityViolation v;
            v.path = path;
            v.expected_hash = expected_hash;
            v.actual_hash = "";
            v.reason = "cannot hash protected file: " + r.status().message();
            violations.push_back(std::move(v));
            continue;
        }

        if (r.value() != expected_hash) {
            IntegrityViolation v;
            v.path = path;
            v.expected_hash = expected_hash;
            v.actual_hash = r.value();
            v.reason = "hash mismatch: protected file was modified";
            violations.push_back(std::move(v));
        }
    }

    if (!violations.empty()) {
        SENTINEL_LOG(Warn) << "integrity: " << violations.size()
                           << " violation(s) detected";
    }
    return violations;
}

}  // namespace sentinel
