#include "sentinel/rollback/shadow_gate.h"

#include <cctype>
#include <filesystem>
#include <system_error>
#include <utility>

#include "sentinel/core/fs.h"
#include "sentinel/core/logging.h"

namespace fs = std::filesystem;

namespace sentinel {
namespace {

// Map a real destination path to a collision-free, traversal-safe relative path
// inside a per-process shadow root. The real filesystem layout is mirrored as a
// subtree (separators kept as separators) so two distinct real paths can never
// land on the same staged file, and so committing later is a faithful inverse.
std::string SanitizeRelative(const std::string& real_path) {
    std::string p = real_path;

    // Strip a Windows drive prefix such as "C:" / "c:" (keeps the mapping the
    // same whether the caller passed a POSIX or a Windows style absolute path).
    if (p.size() >= 2 && std::isalpha(static_cast<unsigned char>(p[0])) &&
        p[1] == ':') {
        p.erase(0, 2);
    }

    // Normalize backslashes so both separator styles mirror identically.
    for (char& c : p) {
        if (c == '\\') c = '/';
    }

    // Split into path components, dropping empties and ".", and neutralizing
    // ".." so a crafted path can never escape the shadow root (traversal guard).
    std::vector<std::string> parts;
    std::string cur;
    auto flush = [&]() {
        if (cur.empty()) return;
        if (cur == ".") {
            cur.clear();
            return;
        }
        if (cur == "..") cur = "__";  // neutralize parent references
        // ':' can appear in NTFS alternate-data-stream names; make it inert.
        for (char& c : cur) {
            if (c == ':') c = '_';
        }
        parts.push_back(cur);
        cur.clear();
    };
    for (char c : p) {
        if (c == '/') {
            flush();
        } else {
            cur += c;
        }
    }
    flush();

    if (parts.empty()) return "_root";  // e.g. input was "/" or a bare drive

    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) {
        if (i) out += '/';
        out += parts[i];
    }
    return out;
}

}  // namespace

ShadowGate::ShadowGate(std::string shadow_base)
    : shadow_base_(std::move(shadow_base)) {}

ShadowGate::~ShadowGate() = default;

Result<std::string> ShadowGate::BeginSession(std::uint32_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);

    // Idempotent: re-begin returns the existing staging root rather than
    // clobbering already-staged state for the process.
    auto existing = sessions_.find(pid);
    if (existing != sessions_.end()) {
        return existing->second.shadow_root;
    }

    const std::string root = JoinPath(shadow_base_, std::to_string(pid));
    if (!MakeDirs(root)) {
        return Status::Error(ErrorCode::IoError,
                             "cannot create shadow root: " + root);
    }

    ShadowSession s;
    s.pid = pid;
    s.shadow_root = root;
    sessions_.emplace(pid, std::move(s));
    commit_map_[pid];  // ensure the per-pid mapping table exists

    SENTINEL_LOG(Debug) << "shadow gate: began session pid=" << pid
                        << " root=" << root;
    return root;
}

bool ShadowGate::IsGated(std::uint32_t pid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    // Sessions are erased on commit/discard, so mere membership means "gated".
    return sessions_.find(pid) != sessions_.end();
}

std::string ShadowGate::RealToShadow(const ShadowSession& s,
                                     const std::string& real_path) const {
    return JoinPath(s.shadow_root, SanitizeRelative(real_path));
}

Result<std::string> ShadowGate::StageWrite(std::uint32_t pid,
                                           const std::string& real_path) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(pid);
    if (it == sessions_.end()) {
        return Status::Error(ErrorCode::NotFound,
                             "process not gated: " + std::to_string(pid));
    }
    ShadowSession& s = it->second;

    const std::string rel = SanitizeRelative(real_path);
    const std::string shadow_path = RealToShadow(s, real_path);

    // The write may target a nested directory; stage its parents first.
    const std::string parent = ParentDir(shadow_path);
    if (!parent.empty() && !MakeDirs(parent)) {
        return Status::Error(ErrorCode::IoError,
                             "cannot stage parent dir: " + parent);
    }

    // Record the shadow-relative -> real destination mapping used at commit.
    // Only track each staged file once even if written repeatedly.
    auto& mapping = commit_map_[pid];
    if (mapping.find(rel) == mapping.end()) {
        s.staged_files.push_back(rel);
    }
    mapping[rel] = real_path;

    return shadow_path;
}

Status ShadowGate::StageWriteData(std::uint32_t pid,
                                  const std::string& real_path,
                                  const Bytes& data) {
    // StageWrite takes the lock and returns the staging path; persist outside
    // the lock via the atomic fs helper (the mutex is not recursive).
    auto staged = StageWrite(pid, real_path);
    if (!staged) return staged.status();
    return WriteFileAtomic(staged.value(), data);
}

SideEffectDecision ShadowGate::OnSideEffect(std::uint32_t pid, SideEffect effect,
                                            std::uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mutex_);
    SideEffectDecision d;

    auto it = sessions_.find(pid);
    if (it == sessions_.end()) {
        // Not gated: the caller should not have asked, but be permissive — an
        // ungated (trusted) process is not subject to the side-effect boundary.
        d.disposition = SideEffectDecision::Disposition::Allow;
        d.reason = "process not gated";
        return d;
    }

    switch (effect) {
        case SideEffect::Network:
            // Hold outbound data until the verdict clears; count the bytes so
            // they can be released on commit (or dropped on discard).
            it->second.buffered_network_bytes += bytes;
            d.disposition = SideEffectDecision::Disposition::Buffer;
            d.reason = "network send buffered until verdict clears";
            break;
        case SideEffect::InterProcess:
            // Injection is irreversible and cannot be rolled back — deny it
            // outright while the process is unproven.
            d.disposition = SideEffectDecision::Disposition::Deny;
            d.reason = "inter-process injection denied while gated";
            break;
        case SideEffect::HardwareOrUi:
            // User-visible / hardware effects are allowed but flagged.
            d.disposition = SideEffectDecision::Disposition::Allow;
            d.reason = "hardware/UI effect allowed with note";
            break;
    }
    return d;
}

Status ShadowGate::Commit(std::uint32_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(pid);
    if (it == sessions_.end()) {
        return Status::Error(ErrorCode::NotFound,
                             "no session to commit: " + std::to_string(pid));
    }
    ShadowSession& s = it->second;

    Status result = Status::Ok();  // remembers the first hard failure, if any

    auto mit = commit_map_.find(pid);
    if (mit != commit_map_.end()) {
        for (const auto& kv : mit->second) {
            const std::string shadow_path = JoinPath(s.shadow_root, kv.first);
            const std::string& real_dest = kv.second;

            std::error_code ec;
            if (!fs::exists(shadow_path, ec)) {
                // Mapping was staged but no bytes were ever written — nothing
                // to commit for this path.
                continue;
            }

            const std::string parent = ParentDir(real_dest);
            if (!parent.empty()) MakeDirs(parent);

            // Prefer an atomic rename; fall back to read+atomic-write across
            // filesystems (rename fails with EXDEV between devices).
            ec.clear();
            fs::rename(shadow_path, real_dest, ec);
            if (ec) {
                auto rd = ReadFile(shadow_path);
                if (rd) {
                    const Status st = WriteFileAtomic(real_dest, rd.value());
                    if (!st && result.ok()) result = st;
                } else if (result.ok()) {
                    result = Status::Error(ErrorCode::IoError,
                                           "commit read failed: " + shadow_path);
                }
            }
        }
    }

    s.committed = true;

    // Tear down the staging layer and all bookkeeping; the session ends here.
    std::error_code ec;
    fs::remove_all(s.shadow_root, ec);
    commit_map_.erase(pid);
    sessions_.erase(it);

    SENTINEL_LOG(Debug) << "shadow gate: committed session pid=" << pid;
    return result;
}

Status ShadowGate::Discard(std::uint32_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);

    auto it = sessions_.find(pid);
    if (it == sessions_.end()) {
        return Status::Error(ErrorCode::NotFound,
                             "no session to discard: " + std::to_string(pid));
    }

    // Perfect rollback: delete the entire shadow layer. Nothing was ever
    // written to the real disk, so this leaves the system exactly as before.
    std::error_code ec;
    fs::remove_all(it->second.shadow_root, ec);
    if (ec) {
        SENTINEL_LOG(Warn) << "shadow gate: discard cleanup incomplete pid="
                           << pid << " (" << ec.message() << ")";
    }

    it->second.discarded = true;
    commit_map_.erase(pid);
    sessions_.erase(it);

    SENTINEL_LOG(Debug) << "shadow gate: discarded session pid=" << pid;
    return Status::Ok();
}

const ShadowSession* ShadowGate::Get(std::uint32_t pid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sessions_.find(pid);
    return it == sessions_.end() ? nullptr : &it->second;
}

std::size_t ShadowGate::active_sessions() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessions_.size();
}

}  // namespace sentinel
