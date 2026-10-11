// Shadow-commit rollback gate. The feature that makes the engine uniquely safe:
// a risky process's changes are reversible by construction. Nothing dangerous is
// truly committed until it is proven safe.
//
//   1. Risk classes.   Trusted processes write straight to disk at zero
//                       overhead. Only Unknown/Suspicious processes are gated.
//   2. Copy-on-write.   For a gated process, writes (files, optionally registry)
//                       are redirected into a per-process shadow layer. The
//                       process believes it wrote to disk; it actually wrote to
//                       a staging area the rest of the system cannot see.
//   3. Live verdict.    The behavioral engine scores the process as it runs. If
//                       the verdict stays clean past a threshold, its shadow
//                       writes are committed to the real disk atomically. If the
//                       verdict turns malicious, the whole shadow layer is
//                       discarded: perfect rollback, no data loss.
//
// The hard part is the side-effect boundary: while a process is gated, its
// irreversible actions (network sends, inter-process injection) are themselves
// gated — held, throttled, or denied — until the verdict clears.
#ifndef SENTINEL_ROLLBACK_SHADOW_GATE_H
#define SENTINEL_ROLLBACK_SHADOW_GATE_H

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "sentinel/core/bytes.h"
#include "sentinel/core/result.h"
#include "sentinel/core/types.h"

namespace sentinel {

enum class SideEffect { Network, InterProcess, HardwareOrUi };

struct SideEffectDecision {
    enum class Disposition { Buffer, Throttle, Deny, Allow } disposition;
    std::string reason;
};

// Tracks the staged state of one gated process.
struct ShadowSession {
    std::uint32_t pid = 0;
    std::string shadow_root;                     // staging dir for this process
    std::vector<std::string> staged_files;       // shadow-relative paths written
    std::uint64_t buffered_network_bytes = 0;
    bool committed = false;
    bool discarded = false;
};

class ShadowGate {
public:
    // `shadow_base` is the root under which per-process staging dirs are created.
    explicit ShadowGate(std::string shadow_base);
    ~ShadowGate();

    // Begin gating a process. Returns the session's shadow root.
    Result<std::string> BeginSession(std::uint32_t pid);

    bool IsGated(std::uint32_t pid) const;

    // Redirect a write: returns the shadow path the caller should write to
    // instead of `real_path`. Records the staging mapping.
    Result<std::string> StageWrite(std::uint32_t pid, const std::string& real_path);

    // Convenience: stage a write AND persist the bytes into the shadow layer.
    Status StageWriteData(std::uint32_t pid, const std::string& real_path,
                          const Bytes& data);

    // Decide what to do with an irreversible side effect from a gated process.
    SideEffectDecision OnSideEffect(std::uint32_t pid, SideEffect effect,
                                    std::uint64_t bytes = 0);

    // Commit: atomically move all staged writes to their real destinations and
    // release any buffered network data. Ends the session.
    Status Commit(std::uint32_t pid);

    // Discard: throw away the entire shadow layer. Perfect rollback. Ends the
    // session. This is what runs on a kill-and-roll-back verdict.
    Status Discard(std::uint32_t pid);

    const ShadowSession* Get(std::uint32_t pid) const;
    std::size_t active_sessions() const;

private:
    std::string RealToShadow(const ShadowSession& s, const std::string& real_path) const;

    mutable std::mutex mutex_;
    std::string shadow_base_;
    std::map<std::uint32_t, ShadowSession> sessions_;
    // Maps a session's shadow-relative file to its real destination for commit.
    std::map<std::uint32_t, std::map<std::string, std::string>> commit_map_;
};

}  // namespace sentinel

#endif  // SENTINEL_ROLLBACK_SHADOW_GATE_H
