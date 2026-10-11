#include "sentinel/behavior/injection.h"

namespace sentinel {

Signal InjectionHeuristic::Evaluate(const ProcessNode& node) const {
    // Count how many stages of the classic injection chain are present:
    //   VirtualAllocEx  -> remote_allocs
    //   WriteProcessMemory -> remote_writes
    //   CreateRemoteThread -> remote_threads
    // Confidence rises as more stages are observed. We count presence of each
    // stage rather than raw counts: one full chain is already conclusive.
    int stages = 0;
    if (node.remote_allocs > 0) ++stages;
    if (node.remote_writes > 0) ++stages;
    if (node.remote_threads > 0) ++stages;

    if (stages >= 3) {
        // Alloc + write + remote-thread: the complete inject-and-run chain.
        return Signal(SignalSource::Injection, RiskLevel::Malicious, 0.95,
                      "full alloc+write+remote-thread injection chain observed",
                      "injection.full_chain");
    }
    if (stages == 2) {
        // Two stages: very likely injection in progress, but not yet executed.
        return Signal(SignalSource::Injection, RiskLevel::Suspicious, 0.70,
                      "partial injection chain (two of alloc/write/remote-thread)",
                      "injection.partial_chain");
    }
    if (node.remote_threads > 0) {
        // A remote thread with no observed alloc/write is still notable: code
        // may have been staged by other means (e.g. a shared section).
        return Signal(SignalSource::Injection, RiskLevel::Suspicious, 0.50,
                      "remote thread created in another process",
                      "injection.remote_thread");
    }
    if (stages == 1) {
        // A lone remote alloc or write is weak on its own.
        return Signal(SignalSource::Injection, RiskLevel::LowRisk, 0.30,
                      "isolated remote-memory operation",
                      "injection.single_stage");
    }

    // No cross-process memory activity at all.
    return Signal(SignalSource::Injection, RiskLevel::Unknown, 0.0,
                  "no injection activity", "injection.none");
}

}  // namespace sentinel
