// Injection & hollowing heuristic. Allocating executable memory in another
// process, writing to it, then starting a remote thread (VirtualAllocEx +
// WriteProcessMemory + CreateRemoteThread), or creating a process suspended and
// swapping its image, is the classic injection chain. The process and thread
// callbacks see it live and can veto the remote thread.
#ifndef SENTINEL_BEHAVIOR_INJECTION_H
#define SENTINEL_BEHAVIOR_INJECTION_H

#include "sentinel/behavior/action_graph.h"
#include "sentinel/core/types.h"

namespace sentinel {

class InjectionHeuristic {
public:
    // Evaluate a process node for the allocate-write-execute chain and for
    // raw remote-thread creation. Confidence rises as more stages of the chain
    // are observed against the same target process.
    Signal Evaluate(const ProcessNode& node) const;
};

}  // namespace sentinel

#endif  // SENTINEL_BEHAVIOR_INJECTION_H
