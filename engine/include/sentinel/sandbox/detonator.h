// Micro-sandbox detonation. For higher-risk unknowns, run the file briefly in an
// isolated, instrumented micro-sandbox and observe what it actually does (files,
// registry, network, injection), then decide before granting real execution. It
// pairs directly with the shadow-commit gate: detonate, judge, and only then
// allow real writes.
//
// The detonator drives the Emulator, maps observed synthetic syscalls onto the
// behavioral action graph, scores the result, and also scans the unpacked
// payload with the static engine (packed zero-days reveal their real payload
// here).
#ifndef SENTINEL_SANDBOX_DETONATOR_H
#define SENTINEL_SANDBOX_DETONATOR_H

#include <string>
#include <vector>

#include "sentinel/behavior/action_graph.h"
#include "sentinel/core/bytes.h"
#include "sentinel/core/types.h"
#include "sentinel/sandbox/emulator.h"

namespace sentinel {

struct DetonationReport {
    EmulationResult emulation;
    std::vector<ActivityEvent> observed_actions;  // mapped to the action-graph model
    std::vector<Signal> signals;
    double score = 0.0;
    bool payload_revealed = false;
    Bytes unpacked_payload;                // for static re-scan by the caller
};

class Detonator {
public:
    // Detonate a (possibly packed) program buffer. `max_instructions` bounds it.
    DetonationReport Detonate(const Bytes& program,
                              int max_instructions = 100000) const;

private:
    Emulator emulator_;
};

}  // namespace sentinel

#endif  // SENTINEL_SANDBOX_DETONATOR_H
