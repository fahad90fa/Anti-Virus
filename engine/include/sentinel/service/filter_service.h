// The Windows filter-service run loop: connect to the kernel minifilter's
// communication port, pump scan requests / behavioral events to the engine, and
// reply with verdicts. This is the transport half of the real-time loop; the
// detection decisions come from the existing Engine (static scan + behavioral
// fusion), never duplicated here.
//
// On Windows this drives FltMgr (FilterConnectCommunicationPort /
// FilterGetMessage / FilterReplyMessage) against the protocol in
// drivers/common/shared_defs.h. Off Windows it is a stub that returns
// Unsupported, so the portable build still links (the folder watcher drives
// scanning there instead).
#ifndef SENTINEL_SERVICE_FILTER_SERVICE_H
#define SENTINEL_SERVICE_FILTER_SERVICE_H

#include <atomic>
#include <string>

#include "sentinel/core/result.h"
#include "sentinel/engine.h"

namespace sentinel {

struct FilterServiceOptions {
    // Deny (block) an unknown image when the engine cannot produce a verdict in
    // time. Default false = fail-open for availability (the machine keeps
    // working if protection stalls); a hardened deployment sets this true.
    bool fail_closed = false;
    // Milliseconds the kernel waits for a verdict before applying the fail-safe.
    unsigned timeout_ms = 5000;
};

// Runs until `stop` is set (e.g. by a Ctrl-C handler) or the port disconnects.
// Returns Ok on clean shutdown, Unsupported off Windows, or an I/O error if the
// port cannot be opened.
Status RunFilterService(Engine& engine, const FilterServiceOptions& options,
                        std::atomic<bool>& stop);

}  // namespace sentinel

#endif  // SENTINEL_SERVICE_FILTER_SERVICE_H
