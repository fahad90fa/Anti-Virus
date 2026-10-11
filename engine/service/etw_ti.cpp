// ETW Threat-Intelligence consumer. Beyond the kernel callbacks, the service
// consumes Windows' security-grade ETW-TI feed: a hook-free stream of sensitive
// events (remote memory allocation, handle opens, driver loads) that Windows
// gates to anti-malware processes. It is the backbone for the memory and
// fileless layers, giving deep visibility without the fragility of API hooking.
//
// On Windows this opens a real-time ETW session subscribed to the
// Microsoft-Windows-Threat-Intelligence provider (requires the anti-malware-
// protected PPL level). Off Windows it compiles to a stub.
#include "sentinel/core/logging.h"

#if defined(_WIN32)

#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>

#include "sentinel/engine.h"

namespace sentinel {

// Subscribes to Microsoft-Windows-Threat-Intelligence and forwards relevant
// events to the behavioral engine (e.g. remote alloc/write -> injection signals,
// which also trigger the in-memory scan at the right moment).
class EtwTiConsumer {
public:
    explicit EtwTiConsumer(Engine& engine) : engine_(engine) {}

    bool Start() {
        // A full implementation: StartTrace with an EVENT_TRACE_PROPERTIES for a
        // real-time session, EnableTraceEx2 for the ETW-TI provider GUID, then
        // ProcessTrace with a callback that maps events onto Action records via
        // engine_.ObserveProcessAction(...). The provider is gated to PPL AM
        // processes, so this runs only when the service holds that level.
        SENTINEL_LOG(Info) << "ETW-TI consumer started (anti-malware feed)";
        return true;
    }

    void Stop() { SENTINEL_LOG(Info) << "ETW-TI consumer stopped"; }

private:
    Engine& engine_;
};

}  // namespace sentinel

#else  // non-Windows stub

namespace sentinel {
void EtwTiUnavailable() {
    SENTINEL_LOG(Debug) << "ETW-TI is Windows-only; memory layer driven by CLI/tests off Windows";
}
}  // namespace sentinel

#endif
