// OS abstraction for process enumeration. Phase 0 enumerates running processes
// in user mode; Phase 2 replaces/augments this with the kernel process
// callbacks. Backends: Linux (/proc) and Windows (Toolhelp snapshot).
#ifndef SENTINEL_PLATFORM_PROCESS_H
#define SENTINEL_PLATFORM_PROCESS_H

#include <cstdint>
#include <string>
#include <vector>

#include "sentinel/core/result.h"

namespace sentinel {

struct ProcessInfo {
    std::uint32_t pid = 0;
    std::uint32_t ppid = 0;
    std::string name;        // image base name
    std::string image_path;  // full path to the executable, when resolvable
};

// Snapshot of currently running processes. Best-effort: processes that exit
// mid-enumeration or that we cannot read are skipped, not fatal.
Result<std::vector<ProcessInfo>> EnumerateProcesses();

// Resolve the full image path for a pid, if permitted.
Result<std::string> GetProcessImagePath(std::uint32_t pid);

// Current process id.
std::uint32_t CurrentProcessId() noexcept;

}  // namespace sentinel

#endif  // SENTINEL_PLATFORM_PROCESS_H
