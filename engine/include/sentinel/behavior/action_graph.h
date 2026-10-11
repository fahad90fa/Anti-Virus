// The action graph. For each process the engine keeps a running record of what
// it has done — files read and written, processes and threads spawned,
// injection attempts, registry edits, network connections, privilege changes.
// Behavior is judged in context: the sequence and combination matter, not any
// single action. Heuristics query this graph.
#ifndef SENTINEL_BEHAVIOR_ACTION_GRAPH_H
#define SENTINEL_BEHAVIOR_ACTION_GRAPH_H

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace sentinel {

enum class ActionType : std::uint8_t {
    ProcessStart,
    ProcessExit,
    FileRead,
    FileWrite,
    FileRename,
    FileDelete,
    ThreadCreate,
    RemoteThreadCreate,   // thread created in another process (injection)
    MemoryAllocRemote,    // VirtualAllocEx into another process
    MemoryWriteRemote,    // WriteProcessMemory into another process
    RegistryWrite,
    RegistryPersistence,  // Run key / service / boot entry
    NetworkConnect,
    PrivilegeChange,
    HandleOpenProcess,    // opened a handle to another process
    ScriptExec,
    ImageLoad,
};

const char* ToString(ActionType type) noexcept;

struct ActivityEvent {
    ActionType type;
    std::uint64_t timestamp_ms = 0;  // caller-supplied monotonic ms
    std::string target;              // file path, remote pid, key, host, etc.
    std::uint32_t target_pid = 0;    // for inter-process actions
    double entropy = 0.0;            // for FileWrite: entropy of written data
    std::uint64_t bytes = 0;         // size involved
};

// Per-process node: identity plus the recorded action list and rolling counters.
struct ProcessNode {
    std::uint32_t pid = 0;
    std::uint32_t ppid = 0;
    std::string image_path;
    std::string image_hash;
    std::uint64_t start_time_ms = 0;
    std::vector<ActivityEvent> actions;

    // Rolling feature counters (cheap to query by heuristics).
    std::uint32_t files_written = 0;
    std::uint32_t files_renamed = 0;
    std::uint32_t high_entropy_writes = 0;
    std::uint32_t remote_threads = 0;
    std::uint32_t remote_allocs = 0;
    std::uint32_t remote_writes = 0;
    std::uint32_t persistence_writes = 0;
    std::uint32_t canary_touches = 0;
};

class ActionGraph {
public:
    // Register a new process (or return the existing node).
    ProcessNode& AddProcess(std::uint32_t pid, std::uint32_t ppid,
                            const std::string& image_path);

    // Record an action for a process. Unknown pids are auto-created so events
    // are never dropped. Updates the rolling counters.
    void Record(std::uint32_t pid, const ActivityEvent& action);

    // Access a node (nullptr if unknown).
    const ProcessNode* Get(std::uint32_t pid) const;
    ProcessNode* GetMutable(std::uint32_t pid);

    // Remove a process and its subtree (on exit + cleanup).
    void Remove(std::uint32_t pid);

    std::size_t process_count() const;

    // Snapshot the whole graph (for the EDR timeline / UI).
    std::vector<ProcessNode> Snapshot() const;

private:
    mutable std::mutex mutex_;
    std::map<std::uint32_t, ProcessNode> nodes_;
};

}  // namespace sentinel

#endif  // SENTINEL_BEHAVIOR_ACTION_GRAPH_H
