#include "sentinel/behavior/action_graph.h"

namespace sentinel {

const char* ToString(ActionType type) noexcept {
    switch (type) {
        case ActionType::ProcessStart: return "ProcessStart";
        case ActionType::ProcessExit: return "ProcessExit";
        case ActionType::FileRead: return "FileRead";
        case ActionType::FileWrite: return "FileWrite";
        case ActionType::FileRename: return "FileRename";
        case ActionType::FileDelete: return "FileDelete";
        case ActionType::ThreadCreate: return "ThreadCreate";
        case ActionType::RemoteThreadCreate: return "RemoteThreadCreate";
        case ActionType::MemoryAllocRemote: return "MemoryAllocRemote";
        case ActionType::MemoryWriteRemote: return "MemoryWriteRemote";
        case ActionType::RegistryWrite: return "RegistryWrite";
        case ActionType::RegistryPersistence: return "RegistryPersistence";
        case ActionType::NetworkConnect: return "NetworkConnect";
        case ActionType::PrivilegeChange: return "PrivilegeChange";
        case ActionType::HandleOpenProcess: return "HandleOpenProcess";
        case ActionType::ScriptExec: return "ScriptExec";
        case ActionType::ImageLoad: return "ImageLoad";
    }
    return "Unknown";
}

ProcessNode& ActionGraph::AddProcess(std::uint32_t pid, std::uint32_t ppid,
                                     const std::string& image_path) {
    std::lock_guard<std::mutex> lock(mutex_);
    // operator[] returns the existing node or default-constructs a fresh one.
    ProcessNode& node = nodes_[pid];
    node.pid = pid;
    // Fill identity fields the first time we actually learn them; never clobber
    // an already-known parent or path with a later, possibly-empty re-register.
    if (node.ppid == 0) node.ppid = ppid;
    if (node.image_path.empty()) node.image_path = image_path;
    return node;
}

void ActionGraph::Record(std::uint32_t pid, const ActivityEvent& action) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Auto-create unknown pids so events are never silently dropped. A node
    // created here still gets its pid set even if AddProcess was never called.
    auto it = nodes_.find(pid);
    if (it == nodes_.end()) {
        it = nodes_.emplace(pid, ProcessNode{}).first;
        it->second.pid = pid;
    }
    ProcessNode& node = it->second;
    node.actions.push_back(action);

    // Update the cheap rolling counters heuristics query. Only the action
    // kinds that feed a behavioral feature are counted here.
    switch (action.type) {
        case ActionType::FileWrite:
            ++node.files_written;
            // 7.0 bits/byte is the practical floor for encrypted/compressed
            // output; such a write is what ransomware mass-encryption produces.
            if (action.entropy >= 7.0) ++node.high_entropy_writes;
            break;
        case ActionType::FileRename:
            ++node.files_renamed;
            break;
        case ActionType::RemoteThreadCreate:
            ++node.remote_threads;
            break;
        case ActionType::MemoryAllocRemote:
            ++node.remote_allocs;
            break;
        case ActionType::MemoryWriteRemote:
            ++node.remote_writes;
            break;
        case ActionType::RegistryPersistence:
            ++node.persistence_writes;
            break;
        default:
            // Other action kinds are recorded in the action list but need no
            // dedicated counter.
            break;
    }
}

const ProcessNode* ActionGraph::Get(std::uint32_t pid) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(pid);
    return it == nodes_.end() ? nullptr : &it->second;
}

ProcessNode* ActionGraph::GetMutable(std::uint32_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = nodes_.find(pid);
    return it == nodes_.end() ? nullptr : &it->second;
}

void ActionGraph::Remove(std::uint32_t pid) {
    std::lock_guard<std::mutex> lock(mutex_);
    // Remove the process and every descendant (matched down the ppid chain) so
    // orphaned child records don't linger after a whole process tree exits.
    // Children are queued before the current node is erased; erasing as we go
    // means a malformed ppid cycle cannot drive an infinite loop.
    std::vector<std::uint32_t> frontier{pid};
    while (!frontier.empty()) {
        const std::uint32_t current = frontier.back();
        frontier.pop_back();
        for (const auto& kv : nodes_) {
            // Skip self-parenting so a pid with ppid == pid can't re-enqueue
            // itself forever.
            if (kv.first != current && kv.second.ppid == current) {
                frontier.push_back(kv.first);
            }
        }
        nodes_.erase(current);
    }
}

std::size_t ActionGraph::process_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return nodes_.size();
}

std::vector<ProcessNode> ActionGraph::Snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ProcessNode> out;
    out.reserve(nodes_.size());
    for (const auto& kv : nodes_) out.push_back(kv.second);
    return out;
}

}  // namespace sentinel
