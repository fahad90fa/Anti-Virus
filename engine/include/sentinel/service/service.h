// The always-on service: the Phase 0 orchestrator. It wires the folder watcher
// to the engine so new/changed files are scanned in real time (the user-mode
// stand-in for the kernel minifilter), drives periodic behavioral sweeps, and
// hosts the IPC endpoint for the UI. On Windows it additionally runs the filter
// port client and the ETW-TI consumer; those are compiled as stubs elsewhere.
#ifndef SENTINEL_SERVICE_SERVICE_H
#define SENTINEL_SERVICE_SERVICE_H

#include <atomic>
#include <memory>
#include <string>
#include <vector>

#include "sentinel/core/config.h"
#include "sentinel/engine.h"
#include "sentinel/platform/file_watcher.h"

namespace sentinel {

class Service {
public:
    explicit Service(const Config& config);
    ~Service();

    // Initialize the engine. Must be called before Run/WatchOnce.
    Status Initialize();

    // Watch the given directories, scanning new/changed files as they appear.
    // Blocks until Stop() is called (or SIGINT in the CLI). Returns when stopped.
    Status Run(const std::vector<std::string>& watch_dirs, bool recursive);

    // Request the run loop to stop.
    void Stop();

    Engine& engine() { return *engine_; }

    // Counters for status reporting.
    std::uint64_t files_scanned() const { return files_scanned_.load(); }
    std::uint64_t threats_blocked() const { return threats_blocked_.load(); }

private:
    void OnFileChange(const FileChange& change);

    Config config_;
    std::unique_ptr<Engine> engine_;
    std::unique_ptr<FileWatcher> watcher_;
    std::atomic<bool> running_{false};
    std::atomic<std::uint64_t> files_scanned_{0};
    std::atomic<std::uint64_t> threats_blocked_{0};
};

}  // namespace sentinel

#endif  // SENTINEL_SERVICE_SERVICE_H
