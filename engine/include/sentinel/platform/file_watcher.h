// Folder watcher for the Phase 0 user-mode scanner: watch directories for newly
// created or modified files and hand each to the scan engine. Backends:
//   - Linux:   inotify (event-driven)
//   - Windows: ReadDirectoryChangesW (event-driven) [compiled on Windows]
//   - Fallback: polling by mtime (portable; used where native is unavailable)
//
// In the shipping product the kernel minifilter (Phase 1) intercepts file I/O
// synchronously before execution; this user-mode watcher is the Phase 0
// stand-in that proves the detection pipeline without any driver.
#ifndef SENTINEL_PLATFORM_FILE_WATCHER_H
#define SENTINEL_PLATFORM_FILE_WATCHER_H

#include <atomic>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "sentinel/core/result.h"

namespace sentinel {

enum class FileChangeKind { Created, Modified, Renamed };

struct FileChange {
    std::string path;
    FileChangeKind kind = FileChangeKind::Created;
};

using FileChangeHandler = std::function<void(const FileChange&)>;

class FileWatcher {
public:
    FileWatcher();
    ~FileWatcher();

    FileWatcher(const FileWatcher&) = delete;
    FileWatcher& operator=(const FileWatcher&) = delete;

    // Watch a directory (optionally recursively). Multiple directories may be
    // added before Start().
    Status AddDirectory(const std::string& dir, bool recursive = true);

    // Begin watching on a background thread, delivering changes to `handler`.
    Status Start(FileChangeHandler handler);

    // Stop watching and join the background thread.
    void Stop();

    bool IsRunning() const noexcept { return running_.load(); }

    // Poll interval for the fallback backend (milliseconds).
    void SetPollIntervalMs(int ms) { poll_interval_ms_ = ms; }

private:
    void RunLoop();

    struct WatchDir {
        std::string path;
        bool recursive;
    };
    std::vector<WatchDir> dirs_;
    FileChangeHandler handler_;
    std::thread thread_;
    std::atomic<bool> running_{false};
    int poll_interval_ms_ = 500;

    // Opaque backend state (inotify fd / snapshot map), defined in the .cpp.
    struct Impl;
    Impl* impl_ = nullptr;
};

}  // namespace sentinel

#endif  // SENTINEL_PLATFORM_FILE_WATCHER_H
