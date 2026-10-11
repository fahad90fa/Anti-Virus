#include "sentinel/platform/file_watcher.h"

#include <chrono>
#include <filesystem>
#include <map>
#include <system_error>

#include "sentinel/core/logging.h"

namespace fs = std::filesystem;

namespace sentinel {

// Portable polling backend. Native event-driven backends (inotify on Linux,
// ReadDirectoryChangesW on Windows) can be slotted in behind the same Impl
// without changing callers; polling is correct everywhere and keeps the Phase 0
// pipeline testable in CI.
struct FileWatcher::Impl {
    std::map<std::string, std::filesystem::file_time_type> seen;
};

FileWatcher::FileWatcher() : impl_(new Impl()) {}

FileWatcher::~FileWatcher() {
    Stop();
    delete impl_;
}

Status FileWatcher::AddDirectory(const std::string& dir, bool recursive) {
    if (!fs::is_directory(dir)) {
        return Status::Error(ErrorCode::NotFound, "not a directory: " + dir);
    }
    dirs_.push_back({dir, recursive});
    return Status::Ok();
}

Status FileWatcher::Start(FileChangeHandler handler) {
    if (running_.load()) {
        return Status::Error(ErrorCode::AlreadyExists, "watcher already running");
    }
    if (dirs_.empty()) {
        return Status::Error(ErrorCode::InvalidArgument, "no directories to watch");
    }
    handler_ = std::move(handler);

    // Prime the "seen" snapshot so pre-existing files are not reported as new.
    std::error_code ec;
    for (const auto& d : dirs_) {
        if (d.recursive) {
            for (auto it = fs::recursive_directory_iterator(
                     d.path, fs::directory_options::skip_permission_denied, ec);
                 it != fs::recursive_directory_iterator(); it.increment(ec)) {
                if (ec) break;
                if (it->is_regular_file(ec)) {
                    impl_->seen[it->path().string()] = it->last_write_time(ec);
                }
            }
        } else {
            for (auto it = fs::directory_iterator(
                     d.path, fs::directory_options::skip_permission_denied, ec);
                 it != fs::directory_iterator(); it.increment(ec)) {
                if (ec) break;
                if (it->is_regular_file(ec)) {
                    impl_->seen[it->path().string()] = it->last_write_time(ec);
                }
            }
        }
    }

    running_.store(true);
    thread_ = std::thread([this] { RunLoop(); });
    return Status::Ok();
}

void FileWatcher::Stop() {
    if (!running_.exchange(false)) return;
    if (thread_.joinable()) thread_.join();
}

void FileWatcher::RunLoop() {
    while (running_.load()) {
        std::error_code ec;
        for (const auto& d : dirs_) {
            auto scan_one = [&](const fs::directory_entry& entry) {
                if (!entry.is_regular_file(ec)) return;
                const std::string p = entry.path().string();
                const auto mtime = entry.last_write_time(ec);
                if (ec) return;
                auto found = impl_->seen.find(p);
                if (found == impl_->seen.end()) {
                    impl_->seen[p] = mtime;
                    if (handler_) handler_({p, FileChangeKind::Created});
                } else if (found->second != mtime) {
                    found->second = mtime;
                    if (handler_) handler_({p, FileChangeKind::Modified});
                }
            };

            if (d.recursive) {
                for (auto it = fs::recursive_directory_iterator(
                         d.path, fs::directory_options::skip_permission_denied, ec);
                     it != fs::recursive_directory_iterator(); it.increment(ec)) {
                    if (ec) break;
                    scan_one(*it);
                }
            } else {
                for (auto it = fs::directory_iterator(
                         d.path, fs::directory_options::skip_permission_denied, ec);
                     it != fs::directory_iterator(); it.increment(ec)) {
                    if (ec) break;
                    scan_one(*it);
                }
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(poll_interval_ms_));
    }
}

}  // namespace sentinel
