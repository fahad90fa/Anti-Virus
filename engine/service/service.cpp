#include "sentinel/service/service.h"

#include <chrono>
#include <thread>

#include "sentinel/core/logging.h"

namespace sentinel {

Service::Service(const Config& config)
    : config_(config), engine_(std::make_unique<Engine>(config)),
      watcher_(std::make_unique<FileWatcher>()) {}

Service::~Service() { Stop(); }

Status Service::Initialize() { return engine_->Initialize(); }

void Service::OnFileChange(const FileChange& change) {
    // The Phase 0 user-mode stand-in for the minifilter: a new or changed file
    // is scanned as soon as the watcher reports it.
    FileScanResult r = engine_->ScanFile(change.path);
    files_scanned_.fetch_add(1);
    if (r.verdict.BlocksExecution() || r.verdict.IsMalicious()) {
        threats_blocked_.fetch_add(1);
        SENTINEL_LOG(Warn) << "THREAT " << ToString(r.verdict.level) << " ["
                           << ToString(r.verdict.action) << "] " << change.path
                           << " :: " << r.verdict.summary
                           << (r.quarantined ? " (quarantined)" : "");
    } else {
        SENTINEL_LOG(Debug) << "clean " << change.path;
    }
}

Status Service::Run(const std::vector<std::string>& watch_dirs, bool recursive) {
    for (const auto& d : watch_dirs) {
        Status s = watcher_->AddDirectory(d, recursive);
        if (!s.ok()) {
            SENTINEL_LOG(Warn) << "cannot watch " << d << ": " << s.message();
        } else {
            SENTINEL_LOG(Info) << "watching " << d << (recursive ? " (recursive)" : "");
        }
    }

    Status s = watcher_->Start([this](const FileChange& c) { OnFileChange(c); });
    if (!s.ok()) return s;

    running_.store(true);
    SENTINEL_LOG(Info) << "Sentinel service running. Real-time protection on.";
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    watcher_->Stop();
    SENTINEL_LOG(Info) << "Sentinel service stopped.";
    return Status::Ok();
}

void Service::Stop() {
    running_.store(false);
    if (watcher_) watcher_->Stop();
}

}  // namespace sentinel
