#include "sentinel/service/watchdog.h"

#include <chrono>

#include "sentinel/core/logging.h"

namespace sentinel {

Watchdog::Watchdog(LivenessCheck check, OnFailure on_failure, int interval_ms)
    : check_(std::move(check)), on_failure_(std::move(on_failure)),
      interval_ms_(interval_ms) {}

Watchdog::~Watchdog() { Stop(); }

void Watchdog::Start() {
    if (running_.exchange(true)) return;
    thread_ = std::thread([this] { Loop(); });
}

void Watchdog::Stop() {
    if (!running_.exchange(false)) return;
    if (thread_.joinable()) thread_.join();
}

void Watchdog::Loop() {
    while (running_.load()) {
        bool healthy = true;
        if (check_) {
            try {
                healthy = check_();
            } catch (...) {
                healthy = false;
            }
        }
        if (!healthy) {
            failures_.fetch_add(1);
            SENTINEL_LOG(Warn) << "watchdog: liveness check failed; recovering";
            if (on_failure_) on_failure_();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(interval_ms_));
    }
}

}  // namespace sentinel
