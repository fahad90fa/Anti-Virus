// Mutual watchdog. Two components watch each other: the kernel driver watches
// the service, and this secondary guard watches the driver/service. If one is
// killed, the other restarts it and raises an alert. This portable core runs a
// liveness check on an interval and invokes a restart callback on failure; the
// kernel half lives in the drivers.
#ifndef SENTINEL_SERVICE_WATCHDOG_H
#define SENTINEL_SERVICE_WATCHDOG_H

#include <atomic>
#include <functional>
#include <thread>

namespace sentinel {

class Watchdog {
public:
    using LivenessCheck = std::function<bool()>;   // true = healthy
    using OnFailure = std::function<void()>;       // called when unhealthy

    Watchdog(LivenessCheck check, OnFailure on_failure, int interval_ms = 1000);
    ~Watchdog();

    void Start();
    void Stop();
    bool IsRunning() const { return running_.load(); }
    std::uint64_t failures() const { return failures_.load(); }

private:
    void Loop();

    LivenessCheck check_;
    OnFailure on_failure_;
    int interval_ms_;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<std::uint64_t> failures_{0};
};

}  // namespace sentinel

#endif  // SENTINEL_SERVICE_WATCHDOG_H
