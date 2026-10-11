// Forensic kill-chain timeline. Holds an in-memory event list and, when opened
// with a path, mirrors every event into a tamper-evident SecureLog so the chain
// of events survives and stays verifiable. See timeline.h for the contract.
#include "sentinel/edr/timeline.h"

#include <algorithm>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#include "sentinel/core/logging.h"

namespace sentinel {
namespace {

// Flatten an event into a single stable line for the sealed log. The SecureLog
// escapes any control characters, so arbitrary actor/description text is safe.
std::string SerializeEvent(const TimelineEvent& ev) {
    std::ostringstream os;
    os << "ts=" << ev.timestamp_ms
       << " pid=" << ev.pid
       << " sev=" << ToString(ev.severity)
       << " cat=" << ev.category
       << " actor=" << ev.actor
       << " desc=" << ev.description;
    return os.str();
}

}  // namespace

// PIMPL: the memory buffer, the optional sealed log, and a per-instance mutex
// that the frozen header cannot hold.
struct Timeline::Impl {
    mutable std::mutex mutex;
    std::vector<TimelineEvent> events;
    SecureLog log;
    bool log_open = false;
};

Timeline::Timeline() : impl_(std::make_unique<Impl>()) {}
Timeline::~Timeline() = default;

Status Timeline::Open(const std::string& sealed_log_path) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    const Status s = impl_->log.Open(sealed_log_path);
    // Only treat the log as backing storage if it opened cleanly; a corrupt or
    // unwritable log must not silently swallow events.
    impl_->log_open = s.ok();
    return s;
}

void Timeline::Record(const TimelineEvent& event) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->events.push_back(event);
    if (impl_->log_open) {
        const Status s =
            impl_->log.Append("timeline", SerializeEvent(event), event.timestamp_ms);
        if (!s.ok()) {
            // Sealing failed: the in-memory copy is still kept, but warn loudly
            // because the forensic guarantee is degraded.
            SENTINEL_LOG(Warn) << "timeline: failed to seal event: " << s.message();
        }
    }
}

void Timeline::RecordDetection(std::uint32_t pid, const std::string& actor,
                               const Verdict& verdict, std::uint64_t timestamp_ms) {
    TimelineEvent ev;
    ev.timestamp_ms = timestamp_ms;
    ev.pid = pid;
    ev.actor = actor;
    ev.category = "detection";
    ev.severity = verdict.level;  // the detection's severity is the fused level

    std::ostringstream os;
    os << (verdict.summary.empty() ? "threat detected" : verdict.summary)
       << " [level=" << ToString(verdict.level)
       << " action=" << ToString(verdict.action)
       << " score=" << verdict.score << "]";
    ev.description = os.str();

    // Record() takes the lock and seals the event; do not lock here to avoid a
    // self-deadlock on the non-recursive mutex.
    Record(ev);
}

std::vector<TimelineEvent> Timeline::ChainForPid(std::uint32_t pid) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    std::vector<TimelineEvent> chain;
    for (const auto& ev : impl_->events) {
        if (ev.pid == pid) chain.push_back(ev);
    }
    // Reconstruct in time order, newest last. Stable so same-timestamp events
    // keep their original recording order.
    std::stable_sort(chain.begin(), chain.end(),
                     [](const TimelineEvent& a, const TimelineEvent& b) {
                         return a.timestamp_ms < b.timestamp_ms;
                     });
    return chain;
}

std::vector<TimelineEvent> Timeline::All() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->events;
}

Status Timeline::VerifyIntegrity() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    // No backing log means nothing to falsify => integrity is trivially intact.
    if (!impl_->log_open) return Status::Ok();
    return impl_->log.Verify();
}

}  // namespace sentinel
