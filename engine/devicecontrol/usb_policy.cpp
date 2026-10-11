#include "sentinel/devicecontrol/usb_policy.h"

#include <algorithm>
#include <cstdint>
#include <string>

#include "sentinel/core/result.h"

namespace sentinel {
namespace {

// DLP thresholds for a short observation window. These are deliberately coarse:
// the goal is to flag bulk staging to removable media / the network, not to
// account for every byte. Tune per deployment; the scaling below degrades
// gracefully for movements that only slightly exceed them.
constexpr std::uint64_t kWindowByteThreshold = 100ull * 1024 * 1024;  // 100 MB
constexpr int kWindowFileThreshold = 200;                             // many files

// Map "how far past the threshold" onto a bounded confidence contribution. At
// the threshold a dimension contributes the mid-band floor; it climbs to the
// ceiling once movement reaches ~2x the threshold, then saturates.
double ExcessConfidence(double ratio) {
    if (ratio <= 1.0) return 0.0;
    constexpr double kFloor = 0.35;  // mid band as soon as a threshold is passed
    constexpr double kSpan = 0.15;   // additional weight for gross overage
    return kFloor + kSpan * std::min(1.0, ratio - 1.0);
}

}  // namespace

DeviceDecision UsbPolicy::Evaluate(const RemovableDevice& device) const {
    DeviceDecision decision;

    // Blocklist wins over everything: a device explicitly denied is never
    // mounted, so there is nothing to scan on insert.
    if (blocked_serials_.count(device.serial) != 0) {
        decision.policy = DevicePolicy::Block;
        decision.scan_on_insert = false;
        decision.reason = "device serial '" + device.serial +
                          "' is on the block list";
        return decision;
    }

    // Allowlisted corporate media is trusted: mount read/write and skip the
    // insert scan for throughput (it has already been vetted).
    if (allowed_serials_.count(device.serial) != 0) {
        decision.policy = DevicePolicy::MountReadWrite;
        decision.scan_on_insert = false;
        decision.reason = "device serial '" + device.serial +
                          "' is corporate-approved (read/write)";
        return decision;
    }

    // Unknown device: apply the configured default and always scan on insert so
    // nothing executes off untrusted media before it has been examined.
    decision.policy = default_policy_;
    decision.scan_on_insert = true;
    decision.reason = "unknown device serial '" + device.serial +
                      "'; applying default policy and scanning on insert";
    return decision;
}

Signal UsbPolicy::AssessDataMovement(std::uint64_t bytes_moved,
                                     std::uint64_t window_bytes,
                                     int files_in_window) const {
    // Aggregate the in-flight movement with the recent window so a burst split
    // across many small operations is judged on its total footprint.
    const std::uint64_t total_bytes = bytes_moved + window_bytes;
    const int files = files_in_window < 0 ? 0 : files_in_window;

    const double byte_ratio =
        static_cast<double>(total_bytes) /
        static_cast<double>(kWindowByteThreshold);
    const double file_ratio =
        static_cast<double>(files) / static_cast<double>(kWindowFileThreshold);

    const double byte_conf = ExcessConfidence(byte_ratio);
    const double file_conf = ExcessConfidence(file_ratio);
    const bool bytes_exceeded = byte_conf > 0.0;
    const bool files_exceeded = file_conf > 0.0;

    if (!bytes_exceeded && !files_exceeded) {
        // Within normal thresholds: emit a benign, low-confidence signal so the
        // caller still has a record of the movement having been assessed.
        return Signal(
            SignalSource::DeviceControl, RiskLevel::Unknown, 0.05,
            "data movement within normal thresholds (" +
                std::to_string(total_bytes) + " bytes across " +
                std::to_string(files) + " files)",
            "devicecontrol.data_movement_normal");
    }

    // Suspicious mid band for a single tripped dimension; the two contributions
    // add, so movement that is both large and spread across many files lands
    // high — the classic bulk-exfiltration staging pattern.
    double confidence = byte_conf + file_conf;
    confidence = std::min(confidence, 0.98);

    std::string detail = "possible exfiltration: " +
                         std::to_string(total_bytes) + " bytes across " +
                         std::to_string(files) + " files in window";
    if (bytes_exceeded && files_exceeded) {
        detail += " (both volume and file-count thresholds exceeded)";
    } else if (bytes_exceeded) {
        detail += " (volume threshold exceeded)";
    } else {
        detail += " (file-count threshold exceeded)";
    }

    return Signal(SignalSource::DeviceControl, RiskLevel::Suspicious, confidence,
                  std::move(detail), "devicecontrol.data_exfiltration");
}

}  // namespace sentinel
