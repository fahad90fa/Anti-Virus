// Device control and data-loss prevention. Enforce policy on removable media
// (USB drives, external disks): block or mount read-only unknown devices, scan
// on insertion, and pair with the network layer to flag large or unusual data
// movements as possible exfiltration. This module holds the policy and the
// scan-on-insert decision; the kernel device driver enforces mount options.
#ifndef SENTINEL_DEVICECONTROL_USB_POLICY_H
#define SENTINEL_DEVICECONTROL_USB_POLICY_H

#include <cstdint>
#include <string>
#include <unordered_set>
#include <vector>

#include "sentinel/core/types.h"

namespace sentinel {

enum class DevicePolicy { Block, MountReadOnly, MountReadWrite };

struct RemovableDevice {
    std::string serial;        // hardware serial / instance id
    std::string vendor;
    std::string product;
    std::uint64_t capacity_bytes = 0;
};

struct DeviceDecision {
    DevicePolicy policy = DevicePolicy::MountReadOnly;
    bool scan_on_insert = true;
    std::string reason;
};

class UsbPolicy {
public:
    // Default policy applied to unknown devices (default: MountReadOnly).
    void SetDefault(DevicePolicy policy) { default_policy_ = policy; }

    // Allowlist a device by serial (corporate-approved media => read/write).
    void Allow(const std::string& serial) { allowed_serials_.insert(serial); }
    // Blocklist a device by serial.
    void Block(const std::string& serial) { blocked_serials_.insert(serial); }

    DeviceDecision Evaluate(const RemovableDevice& device) const;

    // DLP: assess a data movement to removable media / network as possible
    // exfiltration, given bytes moved and a short window of prior movement.
    Signal AssessDataMovement(std::uint64_t bytes_moved,
                              std::uint64_t window_bytes,
                              int files_in_window) const;

private:
    DevicePolicy default_policy_ = DevicePolicy::MountReadOnly;
    std::unordered_set<std::string> allowed_serials_;
    std::unordered_set<std::string> blocked_serials_;
};

}  // namespace sentinel

#endif  // SENTINEL_DEVICECONTROL_USB_POLICY_H
