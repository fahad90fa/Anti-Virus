// Micro-sandbox detonation. Drives the SENTVM emulator, maps the observed
// synthetic syscalls onto the behavioral action-graph model, scores the result,
// and surfaces the unpacked payload for a static re-scan by the caller. Packed
// zero-days reveal their real behavior here before any real execution is allowed.
#include "sentinel/sandbox/detonator.h"

#include "sentinel/behavior/action_graph.h"

namespace sentinel {
namespace {

double NoisyOr(const std::vector<Signal>& signals) {
    double inv = 1.0;
    for (const auto& s : signals) {
        double c = s.confidence;
        if (c < 0.0) c = 0.0;
        if (c > 1.0) c = 1.0;
        inv *= (1.0 - c);
    }
    return 1.0 - inv;
}

// Map an emulated syscall name to an action-graph event type. Returns false for
// syscalls that do not map to a tracked action.
bool MapSyscall(const std::string& name, ActionType& out) {
    if (name == "VirtualAlloc") { out = ActionType::MemoryAllocRemote; return true; }
    if (name == "WriteProcessMemory") { out = ActionType::MemoryWriteRemote; return true; }
    if (name == "CreateRemoteThread") { out = ActionType::RemoteThreadCreate; return true; }
    if (name == "WriteFile") { out = ActionType::FileWrite; return true; }
    if (name == "Connect") { out = ActionType::NetworkConnect; return true; }
    if (name == "RegSetValue") { out = ActionType::RegistryWrite; return true; }
    return false;
}

}  // namespace

DetonationReport Detonator::Detonate(const Bytes& program, int max_instructions) const {
    DetonationReport report;
    report.emulation = emulator_.Run(program, max_instructions);
    report.unpacked_payload = report.emulation.unpacked_payload;
    report.payload_revealed = !report.unpacked_payload.empty();

    // Map observed syscalls onto the action-graph model and tally the injection
    // chain + file-write storm.
    bool alloc = false, write_mem = false, remote_thread = false;
    int file_writes = 0, net_connects = 0;
    std::uint64_t ts = 0;
    for (const auto& sc : report.emulation.syscalls) {
        ActionType type;
        if (!MapSyscall(sc.name, type)) continue;
        ActivityEvent ev;
        ev.type = type;
        ev.timestamp_ms = ts++;
        ev.target = sc.name;
        report.observed_actions.push_back(ev);
        switch (type) {
            case ActionType::MemoryAllocRemote: alloc = true; break;
            case ActionType::MemoryWriteRemote: write_mem = true; break;
            case ActionType::RemoteThreadCreate: remote_thread = true; break;
            case ActionType::FileWrite: ++file_writes; break;
            case ActionType::NetworkConnect: ++net_connects; break;
            default: break;
        }
    }

    // Injection chain: allocate -> write -> create remote thread.
    const int stages = (alloc ? 1 : 0) + (write_mem ? 1 : 0) + (remote_thread ? 1 : 0);
    if (stages >= 3) {
        report.signals.emplace_back(SignalSource::Injection, RiskLevel::Malicious, 0.9,
                                    "full allocate-write-execute chain in sandbox");
    } else if (stages == 2) {
        report.signals.emplace_back(SignalSource::Injection, RiskLevel::Suspicious, 0.6,
                                    "partial injection chain in sandbox");
    }

    // File-write storm (ransomware-like) observed under detonation.
    if (file_writes >= 10) {
        report.signals.emplace_back(SignalSource::Ransomware, RiskLevel::Suspicious, 0.6,
                                    "many file writes under detonation");
    }
    if (net_connects > 0 && (alloc || file_writes > 0)) {
        report.signals.emplace_back(SignalSource::Network, RiskLevel::LowRisk, 0.35,
                                    "network contact paired with local activity");
    }

    // A revealed (unpacked) payload is itself worth flagging for a static re-scan.
    if (report.payload_revealed) {
        report.signals.emplace_back(SignalSource::Sandbox, RiskLevel::LowRisk, 0.3,
                                    "packer stub revealed a hidden payload");
    }

    report.score = NoisyOr(report.signals);
    return report;
}

}  // namespace sentinel
