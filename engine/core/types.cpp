#include "sentinel/core/types.h"

namespace sentinel {

const char* ToString(RiskLevel level) noexcept {
    switch (level) {
        case RiskLevel::Trusted: return "Trusted";
        case RiskLevel::Unknown: return "Unknown";
        case RiskLevel::LowRisk: return "LowRisk";
        case RiskLevel::Suspicious: return "Suspicious";
        case RiskLevel::Malicious: return "Malicious";
    }
    return "Unknown";
}

const char* ToString(Action action) noexcept {
    switch (action) {
        case Action::Allow: return "Allow";
        case Action::MonitorClosely: return "MonitorClosely";
        case Action::HoldInShadow: return "HoldInShadow";
        case Action::Block: return "Block";
        case Action::KillAndRollback: return "KillAndRollback";
    }
    return "Allow";
}

const char* ToString(SignalSource source) noexcept {
    switch (source) {
        case SignalSource::HashLookup: return "HashLookup";
        case SignalSource::YaraRule: return "YaraRule";
        case SignalSource::PeHeuristic: return "PeHeuristic";
        case SignalSource::Behavioral: return "Behavioral";
        case SignalSource::Ransomware: return "Ransomware";
        case SignalSource::Injection: return "Injection";
        case SignalSource::ScriptIntent: return "ScriptIntent";
        case SignalSource::MlModel: return "MlModel";
        case SignalSource::Network: return "Network";
        case SignalSource::Reputation: return "Reputation";
        case SignalSource::MemoryScan: return "MemoryScan";
        case SignalSource::ExploitGuard: return "ExploitGuard";
        case SignalSource::LsassGuard: return "LsassGuard";
        case SignalSource::Rootkit: return "Rootkit";
        case SignalSource::Deception: return "Deception";
        case SignalSource::DeviceControl: return "DeviceControl";
        case SignalSource::Sandbox: return "Sandbox";
        case SignalSource::Elam: return "Elam";
        case SignalSource::DriverBlock: return "DriverBlock";
        case SignalSource::Amsi: return "Amsi";
        case SignalSource::Manual: return "Manual";
    }
    return "Manual";
}

}  // namespace sentinel
