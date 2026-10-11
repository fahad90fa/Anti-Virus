// Sentinel AV — core verdict and risk model.
//
// Every layer in the engine (static scan, behavioral, network, reputation)
// produces signals that the verdict-fusion stage combines into a single
// RiskLevel and a single Action. These types are the shared vocabulary that
// all layers and the IPC protocol speak.
#ifndef SENTINEL_CORE_TYPES_H
#define SENTINEL_CORE_TYPES_H

#include <cstdint>
#include <string>
#include <vector>

namespace sentinel {

// Risk class of a subject (file or process), ordered from safe to hostile.
// The rollback gate routes only Unknown/Suspicious subjects through shadow
// staging; Trusted writes go straight to disk at zero overhead.
enum class RiskLevel : std::uint8_t {
    Trusted = 0,     // known-good: signed Windows/vendor binary or allowlisted
    Unknown = 1,     // never seen; no strong signal either way
    LowRisk = 2,     // mildly suspicious traits, below action threshold
    Suspicious = 3,  // multiple corroborating weak signals
    Malicious = 4,   // convicted by a strong or fused signal
};

// What the engine decides to do with a subject. Ordered by severity.
enum class Action : std::uint8_t {
    Allow = 0,          // let it run / let the I/O complete
    MonitorClosely = 1, // allow but raise behavioral sampling
    HoldInShadow = 2,   // run gated: writes go to the copy-on-write shadow
    Block = 3,          // deny the operation (do not execute / fail the I/O)
    KillAndRollback = 4 // terminate and discard all shadow-staged effects
};

// Which detection layer produced a signal. Used for fusion weighting and for
// explaining a verdict to the user.
enum class SignalSource : std::uint8_t {
    HashLookup = 0,
    YaraRule = 1,
    PeHeuristic = 2,
    Behavioral = 3,
    Ransomware = 4,
    Injection = 5,
    ScriptIntent = 6,
    MlModel = 7,
    Network = 8,
    Reputation = 9,
    MemoryScan = 10,
    ExploitGuard = 11,
    LsassGuard = 12,
    Rootkit = 13,
    Deception = 14,
    DeviceControl = 15,
    Sandbox = 16,
    Elam = 17,
    DriverBlock = 18,
    Amsi = 19,
    Manual = 20,
};

const char* ToString(RiskLevel level) noexcept;
const char* ToString(Action action) noexcept;
const char* ToString(SignalSource source) noexcept;

// A single piece of evidence from one layer. Fusion combines many of these.
struct Signal {
    SignalSource source = SignalSource::Manual;
    RiskLevel level = RiskLevel::Unknown;
    // Confidence in [0,1]. Weak-but-corroborating signals convict together;
    // no single noisy signal should cause a false positive on its own.
    double confidence = 0.0;
    std::string detail;   // human-readable reason, e.g. "imports only LoadLibrary"
    std::string rule_id;  // optional: which rule/heuristic fired

    Signal() = default;
    Signal(SignalSource s, RiskLevel l, double c, std::string d, std::string r = {})
        : source(s), level(l), confidence(c), detail(std::move(d)), rule_id(std::move(r)) {}
};

// The fused outcome for a subject: the single risk level, the chosen action,
// an aggregate score in [0,1], and the signals that produced it.
struct Verdict {
    RiskLevel level = RiskLevel::Unknown;
    Action action = Action::Allow;
    double score = 0.0;  // fused malice score in [0,1]
    std::vector<Signal> signals;
    std::string summary; // one-line explanation for the UI/timeline

    bool IsMalicious() const noexcept { return level == RiskLevel::Malicious; }
    bool BlocksExecution() const noexcept {
        return action == Action::Block || action == Action::KillAndRollback;
    }
};

// Identifies the kind of subject under evaluation.
enum class SubjectKind : std::uint8_t {
    File = 0,
    Process = 1,
    Script = 2,
    Driver = 3,
    Connection = 4,
    MemoryRegion = 5,
    Device = 6,
};

}  // namespace sentinel

#endif  // SENTINEL_CORE_TYPES_H
