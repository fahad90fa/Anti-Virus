// Recovery and remediation. Removing the file is rarely enough, because malware
// leaves persistence and damage behind. Remediation walks the threat's recorded
// action graph and undoes it: delete dropped files, remove persistence (Run
// keys, services, scheduled tasks), restore modified settings, and — where the
// rollback gate was engaged — discard the staged changes.
#ifndef SENTINEL_QUARANTINE_REMEDIATOR_H
#define SENTINEL_QUARANTINE_REMEDIATOR_H

#include <functional>
#include <string>
#include <vector>

#include "sentinel/behavior/action_graph.h"
#include "sentinel/core/result.h"

namespace sentinel {

enum class RemediationKind {
    DeleteDroppedFile,
    RemovePersistence,
    RestoreSetting,
    DiscardShadow,
    QuarantineFile,
};

struct RemediationStep {
    RemediationKind kind;
    std::string target;
    bool applied = false;
    std::string note;
};

struct RemediationPlan {
    std::uint32_t pid = 0;
    std::vector<RemediationStep> steps;
};

// Hooks that actually perform side-effecting remediation, injected for testing.
struct RemediationHooks {
    std::function<bool(const std::string& path)> delete_file;
    std::function<bool(const std::string& key)> remove_persistence;
    std::function<bool(const std::string& setting)> restore_setting;
    std::function<bool(std::uint32_t pid)> discard_shadow;
    std::function<bool(const std::string& path, const std::string& reason)> quarantine;
};

class Remediator {
public:
    // Build a remediation plan from a process node's recorded actions.
    RemediationPlan Plan(const ProcessNode& node) const;

    // Execute a plan via the hooks. Steps with no hook are marked not-applied.
    Status Execute(RemediationPlan& plan, const RemediationHooks& hooks) const;
};

}  // namespace sentinel

#endif  // SENTINEL_QUARANTINE_REMEDIATOR_H
