#include "sentinel/quarantine/remediator.h"

#include <set>
#include <string>

#include "sentinel/core/logging.h"

namespace sentinel {

RemediationPlan Remediator::Plan(const ProcessNode& node) const {
    RemediationPlan plan;
    plan.pid = node.pid;

    // Walk the recorded action graph and turn undo-able actions into steps. A
    // process can touch the same file or persistence key many times, so track
    // what has already been scheduled to avoid issuing redundant operations.
    std::set<std::string> dropped_seen;
    std::set<std::string> persistence_seen;

    for (const ActivityEvent& a : node.actions) {
        switch (a.type) {
            case ActionType::FileWrite:
                // Files the threat wrote are treated as dropped payloads.
                if (!a.target.empty() && dropped_seen.insert(a.target).second) {
                    RemediationStep s;
                    s.kind = RemediationKind::DeleteDroppedFile;
                    s.target = a.target;
                    plan.steps.push_back(std::move(s));
                }
                break;
            case ActionType::RegistryPersistence:
                // Run keys / services / boot entries that re-launch the threat.
                if (!a.target.empty() && persistence_seen.insert(a.target).second) {
                    RemediationStep s;
                    s.kind = RemediationKind::RemovePersistence;
                    s.target = a.target;
                    plan.steps.push_back(std::move(s));
                }
                break;
            default:
                // Other action types carry no undo in this plan.
                break;
        }
    }

    // Discard any staged copy-on-write layer for this process (perfect rollback
    // of its file writes where the shadow gate was engaged).
    {
        RemediationStep s;
        s.kind = RemediationKind::DiscardShadow;
        s.target = std::to_string(node.pid);
        plan.steps.push_back(std::move(s));
    }

    // Finally, move the convicted image itself into the quarantine vault.
    {
        RemediationStep s;
        s.kind = RemediationKind::QuarantineFile;
        s.target = node.image_path;
        plan.steps.push_back(std::move(s));
    }

    return plan;
}

Status Remediator::Execute(RemediationPlan& plan,
                           const RemediationHooks& hooks) const {
    for (RemediationStep& step : plan.steps) {
        switch (step.kind) {
            case RemediationKind::DeleteDroppedFile:
                if (hooks.delete_file) {
                    step.applied = hooks.delete_file(step.target);
                    step.note = step.applied ? "deleted dropped file"
                                             : "delete hook reported failure";
                } else {
                    step.applied = false;
                    step.note = "no hook";
                }
                break;
            case RemediationKind::RemovePersistence:
                if (hooks.remove_persistence) {
                    step.applied = hooks.remove_persistence(step.target);
                    step.note = step.applied ? "removed persistence"
                                             : "remove-persistence hook reported failure";
                } else {
                    step.applied = false;
                    step.note = "no hook";
                }
                break;
            case RemediationKind::RestoreSetting:
                if (hooks.restore_setting) {
                    step.applied = hooks.restore_setting(step.target);
                    step.note = step.applied ? "restored setting"
                                             : "restore-setting hook reported failure";
                } else {
                    step.applied = false;
                    step.note = "no hook";
                }
                break;
            case RemediationKind::DiscardShadow:
                if (hooks.discard_shadow) {
                    // The pid is authoritative here; target is only its string form.
                    step.applied = hooks.discard_shadow(plan.pid);
                    step.note = step.applied ? "discarded shadow layer"
                                             : "discard-shadow hook reported failure";
                } else {
                    step.applied = false;
                    step.note = "no hook";
                }
                break;
            case RemediationKind::QuarantineFile:
                if (hooks.quarantine) {
                    step.applied =
                        hooks.quarantine(step.target, "remediation: convicted image");
                    step.note = step.applied ? "quarantined image"
                                             : "quarantine hook reported failure";
                } else {
                    step.applied = false;
                    step.note = "no hook";
                }
                break;
        }
        SENTINEL_LOG(Debug) << "remediation step kind="
                            << static_cast<int>(step.kind)
                            << " target=" << step.target
                            << " applied=" << (step.applied ? "yes" : "no");
    }
    return Status::Ok();
}

}  // namespace sentinel
