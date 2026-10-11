#include "sentinel/memory/lsass_guard.h"

#include <cctype>
#include <string>

#include "sentinel/core/types.h"

namespace sentinel {
namespace {

// Windows process access-rights bits that matter for credential theft. Defined
// locally because they are Win32 constants, not portable concepts, and we do
// not (and cannot) include <windows.h> in this portable user-mode engine.
constexpr std::uint32_t PROCESS_VM_READ = 0x0010;           // read target memory
constexpr std::uint32_t PROCESS_QUERY_INFORMATION = 0x0400;  // query token/handles

// The access a Mimikatz-style dumper needs to read LSASS credentials: the right
// to read its virtual memory, optionally paired with querying its information.
constexpr std::uint32_t kDangerousAccess =
    PROCESS_VM_READ | PROCESS_QUERY_INFORMATION;

// Take the final path component and lowercase it so that a full image path and
// a bare file name compare equal, and so comparison is case-insensitive. Splits
// on both separators because image paths here are Windows-style ("\\") but may
// arrive POSIX-style ("/").
std::string LowerBasename(const std::string& path) {
    const std::size_t pos = path.find_last_of("/\\");
    std::string base = (pos == std::string::npos) ? path : path.substr(pos + 1);
    for (char& c : base) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return base;
}

}  // namespace

LsassGuard::LsassGuard() {
    // Default policy: protect the Windows credential store.
    ProtectImage("lsass.exe");

    // Known-legitimate readers of protected processes: core OS components that
    // routinely open handles to system processes, the platform AV engine, and
    // this product's own service. Everything else reaching for LSASS memory is
    // treated as a credential-theft attempt.
    AllowReader("wininit.exe");       // early-init system process
    AllowReader("csrss.exe");         // client/server runtime subsystem
    AllowReader("services.exe");      // service control manager
    AllowReader("lsass.exe");         // the protected process itself
    AllowReader("MsMpEng.exe");       // Microsoft Defender engine
    AllowReader("sentinel-svc.exe");  // Sentinel's own service
}

void LsassGuard::AllowReader(const std::string& image_basename) {
    // Store normalized so Evaluate can compare case-insensitively by basename.
    allowed_readers_.insert(LowerBasename(image_basename));
}

void LsassGuard::ProtectImage(const std::string& image_basename) {
    protected_images_.insert(LowerBasename(image_basename));
}

HandleDecision LsassGuard::Evaluate(const HandleRequest& req) const {
    HandleDecision decision;

    const std::string target = LowerBasename(req.target_image);
    const std::string source = LowerBasename(req.source_image);

    const bool target_protected = protected_images_.count(target) != 0;
    const bool source_allowed = allowed_readers_.count(source) != 0;
    const std::uint32_t dangerous = req.desired_access & kDangerousAccess;

    if (target_protected && !source_allowed && dangerous != 0) {
        // An unapproved process is reaching into a protected credential store
        // with memory-read access: the Mimikatz-family dumping pattern. Deny the
        // read bits and raise a severe signal.
        decision.deny = true;
        decision.stripped_access = dangerous;
        decision.signal = Signal(
            SignalSource::LsassGuard, RiskLevel::Malicious, 0.95,
            "credential-theft attempt: '" + req.source_image +
                "' requested memory-read access to protected process '" +
                req.target_image + "'",
            "lsass_guard.credential_theft");
        return decision;
    }

    // Allowed path: not a protected target, an approved reader, or a benign
    // (non-read) access. Permit it and emit a benign, explanatory signal.
    decision.deny = false;
    decision.stripped_access = 0;
    if (target_protected && source_allowed) {
        decision.signal = Signal(
            SignalSource::LsassGuard, RiskLevel::Trusted, 0.60,
            "allowed reader '" + req.source_image +
                "' opened protected process '" + req.target_image + "'",
            "lsass_guard.allowed_reader");
    } else if (target_protected) {
        decision.signal = Signal(
            SignalSource::LsassGuard, RiskLevel::Unknown, 0.0,
            "benign handle to protected process '" + req.target_image +
                "' (no memory-read access requested)",
            "lsass_guard.benign_access");
    } else {
        decision.signal = Signal(
            SignalSource::LsassGuard, RiskLevel::Unknown, 0.0,
            "target '" + req.target_image + "' is not a protected credential store",
            "lsass_guard.not_protected");
    }
    return decision;
}

}  // namespace sentinel
