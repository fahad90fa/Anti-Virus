#include "sentinel/deception/honeytokens.h"

#include <cstddef>

#include "sentinel/core/fs.h"
#include "sentinel/core/logging.h"
#include "sentinel/core/sha256.h"

namespace sentinel {
namespace {

// Innocuous, high-value-looking names an intruder enumerating a share or a
// user's documents would be tempted to open or exfiltrate. Legitimate software
// has no reason to read these, so a touch is a near-certain intruder.
const char* const kCanaryNames[] = {
    "Financial_Report_Q4.xlsx",
    "passwords.txt",
    "backup_keys.dat",
    "vpn_credentials.ovpn",
    "master_password.kdbx",
    "salaries_2024.xlsx",
    "ssh_id_rsa.pem",
    "customer_database.csv",
    "wallet.dat",
    "tax_return_2023.pdf",
};
constexpr std::size_t kCanaryNameCount =
    sizeof(kCanaryNames) / sizeof(kCanaryNames[0]);

// Derive a unique, unforgeable marker for a planted file. Keyed by the final
// path and an index so two files (even same name in different dirs) never share
// a marker; embedding it lets the watcher confirm a tripped token is really
// ours and not a coincidental same-named file.
std::string MakeMarker(const std::string& path, int index) {
    const std::string material =
        "sentinel-honeytoken-v1|" + path + "|" + std::to_string(index);
    const std::string hex = Sha256::HexDigest(material);
    // 32 hex chars (128 bits) is plenty to be unique and unguessable.
    return hex.substr(0, 32);
}

}  // namespace

Result<std::vector<std::string>> HoneytokenManager::PlantCanaryFiles(
    const std::string& dir, int count) {
    if (count <= 0) {
        return Status::Error(ErrorCode::InvalidArgument,
                             "canary count must be positive");
    }
    if (!MakeDirs(dir)) {
        return Status::Error(ErrorCode::IoError,
                             "cannot create canary directory: " + dir);
    }

    std::vector<std::string> planted;
    planted.reserve(static_cast<std::size_t>(count));

    for (int i = 0; i < count; ++i) {
        // Cycle through the name pool; once exhausted, suffix the index so the
        // name stays innocuous-looking yet unique on disk.
        const std::size_t name_idx = static_cast<std::size_t>(i) % kCanaryNameCount;
        std::string name = kCanaryNames[name_idx];
        if (static_cast<std::size_t>(i) >= kCanaryNameCount) {
            // Insert the disambiguator before the extension so it still reads
            // like a real document (e.g. "passwords_2.txt").
            const std::string ext = Extension(name);  // lowercased, includes dot
            if (!ext.empty() && name.size() > ext.size()) {
                name = name.substr(0, name.size() - ext.size()) + "_" +
                       std::to_string(i) + ext;
            } else {
                name += "_" + std::to_string(i);
            }
        }

        const std::string path = JoinPath(dir, name);
        const std::string marker = MakeMarker(path, i);

        // Plausible-looking content carrying the embedded marker. The marker is
        // the ground truth the watcher matches on.
        std::string content;
        content += "# Confidential - do not distribute\r\n";
        content += "# ref: ";
        content += marker;
        content += "\r\n";

        const Status st = WriteFileAtomic(path, content);
        if (!st) {
            // Report the failure rather than silently planting fewer tokens.
            return Status::Error(st.code(),
                                 "failed to plant canary '" + path +
                                     "': " + st.message());
        }

        Honeytoken token;
        token.kind = TokenKind::CanaryFile;
        token.identity = path;
        token.marker = marker;
        Register(token);

        planted.push_back(path);
    }

    SENTINEL_LOG(Info) << "planted " << planted.size()
                       << " canary files under " << dir;
    return planted;
}

void HoneytokenManager::Register(const Honeytoken& token) {
    tokens_.push_back(token);
}

bool HoneytokenManager::IsToken(const std::string& identity) const {
    for (const auto& t : tokens_) {
        if (t.identity == identity) return true;
    }
    return false;
}

Signal HoneytokenManager::OnAccess(const std::string& identity,
                                   std::uint32_t by_pid) const {
    // Any access to a honeytoken is, by construction, an intruder: no legitimate
    // workflow touches these. Emit a near-maximal-confidence conviction naming
    // the token and the offending pid. We stop just short of 1.0 so fusion can
    // still reason about corroboration and never treats any single source as
    // mathematically absolute.
    std::string detail = "honeytoken accessed: '" + identity + "' by pid " +
                         std::to_string(by_pid);

    // Confirm it against the registered set so the timeline records whether the
    // tripped path is a token we actually planted.
    if (IsToken(identity)) {
        detail += " (registered honeytoken)";
    }

    return Signal(SignalSource::Deception, RiskLevel::Malicious, 0.99,
                  std::move(detail), "deception.honeytoken_access");
}

}  // namespace sentinel
