#include "sentinel/scan/hash_store.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <utility>

#include "sentinel/core/fs.h"
#include "sentinel/core/logging.h"

namespace sentinel {

std::string HashStore::Normalize(const std::string& hex) {
    // Trim surrounding whitespace, then lowercase so lookups are canonical
    // regardless of how the signature file or caller cased/spaced the hash.
    std::size_t start = 0;
    std::size_t end = hex.size();
    while (start < end &&
           std::isspace(static_cast<unsigned char>(hex[start]))) {
        ++start;
    }
    while (end > start &&
           std::isspace(static_cast<unsigned char>(hex[end - 1]))) {
        --end;
    }
    std::string out = hex.substr(start, end - start);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return out;
}

namespace {

// Trim leading and trailing ASCII whitespace from a label.
std::string TrimLabel(const std::string& in) {
    const char* ws = " \t\r\n\f\v";
    std::size_t b = in.find_first_not_of(ws);
    if (b == std::string::npos) return std::string();
    std::size_t e = in.find_last_not_of(ws);
    return in.substr(b, e - b + 1);
}

}  // namespace

Status HashStore::LoadAllowlist(const std::string& path) {
    // A missing allowlist is normal (fresh install) — not an error.
    if (!PathExists(path)) {
        return Status::Ok();
    }
    std::ifstream in(path);
    if (!in) {
        return Status::Error(ErrorCode::IoError,
                             "cannot open allowlist: " + path);
    }
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string token;
        if (!(iss >> token)) continue;        // blank / whitespace-only line
        if (token[0] == '#') continue;         // comment line
        allowed_.insert(Normalize(token));
    }
    return Status::Ok();
}

Status HashStore::LoadBlocklist(const std::string& path) {
    if (!PathExists(path)) {
        return Status::Ok();
    }
    std::ifstream in(path);
    if (!in) {
        return Status::Error(ErrorCode::IoError,
                             "cannot open blocklist: " + path);
    }
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string token;
        if (!(iss >> token)) continue;        // blank line
        if (token[0] == '#') continue;         // comment line
        // Everything after the hash token is the (optional) family label.
        std::string rest;
        std::getline(iss, rest);
        blocked_[Normalize(token)] = TrimLabel(rest);
    }
    return Status::Ok();
}

void HashStore::AddAllowed(const std::string& sha256_hex, std::string label) {
    (void)label;  // the allowlist is a set; labels are not retained
    allowed_.insert(Normalize(sha256_hex));
}

void HashStore::AddBlocked(const std::string& sha256_hex, std::string label) {
    blocked_[Normalize(sha256_hex)] = std::move(label);
}

HashVerdict HashStore::Lookup(const std::string& sha256_hex) const {
    const std::string key = Normalize(sha256_hex);
    // Allowlist wins ties: a hash marked good is never treated as bad.
    if (allowed_.find(key) != allowed_.end()) return HashVerdict::Allowed;
    if (blocked_.find(key) != blocked_.end()) return HashVerdict::Blocked;
    return HashVerdict::Unknown;
}

std::string HashStore::BlockedLabel(const std::string& sha256_hex) const {
    auto it = blocked_.find(Normalize(sha256_hex));
    if (it == blocked_.end()) return std::string();
    return it->second;
}

}  // namespace sentinel
