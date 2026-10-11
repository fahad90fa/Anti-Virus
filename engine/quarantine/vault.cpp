#include "sentinel/quarantine/vault.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>

#include "sentinel/core/bytes.h"
#include "sentinel/core/fs.h"
#include "sentinel/core/logging.h"
#include "sentinel/core/sha256.h"

namespace fs = std::filesystem;

namespace sentinel {
namespace {

// Fixed salt mixed into the key derivation. In production the vault key is
// sealed by the trustlet; this software derivation is the documented portable
// placeholder so the stored blobs are still inert without the vault directory.
constexpr char kKeySalt[] = "sentinel-vault-key-salt-v1";
constexpr char kKeyFile[] = ".vaultkey";
constexpr char kIndexFile[] = "index.tsv";

int HexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Percent-encode the field-breaking characters so a path containing a tab or
// newline can round-trip through the TSV index without corrupting it.
std::string Encode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (c == '%' || c == '\t' || c == '\n' || c == '\r') {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%%%02X", c);
            out += buf;
        } else {
            out += static_cast<char>(c);
        }
    }
    return out;
}

std::string Decode(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            const int hi = HexVal(s[i + 1]);
            const int lo = HexVal(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out += static_cast<char>((hi << 4) | lo);
                i += 2;
                continue;
            }
        }
        out += s[i];
    }
    return out;
}

std::uint64_t ParseU64(const std::string& s) {
    // Defensive, exception-free parse; non-numeric input yields 0.
    return static_cast<std::uint64_t>(std::strtoull(s.c_str(), nullptr, 10));
}

}  // namespace

Status QuarantineVault::Open(const std::string& vault_dir) {
    vault_dir_ = vault_dir;
    if (!MakeDirs(vault_dir_)) {
        return Status::Error(ErrorCode::IoError,
                             "cannot create vault dir: " + vault_dir_);
    }
    index_path_ = JoinPath(vault_dir_, kIndexFile);

    const std::string key_path = JoinPath(vault_dir_, kKeyFile);
    if (!PathExists(key_path)) {
        // Derive a 32-byte key = SHA-256(vault_dir || salt). This is the
        // portable placeholder for a trustlet-sealed key.
        const std::string material = vault_dir_ + "|" + kKeySalt;
        const Sha256::Digest d = Sha256::Hash(
            reinterpret_cast<const std::uint8_t*>(material.data()),
            material.size());
        key_.assign(d.begin(), d.end());

        const Bytes kb(key_.begin(), key_.end());
        const Status st = WriteFileAtomic(key_path, kb);
        if (!st) return st;

        // Restrict to the owner (0600). Best-effort on platforms that honor it.
        std::error_code ec;
        fs::permissions(key_path,
                        fs::perms::owner_read | fs::perms::owner_write,
                        fs::perm_options::replace, ec);
    } else {
        auto r = ReadFile(key_path);
        if (!r) return r.status();
        key_.assign(r.value().begin(), r.value().end());
        if (key_.size() < Sha256::kDigestSize) {
            return Status::Error(ErrorCode::Corrupt, "vault key is truncated");
        }
    }

    SENTINEL_LOG(Debug) << "quarantine vault opened at " << vault_dir_;
    return Status::Ok();
}

void QuarantineVault::Keystream(const std::string& salt, std::size_t len,
                                std::vector<std::uint8_t>& out) const {
    out.clear();
    out.reserve(len);
    // Counter-mode KDF: block_i = SHA-256(key || salt || counter_be64).
    std::uint64_t counter = 0;
    while (out.size() < len) {
        Sha256 h;
        h.Update(key_.data(), key_.size());
        h.Update(reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size());
        std::uint8_t cb[8];
        for (int i = 0; i < 8; ++i) {
            cb[i] = static_cast<std::uint8_t>((counter >> (56 - 8 * i)) & 0xFF);
        }
        h.Update(cb, 8);
        const Sha256::Digest d = h.Final();

        const std::size_t take = std::min(len - out.size(), d.size());
        out.insert(out.end(), d.begin(), d.begin() + take);
        ++counter;
    }
}

Result<QuarantineEntry> QuarantineVault::Quarantine(const std::string& path,
                                                    const std::string& reason,
                                                    std::uint64_t timestamp_ms) {
    if (vault_dir_.empty()) {
        return Status::Error(ErrorCode::Internal, "vault not opened");
    }

    // Read the subject fully so the stored blob and recorded hash are exact.
    auto rd = ReadFile(path);
    if (!rd) return rd.status();
    const Bytes& data = rd.value();

    const std::string sha = Sha256::HexDigest(data);
    const std::uint64_t size = static_cast<std::uint64_t>(data.size());

    QuarantineEntry e;
    // Content-derived id: first 16 hex of the hash plus the size keeps distinct
    // files apart even on a partial-hash prefix collision.
    e.id = sha.substr(0, 16) + std::to_string(size);
    e.original_path = path;
    e.detection_reason = reason;
    e.sha256 = sha;
    e.original_size = size;
    e.quarantined_at_ms = timestamp_ms;
    e.stored_file = e.id + ".q";

    // Neutralize: XOR the body with a per-entry keystream so the stored bytes
    // are inert and unreadable without the vault key.
    std::vector<std::uint8_t> ks;
    Keystream(e.id, data.size(), ks);
    Bytes blob(data.size());
    for (std::size_t i = 0; i < data.size(); ++i) {
        blob[i] = static_cast<std::uint8_t>(data[i] ^ ks[i]);
    }

    const std::string blob_path = JoinPath(vault_dir_, e.stored_file);
    const Status wst = WriteFileAtomic(blob_path, blob);
    if (!wst) return wst;

    // Append to the index, replacing any prior entry with the same id.
    std::vector<QuarantineEntry> entries;
    LoadIndex(entries);  // missing/empty index is not an error here
    entries.erase(std::remove_if(entries.begin(), entries.end(),
                                 [&](const QuarantineEntry& x) {
                                     return x.id == e.id;
                                 }),
                  entries.end());
    entries.push_back(e);
    const Status sst = SaveIndex(entries);
    if (!sst) return sst;

    // Remove the original now that a recoverable encrypted copy exists.
    std::error_code ec;
    fs::remove(path, ec);
    if (ec) {
        SENTINEL_LOG(Warn) << "quarantine: stored blob but could not remove "
                              "original " << path << " (" << ec.message() << ")";
    }

    SENTINEL_LOG(Info) << "quarantined " << path << " as " << e.id;
    return e;
}

Status QuarantineVault::Restore(const std::string& id,
                                const std::string& dest_path) {
    std::vector<QuarantineEntry> entries;
    const Status lst = LoadIndex(entries);
    if (!lst) return lst;

    const QuarantineEntry* found = nullptr;
    for (const auto& x : entries) {
        if (x.id == id) {
            found = &x;
            break;
        }
    }
    if (!found) {
        return Status::Error(ErrorCode::NotFound, "no quarantined item: " + id);
    }

    const std::string blob_path = JoinPath(vault_dir_, found->stored_file);
    auto rd = ReadFile(blob_path);
    if (!rd) return rd.status();
    const Bytes& blob = rd.value();

    // Reverse the XOR keystream, then verify integrity before writing anything.
    std::vector<std::uint8_t> ks;
    Keystream(found->id, blob.size(), ks);
    Bytes plain(blob.size());
    for (std::size_t i = 0; i < blob.size(); ++i) {
        plain[i] = static_cast<std::uint8_t>(blob[i] ^ ks[i]);
    }

    const std::string sha = Sha256::HexDigest(plain);
    if (sha != found->sha256) {
        return Status::Error(ErrorCode::Corrupt,
                             "integrity check failed restoring " + id);
    }

    const std::string dest = dest_path.empty() ? found->original_path : dest_path;
    const std::string parent = ParentDir(dest);
    if (!parent.empty()) MakeDirs(parent);

    const Status wst = WriteFileAtomic(dest, plain);
    if (!wst) return wst;

    SENTINEL_LOG(Info) << "restored " << id << " to " << dest;
    return Status::Ok();
}

Status QuarantineVault::Purge(const std::string& id) {
    std::vector<QuarantineEntry> entries;
    const Status lst = LoadIndex(entries);
    if (!lst) return lst;

    bool removed = false;
    for (const auto& x : entries) {
        if (x.id == id) {
            std::error_code ec;
            fs::remove(JoinPath(vault_dir_, x.stored_file), ec);
            removed = true;
            break;
        }
    }
    if (!removed) {
        return Status::Error(ErrorCode::NotFound, "no quarantined item: " + id);
    }

    entries.erase(std::remove_if(entries.begin(), entries.end(),
                                 [&](const QuarantineEntry& x) {
                                     return x.id == id;
                                 }),
                  entries.end());
    const Status sst = SaveIndex(entries);
    if (!sst) return sst;

    SENTINEL_LOG(Info) << "purged quarantined item " << id;
    return Status::Ok();
}

Result<std::vector<QuarantineEntry>> QuarantineVault::List() const {
    std::vector<QuarantineEntry> entries;
    const Status st = LoadIndex(entries);
    if (!st) return st;
    return entries;
}

bool QuarantineVault::Contains(const std::string& id) const {
    std::vector<QuarantineEntry> entries;
    if (!LoadIndex(entries)) return false;
    for (const auto& x : entries) {
        if (x.id == id) return true;
    }
    return false;
}

Status QuarantineVault::LoadIndex(std::vector<QuarantineEntry>& out) const {
    out.clear();
    if (index_path_.empty() || !PathExists(index_path_)) {
        return Status::Ok();  // a vault with nothing quarantined yet
    }

    std::ifstream in(index_path_, std::ios::binary);
    if (!in) {
        return Status::Error(ErrorCode::IoError,
                             "cannot read index: " + index_path_);
    }

    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;

        // Split into exactly the fields we wrote; skip anything malformed
        // rather than trusting a partially-corrupt record.
        std::vector<std::string> fields;
        std::string cur;
        for (char c : line) {
            if (c == '\t') {
                fields.push_back(cur);
                cur.clear();
            } else {
                cur += c;
            }
        }
        fields.push_back(cur);
        if (fields.size() != 7) continue;

        QuarantineEntry e;
        e.id = Decode(fields[0]);
        e.original_path = Decode(fields[1]);
        e.detection_reason = Decode(fields[2]);
        e.sha256 = Decode(fields[3]);
        e.original_size = ParseU64(fields[4]);
        e.quarantined_at_ms = ParseU64(fields[5]);
        e.stored_file = Decode(fields[6]);
        out.push_back(std::move(e));
    }
    return Status::Ok();
}

Status QuarantineVault::SaveIndex(
    const std::vector<QuarantineEntry>& entries) const {
    if (index_path_.empty()) {
        return Status::Error(ErrorCode::Internal, "vault not opened");
    }
    std::string content;
    for (const auto& e : entries) {
        content += Encode(e.id);
        content += '\t';
        content += Encode(e.original_path);
        content += '\t';
        content += Encode(e.detection_reason);
        content += '\t';
        content += Encode(e.sha256);
        content += '\t';
        content += std::to_string(e.original_size);
        content += '\t';
        content += std::to_string(e.quarantined_at_ms);
        content += '\t';
        content += Encode(e.stored_file);
        content += '\n';
    }
    return WriteFileAtomic(index_path_, content);
}

}  // namespace sentinel
