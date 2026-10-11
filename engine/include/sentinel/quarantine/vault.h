// Encrypted quarantine vault. When a file is convicted it is not deleted
// outright (deletion is unrecoverable and false positives happen). Instead it is
// moved to an encrypted quarantine vault:
//   - the file is neutralized by encrypting/encoding it so it can no longer
//     execute or be read by other processes;
//   - metadata records the original path, detection reason, hash, and timestamp;
//   - the vault is itself protected from tampering, so malware cannot reach in
//     and restore its own body.
// The user can review any quarantined item and restore it in one click if it was
// a false positive.
//
// Neutralization here uses a keyed stream cipher (XOR-based keystream derived
// from a per-vault key via SHA-256; a documented placeholder for AES-GCM on the
// Windows build). The point is that the stored bytes are inert and unreadable
// without the vault key, and integrity is verified on restore.
#ifndef SENTINEL_QUARANTINE_VAULT_H
#define SENTINEL_QUARANTINE_VAULT_H

#include <cstdint>
#include <string>
#include <vector>

#include "sentinel/core/result.h"

namespace sentinel {

struct QuarantineEntry {
    std::string id;              // unique id (hash-derived)
    std::string original_path;
    std::string detection_reason;
    std::string sha256;          // original file hash
    std::uint64_t original_size = 0;
    std::uint64_t quarantined_at_ms = 0;
    std::string stored_file;     // encrypted blob filename within the vault
};

class QuarantineVault {
public:
    // Open (or create) the vault at `vault_dir`. A per-vault key file is created
    // on first use (0600). In production this key is sealed by the trustlet.
    Status Open(const std::string& vault_dir);

    // Quarantine a file: neutralize + move into the vault, record metadata, and
    // remove the original. Returns the created entry.
    Result<QuarantineEntry> Quarantine(const std::string& path,
                                       const std::string& reason,
                                       std::uint64_t timestamp_ms);

    // Restore a quarantined item to its original path (or an override path).
    // Verifies integrity before writing. Used for false-positive recovery.
    Status Restore(const std::string& id, const std::string& dest_path = "");

    // Permanently delete a quarantined item.
    Status Purge(const std::string& id);

    Result<std::vector<QuarantineEntry>> List() const;
    bool Contains(const std::string& id) const;

private:
    std::string vault_dir_;
    std::string index_path_;
    std::vector<std::uint8_t> key_;

    Status LoadIndex(std::vector<QuarantineEntry>& out) const;
    Status SaveIndex(const std::vector<QuarantineEntry>& entries) const;
    void Keystream(const std::string& salt, std::size_t len,
                   std::vector<std::uint8_t>& out) const;
};

}  // namespace sentinel

#endif  // SENTINEL_QUARANTINE_VAULT_H
