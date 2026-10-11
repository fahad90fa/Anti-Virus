// Tamper-evident logging. The timeline and logs are append-only and integrity-
// sealed with a hash chain, so malware or a rogue admin cannot quietly erase
// their tracks. Each record's seal = SHA-256(prev_seal || record_bytes). If any
// record is altered or removed, the break in the chain is detectable on verify.
#ifndef SENTINEL_EDR_SECURE_LOG_H
#define SENTINEL_EDR_SECURE_LOG_H

#include <cstdint>
#include <string>
#include <vector>

#include "sentinel/core/result.h"

namespace sentinel {

struct LogRecord {
    std::uint64_t sequence = 0;
    std::uint64_t timestamp_ms = 0;
    std::string category;   // "detection", "action", "system"
    std::string message;    // JSON or text payload
    std::string prev_seal;  // hex
    std::string seal;       // hex = SHA-256(prev_seal || canonical record)
};

class SecureLog {
public:
    // Open (or create) an append-only log file. On open, the existing chain is
    // loaded and its tail seal becomes the chain head.
    Status Open(const std::string& path);
    void Close();

    // Append a record; computes and stores its seal. Thread-safe.
    Status Append(const std::string& category, const std::string& message,
                  std::uint64_t timestamp_ms);

    // Verify the entire on-disk chain. Returns Ok if intact; on a break returns
    // Corrupt with the offending sequence number in the message.
    Status Verify() const;

    // Read all records back (for the UI / forensic export).
    Result<std::vector<LogRecord>> ReadAll() const;

    std::uint64_t count() const;
    std::string head_seal() const;

    // Canonical serialization of a record's sealed fields (deterministic).
    static std::string CanonicalBytes(const LogRecord& r);

private:
    std::string path_;
    std::uint64_t next_sequence_ = 0;
    std::string head_seal_;  // seal of the last appended record ("" = genesis)
};

}  // namespace sentinel

#endif  // SENTINEL_EDR_SECURE_LOG_H
