// Deception grid. Beyond canary files, plant fake credentials, decoy network
// shares, and honeytokens across the system. Legitimate software has no reason
// to touch them, so any access is a near-certain intruder — a detection with
// essentially zero false positives and an early tripwire before real damage.
#ifndef SENTINEL_DECEPTION_HONEYTOKENS_H
#define SENTINEL_DECEPTION_HONEYTOKENS_H

#include <cstdint>
#include <string>
#include <vector>

#include "sentinel/core/result.h"
#include "sentinel/core/types.h"

namespace sentinel {

enum class TokenKind { CanaryFile, FakeCredential, DecoyShare, RegistryToken };

struct Honeytoken {
    TokenKind kind;
    std::string identity;   // path, credential name, share name, or key
    std::string marker;     // unique marker embedded in the token
};

class HoneytokenManager {
public:
    // Plant canary files under a directory (hidden, innocuous-looking names).
    // Returns the planted file paths.
    Result<std::vector<std::string>> PlantCanaryFiles(const std::string& dir,
                                                      int count = 3);

    // Register an already-known token (e.g. a fake credential string to watch).
    void Register(const Honeytoken& token);

    // Is this path/identity a honeytoken?
    bool IsToken(const std::string& identity) const;

    // Report an access to a token: returns a near-maximal-confidence Signal.
    Signal OnAccess(const std::string& identity, std::uint32_t by_pid) const;

    const std::vector<Honeytoken>& tokens() const { return tokens_; }

private:
    std::vector<Honeytoken> tokens_;
};

}  // namespace sentinel

#endif  // SENTINEL_DECEPTION_HONEYTOKENS_H
