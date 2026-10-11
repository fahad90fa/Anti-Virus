// YARA-style pattern-matching engine — Layer 2 of static scanning. We ship our
// own compact rule format and matcher (no third-party YARA dependency):
//
//   rule Eicar_Test : testfile {
//       meta:
//           description = "EICAR antivirus test file"
//           severity    = "high"
//           weight      = 0.95
//       strings:
//           $s = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
//           $hex = { 58 35 4F 21 50 25 }
//       condition:
//           any of them
//   }
//
// Strings may be text (optional `nocase`, `wide`) or hex byte patterns with `??`
// wildcard nibbles. Conditions support: `any of them`, `all of them`,
// `N of them`, and boolean expressions over $identifiers with and/or/not/( ).
#ifndef SENTINEL_SCAN_RULE_ENGINE_H
#define SENTINEL_SCAN_RULE_ENGINE_H

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "sentinel/core/bytes.h"
#include "sentinel/core/result.h"
#include "sentinel/core/types.h"

namespace sentinel {

struct RuleMatch {
    std::string rule_id;
    std::string description;
    std::string severity;       // "low" | "medium" | "high"
    double weight = 0.5;        // contribution to malice score, [0,1]
    std::vector<std::string> tags;
    std::vector<std::string> matched_strings;  // ids that hit, e.g. "$s"
};

// A compiled rule set. Rules are parsed from text (one or many rules per file).
class RuleSet {
public:
    RuleSet();
    ~RuleSet();
    RuleSet(RuleSet&&) noexcept;
    RuleSet& operator=(RuleSet&&) noexcept;

    // Parse rules from a string. Appends to the set. Returns ParseError with a
    // message pointing at the offending rule on failure.
    Status ParseText(const std::string& text);

    // Parse every *.yar / *.rules / *.txt file under a directory (non-fatal per
    // file; errors are logged and skipped). Returns the number parsed via count.
    Status LoadDirectory(const std::string& dir, std::size_t* count = nullptr);

    // Match all rules against a buffer, appending any matches to `out`.
    void Match(const std::uint8_t* data, std::size_t len,
               std::vector<RuleMatch>& out) const;
    void Match(const Bytes& b, std::vector<RuleMatch>& out) const {
        Match(b.data(), b.size(), out);
    }

    std::size_t rule_count() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}  // namespace sentinel

#endif  // SENTINEL_SCAN_RULE_ENGINE_H
