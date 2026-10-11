// rule_compiler — validate and inspect Sentinel's YARA-style rule set, and
// optionally match it against a file. A dev utility that reuses the real engine
// rule engine, so "does my rule compile and fire?" is answered the same way the
// scanner answers it.
//
//   rule_compiler <rules-dir-or-file> [--match <file>]
#include <cstdio>
#include <string>

#include "sentinel/core/fs.h"
#include "sentinel/scan/rule_engine.h"

using namespace sentinel;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <rules-dir-or-file> [--match <file>]\n", argv[0]);
        return 2;
    }
    const std::string target = argv[1];
    std::string match_file;
    for (int i = 2; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--match") match_file = argv[i + 1];
    }

    RuleSet rules;
    std::size_t count = 0;
    Status st = Status::Ok();
    if (IsDirectory(target)) {
        st = rules.LoadDirectory(target, &count);
    } else {
        auto content = ReadFile(target);
        if (!content) {
            std::fprintf(stderr, "cannot read %s\n", target.c_str());
            return 1;
        }
        std::string text(content.value().begin(), content.value().end());
        st = rules.ParseText(text);
        count = rules.rule_count();
    }

    if (!st.ok()) {
        std::fprintf(stderr, "parse error: %s\n", st.message().c_str());
        return 1;
    }
    std::printf("Loaded %zu rule(s) from %s\n", rules.rule_count(), target.c_str());

    if (!match_file.empty()) {
        auto content = ReadFile(match_file);
        if (!content) {
            std::fprintf(stderr, "cannot read match target %s\n", match_file.c_str());
            return 1;
        }
        std::vector<RuleMatch> matches;
        rules.Match(content.value(), matches);
        if (matches.empty()) {
            std::printf("No rules matched %s\n", match_file.c_str());
        } else {
            std::printf("%zu rule(s) matched %s:\n", matches.size(), match_file.c_str());
            for (const auto& m : matches) {
                std::printf("  - %-28s severity=%-6s weight=%.2f  %s\n",
                            m.rule_id.c_str(), m.severity.c_str(), m.weight,
                            m.description.c_str());
            }
        }
    }
    return 0;
}
