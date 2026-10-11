// Runner for the Sentinel test framework. Discovers all registered tests,
// runs them, prints a per-suite summary, and exits non-zero on any failure.
// Supports an optional substring filter argument: sentinel_tests <filter>.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "sentinel_test.h"

namespace sentinel_test {
std::vector<TestCase>& Registry() {
    static std::vector<TestCase> registry;
    return registry;
}
}  // namespace sentinel_test

int main(int argc, char** argv) {
    std::string filter;
    if (argc > 1) filter = argv[1];

    int passed = 0, failed = 0, skipped = 0;
    std::vector<std::string> failures;

    for (auto& tc : sentinel_test::Registry()) {
        const std::string full = tc.suite + "." + tc.name;
        if (!filter.empty() && full.find(filter) == std::string::npos) {
            ++skipped;
            continue;
        }
        std::printf("[ RUN    ] %s\n", full.c_str());
        bool ok = true;
        try {
            tc.fn(ok);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "    FAIL: threw std::exception: %s\n", e.what());
            ok = false;
        } catch (...) {
            std::fprintf(stderr, "    FAIL: threw unknown exception\n");
            ok = false;
        }
        if (ok) {
            std::printf("[   PASS ] %s\n", full.c_str());
            ++passed;
        } else {
            std::printf("[   FAIL ] %s\n", full.c_str());
            failures.push_back(full);
            ++failed;
        }
    }

    std::printf("\n==================================================\n");
    std::printf("  %d passed, %d failed, %d skipped (of %zu total)\n", passed,
                failed, skipped, sentinel_test::Registry().size());
    if (!failures.empty()) {
        std::printf("  Failures:\n");
        for (const auto& f : failures) std::printf("    - %s\n", f.c_str());
    }
    std::printf("==================================================\n");
    return failed == 0 ? 0 : 1;
}
