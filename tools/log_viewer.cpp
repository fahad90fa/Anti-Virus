// log_viewer — read and VERIFY the tamper-evident EDR sealed log. Prints each
// record and reports whether the append-only hash chain is intact. A break in
// the chain (an altered or removed record) is detected and reported.
//
//   log_viewer <sealed-log-path>
#include <cstdio>
#include <string>

#include "sentinel/edr/secure_log.h"

using namespace sentinel;

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr, "usage: %s <sealed-log-path>\n", argv[0]);
        return 2;
    }
    const std::string path = argv[1];

    SecureLog log;
    Status st = log.Open(path);
    if (!st.ok()) {
        std::fprintf(stderr, "cannot open log: %s\n", st.message().c_str());
        return 1;
    }

    auto records = log.ReadAll();
    if (!records) {
        std::fprintf(stderr, "cannot read log: %s\n", records.status().message().c_str());
        return 1;
    }

    std::printf("%llu record(s) in %s\n",
                static_cast<unsigned long long>(records.value().size()), path.c_str());
    for (const auto& r : records.value()) {
        std::printf("  #%-6llu [%s] %s\n",
                    static_cast<unsigned long long>(r.sequence),
                    r.category.c_str(), r.message.c_str());
    }

    Status v = log.Verify();
    if (v.ok()) {
        std::printf("\nINTEGRITY OK — hash chain intact (head seal %.16s...)\n",
                    log.head_seal().c_str());
        return 0;
    }
    std::fprintf(stderr, "\nINTEGRITY FAILURE: %s\n", v.message().c_str());
    return 1;
}
