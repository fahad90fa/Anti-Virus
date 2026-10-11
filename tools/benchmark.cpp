// benchmark — measure the engine's latency against the design budget: cached
// known-good open (< 1 ms), cache-miss static scan of a typical executable (a
// few to low tens of ms), and raw hashing throughput. Synthetic inputs only.
//
//   benchmark [--iterations N] [--size-kb K]
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

#include "sentinel/core/config.h"
#include "sentinel/core/sha256.h"
#include "sentinel/scan/static_scanner.h"
#include "sentinel/scan/subject.h"

using namespace sentinel;
using Clock = std::chrono::steady_clock;

static double MsSince(Clock::time_point t0) {
    return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

int main(int argc, char** argv) {
    int iterations = 2000;
    int size_kb = 256;
    for (int i = 1; i + 1 < argc; ++i) {
        std::string a = argv[i];
        if (a == "--iterations") iterations = std::atoi(argv[i + 1]);
        else if (a == "--size-kb") size_kb = std::atoi(argv[i + 1]);
    }

    // Build a synthetic "executable"-ish buffer (MZ header + pseudo-random body).
    Bytes buf(static_cast<std::size_t>(size_kb) * 1024);
    buf[0] = 'M'; buf[1] = 'Z';
    std::uint32_t x = 0x12345678u;
    for (std::size_t i = 2; i < buf.size(); ++i) {
        x = x * 1664525u + 1013904223u;  // LCG, deterministic
        buf[i] = static_cast<std::uint8_t>(x >> 24);
    }

    // Hashing throughput.
    auto t0 = Clock::now();
    for (int i = 0; i < iterations; ++i) {
        volatile auto d = Sha256::Hash(buf);
        (void)d;
    }
    double hash_ms = MsSince(t0);
    double mb = (static_cast<double>(buf.size()) * iterations) / (1024.0 * 1024.0);
    std::printf("SHA-256: %.1f MB in %.1f ms = %.0f MB/s\n", mb, hash_ms, mb / (hash_ms / 1000.0));

    // Static scan (cache miss): fresh subject each time.
    Config cfg;
    StaticScanner scanner(cfg);
    scanner.LoadSignatures();

    t0 = Clock::now();
    for (int i = 0; i < iterations; ++i) {
        FileSubject s = FileSubject::FromBuffer(buf, "bench.bin");
        // force a unique hash so the cache always misses
        s.sha256 += std::to_string(i);
        volatile auto v = scanner.Scan(s);
        (void)v;
    }
    double scan_ms = MsSince(t0);
    std::printf("Static scan (cache MISS): %.3f ms/scan over %d iters\n",
                scan_ms / iterations, iterations);

    // Static scan (cache hit): same subject repeatedly.
    FileSubject hot = FileSubject::FromBuffer(buf, "hot.bin");
    scanner.Scan(hot);  // prime
    t0 = Clock::now();
    for (int i = 0; i < iterations; ++i) {
        volatile auto v = scanner.Scan(hot);
        (void)v;
    }
    double hit_ms = MsSince(t0);
    std::printf("Static scan (cache HIT):  %.4f ms/scan over %d iters\n",
                hit_ms / iterations, iterations);

    std::printf("\nBudget: cached open < 1 ms, cache-miss scan a few-to-low-tens of ms.\n");
    return 0;
}
