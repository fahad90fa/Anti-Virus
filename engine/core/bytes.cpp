#include "sentinel/core/bytes.h"

#include <array>
#include <cctype>
#include <cmath>

namespace sentinel {

double ShannonEntropy(const std::uint8_t* data, std::size_t len) noexcept {
    if (len == 0) return 0.0;
    std::array<std::size_t, 256> freq{};
    for (std::size_t i = 0; i < len; ++i) freq[data[i]]++;
    double entropy = 0.0;
    const double inv = 1.0 / static_cast<double>(len);
    for (std::size_t c = 0; c < 256; ++c) {
        if (freq[c] == 0) continue;
        const double p = static_cast<double>(freq[c]) * inv;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

std::string ToHex(const std::uint8_t* data, std::size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (std::size_t i = 0; i < len; ++i) {
        out[2 * i] = kHex[(data[i] >> 4) & 0xF];
        out[2 * i + 1] = kHex[data[i] & 0xF];
    }
    return out;
}

static int HexVal(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool FromHex(const std::string& hex, Bytes& out) {
    if (hex.size() % 2 != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        const int hi = HexVal(hex[i]);
        const int lo = HexVal(hex[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
    }
    return true;
}

bool ContainsCaseInsensitive(const std::uint8_t* hay, std::size_t hay_len,
                             const std::string& needle) noexcept {
    if (needle.empty()) return true;
    if (needle.size() > hay_len) return false;
    const std::size_t last = hay_len - needle.size();
    for (std::size_t i = 0; i <= last; ++i) {
        std::size_t j = 0;
        for (; j < needle.size(); ++j) {
            const int a = std::tolower(hay[i + j]);
            const int b = std::tolower(static_cast<unsigned char>(needle[j]));
            if (a != b) break;
        }
        if (j == needle.size()) return true;
    }
    return false;
}

}  // namespace sentinel
