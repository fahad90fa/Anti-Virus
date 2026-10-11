// Byte buffer helpers used across the scan and behavioral layers.
#ifndef SENTINEL_CORE_BYTES_H
#define SENTINEL_CORE_BYTES_H

#include <cstdint>
#include <string>
#include <vector>

namespace sentinel {

using Bytes = std::vector<std::uint8_t>;

// Shannon entropy of a byte buffer, in bits/byte (0..8). High entropy (> ~7.2)
// signals compression or encryption — a packer or encrypted payload.
double ShannonEntropy(const std::uint8_t* data, std::size_t len) noexcept;
inline double ShannonEntropy(const Bytes& b) noexcept {
    return ShannonEntropy(b.data(), b.size());
}

// Lowercase hex encoding of a byte buffer.
std::string ToHex(const std::uint8_t* data, std::size_t len);
inline std::string ToHex(const Bytes& b) { return ToHex(b.data(), b.size()); }

// Parse a lowercase/uppercase hex string into bytes. Returns false on odd
// length or non-hex characters.
bool FromHex(const std::string& hex, Bytes& out);

// Case-insensitive substring search over raw bytes (for ASCII pattern rules).
bool ContainsCaseInsensitive(const std::uint8_t* hay, std::size_t hay_len,
                             const std::string& needle) noexcept;

}  // namespace sentinel

#endif  // SENTINEL_CORE_BYTES_H
