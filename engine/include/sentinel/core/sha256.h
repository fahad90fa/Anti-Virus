// SHA-256, implemented from scratch (FIPS 180-4). Used for the content hash
// that keys the verdict cache and the allow/block hash sets, and for the
// append-only hash chain in the EDR sealed log. No third-party crypto.
#ifndef SENTINEL_CORE_SHA256_H
#define SENTINEL_CORE_SHA256_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "sentinel/core/bytes.h"

namespace sentinel {

class Sha256 {
public:
    static constexpr std::size_t kDigestSize = 32;
    using Digest = std::array<std::uint8_t, kDigestSize>;

    Sha256();
    void Reset();
    void Update(const std::uint8_t* data, std::size_t len);
    void Update(const Bytes& b) { Update(b.data(), b.size()); }
    void Update(const std::string& s) {
        Update(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
    }
    // Finalizes and returns the digest. The object is reset afterward.
    Digest Final();

    // Convenience one-shot helpers.
    static Digest Hash(const std::uint8_t* data, std::size_t len);
    static Digest Hash(const Bytes& b) { return Hash(b.data(), b.size()); }
    static std::string HexDigest(const std::uint8_t* data, std::size_t len);
    static std::string HexDigest(const Bytes& b) {
        return HexDigest(b.data(), b.size());
    }
    static std::string HexDigest(const std::string& s) {
        return HexDigest(reinterpret_cast<const std::uint8_t*>(s.data()), s.size());
    }
    static std::string ToHex(const Digest& d);

private:
    void ProcessBlock(const std::uint8_t* block);

    std::array<std::uint32_t, 8> state_;
    std::uint64_t bit_len_ = 0;
    std::array<std::uint8_t, 64> buffer_;
    std::size_t buffer_len_ = 0;
};

}  // namespace sentinel

#endif  // SENTINEL_CORE_SHA256_H
