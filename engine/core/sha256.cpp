#include "sentinel/core/sha256.h"

#include <algorithm>
#include <cstring>

namespace sentinel {
namespace {

constexpr std::uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline std::uint32_t Rotr(std::uint32_t x, std::uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

}  // namespace

Sha256::Sha256() { Reset(); }

void Sha256::Reset() {
    state_ = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
              0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    bit_len_ = 0;
    buffer_len_ = 0;
}

void Sha256::ProcessBlock(const std::uint8_t* block) {
    std::uint32_t w[64];
    for (int i = 0; i < 16; ++i) {
        w[i] = (static_cast<std::uint32_t>(block[i * 4]) << 24) |
               (static_cast<std::uint32_t>(block[i * 4 + 1]) << 16) |
               (static_cast<std::uint32_t>(block[i * 4 + 2]) << 8) |
               (static_cast<std::uint32_t>(block[i * 4 + 3]));
    }
    for (int i = 16; i < 64; ++i) {
        const std::uint32_t s0 = Rotr(w[i - 15], 7) ^ Rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        const std::uint32_t s1 = Rotr(w[i - 2], 17) ^ Rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    std::uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    std::uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];

    for (int i = 0; i < 64; ++i) {
        const std::uint32_t S1 = Rotr(e, 6) ^ Rotr(e, 11) ^ Rotr(e, 25);
        const std::uint32_t ch = (e & f) ^ (~e & g);
        const std::uint32_t t1 = h + S1 + ch + kK[i] + w[i];
        const std::uint32_t S0 = Rotr(a, 2) ^ Rotr(a, 13) ^ Rotr(a, 22);
        const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        const std::uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
}

void Sha256::Update(const std::uint8_t* data, std::size_t len) {
    bit_len_ += static_cast<std::uint64_t>(len) * 8;
    while (len > 0) {
        const std::size_t take = std::min(len, buffer_.size() - buffer_len_);
        std::memcpy(buffer_.data() + buffer_len_, data, take);
        buffer_len_ += take;
        data += take;
        len -= take;
        if (buffer_len_ == buffer_.size()) {
            ProcessBlock(buffer_.data());
            buffer_len_ = 0;
        }
    }
}

Sha256::Digest Sha256::Final() {
    // Append the 0x80 byte, pad with zeros, then the 64-bit length.
    const std::uint64_t total_bits = bit_len_;
    std::uint8_t pad = 0x80;
    Update(&pad, 1);
    pad = 0x00;
    while (buffer_len_ != 56) {
        Update(&pad, 1);
    }
    std::uint8_t len_bytes[8];
    for (int i = 0; i < 8; ++i) {
        len_bytes[i] = static_cast<std::uint8_t>((total_bits >> (56 - 8 * i)) & 0xFF);
    }
    Update(len_bytes, 8);

    Digest out{};
    for (int i = 0; i < 8; ++i) {
        out[i * 4] = static_cast<std::uint8_t>((state_[i] >> 24) & 0xFF);
        out[i * 4 + 1] = static_cast<std::uint8_t>((state_[i] >> 16) & 0xFF);
        out[i * 4 + 2] = static_cast<std::uint8_t>((state_[i] >> 8) & 0xFF);
        out[i * 4 + 3] = static_cast<std::uint8_t>(state_[i] & 0xFF);
    }
    Reset();
    return out;
}

Sha256::Digest Sha256::Hash(const std::uint8_t* data, std::size_t len) {
    Sha256 h;
    h.Update(data, len);
    return h.Final();
}

std::string Sha256::ToHex(const Digest& d) {
    return sentinel::ToHex(d.data(), d.size());
}

std::string Sha256::HexDigest(const std::uint8_t* data, std::size_t len) {
    return ToHex(Hash(data, len));
}

}  // namespace sentinel
