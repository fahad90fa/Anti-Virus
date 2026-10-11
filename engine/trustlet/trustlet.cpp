#include "sentinel/trustlet/trustlet.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <string>
#include <system_error>
#include <utility>

#include "sentinel/core/fs.h"
#include "sentinel/core/logging.h"
#include "sentinel/core/sha256.h"

namespace fs = std::filesystem;

namespace sentinel {
namespace {

// The software store keeps its derived key here. In production this key would
// be sealed by the VTL1 trustlet and never materialize in normal-world memory;
// this file is the documented software placeholder.
constexpr char kKeyFile[] = ".trustkey";

// Fixed seed mixed with the store directory to derive the key. Kept distinct
// from other modules' salts so stores do not share key material.
constexpr char kKeySeed[] = "sentinel-software-trustlet-key-v1";

// Label folded into nonce derivation so the nonce and the authentication tag,
// which both hash the key and plaintext, never collide on the same digest.
constexpr char kNonceLabel[] = "sentinel-trustlet-nonce-v1";

// A sealed blob is: nonce(16) || ciphertext(len) || tag(32).
constexpr std::size_t kNonceLen = 16;
constexpr std::size_t kTagLen = Sha256::kDigestSize;  // 32

// Counter-mode SHA-256 keystream: block_i = SHA-256(key || salt || counter_be64).
// Same construction the quarantine vault uses, so the whole engine derives
// keystreams one way.
Bytes Keystream(const Bytes& key, const Bytes& salt, std::size_t len) {
    Bytes out;
    out.reserve(len);
    std::uint64_t counter = 0;
    while (out.size() < len) {
        Sha256 h;
        h.Update(key.data(), key.size());
        h.Update(salt.data(), salt.size());
        std::uint8_t cb[8];
        for (int i = 0; i < 8; ++i) {
            cb[i] = static_cast<std::uint8_t>((counter >> (56 - 8 * i)) & 0xFF);
        }
        h.Update(cb, 8);
        const Sha256::Digest d = h.Final();

        const std::size_t take = std::min(len - out.size(), d.size());
        out.insert(out.end(), d.begin(), d.begin() + take);
        ++counter;
    }
    return out;
}

// SHA-256(key || message): the HMAC-like tag used for both the seal integrity
// check and Sign/Verify. (A true HMAC is overkill here; the key is a secret of
// fixed length and the message is length-framed by the fixed-size digest.)
Bytes KeyedTag(const Bytes& key, const std::uint8_t* msg, std::size_t len) {
    Sha256 h;
    h.Update(key.data(), key.size());
    h.Update(msg, len);
    const Sha256::Digest d = h.Final();
    return Bytes(d.begin(), d.end());
}

// Length-checked, data-independent comparison so a tag check does not leak
// where the first mismatching byte is via timing.
bool ConstTimeEqual(const Bytes& a, const Bytes& b) {
    if (a.size() != b.size()) return false;
    std::uint8_t diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        diff |= static_cast<std::uint8_t>(a[i] ^ b[i]);
    }
    return diff == 0;
}

}  // namespace

Result<std::unique_ptr<SoftwareTrustStore>> SoftwareTrustStore::Open(
    const std::string& dir) {
    if (!MakeDirs(dir)) {
        return Status::Error(ErrorCode::IoError,
                             "cannot create trust-store dir: " + dir);
    }

    const std::string key_path = JoinPath(dir, kKeyFile);
    Bytes key;

    if (PathExists(key_path)) {
        auto r = ReadFile(key_path);
        if (!r) return r.status();
        key = r.value();
        if (key.size() < Sha256::kDigestSize) {
            return Status::Error(ErrorCode::Corrupt,
                                 "trust-store key is truncated");
        }
        // Use exactly the digest-sized prefix as the key.
        key.resize(Sha256::kDigestSize);
    } else {
        // Derive key = SHA-256(seed || "|" || dir). Deterministic per directory
        // so the store survives restarts; this is the software fallback and is
        // explicitly NOT hardware-isolated.
        const std::string material = std::string(kKeySeed) + "|" + dir;
        const Sha256::Digest d = Sha256::Hash(
            reinterpret_cast<const std::uint8_t*>(material.data()),
            material.size());
        key.assign(d.begin(), d.end());

        const Status st = WriteFileAtomic(key_path, key);
        if (!st) return st;

        // Best-effort owner-only perms on platforms that honor them.
        std::error_code ec;
        fs::permissions(key_path,
                        fs::perms::owner_read | fs::perms::owner_write,
                        fs::perm_options::replace, ec);
    }

    SENTINEL_LOG(Debug) << "software trust store opened at " << dir
                        << " (NOT hardware-isolated)";
    // Open is a member, so it may reach the private constructor directly.
    return std::unique_ptr<SoftwareTrustStore>(
        new SoftwareTrustStore(std::move(key)));
}

Result<Bytes> SoftwareTrustStore::Seal(const Bytes& plaintext) {
    // Derive a nonce from the key and plaintext so sealing needs no RNG yet the
    // keystream salt is unique per distinct secret. (Sealing is deterministic:
    // identical plaintext seals identically, which is acceptable for a store.)
    Sha256 nh;
    nh.Update(key_.data(), key_.size());
    nh.Update(reinterpret_cast<const std::uint8_t*>(kNonceLabel),
              sizeof(kNonceLabel) - 1);
    nh.Update(plaintext);
    const Sha256::Digest nd = nh.Final();
    const Bytes nonce(nd.begin(), nd.begin() + kNonceLen);

    // Keystream-XOR the plaintext under the nonce-salt.
    const Bytes ks = Keystream(key_, nonce, plaintext.size());
    Bytes sealed;
    sealed.reserve(kNonceLen + plaintext.size() + kTagLen);
    sealed.insert(sealed.end(), nonce.begin(), nonce.end());
    for (std::size_t i = 0; i < plaintext.size(); ++i) {
        sealed.push_back(static_cast<std::uint8_t>(plaintext[i] ^ ks[i]));
    }

    // Tag over key || plaintext binds the ciphertext to the exact secret; any
    // tampering with nonce or ciphertext changes the recovered plaintext and so
    // fails this check on Unseal.
    const Bytes tag = KeyedTag(key_, plaintext.data(), plaintext.size());
    sealed.insert(sealed.end(), tag.begin(), tag.end());
    return sealed;
}

Result<Bytes> SoftwareTrustStore::Unseal(const Bytes& sealed) {
    if (sealed.size() < kNonceLen + kTagLen) {
        return Status::Error(ErrorCode::Corrupt,
                             "sealed blob is too short to be valid");
    }

    const std::size_t ct_len = sealed.size() - kNonceLen - kTagLen;
    const Bytes nonce(sealed.begin(), sealed.begin() + kNonceLen);

    // Recover the plaintext by reversing the keystream XOR.
    const Bytes ks = Keystream(key_, nonce, ct_len);
    Bytes plaintext(ct_len);
    for (std::size_t i = 0; i < ct_len; ++i) {
        plaintext[i] =
            static_cast<std::uint8_t>(sealed[kNonceLen + i] ^ ks[i]);
    }

    // Verify integrity BEFORE returning any bytes to the caller.
    const Bytes expected_tag(sealed.end() - static_cast<std::ptrdiff_t>(kTagLen),
                             sealed.end());
    const Bytes actual_tag = KeyedTag(key_, plaintext.data(), plaintext.size());
    if (!ConstTimeEqual(expected_tag, actual_tag)) {
        return Status::Error(ErrorCode::Corrupt,
                             "sealed blob failed integrity check");
    }
    return plaintext;
}

Result<Bytes> SoftwareTrustStore::Sign(const Bytes& message) {
    // Signature == keyed tag over the message. Verify recomputes and compares.
    return KeyedTag(key_, message.data(), message.size());
}

bool SoftwareTrustStore::Verify(const Bytes& message, const Bytes& signature) {
    const Bytes expected = KeyedTag(key_, message.data(), message.size());
    return ConstTimeEqual(expected, signature);
}

std::string SoftwareTrustStore::TrustAnchor() const {
    // Stable public identity: hex of SHA-256(key). Publishing the hash of the
    // key (not the key) lets callers pin the anchor without exposing the secret.
    return Sha256::HexDigest(key_);
}

Result<std::unique_ptr<TrustStore>> OpenTrustStore(const std::string& dir) {
    // On Windows with Virtualization-Based Security available, this factory
    // would return a VTL1 IUM (isolateduserland) trustlet-backed store whose
    // keys never leave the enclave. Everywhere else we return the clearly-
    // labeled software fallback so the engine stays functional and testable.
    auto r = SoftwareTrustStore::Open(dir);
    if (!r) return r.status();
    std::unique_ptr<TrustStore> store = std::move(r.value());
    return store;
}

}  // namespace sentinel
