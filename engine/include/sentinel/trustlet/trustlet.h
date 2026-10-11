// VBS/HVCI trustlet interface. The crown-jewel logic (verdict-signing keys,
// integrity checks, the rollback gate's trust anchor) runs inside a
// virtualization-isolated enclave: a VTL1 trustlet under Virtualization-Based
// Security, the same mechanism Windows Credential Guard uses. Even malware that
// reaches ring-0 cannot read or tamper with what lives there.
//
// This header defines the trust-store interface the engine depends on. On
// Windows with VBS available, TrustletStore is backed by the IUM trustlet
// (isolateduserland). Everywhere else, a SoftwareTrustStore provides the same
// interface with a clearly-labeled software fallback (NOT hardware-isolated) so
// the engine remains testable and functional in development.
#ifndef SENTINEL_TRUSTLET_TRUSTLET_H
#define SENTINEL_TRUSTLET_TRUSTLET_H

#include <memory>
#include <string>

#include "sentinel/core/bytes.h"
#include "sentinel/core/result.h"

namespace sentinel {

class TrustStore {
public:
    virtual ~TrustStore() = default;

    // True if this store is backed by a hardware-isolated enclave (VTL1).
    virtual bool IsHardwareIsolated() const = 0;

    // Seal (encrypt + integrity-protect) a secret so only this store can unseal
    // it. Returns the sealed blob.
    virtual Result<Bytes> Seal(const Bytes& plaintext) = 0;
    virtual Result<Bytes> Unseal(const Bytes& sealed) = 0;

    // Sign / verify a verdict or config blob with the enclave-held key.
    virtual Result<Bytes> Sign(const Bytes& message) = 0;
    virtual bool Verify(const Bytes& message, const Bytes& signature) = 0;

    // The trust anchor: a stable public identity of this store (e.g. the public
    // key), used to pin update signatures and the rollback gate's anchor.
    virtual std::string TrustAnchor() const = 0;
};

// Software fallback. Clearly NOT hardware-isolated; used in development and on
// machines without VBS. Keys are derived and stored under a protected dir.
class SoftwareTrustStore : public TrustStore {
public:
    static Result<std::unique_ptr<SoftwareTrustStore>> Open(const std::string& dir);

    bool IsHardwareIsolated() const override { return false; }
    Result<Bytes> Seal(const Bytes& plaintext) override;
    Result<Bytes> Unseal(const Bytes& sealed) override;
    Result<Bytes> Sign(const Bytes& message) override;
    bool Verify(const Bytes& message, const Bytes& signature) override;
    std::string TrustAnchor() const override;

private:
    explicit SoftwareTrustStore(Bytes key) : key_(std::move(key)) {}
    Bytes key_;
};

// Factory: returns the best available store (VTL1 trustlet on capable Windows,
// else the software fallback), never null.
Result<std::unique_ptr<TrustStore>> OpenTrustStore(const std::string& dir);

}  // namespace sentinel

#endif  // SENTINEL_TRUSTLET_TRUSTLET_H
