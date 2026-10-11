// Tests for deception (honeytokens), device control, low-level self-integrity,
// and the trustlet (software trust store).
#include <filesystem>
#include <fstream>

#include "sentinel/core/fs.h"
#include "sentinel/deception/honeytokens.h"
#include "sentinel/devicecontrol/usb_policy.h"
#include "sentinel/lowlevel/integrity.h"
#include "sentinel/lowlevel/intrinsics.h"
#include "sentinel/trustlet/trustlet.h"
#include "sentinel_test.h"

using namespace sentinel;
namespace fs = std::filesystem;

static std::string TmpDir(const std::string& name) {
    auto base = fs::temp_directory_path() / ("sentinel_misc_" + name);
    std::error_code ec;
    fs::remove_all(base, ec);
    fs::create_directories(base, ec);
    return base.string();
}

TEST(Honeytokens, PlantAndDetect) {
    std::string dir = TmpDir("decoy");
    HoneytokenManager hm;
    auto planted = hm.PlantCanaryFiles(dir, 3);
    ASSERT_TRUE(planted.ok());
    EXPECT_EQ(planted.value().size(), (std::size_t)3);
    for (const auto& p : planted.value()) {
        EXPECT_TRUE(PathExists(p));
        EXPECT_TRUE(hm.IsToken(p));
    }
    Signal s = hm.OnAccess(planted.value()[0], 1234);
    EXPECT_EQ(s.level, RiskLevel::Malicious);
    EXPECT_GT(s.confidence, 0.9);
}

TEST(UsbPolicy, BlockAllowDefault) {
    UsbPolicy policy;
    policy.SetDefault(DevicePolicy::MountReadOnly);
    RemovableDevice unknown; unknown.serial = "UNKNOWN123";
    EXPECT_EQ(policy.Evaluate(unknown).policy, DevicePolicy::MountReadOnly);
    EXPECT_TRUE(policy.Evaluate(unknown).scan_on_insert);

    policy.Allow("CORP-APPROVED");
    RemovableDevice ok; ok.serial = "CORP-APPROVED";
    EXPECT_EQ(policy.Evaluate(ok).policy, DevicePolicy::MountReadWrite);

    policy.Block("BADUSB");
    RemovableDevice bad; bad.serial = "BADUSB";
    EXPECT_EQ(policy.Evaluate(bad).policy, DevicePolicy::Block);
}

TEST(UsbPolicy, DataMovementExfilSignal) {
    UsbPolicy policy;
    // Large movement of many files should register as suspicious+.
    Signal s = policy.AssessDataMovement(500ull * 1024 * 1024,
                                         600ull * 1024 * 1024, 500);
    EXPECT_GE((int)s.level, (int)RiskLevel::LowRisk);
}

TEST(Intrinsics, DetectDoesNotCrash) {
    auto feat = lowlevel::DetectCpuFeatures();
    (void)feat;
    std::uint64_t t1 = lowlevel::ReadTimestampCounter();
    std::uint64_t t2 = lowlevel::ReadTimestampCounter();
    EXPECT_TRUE(t2 >= t1);  // monotonic within a run
}

TEST(SelfIntegrity, EnrollDetectsTamper) {
    std::string dir = TmpDir("integrity");
    std::string file = dir + "/protected.bin";
    { std::ofstream o(file, std::ios::binary); o << "known good content"; }

    SelfIntegrity si;
    ASSERT_TRUE(si.Enroll(file).ok());
    EXPECT_EQ(si.protected_count(), (std::size_t)1);
    EXPECT_TRUE(si.Verify().empty());  // intact

    { std::ofstream o(file, std::ios::binary); o << "TAMPERED content!!!"; }
    auto violations = si.Verify();
    EXPECT_EQ(violations.size(), (std::size_t)1);
}

TEST(Trustlet, SealUnsealRoundTrip) {
    std::string dir = TmpDir("trust");
    auto storeR = OpenTrustStore(dir);
    ASSERT_TRUE(storeR.ok());
    auto& store = storeR.value();

    Bytes secret = {'k', 'e', 'y', '-', 'm', 'a', 't', '1'};
    auto sealed = store->Seal(secret);
    ASSERT_TRUE(sealed.ok());
    EXPECT_FALSE(sealed.value() == secret);  // sealed form differs
    auto unsealed = store->Unseal(sealed.value());
    ASSERT_TRUE(unsealed.ok());
    EXPECT_TRUE(unsealed.value() == secret);
}

TEST(Trustlet, SignVerify) {
    std::string dir = TmpDir("trust2");
    auto storeR = OpenTrustStore(dir);
    ASSERT_TRUE(storeR.ok());
    auto& store = storeR.value();

    Bytes msg = {'v', 'e', 'r', 'd', 'i', 'c', 't'};
    auto sig = store->Sign(msg);
    ASSERT_TRUE(sig.ok());
    EXPECT_TRUE(store->Verify(msg, sig.value()));
    Bytes tampered = msg;
    tampered[0] = 'V';
    EXPECT_FALSE(store->Verify(tampered, sig.value()));
    EXPECT_FALSE(store->TrustAnchor().empty());
}
