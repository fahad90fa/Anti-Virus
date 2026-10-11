// Tests for engine/core: SHA-256 vectors, entropy, hex, config, verdict model.
#include "sentinel/core/bytes.h"
#include "sentinel/core/config.h"
#include "sentinel/core/sha256.h"
#include "sentinel/core/types.h"
#include "sentinel_test.h"

using namespace sentinel;

TEST(Sha256, EmptyVector) {
    // FIPS 180-4 known answer for the empty string.
    EXPECT_STREQ(Sha256::HexDigest(std::string("")),
                 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(Sha256, AbcVector) {
    EXPECT_STREQ(Sha256::HexDigest(std::string("abc")),
                 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(Sha256, LongerVector) {
    EXPECT_STREQ(
        Sha256::HexDigest(std::string(
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
}

TEST(Sha256, IncrementalMatchesOneShot) {
    Sha256 h;
    h.Update(std::string("hello "));
    h.Update(std::string("world"));
    const std::string a = Sha256::ToHex(h.Final());
    const std::string b = Sha256::HexDigest(std::string("hello world"));
    EXPECT_STREQ(a, b);
}

TEST(Bytes, EntropyExtremes) {
    // All-zero buffer => zero entropy.
    Bytes zeros(256, 0);
    EXPECT_NEAR(ShannonEntropy(zeros), 0.0, 1e-9);
    // Every byte value once => maximum 8 bits/byte.
    Bytes uniform(256);
    for (int i = 0; i < 256; ++i) uniform[i] = static_cast<std::uint8_t>(i);
    EXPECT_NEAR(ShannonEntropy(uniform), 8.0, 1e-9);
}

TEST(Bytes, HexRoundTrip) {
    Bytes in = {0x00, 0x01, 0xab, 0xff, 0x10};
    const std::string hex = ToHex(in);
    EXPECT_STREQ(hex, "0001abff10");
    Bytes out;
    EXPECT_TRUE(FromHex(hex, out));
    EXPECT_TRUE(in == out);
    Bytes bad;
    EXPECT_FALSE(FromHex("abc", bad));   // odd length
    EXPECT_FALSE(FromHex("zz", bad));    // non-hex
}

TEST(Bytes, CaseInsensitiveSearch) {
    const std::string hay = "The Quick Brown Fox";
    EXPECT_TRUE(ContainsCaseInsensitive(
        reinterpret_cast<const std::uint8_t*>(hay.data()), hay.size(), "quick"));
    EXPECT_TRUE(ContainsCaseInsensitive(
        reinterpret_cast<const std::uint8_t*>(hay.data()), hay.size(), "FOX"));
    EXPECT_FALSE(ContainsCaseInsensitive(
        reinterpret_cast<const std::uint8_t*>(hay.data()), hay.size(), "cat"));
}

TEST(Config, SetAndThresholds) {
    Config cfg;
    EXPECT_TRUE(cfg.Set("block_threshold", "0.9"));
    EXPECT_NEAR(cfg.block_threshold, 0.9, 1e-9);
    EXPECT_TRUE(cfg.Set("enable_behavioral", "false"));
    EXPECT_FALSE(cfg.enable_behavioral);
    EXPECT_FALSE(cfg.Set("nonexistent_key", "x"));
}

TEST(Types, VerdictHelpers) {
    Verdict v;
    v.level = RiskLevel::Malicious;
    v.action = Action::KillAndRollback;
    EXPECT_TRUE(v.IsMalicious());
    EXPECT_TRUE(v.BlocksExecution());
    EXPECT_STREQ(ToString(RiskLevel::Malicious), "Malicious");
    EXPECT_STREQ(ToString(Action::Block), "Block");
    EXPECT_STREQ(ToString(SignalSource::Ransomware), "Ransomware");
}
