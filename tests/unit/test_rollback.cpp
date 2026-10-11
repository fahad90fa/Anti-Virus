// Tests for the shadow-commit rollback gate: staging redirection, commit (writes
// reach the real disk), discard (perfect rollback), and the side-effect boundary.
#include <filesystem>
#include <fstream>

#include "sentinel/core/fs.h"
#include "sentinel/rollback/shadow_gate.h"
#include "sentinel_test.h"

using namespace sentinel;
namespace fs = std::filesystem;

static std::string TmpDir(const std::string& name) {
    auto base = fs::temp_directory_path() / ("sentinel_rb_" + name);
    std::error_code ec;
    fs::remove_all(base, ec);
    fs::create_directories(base, ec);
    return base.string();
}

TEST(ShadowGate, CommitPersistsWrites) {
    std::string root = TmpDir("commit");
    std::string shadow = root + "/shadow";
    std::string real = root + "/real/output.dat";

    ShadowGate gate(shadow);
    ASSERT_TRUE(gate.BeginSession(700).ok());
    EXPECT_TRUE(gate.IsGated(700));

    Bytes data = {'h', 'e', 'l', 'l', 'o'};
    Status st = gate.StageWriteData(700, real, data);
    ASSERT_TRUE(st.ok());
    // Before commit, the real file must NOT exist.
    EXPECT_FALSE(PathExists(real));

    ASSERT_TRUE(gate.Commit(700).ok());
    EXPECT_TRUE(PathExists(real));
    auto back = ReadFile(real);
    ASSERT_TRUE(back.ok());
    EXPECT_TRUE(back.value() == data);
    EXPECT_FALSE(gate.IsGated(700));
}

TEST(ShadowGate, DiscardLeavesNoRealWrite) {
    std::string root = TmpDir("discard");
    std::string shadow = root + "/shadow";
    std::string real = root + "/real/evil.locked";

    ShadowGate gate(shadow);
    ASSERT_TRUE(gate.BeginSession(701).ok());
    gate.StageWriteData(701, real, Bytes(32, 0xAA));
    EXPECT_FALSE(PathExists(real));

    ASSERT_TRUE(gate.Discard(701).ok());
    // Perfect rollback: nothing reached the real path.
    EXPECT_FALSE(PathExists(real));
    EXPECT_FALSE(gate.IsGated(701));
}

TEST(ShadowGate, SideEffectBoundary) {
    std::string shadow = TmpDir("sideeffect") + "/shadow";
    ShadowGate gate(shadow);
    gate.BeginSession(702);
    // Inter-process injection from a gated process must be denied.
    auto d = gate.OnSideEffect(702, SideEffect::InterProcess);
    EXPECT_EQ(d.disposition, SideEffectDecision::Disposition::Deny);
    // Network from a gated process is buffered until commit.
    auto n = gate.OnSideEffect(702, SideEffect::Network, 1024);
    EXPECT_EQ(n.disposition, SideEffectDecision::Disposition::Buffer);
}

TEST(ShadowGate, UngatedProcessNotStaged) {
    std::string shadow = TmpDir("ungated") + "/shadow";
    ShadowGate gate(shadow);
    EXPECT_FALSE(gate.IsGated(999));
}
