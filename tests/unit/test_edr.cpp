// Tests for the EDR layer: tamper-evident sealed log (append + verify + tamper
// detection), forensic timeline, and auto-containment decision logic.
#include <filesystem>
#include <fstream>

#include "sentinel/core/config.h"
#include "sentinel/edr/containment.h"
#include "sentinel/edr/secure_log.h"
#include "sentinel/edr/timeline.h"
#include "sentinel_test.h"

using namespace sentinel;
namespace fs = std::filesystem;

static std::string TmpDir(const std::string& name) {
    auto base = fs::temp_directory_path() / ("sentinel_edr_" + name);
    std::error_code ec;
    fs::remove_all(base, ec);
    fs::create_directories(base, ec);
    return base.string();
}

TEST(SecureLog, AppendVerifyIntact) {
    std::string path = TmpDir("log1") + "/sealed.log";
    SecureLog log;
    ASSERT_TRUE(log.Open(path).ok());
    ASSERT_TRUE(log.Append("detection", "eicar found", 100).ok());
    ASSERT_TRUE(log.Append("action", "quarantined", 200).ok());
    ASSERT_TRUE(log.Append("system", "update applied", 300).ok());
    EXPECT_EQ(log.count(), (std::uint64_t)3);
    EXPECT_TRUE(log.Verify().ok());

    auto all = log.ReadAll();
    ASSERT_TRUE(all.ok());
    EXPECT_EQ(all.value().size(), (std::size_t)3);
}

TEST(SecureLog, ReopenContinuesChain) {
    std::string path = TmpDir("log2") + "/sealed.log";
    {
        SecureLog log;
        ASSERT_TRUE(log.Open(path).ok());
        log.Append("system", "first", 1);
    }
    SecureLog log2;
    ASSERT_TRUE(log2.Open(path).ok());
    ASSERT_TRUE(log2.Append("system", "second", 2).ok());
    EXPECT_TRUE(log2.Verify().ok());
    EXPECT_EQ(log2.count(), (std::uint64_t)2);
}

TEST(SecureLog, TamperDetected) {
    std::string path = TmpDir("log3") + "/sealed.log";
    {
        SecureLog log;
        ASSERT_TRUE(log.Open(path).ok());
        log.Append("detection", "record one", 1);
        log.Append("detection", "record two", 2);
        log.Append("detection", "record three", 3);
    }
    // Tamper: flip bytes in the middle of the file.
    {
        std::fstream f(path, std::ios::in | std::ios::out | std::ios::binary);
        ASSERT_TRUE((bool)f);
        f.seekp(0, std::ios::end);
        std::streamoff size = f.tellp();
        if (size > 10) {
            f.seekp(size / 2);
            char c = 'Z';
            f.write(&c, 1);
        }
    }
    SecureLog log;
    // Tamper is caught either at Open (the broken chain is refused as the head)
    // or by an explicit Verify. Both are acceptable detections.
    Status opened = log.Open(path);
    EXPECT_TRUE(!opened.ok() || !log.Verify().ok());
}

TEST(Timeline, RecordsAndChainsByPid) {
    std::string path = TmpDir("tl") + "/timeline.log";
    Timeline tl;
    tl.Open(path);
    TimelineEvent e1; e1.pid = 10; e1.timestamp_ms = 1; e1.category = "process";
    e1.description = "launched"; e1.actor = "a.exe";
    TimelineEvent e2; e2.pid = 10; e2.timestamp_ms = 2; e2.category = "file";
    e2.description = "wrote x"; e2.actor = "a.exe";
    TimelineEvent e3; e3.pid = 20; e3.timestamp_ms = 3; e3.category = "process";
    e3.description = "other"; e3.actor = "b.exe";
    tl.Record(e1); tl.Record(e2); tl.Record(e3);
    EXPECT_EQ(tl.ChainForPid(10).size(), (std::size_t)2);
    EXPECT_EQ(tl.All().size(), (std::size_t)3);
}

TEST(Containment, IsolatesOnStrongVerdictOnly) {
    Config cfg;
    Containment c(cfg);
    bool applied = false;
    c.SetApplier([&](bool isolate) { applied = isolate; return true; });

    Verdict weak;
    weak.level = RiskLevel::Suspicious;
    weak.action = Action::HoldInShadow;
    weak.score = 0.5;
    EXPECT_FALSE(c.Decide(weak).isolate);

    Verdict strong;
    strong.level = RiskLevel::Malicious;
    strong.action = Action::KillAndRollback;
    strong.score = 0.97;
    EXPECT_TRUE(c.Decide(strong).isolate);

    EXPECT_TRUE(c.Isolate("strong detection"));
    EXPECT_EQ(c.state(), ContainmentState::Isolated);
    EXPECT_TRUE(applied);
    EXPECT_TRUE(c.Release());
    EXPECT_EQ(c.state(), ContainmentState::Normal);
}
