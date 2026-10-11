// Tests for the behavioral engine: action graph counters, ransomware heuristic
// (canary + mass-encrypt), injection chain, ML model, and verdict fusion.
#include "sentinel/behavior/action_graph.h"
#include "sentinel/behavior/behavioral_engine.h"
#include "sentinel/behavior/injection.h"
#include "sentinel/behavior/ml_model.h"
#include "sentinel/behavior/ransomware.h"
#include "sentinel/behavior/verdict_fusion.h"
#include "sentinel/core/config.h"
#include "sentinel_test.h"

using namespace sentinel;

static ActivityEvent MakeAction(ActionType t, std::uint64_t ts, std::string target = "",
                         double entropy = 0.0) {
    ActivityEvent a;
    a.type = t;
    a.timestamp_ms = ts;
    a.target = std::move(target);
    a.entropy = entropy;
    return a;
}

TEST(ActionGraph, RecordsAndCounts) {
    ActionGraph g;
    g.AddProcess(100, 1, "/bin/test");
    g.Record(100, MakeAction(ActionType::FileWrite, 1, "/tmp/a", 7.9));
    g.Record(100, MakeAction(ActionType::FileWrite, 2, "/tmp/b", 7.8));
    g.Record(100, MakeAction(ActionType::RemoteThreadCreate, 3, "", 0));
    const ProcessNode* n = g.Get(100);
    ASSERT_TRUE(n != nullptr);
    EXPECT_EQ(n->files_written, (std::uint32_t)2);
    EXPECT_EQ(n->high_entropy_writes, (std::uint32_t)2);
    EXPECT_EQ(n->remote_threads, (std::uint32_t)1);
}

TEST(Ransomware, CanaryTouchIsMalicious) {
    Config cfg;
    RansomwareHeuristic r(cfg);
    r.AddCanary("/home/user/Documents/.sentinel_canary_1");
    ActionGraph g;
    g.AddProcess(200, 1, "/tmp/eviltool");
    g.Record(200, MakeAction(ActionType::FileWrite,
                             1, "/home/user/Documents/.sentinel_canary_1", 7.9));
    const ProcessNode* n = g.Get(200);
    ASSERT_TRUE(n != nullptr);
    Signal s = r.Evaluate(*n);
    EXPECT_EQ(s.level, RiskLevel::Malicious);
    EXPECT_GT(s.confidence, 0.8);
}

TEST(Ransomware, MassEncryptPattern) {
    Config cfg;
    cfg.ransomware_file_window = 10;
    RansomwareHeuristic r(cfg);
    ActionGraph g;
    g.AddProcess(201, 1, "/tmp/crypter");
    for (int i = 0; i < 20; ++i) {
        g.Record(201, MakeAction(ActionType::FileWrite, i,
                                 "/home/user/doc" + std::to_string(i), 7.95));
    }
    const ProcessNode* n = g.Get(201);
    ASSERT_TRUE(n != nullptr);
    Signal s = r.Evaluate(*n);
    EXPECT_GE((int)s.level, (int)RiskLevel::Suspicious);
    EXPECT_GT(s.confidence, 0.5);
}

TEST(Injection, FullChainConvicts) {
    InjectionHeuristic inj;
    ActionGraph g;
    g.AddProcess(300, 1, "/tmp/injector");
    g.Record(300, MakeAction(ActionType::MemoryAllocRemote, 1, "pid:400"));
    g.Record(300, MakeAction(ActionType::MemoryWriteRemote, 2, "pid:400"));
    g.Record(300, MakeAction(ActionType::RemoteThreadCreate, 3, "pid:400"));
    const ProcessNode* n = g.Get(300);
    ASSERT_TRUE(n != nullptr);
    Signal s = inj.Evaluate(*n);
    EXPECT_GE((int)s.level, (int)RiskLevel::Suspicious);
    EXPECT_GT(s.confidence, 0.6);
}

TEST(MlModel, BenignLowMaliciousHigh) {
    MlModel model;
    FeatureVector benign;  // all-zero features => low score
    double low = model.Score(benign);
    FeatureVector bad;
    bad.Set("remote_alloc_write", 1.0);
    bad.Set("remote_thread", 1.0);
    bad.Set("rwx_section", 1.0);
    bad.Set("high_entropy_writes", 1.0);
    double high = model.Score(bad);
    EXPECT_LT(low, high);
    EXPECT_GE(high, 0.0);
    EXPECT_LE(high, 1.0);
}

TEST(VerdictFusion, AllowlistShortCircuits) {
    Config cfg;
    VerdictFusion fusion(cfg);
    Verdict v = fusion.Fuse({}, /*allowlisted=*/true, /*blocklisted=*/false);
    EXPECT_EQ(v.level, RiskLevel::Trusted);
    EXPECT_EQ(v.action, Action::Allow);
}

TEST(VerdictFusion, BlocklistConvicts) {
    Config cfg;
    VerdictFusion fusion(cfg);
    Verdict v = fusion.Fuse({}, false, true);
    EXPECT_TRUE(v.IsMalicious());
    EXPECT_TRUE(v.BlocksExecution());
}

TEST(VerdictFusion, StrongSignalConvicts) {
    Config cfg;
    VerdictFusion fusion(cfg);
    std::vector<Signal> signals = {
        Signal(SignalSource::Ransomware, RiskLevel::Malicious, 0.97, "mass encrypt")};
    Verdict v = fusion.Fuse(signals);
    EXPECT_TRUE(v.IsMalicious());
}

TEST(VerdictFusion, WeakSignalsCorroborate) {
    Config cfg;
    VerdictFusion fusion(cfg);
    // Several weak signals should accumulate above a single one.
    std::vector<Signal> one = {
        Signal(SignalSource::PeHeuristic, RiskLevel::LowRisk, 0.3, "packed")};
    std::vector<Signal> many = {
        Signal(SignalSource::PeHeuristic, RiskLevel::LowRisk, 0.3, "packed"),
        Signal(SignalSource::YaraRule, RiskLevel::Suspicious, 0.4, "suspicious import"),
        Signal(SignalSource::Network, RiskLevel::Suspicious, 0.4, "beacon")};
    EXPECT_LT(fusion.Fuse(one).score, fusion.Fuse(many).score);
}

TEST(BehavioralEngine, ObserveAndAssessInjection) {
    Config cfg;
    BehavioralEngine eng(cfg);
    eng.Observe(500, 1, "/tmp/injector",
                MakeAction(ActionType::MemoryAllocRemote, 1, "pid:600"));
    eng.Observe(500, 1, "/tmp/injector",
                MakeAction(ActionType::MemoryWriteRemote, 2, "pid:600"));
    eng.Observe(500, 1, "/tmp/injector",
                MakeAction(ActionType::RemoteThreadCreate, 3, "pid:600"));
    BehavioralAssessment a = eng.Assess(500);
    EXPECT_EQ(a.pid, (std::uint32_t)500);
    EXPECT_GT(a.behavioral_score, 0.5);
}
