// End-to-end integration tests for the Sentinel engine facade. Drives the whole
// user-mode pipeline: EICAR self-test, tree scan with detection + quarantine,
// script-intent scan, quarantine round-trip, and behavioral process observation.
//
// Runs with the working directory at the repo root (set by ctest), so the real
// signatures/ database is loaded. Runtime state is redirected to a temp dir.
#include <filesystem>
#include <fstream>

#include "sentinel/core/config.h"
#include "sentinel/core/fs.h"
#include "sentinel/engine.h"
#include "sentinel_test.h"

using namespace sentinel;
namespace fs = std::filesystem;

static std::string EicarString() {
    return std::string("X5O!P%@AP[4\\PZX54(P^)7CC)7}") +
           "$EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*";
}

static Config TestConfig(const std::string& name) {
    auto base = fs::temp_directory_path() / ("sentinel_engine_" + name);
    std::error_code ec;
    fs::remove_all(base, ec);
    fs::create_directories(base, ec);
    Config cfg;
    cfg.state_dir = (base / "state").string();
    cfg.quarantine_dir = (base / "quarantine").string();
    cfg.shadow_dir = (base / "shadow").string();
    cfg.timeline_path = (base / "timeline.log").string();
    // signatures_* keep their defaults (repo-relative), loaded from the CWD.
    return cfg;
}

TEST(EngineIntegration, SelfTestPasses) {
    Engine engine(TestConfig("selftest"));
    ASSERT_TRUE(engine.Initialize().ok());
    auto r = engine.SelfTest();
    EXPECT_TRUE(r.eicar_detected);
    EXPECT_TRUE(r.clean_file_allowed);
    EXPECT_TRUE(r.sha256_ok);
    EXPECT_TRUE(r.Passed());
}

TEST(EngineIntegration, ScanTreeDetectsEicar) {
    Config cfg = TestConfig("tree");
    // A scan target dir with one EICAR file and one benign file.
    auto target = fs::temp_directory_path() / "sentinel_engine_tree/scan";
    std::error_code ec;
    fs::create_directories(target, ec);
    {
        std::ofstream o((target / "eicar.com").string(), std::ios::binary);
        const std::string e = EicarString();
        o.write(e.data(), (std::streamsize)e.size());
    }
    {
        std::ofstream o((target / "notes.txt").string(), std::ios::binary);
        o << "nothing to see here, a perfectly ordinary document";
    }

    Engine engine(cfg);
    ASSERT_TRUE(engine.Initialize().ok());
    TreeScanResult r = engine.ScanTree(target.string(), true);
    EXPECT_EQ(r.files_scanned, 2);
    EXPECT_GE(r.malicious, 1);
    // The EICAR file should have been quarantined (default policy).
    EXPECT_GE(r.quarantined, 1);
}

TEST(EngineIntegration, ScriptScanFlagsCradle) {
    Engine engine(TestConfig("script"));
    ASSERT_TRUE(engine.Initialize().ok());
    std::string cradle =
        "powershell -nop -w hidden -enc "
        "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8v"
        "MTI3LjAuMC4xL2EnKQ==";
    Verdict v = engine.ScanScript(cradle, "PowerShell");
    EXPECT_GE((int)v.level, (int)RiskLevel::Suspicious);
}

TEST(EngineIntegration, QuarantineRoundTrip) {
    Config cfg = TestConfig("quar");
    Engine engine(cfg);
    ASSERT_TRUE(engine.Initialize().ok());

    auto dir = fs::temp_directory_path() / "sentinel_engine_quar/files";
    std::error_code ec;
    fs::create_directories(dir, ec);
    std::string victim = (dir / "suspect.bin").string();
    { std::ofstream o(victim, std::ios::binary); o << "suspicious body"; }

    auto e = engine.QuarantineFile(victim, "integration-test");
    ASSERT_TRUE(e.ok());
    EXPECT_FALSE(PathExists(victim));

    auto list = engine.ListQuarantine();
    ASSERT_TRUE(list.ok());
    EXPECT_GE(list.value().size(), (std::size_t)1);

    std::string restored = (dir / "restored.bin").string();
    ASSERT_TRUE(engine.RestoreQuarantined(e.value().id, restored).ok());
    EXPECT_TRUE(PathExists(restored));
}

TEST(EngineIntegration, ObserveInjectionChainConvicts) {
    Engine engine(TestConfig("inject"));
    ASSERT_TRUE(engine.Initialize().ok());

    ActivityEvent a1; a1.type = ActionType::MemoryAllocRemote; a1.target = "pid:600";
    ActivityEvent a2; a2.type = ActionType::MemoryWriteRemote; a2.target = "pid:600";
    ActivityEvent a3; a3.type = ActionType::RemoteThreadCreate; a3.target = "pid:600";
    engine.ObserveProcessAction(600, 1, "/tmp/injector", a1);
    engine.ObserveProcessAction(600, 1, "/tmp/injector", a2);
    Verdict v = engine.ObserveProcessAction(600, 1, "/tmp/injector", a3);
    EXPECT_GE((int)v.level, (int)RiskLevel::Suspicious);
}
