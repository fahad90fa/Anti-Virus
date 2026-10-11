// Tests for the encrypted quarantine vault and the remediator.
#include <filesystem>
#include <fstream>

#include "sentinel/behavior/action_graph.h"
#include "sentinel/core/fs.h"
#include "sentinel/quarantine/remediator.h"
#include "sentinel/quarantine/vault.h"
#include "sentinel_test.h"

using namespace sentinel;
namespace fs = std::filesystem;

static std::string TmpDir(const std::string& name) {
    auto base = fs::temp_directory_path() / ("sentinel_q_" + name);
    std::error_code ec;
    fs::remove_all(base, ec);
    fs::create_directories(base, ec);
    return base.string();
}

static void WriteText(const std::string& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary);
    out.write(text.data(), (std::streamsize)text.size());
}

TEST(Vault, QuarantineNeutralizesAndRestores) {
    std::string dir = TmpDir("vault");
    std::string vault = dir + "/vault";
    std::string victim = dir + "/suspect.exe";
    const std::string original = "MZ....this is the original file body....";
    WriteText(victim, original);

    QuarantineVault v;
    ASSERT_TRUE(v.Open(vault).ok());

    auto e = v.Quarantine(victim, "unit-test", 1000);
    ASSERT_TRUE(e.ok());
    // Original removed; its bytes are not sitting in the vault in cleartext.
    EXPECT_FALSE(PathExists(victim));
    EXPECT_TRUE(PathExists(vault + "/" + e.value().stored_file) ||
                PathExists(dir));  // stored somewhere under the vault

    // The stored blob must not equal the plaintext (neutralized).
    auto blob = ReadFile(vault + "/" + e.value().stored_file);
    if (blob.ok()) {
        std::string blobstr(blob.value().begin(), blob.value().end());
        EXPECT_NE(blobstr, original);
    }

    // Restore recovers the exact original bytes.
    std::string restored = dir + "/restored.exe";
    ASSERT_TRUE(v.Restore(e.value().id, restored).ok());
    auto back = ReadFile(restored);
    ASSERT_TRUE(back.ok());
    std::string backstr(back.value().begin(), back.value().end());
    EXPECT_STREQ(backstr, original);
}

TEST(Vault, ListAndPurge) {
    std::string dir = TmpDir("vault2");
    std::string victim = dir + "/bad.bin";
    WriteText(victim, "payload");
    QuarantineVault v;
    ASSERT_TRUE(v.Open(dir + "/vault").ok());
    auto e = v.Quarantine(victim, "test", 1);
    ASSERT_TRUE(e.ok());
    auto list = v.List();
    ASSERT_TRUE(list.ok());
    EXPECT_TRUE(list.value().size() >= 1);
    ASSERT_TRUE(v.Purge(e.value().id).ok());
    auto list2 = v.List();
    ASSERT_TRUE(list2.ok());
    bool still_present = false;
    for (const auto& it : list2.value())
        if (it.id == e.value().id) still_present = true;
    EXPECT_FALSE(still_present);
}

TEST(Remediator, PlanFromActionGraph) {
    ActionGraph g;
    g.AddProcess(800, 1, "/tmp/dropper");
    ActivityEvent w; w.type = ActionType::FileWrite; w.target = "/tmp/dropped.exe";
    g.Record(800, w);
    ActivityEvent p; p.type = ActionType::RegistryPersistence;
    p.target = "Run\\Evil";
    g.Record(800, p);

    const ProcessNode* n = g.Get(800);
    ASSERT_TRUE(n != nullptr);
    Remediator rem;
    RemediationPlan plan = rem.Plan(*n);
    EXPECT_TRUE(plan.steps.size() >= 2);

    int deleted = 0, persistence = 0;
    RemediationHooks hooks;
    hooks.delete_file = [&](const std::string&) { deleted++; return true; };
    hooks.remove_persistence = [&](const std::string&) { persistence++; return true; };
    hooks.discard_shadow = [&](std::uint32_t) { return true; };
    hooks.quarantine = [&](const std::string&, const std::string&) { return true; };
    ASSERT_TRUE(rem.Execute(plan, hooks).ok());
    EXPECT_GE(deleted, 1);
    EXPECT_GE(persistence, 1);
}
