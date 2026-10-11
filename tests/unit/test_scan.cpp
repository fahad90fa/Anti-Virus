// Tests for the static scan engine: hash store, rule engine (incl. EICAR and
// condition grammar), PE parser heuristics, verdict cache, and the combined
// static scanner.
#include "sentinel/core/config.h"
#include "sentinel/scan/cache.h"
#include "sentinel/scan/hash_store.h"
#include "sentinel/scan/pe_parser.h"
#include "sentinel/scan/rule_engine.h"
#include "sentinel/scan/static_scanner.h"
#include "sentinel/scan/subject.h"
#include "sentinel_test.h"

using namespace sentinel;

// The canonical EICAR string, assembled at runtime (not stored verbatim).
static std::string EicarString() {
    return std::string("X5O!P%@AP[4\\PZX54(P^)7CC)7}") +
           "$EICAR-STANDARD-ANTIVIRUS-" + "TEST-FILE!$H+H*";
}

TEST(HashStore, AllowAndBlock) {
    HashStore store;
    store.AddBlocked("abc123", "Win32.Test");
    store.AddAllowed("def456");
    EXPECT_EQ(store.Lookup("ABC123"), HashVerdict::Blocked);  // case-insensitive
    EXPECT_EQ(store.Lookup("def456"), HashVerdict::Allowed);
    EXPECT_EQ(store.Lookup("000000"), HashVerdict::Unknown);
    EXPECT_STREQ(store.BlockedLabel("abc123"), "Win32.Test");
}

TEST(RuleEngine, EicarTextRule) {
    RuleSet rules;
    Status s = rules.ParseText(
        "rule Eicar : test {\n"
        "  meta:\n"
        "    description = \"EICAR test\"\n"
        "    severity = \"high\"\n"
        "    weight = 0.95\n"
        "  strings:\n"
        "    $m = \"EICAR-STANDARD-ANTIVIRUS-TEST-FILE\"\n"
        "  condition:\n"
        "    any of them\n"
        "}\n");
    ASSERT_TRUE(s.ok());
    EXPECT_EQ(rules.rule_count(), (std::size_t)1);

    const std::string eicar = EicarString();
    std::vector<RuleMatch> matches;
    rules.Match(reinterpret_cast<const std::uint8_t*>(eicar.data()), eicar.size(),
                matches);
    ASSERT_TRUE(matches.size() >= 1);
    EXPECT_STREQ(matches[0].rule_id, "Eicar");
}

TEST(RuleEngine, ConditionAllAndCount) {
    RuleSet rules;
    ASSERT_TRUE(rules.ParseText(
        "rule TwoOfThree {\n"
        "  strings:\n"
        "    $a = \"alpha\"\n"
        "    $b = \"bravo\"\n"
        "    $c = \"charlie\"\n"
        "  condition:\n"
        "    2 of them\n"
        "}\n").ok());

    std::string two = "has alpha and bravo";
    std::string one = "only alpha here";
    std::vector<RuleMatch> m1, m2;
    rules.Match(reinterpret_cast<const std::uint8_t*>(two.data()), two.size(), m1);
    rules.Match(reinterpret_cast<const std::uint8_t*>(one.data()), one.size(), m2);
    EXPECT_TRUE(m1.size() >= 1);
    EXPECT_EQ(m2.size(), (std::size_t)0);
}

TEST(RuleEngine, HexPatternWithWildcard) {
    RuleSet rules;
    ASSERT_TRUE(rules.ParseText(
        "rule HexPat {\n"
        "  strings:\n"
        "    $h = { DE AD ?? EF }\n"
        "  condition:\n"
        "    $h\n"
        "}\n").ok());
    std::uint8_t data[] = {0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x11};
    std::vector<RuleMatch> m;
    rules.Match(data, sizeof(data), m);
    EXPECT_TRUE(m.size() >= 1);
}

TEST(RuleEngine, MalformedRuleRejected) {
    RuleSet rules;
    Status s = rules.ParseText("rule Broken { this is not valid ");
    EXPECT_FALSE(s.ok());
}

TEST(PeParser, NonPeRejected) {
    Bytes notpe = {'h', 'e', 'l', 'l', 'o'};
    auto r = PeParser::Parse(notpe);
    EXPECT_FALSE(r.ok());
}

TEST(PeParser, MinimalPeHeaderParses) {
    // Build a minimal PE: MZ at 0, e_lfanew=0x40, "PE\0\0" there, a COFF header.
    Bytes pe(0x200, 0);
    pe[0] = 'M'; pe[1] = 'Z';
    pe[0x3C] = 0x40;  // e_lfanew = 0x40
    pe[0x40] = 'P'; pe[0x41] = 'E'; pe[0x42] = 0; pe[0x43] = 0;
    // COFF: Machine (0x8664), NumberOfSections=0 at 0x46
    pe[0x44] = 0x64; pe[0x45] = 0x86;
    // Optional header magic 0x20b (PE32+) at 0x58 (0x40 + 24)
    pe[0x58] = 0x0b; pe[0x59] = 0x02;
    auto r = PeParser::Parse(pe);
    ASSERT_TRUE(r.ok());
    EXPECT_TRUE(r.value().is_pe);
    EXPECT_TRUE(r.value().is_64bit);
}

TEST(VerdictCache, PutGetEvict) {
    VerdictCache cache(2);
    Verdict v;
    v.level = RiskLevel::Trusted;
    cache.Put("a", v);
    cache.Put("b", v);
    Verdict out;
    EXPECT_TRUE(cache.Get("a", out));
    cache.Put("c", v);  // evicts LRU ("b", since "a" was just touched)
    EXPECT_TRUE(cache.Get("a", out));
    EXPECT_TRUE(cache.Get("c", out));
    EXPECT_FALSE(cache.Get("b", out));
}

TEST(StaticScanner, EicarBufferIsMalicious) {
    Config cfg;  // uses signatures/ relative to the test working dir (repo root)
    StaticScanner scanner(cfg);
    scanner.LoadSignatures();
    const std::string eicar = EicarString();
    FileSubject s = FileSubject::FromBuffer(
        Bytes(eicar.begin(), eicar.end()), "eicar.com");
    Verdict v = scanner.Scan(s);
    EXPECT_TRUE(v.IsMalicious());
    EXPECT_TRUE(v.BlocksExecution());
}

TEST(StaticScanner, BenignBufferAllowed) {
    Config cfg;
    StaticScanner scanner(cfg);
    scanner.LoadSignatures();
    std::string benign = "This is an ordinary, harmless text document. Nothing to see.";
    FileSubject s = FileSubject::FromBuffer(
        Bytes(benign.begin(), benign.end()), "notes.txt");
    Verdict v = scanner.Scan(s);
    EXPECT_FALSE(v.IsMalicious());
}
