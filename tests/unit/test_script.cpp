// Tests for script de-obfuscation and intent classification.
#include <string>

#include "sentinel/core/config.h"
#include "sentinel/script/classifier.h"
#include "sentinel/script/deobfuscator.h"
#include "sentinel/script/script_analyzer.h"
#include "sentinel_test.h"

using namespace sentinel;

TEST(Deobfuscator, Base64RoundTrip) {
    // "Sentinel" -> base64 "U2VudGluZWw="
    EXPECT_STREQ(Deobfuscator::Base64Decode("U2VudGluZWw="), "Sentinel");
    EXPECT_STREQ(Deobfuscator::Base64Decode(""), "");
}

TEST(Deobfuscator, PeelsEncodedCommand) {
    Deobfuscator d;
    // base64 of "IEX (do bad things)" style content with markers.
    // "SUVYIGJhZA==" is base64 for "IEX bad".
    std::string script = "powershell -enc SUVYIGJhZA==";
    DeobfuscationResult r = d.Deobfuscate(script);
    EXPECT_TRUE(r.found_encoded_command);
    EXPECT_GE(r.layers_peeled, 1);
}

TEST(Classifier, FlagsDownloadExecute) {
    ScriptClassifier c;
    std::string s = "IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1/x')";
    ScriptIntent intent = c.Classify(s, 0);
    EXPECT_TRUE(intent.download_execute || intent.in_memory_execution);
    EXPECT_GT(intent.score, 0.4);
}

TEST(Classifier, BenignScoresLow) {
    ScriptClassifier c;
    std::string s = "Get-ChildItem -Path C:/Users/Public -Filter *.txt | Format-Table";
    ScriptIntent intent = c.Classify(s, 0);
    EXPECT_FALSE(intent.download_execute);
    EXPECT_LT(intent.score, 0.4);
}

TEST(Classifier, FlagsAmsiBypass) {
    ScriptClassifier c;
    std::string s = "[Ref].Assembly.GetType('...AmsiUtils').GetField('amsiInitFailed')";
    ScriptIntent intent = c.Classify(s, 2);
    EXPECT_TRUE(intent.amsi_bypass);
    EXPECT_GT(intent.score, 0.4);
}

TEST(ScriptAnalyzer, MaliciousCradleSignal) {
    ScriptAnalyzer a;
    std::string s =
        "powershell -nop -w hidden -enc "
        "SUVYIChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwOi8v"
        "MTI3LjAuMC4xL2EnKQ==";
    ScriptAnalysis an = a.Analyze(s);
    EXPECT_GE((int)an.signal.level, (int)RiskLevel::Suspicious);
}

TEST(ScriptAnalyzer, BenignScriptSignalLow) {
    ScriptAnalyzer a;
    std::string s = "Write-Output 'hello world'";
    ScriptAnalysis an = a.Analyze(s);
    EXPECT_LT(an.intent.score, 0.4);
}
