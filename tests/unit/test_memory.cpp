// Tests for the memory & exploit layer: in-memory scan (RWX/injected), exploit
// guard technique scoring, and the LSASS credential-theft guard policy.
#include "sentinel/memory/exploit_guard.h"
#include "sentinel/memory/lsass_guard.h"
#include "sentinel/memory/mem_scan.h"
#include "sentinel_test.h"

using namespace sentinel;

TEST(MemScan, PrivateRwxIsSuspicious) {
    MemoryScanner scanner;
    MemoryRegion region;
    region.base = 0x10000;
    region.size = 0x1000;
    region.executable = true;
    region.writable = true;
    region.private_commit = true;
    region.image_backed = false;
    region.contents = Bytes(256, 0x90);  // NOP sled
    MemoryScanResult r = scanner.ScanRegion(1234, region);
    EXPECT_GT(r.score, 0.5);
    EXPECT_TRUE(r.signals.size() >= 1);
}

TEST(MemScan, ImageBackedRxIsClean) {
    MemoryScanner scanner;
    MemoryRegion region;
    region.executable = true;
    region.writable = false;
    region.image_backed = true;
    region.private_commit = false;
    region.contents = Bytes(256, 0x00);
    MemoryScanResult r = scanner.ScanRegion(1234, region);
    EXPECT_LT(r.score, 0.5);
}

TEST(ExploitGuard, WriteExecuteViolationConvicts) {
    ExploitGuard guard;
    ExploitContext ctx;
    ctx.pid = 10;
    ctx.executing_from_writable = true;
    Signal s = guard.Evaluate(ctx);
    EXPECT_EQ(s.level, RiskLevel::Malicious);
    EXPECT_GT(s.confidence, 0.7);
}

TEST(ExploitGuard, RopIndicatorsCorroborate) {
    ExploitGuard guard;
    ExploitContext ctx;
    ctx.return_into_non_image = true;
    ctx.stack_pivot_suspected = true;
    ctx.rop_gadget_chain_len = 5;
    Signal s = guard.Evaluate(ctx);
    EXPECT_GE((int)s.level, (int)RiskLevel::Suspicious);
}

TEST(LsassGuard, DeniesUntrustedReader) {
    LsassGuard guard;
    HandleRequest req;
    req.source_pid = 42;
    req.source_image = "C:/evil/mimikatz.exe";
    req.target_pid = 500;
    req.target_image = "C:/Windows/System32/lsass.exe";
    req.desired_access = 0x0010;  // PROCESS_VM_READ
    HandleDecision d = guard.Evaluate(req);
    EXPECT_TRUE(d.deny);
    EXPECT_EQ(d.signal.level, RiskLevel::Malicious);
}

TEST(LsassGuard, AllowsNonProtectedTarget) {
    LsassGuard guard;
    HandleRequest req;
    req.source_image = "C:/app/tool.exe";
    req.target_image = "C:/app/notepad.exe";
    req.desired_access = 0x0010;
    HandleDecision d = guard.Evaluate(req);
    EXPECT_FALSE(d.deny);
}
