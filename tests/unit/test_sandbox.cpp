// Tests for the SENTVM unpacking emulator and the detonator. Synthetic programs
// only — no native code ever runs. See docs/sandbox-vm.md.
#include "sentinel/sandbox/detonator.h"
#include "sentinel/sandbox/emulator.h"
#include "sentinel_test.h"

using namespace sentinel;

TEST(Emulator, AssembleAndRunBasic) {
    Emulator emu;
    auto prog = Emulator::Assemble(
        "  MOV R0, 5\n"
        "  SYSCALL WriteFile\n"
        "  HALT\n");
    ASSERT_TRUE(prog.ok());
    EmulationResult r = emu.Run(prog.value());
    EXPECT_TRUE(r.completed);
    ASSERT_TRUE(r.syscalls.size() >= 1);
    EXPECT_STREQ(r.syscalls[0].name, "WriteFile");
}

TEST(Emulator, UnpacksEmbeddedBlob) {
    Emulator emu;
    // Decrypt two bytes from the data section (XOR 0x5A) into VM memory.
    // data[0]=0x58 ^ 0x5A = 0x02 ; data[1]=0x35 ^ 0x5A = 0x6F
    auto prog = Emulator::Assemble(
        "  LOADK R1, 0\n"
        "  XORK  R1, 0x5A\n"
        "  WRITE 0, R1\n"
        "  LOADK R1, 1\n"
        "  XORK  R1, 0x5A\n"
        "  WRITE 1, R1\n"
        "  HALT\n"
        "  .data 0x58 0x35\n");
    ASSERT_TRUE(prog.ok());
    EmulationResult r = emu.Run(prog.value());
    EXPECT_TRUE(r.completed);
    ASSERT_TRUE(r.unpacked_payload.size() >= 2);
    EXPECT_EQ((int)r.unpacked_payload[0], 0x02);
    EXPECT_EQ((int)r.unpacked_payload[1], 0x6F);
}

TEST(Emulator, RejectsUnknownMnemonic) {
    auto prog = Emulator::Assemble("  FROBNICATE R0\n");
    EXPECT_FALSE(prog.ok());
}

TEST(Emulator, InstructionLimitHalts) {
    Emulator emu;
    // Infinite loop: R0 stays non-zero, JNZ back to itself.
    auto prog = Emulator::Assemble(
        "start:\n"
        "  MOV R0, 1\n"
        "  JNZ R0, start\n");
    ASSERT_TRUE(prog.ok());
    EmulationResult r = emu.Run(prog.value(), 1000);
    EXPECT_FALSE(r.completed);
    EXPECT_EQ(r.instructions_executed, 1000);
}

TEST(Detonator, DetectsInjectionChain) {
    Detonator det;
    auto prog = Emulator::Assemble(
        "  SYSCALL VirtualAlloc\n"
        "  SYSCALL WriteProcessMemory\n"
        "  SYSCALL CreateRemoteThread\n"
        "  HALT\n");
    ASSERT_TRUE(prog.ok());
    DetonationReport r = det.Detonate(prog.value());
    EXPECT_EQ(r.observed_actions.size(), (std::size_t)3);
    EXPECT_GT(r.score, 0.7);
    bool injection = false;
    for (const auto& s : r.signals)
        if (s.source == SignalSource::Injection && s.level == RiskLevel::Malicious)
            injection = true;
    EXPECT_TRUE(injection);
}
