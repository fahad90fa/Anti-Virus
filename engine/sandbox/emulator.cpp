// SENTVM — a small, safe synthetic VM used to unpack and observe suspicious
// samples WITHOUT running native code. See docs/sandbox-vm.md for the model.
//
// Program layout produced by Assemble():
//   [4 bytes: code_length (LE)] [code bytes...] [data bytes...]
// Code is a stream of fixed-size instructions; the data section holds the
// embedded (possibly encrypted) blob that a packer stub decrypts into VM memory.
//
// Instruction encoding (opcode byte + operands):
//   0x00 NOP                         (1)
//   0x01 MOV   reg, imm32            (1+1+4)  reg = imm
//   0x02 LOADK reg, addr16           (1+1+2)  reg = data[addr]
//   0x03 XORK  reg, imm8             (1+1+1)  reg ^= imm
//   0x04 WRITE addr16, reg           (1+2+1)  mem[addr] = reg & 0xFF
//   0x05 SYSCALL id8                 (1+1)    record a synthetic syscall
//   0x06 JMP   addr16                (1+2)    pc = addr (code offset)
//   0x07 JNZ   reg, addr16           (1+1+2)  if reg != 0: pc = addr
//   0x08 HALT                        (1)
//   0x09 INC   reg                   (1+1)    reg += 1
//   0x0A DEC   reg                   (1+1)    reg -= 1
//   0x0B MOVR  dst, src              (1+1+1)  dst = src
#include "sentinel/sandbox/emulator.h"

#include <array>
#include <cctype>
#include <cstring>
#include <map>
#include <sstream>
#include <unordered_map>

namespace sentinel {
namespace {

enum Op : std::uint8_t {
    OP_NOP = 0x00, OP_MOV = 0x01, OP_LOADK = 0x02, OP_XORK = 0x03,
    OP_WRITE = 0x04, OP_SYSCALL = 0x05, OP_JMP = 0x06, OP_JNZ = 0x07,
    OP_HALT = 0x08, OP_INC = 0x09, OP_DEC = 0x0A, OP_MOVR = 0x0B,
};

constexpr std::size_t kVmMemory = 64 * 1024;
constexpr int kNumRegs = 8;

// Syscall id <-> name mapping shared by the assembler and the interpreter.
const std::map<std::string, std::uint8_t>& SyscallIds() {
    static const std::map<std::string, std::uint8_t> m = {
        {"VirtualAlloc", 1}, {"WriteProcessMemory", 2}, {"CreateRemoteThread", 3},
        {"WriteFile", 4}, {"Connect", 5}, {"RegSetValue", 6},
    };
    return m;
}

std::string SyscallName(std::uint8_t id) {
    for (const auto& kv : SyscallIds()) {
        if (kv.second == id) return kv.first;
    }
    return "Syscall" + std::to_string(id);
}

std::uint16_t Read16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0]) |
           (static_cast<std::uint16_t>(p[1]) << 8);
}
std::uint32_t Read32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}
void Put16(Bytes& b, std::uint16_t v) {
    b.push_back(static_cast<std::uint8_t>(v & 0xFF));
    b.push_back(static_cast<std::uint8_t>((v >> 8) & 0xFF));
}
void Put32(Bytes& b, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>((v >> (8 * i)) & 0xFF));
}

std::vector<std::string> Tokenize(const std::string& line) {
    std::vector<std::string> toks;
    std::string cur;
    for (char c : line) {
        if (c == ',' || std::isspace(static_cast<unsigned char>(c))) {
            if (!cur.empty()) { toks.push_back(cur); cur.clear(); }
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) toks.push_back(cur);
    return toks;
}

bool ParseReg(const std::string& t, int& out) {
    if (t.size() < 2 || (t[0] != 'R' && t[0] != 'r')) return false;
    char* end = nullptr;
    long v = std::strtol(t.c_str() + 1, &end, 10);
    if (end == t.c_str() + 1 || v < 0 || v >= kNumRegs) return false;
    out = static_cast<int>(v);
    return true;
}

bool ParseImm(const std::string& t, long& out) {
    char* end = nullptr;
    long v = std::strtol(t.c_str(), &end, 0);  // 0 => accept 0x.. and decimal
    if (end == t.c_str()) return false;
    out = v;
    return true;
}

// Fixed instruction sizes by opcode (for the label pre-pass).
int InstrSize(Op op) {
    switch (op) {
        case OP_NOP: case OP_HALT: return 1;
        case OP_SYSCALL: case OP_INC: case OP_DEC: return 2;
        case OP_XORK: case OP_MOVR: return 3;
        case OP_JMP: return 3;
        case OP_LOADK: case OP_WRITE: case OP_JNZ: return 4;
        case OP_MOV: return 6;
    }
    return 1;
}

}  // namespace

Result<Bytes> Emulator::Assemble(const std::string& source) {
    // Split into logical lines, stripping ';' comments.
    std::vector<std::string> lines;
    {
        std::istringstream in(source);
        std::string raw;
        while (std::getline(in, raw)) {
            auto semi = raw.find(';');
            if (semi != std::string::npos) raw = raw.substr(0, semi);
            lines.push_back(raw);
        }
    }

    // Pass 1: compute label -> code offset, and collect .data bytes.
    std::unordered_map<std::string, std::uint16_t> labels;
    Bytes data;
    std::uint16_t offset = 0;
    auto mnemonic_op = [](const std::string& m, Op& op) -> bool {
        static const std::unordered_map<std::string, Op> ops = {
            {"NOP", OP_NOP}, {"MOV", OP_MOV}, {"LOADK", OP_LOADK}, {"XORK", OP_XORK},
            {"WRITE", OP_WRITE}, {"SYSCALL", OP_SYSCALL}, {"JMP", OP_JMP},
            {"JNZ", OP_JNZ}, {"HALT", OP_HALT}, {"INC", OP_INC}, {"DEC", OP_DEC},
            {"MOVR", OP_MOVR}};
        std::string u;
        for (char c : m) u.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
        auto it = ops.find(u);
        if (it == ops.end()) return false;
        op = it->second;
        return true;
    };

    for (const auto& line : lines) {
        auto toks = Tokenize(line);
        if (toks.empty()) continue;
        if (toks[0].back() == ':') {  // label
            std::string name = toks[0].substr(0, toks[0].size() - 1);
            labels[name] = offset;
            toks.erase(toks.begin());
            if (toks.empty()) continue;
        }
        std::string head = toks[0];
        std::string headlow;
        for (char c : head) headlow.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        if (headlow == ".data") {
            for (std::size_t i = 1; i < toks.size(); ++i) {
                long v = 0;
                if (!ParseImm(toks[i], v)) {
                    return Status::Error(ErrorCode::ParseError,
                                         "bad .data byte: " + toks[i]);
                }
                data.push_back(static_cast<std::uint8_t>(v & 0xFF));
            }
            continue;
        }
        Op op;
        if (!mnemonic_op(head, op)) {
            return Status::Error(ErrorCode::ParseError, "unknown mnemonic: " + head);
        }
        offset = static_cast<std::uint16_t>(offset + InstrSize(op));
    }

    // Pass 2: emit code.
    Bytes code;
    auto resolve_addr = [&](const std::string& t, std::uint16_t& out) -> bool {
        auto it = labels.find(t);
        if (it != labels.end()) { out = it->second; return true; }
        long v = 0;
        if (!ParseImm(t, v) || v < 0 || v > 0xFFFF) return false;
        out = static_cast<std::uint16_t>(v);
        return true;
    };

    for (const auto& line : lines) {
        auto toks = Tokenize(line);
        if (toks.empty()) continue;
        if (toks[0].back() == ':') {
            toks.erase(toks.begin());
            if (toks.empty()) continue;
        }
        std::string head = toks[0];
        std::string headlow;
        for (char c : head) headlow.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        if (headlow == ".data") continue;

        Op op;
        mnemonic_op(head, op);  // already validated in pass 1
        auto need = [&](std::size_t n) -> bool { return toks.size() >= n + 1; };

        switch (op) {
            case OP_NOP: code.push_back(OP_NOP); break;
            case OP_HALT: code.push_back(OP_HALT); break;
            case OP_MOV: {
                int r; long imm;
                if (!need(2) || !ParseReg(toks[1], r) || !ParseImm(toks[2], imm))
                    return Status::Error(ErrorCode::ParseError, "bad MOV: " + line);
                code.push_back(OP_MOV);
                code.push_back(static_cast<std::uint8_t>(r));
                Put32(code, static_cast<std::uint32_t>(imm));
                break;
            }
            case OP_LOADK: {
                int r; std::uint16_t addr;
                if (!need(2) || !ParseReg(toks[1], r) || !resolve_addr(toks[2], addr))
                    return Status::Error(ErrorCode::ParseError, "bad LOADK: " + line);
                code.push_back(OP_LOADK);
                code.push_back(static_cast<std::uint8_t>(r));
                Put16(code, addr);
                break;
            }
            case OP_XORK: {
                int r; long imm;
                if (!need(2) || !ParseReg(toks[1], r) || !ParseImm(toks[2], imm))
                    return Status::Error(ErrorCode::ParseError, "bad XORK: " + line);
                code.push_back(OP_XORK);
                code.push_back(static_cast<std::uint8_t>(r));
                code.push_back(static_cast<std::uint8_t>(imm & 0xFF));
                break;
            }
            case OP_WRITE: {
                std::uint16_t addr; int r;
                if (!need(2) || !resolve_addr(toks[1], addr) || !ParseReg(toks[2], r))
                    return Status::Error(ErrorCode::ParseError, "bad WRITE: " + line);
                code.push_back(OP_WRITE);
                Put16(code, addr);
                code.push_back(static_cast<std::uint8_t>(r));
                break;
            }
            case OP_SYSCALL: {
                if (!need(1))
                    return Status::Error(ErrorCode::ParseError, "bad SYSCALL: " + line);
                std::uint8_t id = 0;
                auto it = SyscallIds().find(toks[1]);
                if (it != SyscallIds().end()) {
                    id = it->second;
                } else {
                    long v = 0;
                    if (!ParseImm(toks[1], v))
                        return Status::Error(ErrorCode::ParseError,
                                             "unknown syscall: " + toks[1]);
                    id = static_cast<std::uint8_t>(v & 0xFF);
                }
                code.push_back(OP_SYSCALL);
                code.push_back(id);
                break;
            }
            case OP_JMP: {
                std::uint16_t addr;
                if (!need(1) || !resolve_addr(toks[1], addr))
                    return Status::Error(ErrorCode::ParseError, "bad JMP: " + line);
                code.push_back(OP_JMP);
                Put16(code, addr);
                break;
            }
            case OP_JNZ: {
                int r; std::uint16_t addr;
                if (!need(2) || !ParseReg(toks[1], r) || !resolve_addr(toks[2], addr))
                    return Status::Error(ErrorCode::ParseError, "bad JNZ: " + line);
                code.push_back(OP_JNZ);
                code.push_back(static_cast<std::uint8_t>(r));
                Put16(code, addr);
                break;
            }
            case OP_INC: case OP_DEC: {
                int r;
                if (!need(1) || !ParseReg(toks[1], r))
                    return Status::Error(ErrorCode::ParseError, "bad INC/DEC: " + line);
                code.push_back(static_cast<std::uint8_t>(op));
                code.push_back(static_cast<std::uint8_t>(r));
                break;
            }
            case OP_MOVR: {
                int d, s;
                if (!need(2) || !ParseReg(toks[1], d) || !ParseReg(toks[2], s))
                    return Status::Error(ErrorCode::ParseError, "bad MOVR: " + line);
                code.push_back(OP_MOVR);
                code.push_back(static_cast<std::uint8_t>(d));
                code.push_back(static_cast<std::uint8_t>(s));
                break;
            }
        }
    }

    // Assemble final program: [code_len LE][code][data].
    Bytes program;
    Put32(program, static_cast<std::uint32_t>(code.size()));
    program.insert(program.end(), code.begin(), code.end());
    program.insert(program.end(), data.begin(), data.end());
    return program;
}

EmulationResult Emulator::Run(const Bytes& program, int max_instructions) const {
    EmulationResult result;
    if (program.size() < 4) {
        result.halt_reason = "program too short";
        return result;
    }
    const std::uint32_t code_len = Read32(program.data());
    if (4 + code_len > program.size()) {
        result.halt_reason = "corrupt header (code_len out of range)";
        return result;
    }
    const std::uint8_t* code = program.data() + 4;
    const std::uint8_t* data = code + code_len;
    const std::size_t data_len = program.size() - 4 - code_len;

    std::array<std::uint32_t, kNumRegs> regs{};
    std::vector<std::uint8_t> mem(kVmMemory, 0);
    bool mem_written = false;
    std::size_t min_w = kVmMemory, max_w = 0;

    std::uint32_t pc = 0;
    int executed = 0;
    while (executed < max_instructions) {
        if (pc >= code_len) { result.halt_reason = "ran off end of code"; break; }
        const Op op = static_cast<Op>(code[pc]);
        const int size = InstrSize(op);
        if (pc + static_cast<std::uint32_t>(size) > code_len) {
            result.halt_reason = "truncated instruction";
            break;
        }
        ++executed;

        switch (op) {
            case OP_NOP: pc += 1; break;
            case OP_HALT: result.completed = true; result.halt_reason = "HALT"; break;
            case OP_MOV:
                regs[code[pc + 1] % kNumRegs] = Read32(code + pc + 2);
                pc += 6; break;
            case OP_LOADK: {
                const std::uint16_t addr = Read16(code + pc + 2);
                regs[code[pc + 1] % kNumRegs] = (addr < data_len) ? data[addr] : 0;
                pc += 4; break;
            }
            case OP_XORK:
                regs[code[pc + 1] % kNumRegs] ^= code[pc + 2];
                pc += 3; break;
            case OP_WRITE: {
                const std::uint16_t addr = Read16(code + pc + 1);
                const std::uint8_t val =
                    static_cast<std::uint8_t>(regs[code[pc + 3] % kNumRegs] & 0xFF);
                if (addr < mem.size()) {
                    mem[addr] = val;
                    mem_written = true;
                    if (addr < min_w) min_w = addr;
                    if (addr > max_w) max_w = addr;
                }
                pc += 4; break;
            }
            case OP_SYSCALL: {
                EmulatedSyscall sc;
                sc.value = code[pc + 1];
                sc.name = SyscallName(code[pc + 1]);
                result.syscalls.push_back(sc);
                pc += 2; break;
            }
            case OP_JMP: {
                const std::uint16_t addr = Read16(code + pc + 1);
                if (addr >= code_len) { result.halt_reason = "JMP out of range"; goto done; }
                pc = addr; break;
            }
            case OP_JNZ: {
                const std::uint16_t addr = Read16(code + pc + 2);
                if (regs[code[pc + 1] % kNumRegs] != 0) {
                    if (addr >= code_len) { result.halt_reason = "JNZ out of range"; goto done; }
                    pc = addr;
                } else {
                    pc += 4;
                }
                break;
            }
            case OP_INC: regs[code[pc + 1] % kNumRegs] += 1; pc += 2; break;
            case OP_DEC: regs[code[pc + 1] % kNumRegs] -= 1; pc += 2; break;
            case OP_MOVR:
                regs[code[pc + 1] % kNumRegs] = regs[code[pc + 2] % kNumRegs];
                pc += 3; break;
            default:
                result.halt_reason = "illegal opcode";
                goto done;
        }
        if (result.completed) break;
    }
    if (executed >= max_instructions && !result.completed) {
        result.halt_reason = "instruction limit reached";
    }

done:
    result.instructions_executed = executed;
    if (mem_written && max_w >= min_w) {
        result.unpacked_payload.assign(mem.begin() + min_w, mem.begin() + max_w + 1);
    }
    return result;
}

}  // namespace sentinel
