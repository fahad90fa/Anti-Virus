// sentinel-cli / sentinel service entry point.
//
// With a subcommand it acts as a CLI exposing every Phase 0 capability; the
// `watch` subcommand runs it as the always-on real-time service. No kernel
// driver is required — the folder watcher is the Phase 0 stand-in for the
// minifilter, and the full engine (static scan, behavior, script analysis,
// quarantine, rollback, EDR) runs in user mode.
//
//   sentinel <command> [options]
//
// Commands:
//   scan <path> [--recursive]            Scan a file or directory tree
//   watch <dir>... [--recursive]         Real-time watch + scan (the service)
//   selftest                             EICAR detection self-test
//   script <file>                        Analyze a script file for intent
//   quarantine list                      List the quarantine vault
//   quarantine restore <id> [dest]       Restore a quarantined item
//   config                               Print the effective configuration
//   version                              Print version information
//
// Global options:
//   --config <file>        Load key=value config
//   --set key=value        Override a single config value (repeatable)
//   --signatures <dir>     Signature database directory
//   --state <dir>          Runtime state directory
//   --log <level>          trace|debug|info|warn|error|off
#include <atomic>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "sentinel/core/config.h"
#include "sentinel/core/fs.h"
#include "sentinel/core/logging.h"
#include "sentinel/engine.h"
#include "sentinel/service/filter_service.h"
#include "sentinel/service/service.h"

using namespace sentinel;

namespace {

constexpr const char* kVersion = "Sentinel AV engine 0.1.0 (Phase 0 user-mode)";

Service* g_service = nullptr;
std::atomic<bool> g_filter_stop{false};

void HandleSignal(int) {
    if (g_service) g_service->Stop();
    g_filter_stop.store(true);
}

void PrintUsage() {
    std::printf(
        "%s\n\n"
        "Usage: sentinel <command> [options]\n\n"
        "Commands:\n"
        "  scan <path> [--recursive]          Scan a file or directory tree\n"
        "  watch <dir>... [--recursive]       Real-time watch + scan (user-mode)\n"
        "  service [--fail-closed]            Connect to the kernel minifilter port (Windows)\n"
        "  selftest                           EICAR detection self-test\n"
        "  script <file>                      Analyze a script file for intent\n"
        "  quarantine list                    List the quarantine vault\n"
        "  quarantine restore <id> [dest]     Restore a quarantined item\n"
        "  config                             Print the effective configuration\n"
        "  version                            Print version information\n\n"
        "Global options:\n"
        "  --config <file>    Load key=value config\n"
        "  --set key=value    Override one config value (repeatable)\n"
        "  --signatures <dir> Signature database directory\n"
        "  --state <dir>      Runtime state directory\n"
        "  --log <level>      trace|debug|info|warn|error|off\n",
        kVersion);
}

const char* RiskColor(RiskLevel l) {
    switch (l) {
        case RiskLevel::Malicious: return "\x1b[31m";   // red
        case RiskLevel::Suspicious: return "\x1b[33m";  // yellow
        case RiskLevel::LowRisk: return "\x1b[33m";
        case RiskLevel::Trusted: return "\x1b[32m";     // green
        default: return "";
    }
}

void PrintVerdict(const std::string& target, const Verdict& v, bool quarantined) {
    const char* color = RiskColor(v.level);
    std::printf("%s%-10s\x1b[0m %-16s %-6.2f  %s%s\n", color, ToString(v.level),
                ToString(v.action), v.score, target.c_str(),
                quarantined ? "  [quarantined]" : "");
    if (!v.summary.empty()) {
        std::printf("            %s\n", v.summary.c_str());
    }
    for (const auto& s : v.signals) {
        std::printf("              - %-12s %-10s conf=%.2f %s\n",
                    ToString(s.source), ToString(s.level), s.confidence,
                    s.detail.c_str());
    }
}

// Parse global options, mutating cfg and returning the positional args.
std::vector<std::string> ParseGlobals(int argc, char** argv, Config& cfg) {
    std::vector<std::string> positional;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&](const char* name) -> std::string {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "%s requires an argument\n", name);
                return "";
            }
            return argv[++i];
        };
        if (a == "--config") {
            cfg.LoadFromFile(next("--config"));
        } else if (a == "--set") {
            std::string kv = next("--set");
            auto eq = kv.find('=');
            if (eq != std::string::npos) cfg.Set(kv.substr(0, eq), kv.substr(eq + 1));
        } else if (a == "--signatures") {
            cfg.Set("signatures_dir", next("--signatures"));
        } else if (a == "--state") {
            cfg.Set("state_dir", next("--state"));
        } else if (a == "--log") {
            cfg.Set("log_level", next("--log"));
        } else {
            positional.push_back(a);
        }
    }
    return positional;
}

bool HasFlag(const std::vector<std::string>& args, const std::string& flag) {
    for (const auto& a : args) if (a == flag) return true;
    return false;
}

int CmdScan(Engine& engine, const std::vector<std::string>& args) {
    // args[0] == "scan"
    std::string path;
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i][0] != '-') { path = args[i]; break; }
    }
    if (path.empty()) {
        std::fprintf(stderr, "scan: missing <path>\n");
        return 2;
    }
    bool recursive = HasFlag(args, "--recursive") || HasFlag(args, "-r");

    if (IsDirectory(path)) {
        TreeScanResult r = engine.ScanTree(path, recursive);
        std::printf("Scanned %d file(s): %d malicious, %d suspicious, %d quarantined\n",
                    r.files_scanned, r.malicious, r.suspicious, r.quarantined);
        for (const auto& d : r.detections) {
            PrintVerdict(d.path, d.verdict, d.quarantined);
        }
        return r.malicious > 0 ? 1 : 0;
    }

    FileScanResult r = engine.ScanFile(path);
    PrintVerdict(path, r.verdict, r.quarantined);
    return r.verdict.IsMalicious() ? 1 : 0;
}

int CmdSelfTest(Engine& engine) {
    auto r = engine.SelfTest();
    std::printf("EICAR detected:      %s\n", r.eicar_detected ? "yes" : "NO");
    std::printf("Clean file allowed:  %s\n", r.clean_file_allowed ? "yes" : "NO");
    std::printf("SHA-256 self-check:  %s\n", r.sha256_ok ? "yes" : "NO");
    if (!r.detail.empty()) std::printf("Detail: %s\n", r.detail.c_str());
    std::printf("\nSelf-test %s\n", r.Passed() ? "PASSED" : "FAILED");
    return r.Passed() ? 0 : 1;
}

int CmdScript(Engine& engine, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::fprintf(stderr, "script: missing <file>\n");
        return 2;
    }
    auto content = ReadFile(args[1]);
    if (!content) {
        std::fprintf(stderr, "cannot read %s\n", args[1].c_str());
        return 1;
    }
    std::string text(content.value().begin(), content.value().end());
    Verdict v = engine.ScanScript(text, FileName(args[1]));
    PrintVerdict(args[1], v, false);
    return v.IsMalicious() ? 1 : 0;
}

int CmdQuarantine(Engine& engine, const std::vector<std::string>& args) {
    if (args.size() < 2) {
        std::fprintf(stderr, "quarantine: list | restore <id> [dest]\n");
        return 2;
    }
    if (args[1] == "list") {
        auto list = engine.ListQuarantine();
        if (!list) {
            std::fprintf(stderr, "cannot read vault: %s\n", list.status().message().c_str());
            return 1;
        }
        if (list.value().empty()) {
            std::printf("Quarantine vault is empty.\n");
            return 0;
        }
        for (const auto& e : list.value()) {
            std::printf("  %s  %s\n      reason: %s  sha256: %.16s...\n",
                        e.id.c_str(), e.original_path.c_str(),
                        e.detection_reason.c_str(), e.sha256.c_str());
        }
        return 0;
    }
    if (args[1] == "restore") {
        if (args.size() < 3) {
            std::fprintf(stderr, "quarantine restore <id> [dest]\n");
            return 2;
        }
        std::string dest = args.size() > 3 ? args[3] : "";
        Status s = engine.RestoreQuarantined(args[2], dest);
        if (!s.ok()) {
            std::fprintf(stderr, "restore failed: %s\n", s.message().c_str());
            return 1;
        }
        std::printf("Restored %s\n", args[2].c_str());
        return 0;
    }
    std::fprintf(stderr, "unknown quarantine subcommand: %s\n", args[1].c_str());
    return 2;
}

int CmdConfig(const Config& cfg) {
    for (const auto& kv : cfg.AsMap()) {
        std::printf("%-24s = %s\n", kv.first.c_str(), kv.second.c_str());
    }
    return 0;
}

int CmdWatch(const Config& cfg, const std::vector<std::string>& args) {
    std::vector<std::string> dirs;
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i][0] != '-') dirs.push_back(args[i]);
    }
    if (dirs.empty()) {
        std::fprintf(stderr, "watch: missing <dir>\n");
        return 2;
    }
    bool recursive = HasFlag(args, "--recursive") || HasFlag(args, "-r");

    Service service(cfg);
    g_service = &service;
    std::signal(SIGINT, HandleSignal);
    std::signal(SIGTERM, HandleSignal);

    Status s = service.Initialize();
    if (!s.ok()) {
        std::fprintf(stderr, "initialize failed: %s\n", s.message().c_str());
        return 1;
    }
    std::printf("Sentinel real-time protection active. Watching %zu dir(s). Ctrl-C to stop.\n",
                dirs.size());
    service.Run(dirs, recursive);
    std::printf("Scanned %llu file(s), blocked %llu threat(s).\n",
                static_cast<unsigned long long>(service.files_scanned()),
                static_cast<unsigned long long>(service.threats_blocked()));
    g_service = nullptr;
    return 0;
}

int CmdService(const Config& cfg, const std::vector<std::string>& args) {
    // Windows real-time service: connect to the minifilter port and answer
    // verdicts from the engine. On non-Windows this reports Unsupported (use
    // `watch` there). Fail-open by default; --fail-closed denies unknowns when
    // the engine cannot produce a verdict in time.
    FilterServiceOptions opts;
    opts.fail_closed = HasFlag(args, "--fail-closed");

    Engine engine(cfg);
    Status init = engine.Initialize();
    if (!init.ok()) {
        std::fprintf(stderr, "engine init failed: %s\n", init.message().c_str());
        return 1;
    }
    std::signal(SIGINT, HandleSignal);
    std::signal(SIGTERM, HandleSignal);
    g_filter_stop.store(false);

    std::printf("Sentinel filter service starting (%s). Ctrl-C to stop.\n",
                opts.fail_closed ? "fail-closed" : "fail-open");
    Status s = RunFilterService(engine, opts, g_filter_stop);
    if (!s.ok()) {
        std::fprintf(stderr, "filter service: %s\n", s.message().c_str());
        return s.code() == ErrorCode::Unsupported ? 2 : 1;
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    Config cfg;
    std::vector<std::string> args = ParseGlobals(argc, argv, cfg);
    Log::SetLevel(cfg.log_level);

    if (args.empty()) {
        PrintUsage();
        return 2;
    }

    const std::string& cmd = args[0];
    if (cmd == "version" || cmd == "--version" || cmd == "-v") {
        std::printf("%s\n", kVersion);
        return 0;
    }
    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        PrintUsage();
        return 0;
    }
    if (cmd == "config") {
        return CmdConfig(cfg);
    }
    if (cmd == "watch") {
        return CmdWatch(cfg, args);
    }
    if (cmd == "service") {
        return CmdService(cfg, args);
    }

    // Commands that need a live engine.
    Engine engine(cfg);
    Status init = engine.Initialize();
    if (!init.ok()) {
        std::fprintf(stderr, "engine init failed: %s\n", init.message().c_str());
        return 1;
    }

    if (cmd == "scan") return CmdScan(engine, args);
    if (cmd == "selftest") return CmdSelfTest(engine);
    if (cmd == "script") return CmdScript(engine, args);
    if (cmd == "quarantine") return CmdQuarantine(engine, args);

    std::fprintf(stderr, "unknown command: %s\n\n", cmd.c_str());
    PrintUsage();
    return 2;
}
