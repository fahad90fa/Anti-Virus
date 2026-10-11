#include "sentinel/platform/process.h"

#include <cctype>

#if defined(_WIN32)
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#else
#include <unistd.h>
#include <filesystem>
#include <fstream>
#include <sstream>
#endif

namespace sentinel {

std::uint32_t CurrentProcessId() noexcept {
#if defined(_WIN32)
    return static_cast<std::uint32_t>(::GetCurrentProcessId());
#else
    return static_cast<std::uint32_t>(::getpid());
#endif
}

#if defined(_WIN32)

Result<std::vector<ProcessInfo>> EnumerateProcesses() {
    std::vector<ProcessInfo> out;
    HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        return Status::Error(ErrorCode::IoError, "CreateToolhelp32Snapshot failed");
    }
    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (::Process32FirstW(snap, &pe)) {
        do {
            ProcessInfo info;
            info.pid = pe.th32ProcessID;
            info.ppid = pe.th32ParentProcessID;
            // Convert wide name to UTF-8 (best effort).
            char name[MAX_PATH];
            int n = ::WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name,
                                          sizeof(name), nullptr, nullptr);
            if (n > 0) info.name = name;
            auto path = GetProcessImagePath(info.pid);
            if (path) info.image_path = path.value();
            out.push_back(std::move(info));
        } while (::Process32NextW(snap, &pe));
    }
    ::CloseHandle(snap);
    return out;
}

Result<std::string> GetProcessImagePath(std::uint32_t pid) {
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return Status::Error(ErrorCode::PermissionDenied, "OpenProcess failed");
    wchar_t buf[MAX_PATH];
    DWORD size = MAX_PATH;
    std::string result;
    if (::QueryFullProcessImageNameW(h, 0, buf, &size)) {
        char utf8[MAX_PATH * 2];
        int n = ::WideCharToMultiByte(CP_UTF8, 0, buf, -1, utf8, sizeof(utf8),
                                      nullptr, nullptr);
        if (n > 0) result = utf8;
    }
    ::CloseHandle(h);
    if (result.empty()) return Status::Error(ErrorCode::NotFound, "no image path");
    return result;
}

#else  // POSIX / Linux

namespace {
std::string ReadFirstLine(const std::string& path) {
    std::ifstream in(path);
    std::string line;
    std::getline(in, line);
    return line;
}
}  // namespace

Result<std::string> GetProcessImagePath(std::uint32_t pid) {
    std::error_code ec;
    const std::string link = "/proc/" + std::to_string(pid) + "/exe";
    auto target = std::filesystem::read_symlink(link, ec);
    if (ec) return Status::Error(ErrorCode::NotFound, "cannot read " + link);
    return target.string();
}

Result<std::vector<ProcessInfo>> EnumerateProcesses() {
    std::vector<ProcessInfo> out;
    std::error_code ec;
    for (auto it = std::filesystem::directory_iterator("/proc", ec);
         it != std::filesystem::directory_iterator(); it.increment(ec)) {
        if (ec) break;
        const std::string name = it->path().filename().string();
        if (name.empty() || !std::isdigit(static_cast<unsigned char>(name[0]))) continue;
        bool all_digit = true;
        for (char c : name) {
            if (!std::isdigit(static_cast<unsigned char>(c))) { all_digit = false; break; }
        }
        if (!all_digit) continue;

        ProcessInfo info;
        info.pid = static_cast<std::uint32_t>(std::stoul(name));

        // /proc/<pid>/stat: "pid (comm) state ppid ..."
        const std::string stat = ReadFirstLine("/proc/" + name + "/stat");
        const auto open_paren = stat.find('(');
        const auto close_paren = stat.rfind(')');
        if (open_paren != std::string::npos && close_paren != std::string::npos &&
            close_paren > open_paren) {
            info.name = stat.substr(open_paren + 1, close_paren - open_paren - 1);
            std::istringstream rest(stat.substr(close_paren + 1));
            std::string state;
            unsigned long ppid = 0;
            rest >> state >> ppid;
            info.ppid = static_cast<std::uint32_t>(ppid);
        }
        auto path = GetProcessImagePath(info.pid);
        if (path) info.image_path = path.value();
        out.push_back(std::move(info));
    }
    return out;
}

#endif

}  // namespace sentinel
