#include "sentinel/core/logging.h"

#include <cstdio>
#include <ctime>
#include <mutex>

namespace sentinel {
namespace {

std::mutex g_mutex;
LogLevel g_level = LogLevel::Info;
std::FILE* g_file = nullptr;

void TimestampNow(char* buf, std::size_t n) {
    std::time_t t = std::time(nullptr);
    std::tm tm_buf{};
#if defined(_WIN32)
    localtime_s(&tm_buf, &t);
#else
    localtime_r(&t, &tm_buf);
#endif
    std::strftime(buf, n, "%Y-%m-%d %H:%M:%S", &tm_buf);
}

}  // namespace

void Log::SetLevel(LogLevel level) {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_level = level;
}

LogLevel Log::GetLevel() {
    std::lock_guard<std::mutex> lock(g_mutex);
    return g_level;
}

bool Log::SetFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_file) {
        std::fclose(g_file);
        g_file = nullptr;
    }
    if (path.empty()) return true;
    g_file = std::fopen(path.c_str(), "a");
    return g_file != nullptr;
}

void Log::CloseFile() {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_file) {
        std::fclose(g_file);
        g_file = nullptr;
    }
}

const char* Log::LevelName(LogLevel level) {
    switch (level) {
        case LogLevel::Trace: return "TRACE";
        case LogLevel::Debug: return "DEBUG";
        case LogLevel::Info: return "INFO";
        case LogLevel::Warn: return "WARN";
        case LogLevel::Error: return "ERROR";
        case LogLevel::Off: return "OFF";
    }
    return "INFO";
}

void Log::Write(LogLevel level, const std::string& message) {
    std::lock_guard<std::mutex> lock(g_mutex);
    if (level < g_level || g_level == LogLevel::Off) return;
    char ts[32];
    TimestampNow(ts, sizeof(ts));
    std::fprintf(stderr, "[%s] %-5s sentinel: %s\n", ts, LevelName(level), message.c_str());
    std::fflush(stderr);
    if (g_file) {
        std::fprintf(g_file, "[%s] %-5s sentinel: %s\n", ts, LevelName(level), message.c_str());
        std::fflush(g_file);
    }
}

}  // namespace sentinel
