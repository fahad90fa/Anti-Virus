// Lightweight leveled logger. Thread-safe, lock-guarded, writes to stderr and
// optionally to a file sink. The EDR sealed log (edr/secure_log) is separate;
// this is operational logging for the engine itself.
#ifndef SENTINEL_CORE_LOGGING_H
#define SENTINEL_CORE_LOGGING_H

#include <sstream>
#include <string>

namespace sentinel {

enum class LogLevel : int {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
    Off = 5,
};

class Log {
public:
    static void SetLevel(LogLevel level);
    static LogLevel GetLevel();
    // Redirect output to a file (appends). Empty path restores stderr only.
    static bool SetFile(const std::string& path);
    static void CloseFile();

    static void Write(LogLevel level, const std::string& message);
    static const char* LevelName(LogLevel level);
};

// Stream-style logging: SENTINEL_LOG(Info) << "scanned " << n << " files";
class LogStream {
public:
    explicit LogStream(LogLevel level) : level_(level) {}
    ~LogStream() { Log::Write(level_, stream_.str()); }

    template <typename T>
    LogStream& operator<<(const T& value) {
        stream_ << value;
        return *this;
    }

private:
    LogLevel level_;
    std::ostringstream stream_;
};

}  // namespace sentinel

#define SENTINEL_LOG(lvl)                                      \
    if (::sentinel::Log::GetLevel() > ::sentinel::LogLevel::lvl) \
        ;                                                      \
    else                                                       \
        ::sentinel::LogStream(::sentinel::LogLevel::lvl)

#endif  // SENTINEL_CORE_LOGGING_H
