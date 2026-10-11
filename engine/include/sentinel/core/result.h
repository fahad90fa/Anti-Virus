// A minimal Result<T> / Status type so the engine can return errors without
// exceptions on the hot path. Kernel-adjacent code and the real-time scan path
// both avoid throwing; user-facing CLI code may convert a failed Status into a
// thrown exception at the boundary if it prefers.
#ifndef SENTINEL_CORE_RESULT_H
#define SENTINEL_CORE_RESULT_H

#include <string>
#include <utility>

namespace sentinel {

enum class ErrorCode : int {
    Ok = 0,
    NotFound = 1,
    IoError = 2,
    InvalidArgument = 3,
    ParseError = 4,
    PermissionDenied = 5,
    Unsupported = 6,
    Corrupt = 7,
    AlreadyExists = 8,
    Internal = 9,
    Timeout = 10,
};

class Status {
public:
    Status() = default;  // Ok
    Status(ErrorCode code, std::string message)
        : code_(code), message_(std::move(message)) {}

    static Status Ok() { return Status{}; }
    static Status Error(ErrorCode code, std::string message) {
        return Status{code, std::move(message)};
    }

    bool ok() const noexcept { return code_ == ErrorCode::Ok; }
    explicit operator bool() const noexcept { return ok(); }
    ErrorCode code() const noexcept { return code_; }
    const std::string& message() const noexcept { return message_; }

private:
    ErrorCode code_ = ErrorCode::Ok;
    std::string message_;
};

// Result<T>: either a value or a Status error. Keep it simple; no monadic sugar.
template <typename T>
class Result {
public:
    Result(T value) : status_(Status::Ok()), value_(std::move(value)), has_value_(true) {}
    Result(Status status) : status_(std::move(status)), has_value_(false) {}

    bool ok() const noexcept { return status_.ok() && has_value_; }
    explicit operator bool() const noexcept { return ok(); }

    const Status& status() const noexcept { return status_; }
    ErrorCode code() const noexcept { return status_.code(); }

    T& value() { return value_; }
    const T& value() const { return value_; }
    T value_or(T fallback) const { return has_value_ ? value_ : std::move(fallback); }

private:
    Status status_;
    T value_{};
    bool has_value_ = false;
};

}  // namespace sentinel

#endif  // SENTINEL_CORE_RESULT_H
