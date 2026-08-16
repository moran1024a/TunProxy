#pragma once

#include <optional>
#include <string>
#include <utility>

namespace tunproxy {

enum class ErrorCode {
    Generic = 1,
    InvalidArguments = 2,
    InsufficientPrivileges = 3,
    InvalidConfiguration = 4,
    UpstreamUnreachable = 5,
    CoreVerificationFailure = 6,
    CoreDownloadFailure = 7,
    CoreStartFailure = 8,
    StateError = 9,
};

struct Error {
    ErrorCode code{ErrorCode::Generic};
    std::string message;
};

template <typename T>
class Result {
public:
    static Result success(T value) {
        Result result;
        result.value_ = std::move(value);
        return result;
    }

    static Result failure(Error error) {
        Result result;
        result.error_ = std::move(error);
        return result;
    }

    [[nodiscard]] bool ok() const { return value_.has_value(); }
    [[nodiscard]] const T& value() const { return *value_; }
    [[nodiscard]] T& value() { return *value_; }
    [[nodiscard]] const Error& error() const { return *error_; }

private:
    std::optional<T> value_;
    std::optional<Error> error_;
};

template <>
class Result<void> {
public:
    static Result success() { return Result(true, {}); }
    static Result failure(Error error) { return Result(false, std::move(error)); }

    [[nodiscard]] bool ok() const { return ok_; }
    [[nodiscard]] const Error& error() const { return error_; }

private:
    Result(bool ok, Error error) : ok_(ok), error_(std::move(error)) {}
    bool ok_;
    Error error_;
};

inline Error makeError(ErrorCode code, std::string message) {
    return Error{code, std::move(message)};
}

} // namespace tunproxy
