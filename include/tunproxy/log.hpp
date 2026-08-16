#pragma once

#include <functional>
#include <string>
#include <string_view>

namespace tunproxy {

enum class LogLevel {
    Info,
    Warning,
    Progress,
};

using LogCallback = std::function<void(LogLevel, std::string_view)>;

inline void emitLog(const LogCallback& callback, LogLevel level, std::string message) {
    if (callback) {
        callback(level, message);
    }
}

} // namespace tunproxy
