#pragma once

#include "tunproxy/result.hpp"

#include <chrono>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace tunproxy {

struct ProcessOutput {
    int exit_code{-1};
    std::string stdout_text;
    std::string stderr_text;
};

enum class ProcessStream {
    Stdout,
    Stderr,
};

using ProcessOutputCallback = std::function<void(ProcessStream, std::string_view)>;

Result<ProcessOutput> runCapture(
    const std::vector<std::string>& arguments,
    std::chrono::milliseconds timeout,
    ProcessOutputCallback callback = {});

} // namespace tunproxy
