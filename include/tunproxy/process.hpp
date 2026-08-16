#pragma once

#include "tunproxy/result.hpp"

#include <chrono>
#include <string>
#include <vector>

namespace tunproxy {

struct ProcessOutput {
    int exit_code{-1};
    std::string stdout_text;
    std::string stderr_text;
};

Result<ProcessOutput> runCapture(
    const std::vector<std::string>& arguments,
    std::chrono::milliseconds timeout);

} // namespace tunproxy
