#pragma once

#include "tunproxy/result.hpp"
#include "tunproxy/upstream.hpp"

#include <filesystem>
#include <string>

namespace tunproxy {

struct SingBoxRuntimeConfig {
    std::filesystem::path log_file;
    ResolvedUpstream upstream;
    bool auto_redirect{true};
};

Result<std::string> buildSingBoxConfig(const SingBoxRuntimeConfig& config);

} // namespace tunproxy
