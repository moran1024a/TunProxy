#pragma once

#include "tunproxy/constants.hpp"
#include "tunproxy/result.hpp"
#include "tunproxy/upstream.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace tunproxy {

struct SingBoxRuntimeConfig {
    std::filesystem::path log_file;
    ResolvedUpstream upstream;
    std::vector<std::string> bypass_cidrs;
    bool auto_redirect{true};
    std::string interface_name{kTunInterfaceName};
};

Result<std::string> buildSingBoxConfig(const SingBoxRuntimeConfig& config);

} // namespace tunproxy
