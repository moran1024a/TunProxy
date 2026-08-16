#pragma once

#include "tunproxy/config.hpp"
#include "tunproxy/result.hpp"

#include <chrono>
#include <string>

namespace tunproxy {

struct ResolvedUpstream {
    Upstream configured;
    std::string address;
};

Result<ResolvedUpstream> resolveAndProbeUpstream(
    const Upstream& upstream,
    std::chrono::milliseconds timeout = std::chrono::seconds(3));

} // namespace tunproxy
