#pragma once

#include "tunproxy/config.hpp"
#include "tunproxy/constants.hpp"
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
    std::chrono::milliseconds timeout = kUpstreamProbeTimeout);

} // namespace tunproxy
