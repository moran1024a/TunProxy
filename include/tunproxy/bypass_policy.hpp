#pragma once

#include "tunproxy/result.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace tunproxy {

struct BypassPolicy {
    std::vector<std::string> fixed_cidrs;
    std::vector<std::string> detected_cidrs;
    std::string upstream_cidr;

    std::vector<std::string> allCidrs() const;
};

const std::vector<std::string>& fixedBypassCidrs();
Result<std::string> canonicalizeCidr(std::string_view cidr);
Result<std::string> addressHostCidr(std::string_view address);
Result<BypassPolicy> collectBypassPolicy(std::string_view upstream_address = {});

} // namespace tunproxy
