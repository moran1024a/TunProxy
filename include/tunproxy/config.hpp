#pragma once

#include "tunproxy/paths.hpp"
#include "tunproxy/result.hpp"

#include <cstdint>
#include <string>

namespace tunproxy {

struct Upstream {
    std::string protocol{"socks5"};
    std::string host{"127.0.0.1"};
    std::uint16_t port{10808};
};

Result<Upstream> parseUpstreamUri(const std::string& uri);
std::string formatUpstreamUri(const Upstream& upstream);
Result<Upstream> validateUpstream(const Upstream& upstream);

class ConfigManager {
public:
    explicit ConfigManager(AppPaths paths = {});

    Result<Upstream> load() const;
    Result<void> save(const Upstream& upstream) const;
    [[nodiscard]] const AppPaths& paths() const { return paths_; }

private:
    AppPaths paths_;
};

} // namespace tunproxy
