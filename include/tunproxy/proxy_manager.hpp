#pragma once

#include "tunproxy/config.hpp"
#include "tunproxy/core_manager.hpp"
#include "tunproxy/log.hpp"
#include "tunproxy/paths.hpp"
#include "tunproxy/result.hpp"
#include "tunproxy/runtime_state.hpp"

#include <chrono>
#include <filesystem>
#include <string>

namespace tunproxy {

struct ProxyStatus {
    bool running{false};
    std::string upstream;
    std::string core_version;
    pid_t pid{-1};
    std::string routing_mode;
};

class ProxyManager {
public:
    explicit ProxyManager(AppPaths paths = {}, LogCallback logger = {});

    Result<ProxyStatus> start();
    Result<void> stop();
    Result<ProxyStatus> status() const;

private:
    Result<pid_t> spawnCore(
        const std::filesystem::path& executable,
        const std::filesystem::path& config,
        const std::filesystem::path& log) const;
    Result<void> terminateCore(const RuntimeState& state) const;
    Result<bool> waitForTun(pid_t pid, std::chrono::milliseconds timeout) const;

    AppPaths paths_;
    LogCallback logger_;
    ConfigManager config_;
    CoreManager core_;
    RuntimeStateStore state_;
};

} // namespace tunproxy
