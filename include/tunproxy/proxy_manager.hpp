#pragma once

#include "tunproxy/config.hpp"
#include "tunproxy/core_manager.hpp"
#include "tunproxy/core_manifest.hpp"
#include "tunproxy/log.hpp"
#include "tunproxy/paths.hpp"
#include "tunproxy/result.hpp"
#include "tunproxy/runtime_state.hpp"

#include <chrono>
#include <filesystem>
#include <string>
#include <vector>

namespace tunproxy {

struct ProxyStatus {
    bool running{false};
    std::string upstream;
    std::string core_version;
    bool core_installed{false};
    pid_t pid{-1};
    std::string routing_mode;
    std::string upstream_address;
    std::vector<std::string> bypass_cidrs;
};

class ProxyManager {
public:
    explicit ProxyManager(
        AppPaths paths = {},
        LogCallback logger = {},
        CoreReleaseManifest manifest = kSingBoxRelease);

    Result<ProxyStatus> start();
    Result<void> stop();
    Result<ProxyStatus> status() const;

private:
    enum class TunWait {
        Ready,
        CoreExited,
        TimedOut,
    };

    Result<pid_t> spawnCore(
        const std::filesystem::path& executable,
        const std::filesystem::path& config,
        const std::filesystem::path& log) const;
    Result<void> terminateCore(const RuntimeState& state) const;
    Result<TunWait> waitForTun(pid_t pid, std::chrono::milliseconds timeout) const;
    [[nodiscard]] bool tunExists() const;
    Result<void> awaitTunRemoval(ErrorCode code) const;

    AppPaths paths_;
    LogCallback logger_;
    CoreReleaseManifest manifest_;
    ConfigManager config_;
    CoreManager core_;
    RuntimeStateStore state_;
};

} // namespace tunproxy
