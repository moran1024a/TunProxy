#pragma once

#include "tunproxy/core_manifest.hpp"
#include "tunproxy/log.hpp"
#include "tunproxy/paths.hpp"
#include "tunproxy/result.hpp"

#include <filesystem>
#include <string>

namespace tunproxy {

struct CoreInfo {
    std::filesystem::path executable;
    std::string version;
    std::string revision;
};

class CoreManager {
public:
    explicit CoreManager(
        AppPaths paths = {},
        CoreReleaseManifest manifest = kSingBoxRelease,
        LogCallback logger = {});

    Result<CoreInfo> ensureCore();
    Result<CoreInfo> verifyInstalledCore() const;
    Result<CoreInfo> repairCore();

    [[nodiscard]] std::filesystem::path coreDirectory() const;
    [[nodiscard]] std::filesystem::path corePath() const;

private:
    Result<CoreInfo> verifyCandidate(const std::filesystem::path& executable) const;

    AppPaths paths_;
    CoreReleaseManifest manifest_;
    LogCallback logger_;
};

} // namespace tunproxy
