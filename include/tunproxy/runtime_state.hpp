#pragma once

#include "tunproxy/paths.hpp"
#include "tunproxy/result.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include <sys/types.h>

namespace tunproxy {

struct RuntimeState {
    pid_t pid{-1};
    std::uint64_t start_ticks{0};
    std::filesystem::path executable;
    std::string core_version;
    std::string upstream;
    std::string routing_mode;
    std::string upstream_address;
    std::vector<std::string> bypass_cidrs;
    std::string phase{"running"};
};

class RuntimeStateStore {
public:
    explicit RuntimeStateStore(AppPaths paths = {});

    Result<RuntimeState> load() const;
    Result<void> save(const RuntimeState& state) const;
    Result<void> clear() const;
    Result<bool> isManagedProcessRunning(const RuntimeState& state) const;
    Result<std::uint64_t> processStartTicks(pid_t pid) const;

private:
    AppPaths paths_;
};

class FileLock {
public:
    FileLock() = default;
    ~FileLock();
    FileLock(const FileLock&) = delete;
    FileLock& operator=(const FileLock&) = delete;
    FileLock(FileLock&& other) noexcept;
    FileLock& operator=(FileLock&& other) noexcept;

    // Acquires an exclusive lock. When the lock is already held elsewhere,
    // on_wait is invoked once before blocking.
    static Result<FileLock> acquire(
        const std::filesystem::path& path,
        const std::function<void()>& on_wait = {});

private:
    explicit FileLock(int descriptor) : descriptor_(descriptor) {}
    int descriptor_{-1};
};

} // namespace tunproxy
