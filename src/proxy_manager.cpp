#include "tunproxy/proxy_manager.hpp"

#include "tunproxy/bypass_policy.hpp"
#include "tunproxy/constants.hpp"
#include "tunproxy/filesystem.hpp"
#include "tunproxy/process.hpp"
#include "tunproxy/singbox_config.hpp"
#include "tunproxy/upstream.hpp"

#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <thread>

namespace tunproxy {
namespace {

Result<void> ensureTunDevice(const AppPaths& paths) {
    struct stat status {};
    if (::lstat(paths.tun_device.c_str(), &status) == 0) {
        if (S_ISCHR(status.st_mode)) {
            return Result<void>::success();
        }
        return Result<void>::failure(makeError(
            ErrorCode::StateError,
            paths.tun_device.string() + " exists but is not a character device"));
    }
    const auto sysfs = readTextFile(paths.tun_sysfs);
    if (!sysfs.ok()) {
        return Result<void>::failure(makeError(
            ErrorCode::StateError,
            "TUN is unavailable: /dev/net/tun is missing and the kernel does not expose tun"));
    }
    unsigned int major_number = 0;
    unsigned int minor_number = 0;
    if (std::sscanf(sysfs.value().c_str(), "%u:%u", &major_number, &minor_number) != 2) {
        return Result<void>::failure(makeError(ErrorCode::StateError, "invalid kernel TUN device metadata"));
    }
    const auto directory = ensureDirectory(paths.tun_device.parent_path(), 0755);
    if (!directory.ok()) {
        return directory;
    }
    if (::mknod(
            paths.tun_device.c_str(),
            static_cast<mode_t>(S_IFCHR | 0666),
            ::makedev(major_number, minor_number)) != 0 && errno != EEXIST) {
        return Result<void>::failure(makeError(ErrorCode::StateError, "cannot create /dev/net/tun"));
    }
    return Result<void>::success();
}

ProxyStatus statusFromState(const RuntimeState& state) {
    ProxyStatus status;
    status.running = true;
    status.upstream = state.upstream;
    status.core_version = state.core_version;
    status.core_installed = true;
    status.pid = state.pid;
    status.routing_mode = state.routing_mode;
    status.upstream_address = state.upstream_address;
    status.bypass_cidrs = state.bypass_cidrs;
    return status;
}

const char* routingModeName(bool auto_redirect) {
    return auto_redirect ? "auto-redirect" : "tun-route";
}

int pollIterations(std::chrono::milliseconds total) {
    return static_cast<int>(total / kPollInterval);
}

} // namespace

ProxyManager::ProxyManager(AppPaths paths, LogCallback logger, CoreReleaseManifest manifest)
    : paths_(std::move(paths)),
      logger_(std::move(logger)),
      manifest_(manifest),
      config_(paths_),
      core_(paths_, manifest_, logger_),
      state_(paths_) {}

bool ProxyManager::tunExists() const {
    return ::if_nametoindex(paths_.tun_interface.c_str()) != 0;
}

Result<void> ProxyManager::awaitTunRemoval(ErrorCode code) const {
    for (int attempt = 0; attempt < pollIterations(kTunRemovalTimeout) && tunExists(); ++attempt) {
        std::this_thread::sleep_for(kPollInterval);
    }
    if (tunExists()) {
        return Result<void>::failure(makeError(
            code, paths_.tun_interface + " did not disappear after sing-box stopped"));
    }
    return Result<void>::success();
}

Result<pid_t> ProxyManager::spawnCore(
    const std::filesystem::path& executable,
    const std::filesystem::path& config,
    const std::filesystem::path& log) const {
    const int core_fd = ::open(executable.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (core_fd < 0) {
        return Result<pid_t>::failure(makeError(ErrorCode::CoreStartFailure, "cannot open verified sing-box core"));
    }
    const int log_fd = ::open(log.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NOFOLLOW, 0640);
    if (log_fd < 0) {
        (void)::close(core_fd);
        return Result<pid_t>::failure(makeError(ErrorCode::CoreStartFailure, "cannot open sing-box log"));
    }
    int exec_pipe[2]{-1, -1};
    if (::pipe2(exec_pipe, O_CLOEXEC) != 0) {
        (void)::close(core_fd);
        (void)::close(log_fd);
        return Result<pid_t>::failure(makeError(ErrorCode::CoreStartFailure, "cannot create sing-box exec handshake"));
    }
    const pid_t child = ::fork();
    if (child < 0) {
        (void)::close(core_fd);
        (void)::close(log_fd);
        (void)::close(exec_pipe[0]);
        (void)::close(exec_pipe[1]);
        return Result<pid_t>::failure(makeError(ErrorCode::CoreStartFailure, "cannot fork sing-box"));
    }
    if (child == 0) {
        (void)::close(exec_pipe[0]);
        (void)::setsid();
        const int null_fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (null_fd >= 0) {
            (void)::dup2(null_fd, STDIN_FILENO);
            (void)::close(null_fd);
        }
        (void)::dup2(log_fd, STDOUT_FILENO);
        (void)::dup2(log_fd, STDERR_FILENO);
        (void)::close(log_fd);
        const std::string config_string = config.string();
        char* const arguments[] = {
            const_cast<char*>(executable.c_str()),
            const_cast<char*>("run"),
            const_cast<char*>("--disable-color"),
            const_cast<char*>("-c"),
            const_cast<char*>(config_string.c_str()),
            nullptr,
        };
        ::fexecve(core_fd, arguments, environ);
        const int exec_error = errno;
        const ssize_t sent = ::write(exec_pipe[1], &exec_error, sizeof(exec_error));
        (void)sent;
        _exit(127);
    }
    (void)::close(core_fd);
    (void)::close(log_fd);
    (void)::close(exec_pipe[1]);

    struct pollfd handshake_descriptor{exec_pipe[0], POLLIN | POLLHUP, 0};
    const int handshake_result = ::poll(
        &handshake_descriptor, 1,
        static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(kCoreExecHandshakeTimeout).count()));
    if (handshake_result <= 0 || (handshake_descriptor.revents & (POLLERR | POLLNVAL)) != 0) {
        (void)::kill(child, SIGKILL);
        (void)::waitpid(child, nullptr, 0);
        (void)::close(exec_pipe[0]);
        return Result<pid_t>::failure(makeError(
            ErrorCode::CoreStartFailure, "sing-box exec handshake timed out"));
    }
    int exec_error = 0;
    const ssize_t received = ::read(exec_pipe[0], &exec_error, sizeof(exec_error));
    (void)::close(exec_pipe[0]);
    if (received == 0) {
        return Result<pid_t>::success(child);
    }
    if (received != static_cast<ssize_t>(sizeof(exec_error))) {
        (void)::waitpid(child, nullptr, 0);
        return Result<pid_t>::failure(makeError(
            ErrorCode::CoreStartFailure, "invalid sing-box exec handshake"));
    }
    (void)::waitpid(child, nullptr, 0);
    return Result<pid_t>::failure(makeError(
        ErrorCode::CoreStartFailure,
        "cannot execute sing-box: " + std::string(std::strerror(exec_error))));
}

Result<ProxyManager::TunWait> ProxyManager::waitForTun(pid_t pid, std::chrono::milliseconds timeout) const {
    const auto started = std::chrono::steady_clock::now();
    const auto deadline = started + timeout;
    const auto total_seconds = std::chrono::duration_cast<std::chrono::seconds>(timeout).count();
    long long last_reported_second = -1;
    while (std::chrono::steady_clock::now() < deadline) {
        int status = 0;
        const pid_t waited = ::waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            return Result<TunWait>::success(TunWait::CoreExited);
        }
        if (waited < 0 && errno != EINTR && errno != ECHILD) {
            return Result<TunWait>::failure(makeError(ErrorCode::StateError, "cannot inspect sing-box process"));
        }
        if (tunExists()) {
            return Result<TunWait>::success(TunWait::Ready);
        }
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - started).count();
        if (elapsed >= kTunReadyQuietPeriod.count() && elapsed != last_reported_second) {
            last_reported_second = elapsed;
            emitLog(logger_, LogLevel::Info,
                "Waiting for TUN interface (" + std::to_string(elapsed) + "/" +
                std::to_string(total_seconds) + "s)");
        }
        std::this_thread::sleep_for(kPollInterval);
    }
    return Result<TunWait>::success(TunWait::TimedOut);
}

Result<void> ProxyManager::terminateCore(const RuntimeState& state) const {
    if (state.pid <= 0) {
        return Result<void>::success();
    }
    const auto initially_managed = state_.isManagedProcessRunning(state);
    if (!initially_managed.ok()) {
        return Result<void>::failure(initially_managed.error());
    }
    if (!initially_managed.value()) {
        return Result<void>::success();
    }
    if (::kill(state.pid, SIGTERM) != 0 && errno != ESRCH) {
        return Result<void>::failure(makeError(ErrorCode::StateError, "cannot signal sing-box"));
    }
    for (int attempt = 0; attempt < pollIterations(kCoreTerminateTimeout); ++attempt) {
        int status = 0;
        const pid_t waited = ::waitpid(state.pid, &status, WNOHANG);
        if (waited == state.pid) {
            return Result<void>::success();
        }
        const auto managed = state_.isManagedProcessRunning(state);
        if (!managed.ok()) {
            return Result<void>::failure(managed.error());
        }
        if (!managed.value()) {
            return Result<void>::success();
        }
        std::this_thread::sleep_for(kPollInterval);
    }
    const auto before_kill = state_.isManagedProcessRunning(state);
    if (!before_kill.ok()) {
        return Result<void>::failure(before_kill.error());
    }
    if (!before_kill.value()) {
        return Result<void>::success();
    }
    emitLog(logger_, LogLevel::Warning, "sing-box did not stop; sending SIGKILL");
    if (::kill(state.pid, SIGKILL) != 0 && errno != ESRCH) {
        return Result<void>::failure(makeError(ErrorCode::StateError, "cannot force-stop sing-box"));
    }
    for (int attempt = 0; attempt < pollIterations(kCoreKillTimeout); ++attempt) {
        int status = 0;
        const pid_t waited = ::waitpid(state.pid, &status, WNOHANG);
        if (waited == state.pid) {
            return Result<void>::success();
        }
        const auto managed = state_.isManagedProcessRunning(state);
        if (!managed.ok()) {
            return Result<void>::failure(managed.error());
        }
        if (!managed.value()) {
            return Result<void>::success();
        }
        std::this_thread::sleep_for(kPollInterval);
    }
    return Result<void>::failure(makeError(ErrorCode::StateError, "sing-box did not stop"));
}

Result<ProxyStatus> ProxyManager::start() {
    bool terminated_previous = false;
    const auto existing_state = state_.load();
    if (existing_state.ok()) {
        const auto running = state_.isManagedProcessRunning(existing_state.value());
        if (running.ok() && running.value() && existing_state.value().phase == "running") {
            return Result<ProxyStatus>::success(statusFromState(existing_state.value()));
        }
        if (running.ok() && running.value()) {
            emitLog(logger_, LogLevel::Warning, "cleaning up incomplete previous start");
            const auto stopped = terminateCore(existing_state.value());
            if (!stopped.ok()) {
                return Result<ProxyStatus>::failure(stopped.error());
            }
            terminated_previous = true;
        }
    }
    const auto cleared_existing = state_.clear();
    if (!cleared_existing.ok()) {
        return Result<ProxyStatus>::failure(cleared_existing.error());
    }
    if (terminated_previous) {
        const auto previous_removed = awaitTunRemoval(ErrorCode::CoreStartFailure);
        if (!previous_removed.ok()) {
            return Result<ProxyStatus>::failure(previous_removed.error());
        }
    }

    const auto tun = ensureTunDevice(paths_);
    if (!tun.ok()) {
        return Result<ProxyStatus>::failure(tun.error());
    }
    const auto configured = config_.load();
    if (!configured.ok()) {
        return Result<ProxyStatus>::failure(configured.error());
    }
    const auto resolved = resolveAndProbeUpstream(configured.value());
    if (!resolved.ok()) {
        return Result<ProxyStatus>::failure(resolved.error());
    }
    const auto bypass = collectBypassPolicy(resolved.value().address, paths_.tun_interface);
    if (!bypass.ok()) {
        return Result<ProxyStatus>::failure(bypass.error());
    }
    const auto bypass_cidrs = bypass.value().allCidrs();
    const auto core = core_.ensureCore();
    if (!core.ok()) {
        return Result<ProxyStatus>::failure(core.error());
    }
    const auto runtime_directory = ensureDirectory(paths_.runtime_dir, 0755);
    if (!runtime_directory.ok()) {
        return Result<ProxyStatus>::failure(runtime_directory.error());
    }
    const auto config_path = paths_.core_config_file();
    const auto log_path = paths_.core_log_file();

    Error last_error = makeError(ErrorCode::CoreStartFailure, "sing-box failed to establish TUN");
    bool routing_failure = false;
    for (const bool auto_redirect : {true, false}) {
        if (tunExists()) {
            return Result<ProxyStatus>::failure(makeError(
                ErrorCode::CoreStartFailure, paths_.tun_interface + " already exists outside TunProxy"));
        }
        if (!auto_redirect) {
            emitLog(logger_, LogLevel::Warning,
                routing_failure
                    ? "auto-redirect failed (" + last_error.message + "); retrying with tun-route"
                    : "sing-box failed to start (" + last_error.message + "); retrying");
        }
        SingBoxRuntimeConfig runtime_config;
        runtime_config.log_file = log_path;
        runtime_config.upstream = resolved.value();
        runtime_config.bypass_cidrs = bypass_cidrs;
        runtime_config.auto_redirect = auto_redirect;
        runtime_config.interface_name = paths_.tun_interface;
        const auto json = buildSingBoxConfig(runtime_config);
        if (!json.ok()) {
            return Result<ProxyStatus>::failure(json.error());
        }
        const auto written = writeFileAtomic(config_path, json.value(), 0600);
        if (!written.ok()) {
            return Result<ProxyStatus>::failure(written.error());
        }
        const auto checked = runCapture(
            {core.value().executable.string(), "check", "--disable-color", "-c", config_path.string()},
            kCoreCheckTimeout);
        if (!checked.ok() || checked.value().exit_code != 0) {
            const std::string detail = !checked.ok()
                ? checked.error().message
                : (!checked.value().stderr_text.empty()
                       ? checked.value().stderr_text
                       : "process exited with status " + std::to_string(checked.value().exit_code));
            return Result<ProxyStatus>::failure(makeError(
                ErrorCode::InvalidConfiguration, "sing-box config check failed: " + detail));
        }
        const auto spawned = spawnCore(core.value().executable, config_path, log_path);
        if (!spawned.ok()) {
            last_error = spawned.error();
            routing_failure = false;
            continue;
        }
        const auto start_ticks = state_.processStartTicks(spawned.value());
        if (!start_ticks.ok()) {
            // The child is still owned by this process, so it cannot be
            // replaced by another process before it is reaped.
            if (::kill(spawned.value(), SIGKILL) != 0 && errno != ESRCH) {
                return Result<ProxyStatus>::failure(makeError(
                    ErrorCode::CoreStartFailure, "cannot clean up sing-box child"));
            }
            while (::waitpid(spawned.value(), nullptr, 0) < 0 && errno == EINTR) {
            }
            return Result<ProxyStatus>::failure(start_ticks.error());
        }
        RuntimeState runtime_state;
        runtime_state.pid = spawned.value();
        runtime_state.start_ticks = start_ticks.value();
        runtime_state.executable = core.value().executable;
        runtime_state.core_version = core.value().version;
        runtime_state.upstream = formatUpstreamUri(configured.value());
        runtime_state.routing_mode = routingModeName(auto_redirect);
        runtime_state.upstream_address = resolved.value().address;
        runtime_state.bypass_cidrs = bypass_cidrs;
        runtime_state.phase = "starting";
        const auto provisional = state_.save(runtime_state);
        if (!provisional.ok()) {
            const auto stopped = terminateCore(runtime_state);
            if (!stopped.ok()) {
                return Result<ProxyStatus>::failure(stopped.error());
            }
            const auto removed = awaitTunRemoval(ErrorCode::CoreStartFailure);
            if (!removed.ok()) {
                return Result<ProxyStatus>::failure(removed.error());
            }
            return Result<ProxyStatus>::failure(provisional.error());
        }
        const auto ready = waitForTun(spawned.value(), kTunReadyTimeout);
        if (!ready.ok()) {
            const auto stopped = terminateCore(runtime_state);
            if (!stopped.ok()) {
                return Result<ProxyStatus>::failure(stopped.error());
            }
            (void)state_.clear();
            (void)awaitTunRemoval(ErrorCode::CoreStartFailure);
            return Result<ProxyStatus>::failure(ready.error());
        }
        if (ready.value() == TunWait::Ready) {
            runtime_state.phase = "running";
            const auto saved = state_.save(runtime_state);
            if (!saved.ok()) {
                const auto stopped = terminateCore(runtime_state);
                if (!stopped.ok()) {
                    return Result<ProxyStatus>::failure(stopped.error());
                }
                (void)state_.clear();
                const auto removed = awaitTunRemoval(ErrorCode::CoreStartFailure);
                if (!removed.ok()) {
                    return Result<ProxyStatus>::failure(removed.error());
                }
                return Result<ProxyStatus>::failure(saved.error());
            }
            return Result<ProxyStatus>::success(statusFromState(runtime_state));
        }
        if (ready.value() == TunWait::TimedOut) {
            const auto stopped = terminateCore(runtime_state);
            if (!stopped.ok()) {
                return Result<ProxyStatus>::failure(stopped.error());
            }
            last_error = makeError(ErrorCode::CoreStartFailure,
                "sing-box did not establish TUN within " +
                std::to_string(std::chrono::duration_cast<std::chrono::seconds>(kTunReadyTimeout).count()) +
                " seconds");
        } else {
            // The child exited and has already been reaped by waitForTun.
            last_error = makeError(ErrorCode::CoreStartFailure, "sing-box exited before TUN became ready");
        }
        routing_failure = true;
        const auto cleared = state_.clear();
        if (!cleared.ok()) {
            return Result<ProxyStatus>::failure(cleared.error());
        }
        const auto removed = awaitTunRemoval(ErrorCode::CoreStartFailure);
        if (!removed.ok()) {
            return Result<ProxyStatus>::failure(removed.error());
        }
    }
    return Result<ProxyStatus>::failure(std::move(last_error));
}

Result<void> ProxyManager::stop() {
    const auto runtime_state = state_.load();
    if (!runtime_state.ok()) {
        return state_.clear();
    }
    const auto running = state_.isManagedProcessRunning(runtime_state.value());
    if (running.ok() && running.value()) {
        const auto stopped = terminateCore(runtime_state.value());
        if (!stopped.ok()) {
            return stopped;
        }
        const auto removed = awaitTunRemoval(ErrorCode::StateError);
        if (!removed.ok()) {
            return removed;
        }
    } else {
        emitLog(logger_, LogLevel::Warning, "no managed sing-box process; clearing stale state");
    }
    const auto cleared = state_.clear();
    if (!cleared.ok()) {
        return cleared;
    }
    std::error_code ignored;
    std::filesystem::remove(paths_.core_config_file(), ignored);
    return Result<void>::success();
}

Result<ProxyStatus> ProxyManager::status() const {
    ProxyStatus status;
    const auto configured = config_.load();
    if (configured.ok()) {
        status.upstream = formatUpstreamUri(configured.value());
    }
    status.core_version = std::string(manifest_.version);
    std::error_code ignored;
    status.core_installed =
        std::filesystem::symlink_status(core_.corePath(), ignored).type() == std::filesystem::file_type::regular;
    const auto runtime_state = state_.load();
    if (!runtime_state.ok()) {
        return Result<ProxyStatus>::success(std::move(status));
    }
    const auto running = state_.isManagedProcessRunning(runtime_state.value());
    if (!running.ok() || !running.value() || runtime_state.value().phase != "running") {
        return Result<ProxyStatus>::success(std::move(status));
    }
    status = statusFromState(runtime_state.value());
    return Result<ProxyStatus>::success(std::move(status));
}

} // namespace tunproxy
