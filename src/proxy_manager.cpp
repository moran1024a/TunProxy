#include "tunproxy/proxy_manager.hpp"

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

void waitForTunRemoval() {
    for (int attempt = 0; attempt < 30 && ::if_nametoindex("tunproxy0") != 0; ++attempt) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

} // namespace

ProxyManager::ProxyManager(AppPaths paths, LogCallback logger)
    : paths_(std::move(paths)),
      logger_(std::move(logger)),
      config_(paths_),
      core_(paths_, kSingBoxRelease, logger_),
      state_(paths_) {}

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
    const int handshake_result = ::poll(&handshake_descriptor, 1, 5000);
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

Result<bool> ProxyManager::waitForTun(pid_t pid, std::chrono::milliseconds timeout) const {
    const auto started = std::chrono::steady_clock::now();
    const auto deadline = started + timeout;
    int last_reported_second = -1;
    while (std::chrono::steady_clock::now() < deadline) {
        int status = 0;
        const pid_t waited = ::waitpid(pid, &status, WNOHANG);
        if (waited == pid) {
            return Result<bool>::success(false);
        }
        if (waited < 0 && errno != EINTR && errno != ECHILD) {
            return Result<bool>::failure(makeError(ErrorCode::StateError, "cannot inspect sing-box process"));
        }
        if (::if_nametoindex("tunproxy0") != 0) {
            emitLog(logger_, LogLevel::Info, "TUN interface tunproxy0 is ready");
            return Result<bool>::success(true);
        }
        const int elapsed = static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - started).count());
        if (elapsed != last_reported_second) {
            last_reported_second = elapsed;
            emitLog(logger_, LogLevel::Info,
                "Waiting for TUN interface tunproxy0 (" + std::to_string(elapsed) + "/" +
                std::to_string(std::chrono::duration_cast<std::chrono::seconds>(timeout).count()) +
                " seconds)...");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return Result<bool>::success(false);
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
        emitLog(logger_, LogLevel::Warning,
            "sing-box process " + std::to_string(state.pid) + " is no longer running");
        return Result<void>::success();
    }
    emitLog(logger_, LogLevel::Info,
        "Stopping sing-box (PID " + std::to_string(state.pid) + ")...");
    if (::kill(state.pid, SIGTERM) != 0 && errno != ESRCH) {
        return Result<void>::failure(makeError(ErrorCode::StateError, "cannot signal sing-box"));
    }
    for (int attempt = 0; attempt < 50; ++attempt) {
        int status = 0;
        const pid_t waited = ::waitpid(state.pid, &status, WNOHANG);
        if (waited == state.pid) {
            emitLog(logger_, LogLevel::Info, "sing-box stopped gracefully");
            return Result<void>::success();
        }
        const auto managed = state_.isManagedProcessRunning(state);
        if (!managed.ok()) {
            return Result<void>::failure(managed.error());
        }
        if (!managed.value()) {
            return Result<void>::success();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    const auto before_kill = state_.isManagedProcessRunning(state);
    if (!before_kill.ok()) {
        return Result<void>::failure(before_kill.error());
    }
    if (!before_kill.value()) {
        emitLog(logger_, LogLevel::Info, "sing-box stopped gracefully");
        return Result<void>::success();
    }
    emitLog(logger_, LogLevel::Warning, "sing-box did not stop; sending SIGKILL");
    if (::kill(state.pid, SIGKILL) != 0 && errno != ESRCH) {
        return Result<void>::failure(makeError(ErrorCode::StateError, "cannot force-stop sing-box"));
    }
    for (int attempt = 0; attempt < 20; ++attempt) {
        int status = 0;
        const pid_t waited = ::waitpid(state.pid, &status, WNOHANG);
        if (waited == state.pid) {
            emitLog(logger_, LogLevel::Info, "sing-box force-stopped");
            return Result<void>::success();
        }
        const auto managed = state_.isManagedProcessRunning(state);
        if (!managed.ok()) {
            return Result<void>::failure(managed.error());
        }
        if (!managed.value()) {
            return Result<void>::success();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return Result<void>::failure(makeError(ErrorCode::StateError, "sing-box did not stop"));
}

Result<ProxyStatus> ProxyManager::start() {
    emitLog(logger_, LogLevel::Info, "Starting TunProxy...");
    const auto existing_state = state_.load();
    if (existing_state.ok()) {
        const auto running = state_.isManagedProcessRunning(existing_state.value());
        if (running.ok() && running.value() && existing_state.value().phase == "running") {
            emitLog(logger_, LogLevel::Info,
                "TunProxy is already running (PID " + std::to_string(existing_state.value().pid) + ")");
            return Result<ProxyStatus>::success(ProxyStatus{
                true,
                existing_state.value().upstream,
                existing_state.value().core_version,
                existing_state.value().pid,
                existing_state.value().routing_mode,
            });
        }
        if (running.ok() && running.value()) {
            emitLog(logger_, LogLevel::Warning, "Found an incomplete previous start; cleaning it up");
            const auto stopped = terminateCore(existing_state.value());
            if (!stopped.ok()) {
                return Result<ProxyStatus>::failure(stopped.error());
            }
            waitForTunRemoval();
        }
    }
    const auto cleared_existing = state_.clear();
    if (!cleared_existing.ok()) {
        return Result<ProxyStatus>::failure(cleared_existing.error());
    }

    const auto tun = ensureTunDevice(paths_);
    if (!tun.ok()) {
        return Result<ProxyStatus>::failure(tun.error());
    }
    emitLog(logger_, LogLevel::Info, "TUN device is available: " + paths_.tun_device.string());

    const auto configured = config_.load();
    if (!configured.ok()) {
        return Result<ProxyStatus>::failure(configured.error());
    }
    emitLog(logger_, LogLevel::Info,
        "Checking SOCKS5 upstream " + formatUpstreamUri(configured.value()) + "...");
    const auto resolved = resolveAndProbeUpstream(configured.value());
    if (!resolved.ok()) {
        return Result<ProxyStatus>::failure(resolved.error());
    }
    emitLog(logger_, LogLevel::Info,
        "Upstream connection succeeded via " + resolved.value().address);
    const auto core = core_.ensureCore();
    if (!core.ok()) {
        return Result<ProxyStatus>::failure(core.error());
    }
    emitLog(logger_, LogLevel::Info,
        "Using verified sing-box " + core.value().version + " (" + core.value().revision + ")");
    const auto runtime_directory = ensureDirectory(paths_.runtime_dir, 0755);
    if (!runtime_directory.ok()) {
        return Result<ProxyStatus>::failure(runtime_directory.error());
    }
    const auto config_path = paths_.runtime_dir / "sing-box.json";
    const auto log_path = paths_.runtime_dir / "sing-box.log";

    if (::if_nametoindex("tunproxy0") != 0) {
        return Result<ProxyStatus>::failure(makeError(
            ErrorCode::CoreStartFailure, "tunproxy0 already exists outside TunProxy"));
    }

    Error last_error = makeError(ErrorCode::CoreStartFailure, "sing-box failed to establish TUN");
    bool first_attempt = true;
    for (const bool auto_redirect : {true, false}) {
        if (::if_nametoindex("tunproxy0") != 0) {
            return Result<ProxyStatus>::failure(makeError(
                ErrorCode::CoreStartFailure, "tunproxy0 already exists outside TunProxy"));
        }
        if (!first_attempt) {
            emitLog(logger_, LogLevel::Warning,
                "Retrying sing-box with compatibility TUN routing mode");
        }
        first_attempt = false;
        emitLog(logger_, LogLevel::Info,
            std::string("Generating sing-box configuration (mode: ") +
            (auto_redirect ? "auto-redirect" : "tun-route") + ")...");
        const auto json = buildSingBoxConfig(SingBoxRuntimeConfig{log_path, resolved.value(), auto_redirect});
        if (!json.ok()) {
            return Result<ProxyStatus>::failure(json.error());
        }
        const auto written = writeFileAtomic(config_path, json.value(), 0600);
        if (!written.ok()) {
            return Result<ProxyStatus>::failure(written.error());
        }
        emitLog(logger_, LogLevel::Info, "Validating sing-box configuration...");
        const auto checked = runCapture(
            {core.value().executable.string(), "check", "--disable-color", "-c", config_path.string()},
            std::chrono::seconds(10));
        if (!checked.ok() || checked.value().exit_code != 0) {
            const std::string detail = checked.ok() ? checked.value().stderr_text : checked.error().message;
            return Result<ProxyStatus>::failure(makeError(ErrorCode::InvalidConfiguration, "sing-box config check failed: " + detail));
        }
        emitLog(logger_, LogLevel::Info, "sing-box configuration is valid");
        const auto spawned = spawnCore(core.value().executable, config_path, log_path);
        if (!spawned.ok()) {
            emitLog(logger_, LogLevel::Warning, "sing-box failed to start: " + spawned.error().message);
            last_error = spawned.error();
            continue;
        }
        emitLog(logger_, LogLevel::Info,
            "sing-box process started (PID " + std::to_string(spawned.value()) + ")");
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
        runtime_state.routing_mode = auto_redirect ? "auto-redirect" : "tun-route";
        runtime_state.phase = "starting";
        const auto provisional = state_.save(runtime_state);
        if (!provisional.ok()) {
            const auto stopped = terminateCore(runtime_state);
            if (!stopped.ok()) {
                return Result<ProxyStatus>::failure(stopped.error());
            }
            waitForTunRemoval();
            if (::if_nametoindex("tunproxy0") != 0) {
                return Result<ProxyStatus>::failure(makeError(
                    ErrorCode::CoreStartFailure, "tunproxy0 did not disappear after sing-box stopped"));
            }
            return Result<ProxyStatus>::failure(provisional.error());
        }
        const auto ready = waitForTun(spawned.value(), std::chrono::seconds(8));
        if (!ready.ok() || !ready.value()) {
            const auto stopped = terminateCore(runtime_state);
            if (!stopped.ok()) {
                return Result<ProxyStatus>::failure(stopped.error());
            }
            waitForTunRemoval();
            const auto cleared = state_.clear();
            if (!cleared.ok()) {
                return Result<ProxyStatus>::failure(cleared.error());
            }
            if (::if_nametoindex("tunproxy0") != 0) {
                return Result<ProxyStatus>::failure(makeError(
                    ErrorCode::CoreStartFailure, "tunproxy0 did not disappear after sing-box stopped"));
            }
            last_error = makeError(ErrorCode::CoreStartFailure, "sing-box exited before TUN became ready");
            emitLog(logger_, LogLevel::Warning, last_error.message);
            continue;
        }
        runtime_state.phase = "running";
        const auto saved = state_.save(runtime_state);
        if (!saved.ok()) {
            const auto stopped = terminateCore(runtime_state);
            if (!stopped.ok()) {
                return Result<ProxyStatus>::failure(stopped.error());
            }
            waitForTunRemoval();
            if (::if_nametoindex("tunproxy0") != 0) {
                return Result<ProxyStatus>::failure(makeError(
                    ErrorCode::CoreStartFailure, "tunproxy0 did not disappear after sing-box stopped"));
            }
            return Result<ProxyStatus>::failure(saved.error());
        }
        return Result<ProxyStatus>::success(ProxyStatus{
            true,
            runtime_state.upstream,
            runtime_state.core_version,
            runtime_state.pid,
            runtime_state.routing_mode,
        });
    }
    return Result<ProxyStatus>::failure(std::move(last_error));
}

Result<void> ProxyManager::stop() {
    emitLog(logger_, LogLevel::Info, "Stopping TunProxy...");
    const auto runtime_state = state_.load();
    if (!runtime_state.ok()) {
        const auto cleared = state_.clear();
        if (cleared.ok()) {
            emitLog(logger_, LogLevel::Info, "TunProxy is already stopped");
        }
        return cleared;
    }
    const auto running = state_.isManagedProcessRunning(runtime_state.value());
    if (running.ok() && running.value()) {
        const auto stopped = terminateCore(runtime_state.value());
        if (!stopped.ok()) {
            return stopped;
        }
        waitForTunRemoval();
        if (::if_nametoindex("tunproxy0") != 0) {
            return Result<void>::failure(makeError(
                ErrorCode::StateError, "tunproxy0 did not disappear after sing-box stopped"));
        }
        emitLog(logger_, LogLevel::Info, "TUN interface tunproxy0 removed");
    } else {
        emitLog(logger_, LogLevel::Info, "No managed sing-box process is running; clearing state");
    }
    const auto cleared = state_.clear();
    if (!cleared.ok()) {
        return cleared;
    }
    std::error_code ignored;
    std::filesystem::remove(paths_.runtime_dir / "sing-box.json", ignored);
    emitLog(logger_, LogLevel::Info, "TunProxy stopped");
    return Result<void>::success();
}

Result<ProxyStatus> ProxyManager::status() const {
    ProxyStatus status;
    const auto configured = config_.load();
    if (configured.ok()) {
        status.upstream = formatUpstreamUri(configured.value());
    }
    const auto runtime_state = state_.load();
    if (!runtime_state.ok()) {
        return Result<ProxyStatus>::success(std::move(status));
    }
    const auto running = state_.isManagedProcessRunning(runtime_state.value());
    if (!running.ok() || !running.value() || runtime_state.value().phase != "running") {
        return Result<ProxyStatus>::success(std::move(status));
    }
    status.running = true;
    status.upstream = runtime_state.value().upstream;
    status.core_version = runtime_state.value().core_version;
    status.pid = runtime_state.value().pid;
    status.routing_mode = runtime_state.value().routing_mode;
    return Result<ProxyStatus>::success(std::move(status));
}

} // namespace tunproxy
