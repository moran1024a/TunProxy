#include "tunproxy/authorization.hpp"
#include "tunproxy/constants.hpp"
#include "tunproxy/controller.hpp"
#include "tunproxy/filesystem.hpp"
#include "tunproxy/ipc.hpp"
#include "tunproxy/paths.hpp"

#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <limits>
#include <mutex>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

namespace {

// Local administrators must belong to this group to reach the control socket.
constexpr const char* kAdminGroup = "sudo";

volatile sig_atomic_t stop_requested = 0;

void handleSignal(int) {
    stop_requested = 1;
}

bool parseUnsigned(const char* text, unsigned long& value) {
    if (text == nullptr || *text == '\0') {
        return false;
    }
    char* end = nullptr;
    errno = 0;
    value = std::strtoul(text, &end, 10);
    return errno == 0 && end != text && *end == '\0';
}

bool isSocketDescriptor(int descriptor) {
    struct stat status {};
    if (::fstat(descriptor, &status) != 0 || !S_ISSOCK(status.st_mode)) {
        return false;
    }
    sockaddr_un address{};
    socklen_t length = sizeof(address);
    return ::getsockname(descriptor, reinterpret_cast<sockaddr*>(&address), &length) == 0 &&
        address.sun_family == AF_UNIX;
}

int inheritedSocket() {
    unsigned long listen_pid = 0;
    unsigned long listen_fds = 0;
    if (!parseUnsigned(std::getenv("LISTEN_PID"), listen_pid) ||
        !parseUnsigned(std::getenv("LISTEN_FDS"), listen_fds) ||
        listen_pid != static_cast<unsigned long>(::getpid()) || listen_fds != 1) {
        return -1;
    }
    constexpr int descriptor = 3;
    if (!isSocketDescriptor(descriptor)) {
        return -1;
    }
    (void)::fcntl(descriptor, F_SETFD, FD_CLOEXEC);
    (void)::unsetenv("LISTEN_PID");
    (void)::unsetenv("LISTEN_FDS");
    (void)::unsetenv("LISTEN_FDNAMES");
    return descriptor;
}

tunproxy::Result<int> createSocket(const std::filesystem::path& path) {
    const std::string path_string = path.string();
    sockaddr_un address{};
    if (path_string.empty() || path_string.size() >= sizeof(address.sun_path)) {
        return tunproxy::Result<int>::failure(tunproxy::makeError(
            tunproxy::ErrorCode::InvalidArguments, "control socket path is invalid"));
    }
    const auto directory = tunproxy::ensureDirectory(path.parent_path(), 0755);
    if (!directory.ok()) {
        return tunproxy::Result<int>::failure(directory.error());
    }
    struct stat existing {};
    if (::lstat(path.c_str(), &existing) == 0) {
        if (!S_ISSOCK(existing.st_mode)) {
            return tunproxy::Result<int>::failure(tunproxy::makeError(
                tunproxy::ErrorCode::StateError, "control socket path exists and is not a socket"));
        }
        if (::unlink(path.c_str()) != 0) {
            return tunproxy::Result<int>::failure(tunproxy::makeError(
                tunproxy::ErrorCode::StateError, "cannot remove stale control socket"));
        }
    } else if (errno != ENOENT) {
        return tunproxy::Result<int>::failure(tunproxy::makeError(
            tunproxy::ErrorCode::StateError, "cannot inspect control socket path"));
    }
    const int descriptor = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
        return tunproxy::Result<int>::failure(tunproxy::makeError(
            tunproxy::ErrorCode::StateError, "cannot create control socket"));
    }
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path_string.c_str(), path_string.size() + 1U);
    if (::bind(descriptor, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        const std::string detail = std::strerror(errno);
        (void)::close(descriptor);
        return tunproxy::Result<int>::failure(tunproxy::makeError(
            tunproxy::ErrorCode::StateError, "cannot bind control socket: " + detail));
    }
    const group* admin_group = ::getgrnam(kAdminGroup);
    if (admin_group == nullptr) {
        (void)::close(descriptor);
        (void)::unlink(path.c_str());
        return tunproxy::Result<int>::failure(tunproxy::makeError(
            tunproxy::ErrorCode::StateError, std::string("system group '") + kAdminGroup + "' does not exist"));
    }
    if (::chown(path.c_str(), 0, admin_group->gr_gid) != 0 || ::chmod(path.c_str(), 0660) != 0 ||
        ::listen(descriptor, 8) != 0) {
        const std::string detail = std::strerror(errno);
        (void)::close(descriptor);
        (void)::unlink(path.c_str());
        return tunproxy::Result<int>::failure(tunproxy::makeError(
            tunproxy::ErrorCode::StateError, "cannot secure control socket: " + detail));
    }
    return tunproxy::Result<int>::success(descriptor);
}

struct DaemonState {
    std::mutex operation;
    std::mutex active_name_mutex;
    std::string active_name;
    std::mutex clients_mutex;
    std::condition_variable clients_finished;
    std::size_t active_clients{0};
};

bool isMutating(tunproxy::Command command) {
    return command == tunproxy::Command::On || command == tunproxy::Command::Off ||
        command == tunproxy::Command::SetSetting;
}

const char* commandName(tunproxy::Command command) {
    switch (command) {
    case tunproxy::Command::On:
        return "on";
    case tunproxy::Command::Off:
        return "off";
    case tunproxy::Command::Status:
        return "status";
    case tunproxy::Command::GetSetting:
        return "setting query";
    case tunproxy::Command::SetSetting:
        return "setting update";
    case tunproxy::Command::Bypass:
        return "bypass query";
    }
    return "unknown";
}

bool authorizeClient(int descriptor, uid_t& uid) {
    ucred credentials{};
    socklen_t length = sizeof(credentials);
    if (::getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
        length != sizeof(credentials)) {
        return false;
    }
    uid = credentials.uid;
    return tunproxy::isAuthorizedUser(credentials.uid, credentials.gid, kAdminGroup);
}

void sendError(int descriptor, const tunproxy::Error& error) {
    const std::string message = error.message.size() <= tunproxy::kIpcMaximumPayload
        ? error.message
        : error.message.substr(0, tunproxy::kIpcMaximumPayload);
    (void)tunproxy::sendIpcFrame(descriptor, tunproxy::IpcFrame{
        tunproxy::IpcFrameType::Error, static_cast<std::uint32_t>(error.code), message});
}

void serveClient(
    int descriptor, const tunproxy::CommandController& controller, DaemonState& daemon_state) {
    const auto request = tunproxy::receiveIpcFrame(descriptor);
    if (!request.ok()) {
        sendError(descriptor, request.error());
        return;
    }
    const auto decoded = tunproxy::decodeCommand(request.value().code);
    if (request.value().type != tunproxy::IpcFrameType::Request || !decoded.ok()) {
        sendError(descriptor, tunproxy::makeError(
            tunproxy::ErrorCode::InvalidArguments, "unsupported IPC protocol or command"));
        return;
    }
    const tunproxy::Command command = decoded.value();
    std::unique_lock<std::mutex> operation_lock(daemon_state.operation, std::defer_lock);
    if (isMutating(command) && !operation_lock.try_lock()) {
        std::string active;
        {
            const std::lock_guard<std::mutex> lock(daemon_state.active_name_mutex);
            active = daemon_state.active_name;
        }
        sendError(descriptor, tunproxy::makeError(
            tunproxy::ErrorCode::StateError,
            "another operation is in progress" + (active.empty() ? std::string{} : ": " + active)));
        return;
    }
    if (operation_lock.owns_lock()) {
        const std::lock_guard<std::mutex> lock(daemon_state.active_name_mutex);
        daemon_state.active_name = commandName(command);
    }
    bool connected = true;
    const tunproxy::LogCallback logger = [descriptor, &connected, &daemon_state, command](
        tunproxy::LogLevel level, std::string_view message) {
        if (!connected) {
            return;
        }
        if (isMutating(command) && level != tunproxy::LogLevel::Progress) {
            const std::lock_guard<std::mutex> lock(daemon_state.active_name_mutex);
            daemon_state.active_name = std::string(commandName(command)) + ": " + std::string(message);
        }
        for (std::size_t offset = 0; offset < message.size() && connected;
             offset += tunproxy::kIpcMaximumPayload) {
            const std::size_t count = std::min<std::size_t>(
                tunproxy::kIpcMaximumPayload, message.size() - offset);
            const auto sent = tunproxy::sendIpcFrame(descriptor, tunproxy::IpcFrame{
                tunproxy::IpcFrameType::Log,
                static_cast<std::uint32_t>(level),
                std::string(message.substr(offset, count))});
            connected = sent.ok();
        }
    };
    const auto result = controller.execute(command, request.value().payload, logger);
    if (operation_lock.owns_lock()) {
        const std::lock_guard<std::mutex> lock(daemon_state.active_name_mutex);
        daemon_state.active_name.clear();
    }
    if (!connected) {
        return;
    }
    if (!result.ok()) {
        sendError(descriptor, result.error());
        return;
    }
    (void)tunproxy::sendIpcFrame(descriptor, tunproxy::IpcFrame{
        tunproxy::IpcFrameType::Result, 0, result.value()});
}

} // namespace

int main() {
    if (::geteuid() != 0) {
        std::cerr << "tunproxyd: root privileges are required\n";
        return static_cast<int>(tunproxy::ErrorCode::InsufficientPrivileges);
    }
    (void)::umask(0077);
    struct sigaction action {};
    action.sa_handler = handleSignal;
    ::sigemptyset(&action.sa_mask);
    if (::sigaction(SIGTERM, &action, nullptr) != 0 || ::sigaction(SIGINT, &action, nullptr) != 0) {
        std::cerr << "tunproxyd: cannot install signal handlers\n";
        return static_cast<int>(tunproxy::ErrorCode::StateError);
    }
    (void)::signal(SIGPIPE, SIG_IGN);

    tunproxy::AppPaths paths;
    int listener = inheritedSocket();
    bool owns_socket = false;
    if (listener < 0) {
        const auto created = createSocket(paths.control_socket());
        if (!created.ok()) {
            std::cerr << "tunproxyd: " << created.error().message << '\n';
            return static_cast<int>(created.error().code);
        }
        listener = created.value();
        owns_socket = true;
    }

    const tunproxy::CommandController controller(paths);
    DaemonState daemon_state;
    while (stop_requested == 0) {
        pollfd event{listener, POLLIN, 0};
        const int ready = ::poll(&event, 1, 500);
        if (ready < 0 && errno == EINTR) {
            continue;
        }
        if (ready == 0) {
            continue;
        }
        if (ready < 0 || (event.revents & POLLIN) == 0) {
            std::cerr << "tunproxyd: control listener failed\n";
            break;
        }
        const int client = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) {
            if (errno == EINTR) {
                continue;
            }
            std::cerr << "tunproxyd: accept failed: " << std::strerror(errno) << '\n';
            break;
        }
        uid_t uid = std::numeric_limits<uid_t>::max();
        if (!authorizeClient(client, uid)) {
            std::cerr << "tunproxyd: rejected unauthorized local client uid=" << uid << '\n';
            sendError(client, tunproxy::makeError(
                tunproxy::ErrorCode::InsufficientPrivileges,
                "client is not authorized to control TunProxy"));
            (void)::close(client);
            continue;
        }
        timeval timeout{static_cast<time_t>(tunproxy::kClientSocketTimeout.count()), 0};
        (void)::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        (void)::setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        {
            const std::lock_guard<std::mutex> lock(daemon_state.clients_mutex);
            ++daemon_state.active_clients;
        }
        try {
            std::thread([client, &controller, &daemon_state] {
                serveClient(client, controller, daemon_state);
                (void)::close(client);
                {
                    const std::lock_guard<std::mutex> lock(daemon_state.clients_mutex);
                    --daemon_state.active_clients;
                }
                daemon_state.clients_finished.notify_all();
            }).detach();
        } catch (const std::system_error& error) {
            {
                const std::lock_guard<std::mutex> lock(daemon_state.clients_mutex);
                --daemon_state.active_clients;
            }
            daemon_state.clients_finished.notify_all();
            sendError(client, tunproxy::makeError(
                tunproxy::ErrorCode::StateError,
                "cannot create client worker: " + std::string(error.what())));
            (void)::close(client);
        }
    }

    {
        std::unique_lock<std::mutex> lock(daemon_state.clients_mutex);
        daemon_state.clients_finished.wait(lock, [&daemon_state] {
            return daemon_state.active_clients == 0;
        });
    }

    if (std::filesystem::exists(paths.state_file())) {
        const tunproxy::LogCallback logger = [](tunproxy::LogLevel, std::string_view message) {
            std::cerr << "tunproxyd: " << message << '\n';
        };
        const auto stopped = controller.execute(tunproxy::Command::Off, {}, logger);
        if (!stopped.ok()) {
            std::cerr << "tunproxyd: shutdown cleanup failed: " << stopped.error().message << '\n';
        }
    }
    (void)::close(listener);
    if (owns_socket) {
        (void)::unlink(paths.control_socket().c_str());
    }
    return 0;
}
