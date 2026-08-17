#include "tunproxy/process.hpp"

#include "tunproxy/result.hpp"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/securebits.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <thread>

namespace tunproxy {
namespace {

struct Pipe {
    int read{-1};
    int write{-1};
};

void closeFd(int& fd) {
    if (fd >= 0) {
        (void)::close(fd);
        fd = -1;
    }
}

bool setNonBlocking(int fd) {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    return flags >= 0 && ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

std::string readAvailable(int fd) {
    std::string result;
    std::array<char, 4096> buffer{};
    for (;;) {
        const ssize_t count = ::read(fd, buffer.data(), buffer.size());
        if (count > 0) {
            result.append(buffer.data(), static_cast<std::size_t>(count));
            continue;
        }
        if (count < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) {
            break;
        }
        break;
    }
    return result;
}

bool dropUtilityCapabilities() {
    if (::geteuid() != 0) {
        return true;
    }
    constexpr int required_securebits =
        SECBIT_NOROOT | SECBIT_NOROOT_LOCKED | SECBIT_NO_SETUID_FIXUP |
        SECBIT_NO_SETUID_FIXUP_LOCKED;
    const int current_securebits = ::prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
    if (current_securebits < 0 ||
        ((current_securebits & required_securebits) != required_securebits &&
         ::prctl(PR_SET_SECUREBITS, required_securebits, 0, 0, 0) != 0)) {
        return false;
    }
#ifdef PR_CAP_AMBIENT
    if (::prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 && errno != EINVAL) {
        return false;
    }
#endif
    __user_cap_header_struct header{};
    header.version = _LINUX_CAPABILITY_VERSION_3;
    header.pid = 0;
    __user_cap_data_struct capabilities[2]{};
    return ::syscall(SYS_capset, &header, capabilities) == 0;
}

} // namespace

Result<ProcessOutput> runCapture(
    const std::vector<std::string>& arguments,
    std::chrono::milliseconds timeout,
    ProcessOutputCallback callback) {
    if (arguments.empty() || arguments.front().empty()) {
        return Result<ProcessOutput>::failure(
            makeError(ErrorCode::InvalidArguments, "empty process command"));
    }

    int stdout_fds[2]{-1, -1};
    int stderr_fds[2]{-1, -1};
    if (::pipe2(stdout_fds, O_CLOEXEC) != 0 || ::pipe2(stderr_fds, O_CLOEXEC) != 0) {
        closeFd(stdout_fds[0]);
        closeFd(stdout_fds[1]);
        closeFd(stderr_fds[0]);
        closeFd(stderr_fds[1]);
        return Result<ProcessOutput>::failure(
            makeError(ErrorCode::Generic, "pipe failed: " + std::string(std::strerror(errno))));
    }
    Pipe stdout_pipe{stdout_fds[0], stdout_fds[1]};
    Pipe stderr_pipe{stderr_fds[0], stderr_fds[1]};

    const pid_t child = ::fork();
    if (child < 0) {
        closeFd(stdout_pipe.read);
        closeFd(stdout_pipe.write);
        closeFd(stderr_pipe.read);
        closeFd(stderr_pipe.write);
        return Result<ProcessOutput>::failure(
            makeError(ErrorCode::Generic, "fork failed: " + std::string(std::strerror(errno))));
    }

    if (child == 0) {
        (void)::dup2(stdout_pipe.write, STDOUT_FILENO);
        (void)::dup2(stderr_pipe.write, STDERR_FILENO);
        closeFd(stdout_pipe.read);
        closeFd(stdout_pipe.write);
        closeFd(stderr_pipe.read);
        closeFd(stderr_pipe.write);

        if (!dropUtilityCapabilities()) {
            _exit(126);
        }

        std::vector<char*> argv;
        argv.reserve(arguments.size() + 1);
        for (const std::string& argument : arguments) {
            argv.push_back(const_cast<char*>(argument.c_str()));
        }
        argv.push_back(nullptr);
        ::execv(arguments.front().c_str(), argv.data());
        _exit(127);
    }

    closeFd(stdout_pipe.write);
    closeFd(stderr_pipe.write);
    if (!setNonBlocking(stdout_pipe.read) || !setNonBlocking(stderr_pipe.read)) {
        (void)::kill(child, SIGKILL);
        (void)::waitpid(child, nullptr, 0);
        closeFd(stdout_pipe.read);
        closeFd(stderr_pipe.read);
        return Result<ProcessOutput>::failure(
            makeError(ErrorCode::Generic, "fcntl failed: " + std::string(std::strerror(errno))));
    }

    ProcessOutput output;
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    bool exited = false;
    int status = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        const std::string stdout_chunk = readAvailable(stdout_pipe.read);
        const std::string stderr_chunk = readAvailable(stderr_pipe.read);
        output.stdout_text += stdout_chunk;
        output.stderr_text += stderr_chunk;
        if (callback) {
            if (!stdout_chunk.empty()) {
                callback(ProcessStream::Stdout, stdout_chunk);
            }
            if (!stderr_chunk.empty()) {
                callback(ProcessStream::Stderr, stderr_chunk);
            }
        }
        const pid_t waited = ::waitpid(child, &status, WNOHANG);
        if (waited == child) {
            exited = true;
            break;
        }
        if (waited < 0 && errno != EINTR) {
            break;
        }
        struct pollfd descriptors[2] = {
            {stdout_pipe.read, POLLIN, 0},
            {stderr_pipe.read, POLLIN, 0},
        };
        (void)::poll(descriptors, 2, 25);
    }

    if (!exited) {
        (void)::kill(child, SIGKILL);
        (void)::waitpid(child, &status, 0);
        closeFd(stdout_pipe.read);
        closeFd(stderr_pipe.read);
        return Result<ProcessOutput>::failure(
            makeError(ErrorCode::Generic, "process timed out"));
    }

    const std::string stdout_chunk = readAvailable(stdout_pipe.read);
    const std::string stderr_chunk = readAvailable(stderr_pipe.read);
    output.stdout_text += stdout_chunk;
    output.stderr_text += stderr_chunk;
    if (callback) {
        if (!stdout_chunk.empty()) {
            callback(ProcessStream::Stdout, stdout_chunk);
        }
        if (!stderr_chunk.empty()) {
            callback(ProcessStream::Stderr, stderr_chunk);
        }
    }
    closeFd(stdout_pipe.read);
    closeFd(stderr_pipe.read);

    if (WIFEXITED(status)) {
        output.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        output.exit_code = 128 + WTERMSIG(status);
    }
    return Result<ProcessOutput>::success(std::move(output));
}

} // namespace tunproxy
