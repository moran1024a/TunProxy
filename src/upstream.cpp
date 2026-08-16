#include "tunproxy/upstream.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <memory>

namespace tunproxy {
namespace {

struct AddrInfoDeleter {
    void operator()(addrinfo* value) const { ::freeaddrinfo(value); }
};

bool waitForSocket(int descriptor, short events, std::chrono::milliseconds timeout) {
    struct pollfd poll_descriptor {descriptor, events, 0};
    for (;;) {
        const int result = ::poll(&poll_descriptor, 1, static_cast<int>(timeout.count()));
        if (result > 0) {
            return (poll_descriptor.revents & events) != 0;
        }
        if (result < 0 && errno == EINTR) {
            continue;
        }
        return false;
    }
}

Result<std::string> probeAddress(
    const addrinfo& address,
    std::chrono::milliseconds timeout) {
    const int socket_fd = ::socket(address.ai_family, address.ai_socktype | SOCK_CLOEXEC, address.ai_protocol);
    if (socket_fd < 0) {
        return Result<std::string>::failure(makeError(ErrorCode::UpstreamUnreachable, "cannot create probe socket"));
    }
    const int flags = ::fcntl(socket_fd, F_GETFL, 0);
    (void)::fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK);
    int connected = ::connect(socket_fd, address.ai_addr, address.ai_addrlen);
    if (connected != 0 && errno == EINPROGRESS) {
        if (!waitForSocket(socket_fd, POLLOUT, timeout)) {
            (void)::close(socket_fd);
            return Result<std::string>::failure(makeError(ErrorCode::UpstreamUnreachable, "upstream connect timed out"));
        }
        int socket_error = 0;
        socklen_t length = sizeof(socket_error);
        if (::getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, &socket_error, &length) != 0 || socket_error != 0) {
            (void)::close(socket_fd);
            return Result<std::string>::failure(makeError(ErrorCode::UpstreamUnreachable, "upstream connection failed"));
        }
    } else if (connected != 0) {
        (void)::close(socket_fd);
        return Result<std::string>::failure(makeError(ErrorCode::UpstreamUnreachable, "upstream connection failed"));
    }
    (void)::fcntl(socket_fd, F_SETFL, flags);

    const auto timeout_microseconds =
        std::chrono::duration_cast<std::chrono::microseconds>(timeout).count();
    struct timeval socket_timeout {
        static_cast<time_t>(timeout_microseconds / 1000000),
        static_cast<suseconds_t>(timeout_microseconds % 1000000),
    };
    (void)::setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &socket_timeout, sizeof(socket_timeout));
    (void)::setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, &socket_timeout, sizeof(socket_timeout));

    const std::array<unsigned char, 3> greeting{0x05, 0x01, 0x00};
    if (::send(socket_fd, greeting.data(), greeting.size(), MSG_NOSIGNAL) !=
        static_cast<ssize_t>(greeting.size()) || !waitForSocket(socket_fd, POLLIN, timeout)) {
        (void)::close(socket_fd);
        return Result<std::string>::failure(makeError(ErrorCode::UpstreamUnreachable, "SOCKS5 greeting failed"));
    }
    std::array<unsigned char, 2> response{};
    const ssize_t received = ::recv(socket_fd, response.data(), response.size(), MSG_WAITALL);
    (void)::close(socket_fd);
    if (received != static_cast<ssize_t>(response.size()) || response[0] != 0x05 || response[1] != 0x00) {
        return Result<std::string>::failure(makeError(ErrorCode::UpstreamUnreachable, "upstream rejected unauthenticated SOCKS5"));
    }

    std::array<char, INET6_ADDRSTRLEN> text{};
    const void* raw_address = nullptr;
    if (address.ai_family == AF_INET) {
        raw_address = &reinterpret_cast<const sockaddr_in*>(address.ai_addr)->sin_addr;
    } else if (address.ai_family == AF_INET6) {
        raw_address = &reinterpret_cast<const sockaddr_in6*>(address.ai_addr)->sin6_addr;
    }
    if (raw_address == nullptr || ::inet_ntop(address.ai_family, raw_address, text.data(), text.size()) == nullptr) {
        return Result<std::string>::failure(makeError(ErrorCode::UpstreamUnreachable, "cannot format upstream address"));
    }
    return Result<std::string>::success(text.data());
}

} // namespace

Result<ResolvedUpstream> resolveAndProbeUpstream(
    const Upstream& upstream,
    std::chrono::milliseconds timeout) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* raw_addresses = nullptr;
    const std::string service = std::to_string(upstream.port);
    const int resolved = ::getaddrinfo(upstream.host.c_str(), service.c_str(), &hints, &raw_addresses);
    if (resolved != 0) {
        return Result<ResolvedUpstream>::failure(makeError(
            ErrorCode::UpstreamUnreachable,
            "cannot resolve upstream: " + std::string(::gai_strerror(resolved))));
    }
    std::unique_ptr<addrinfo, AddrInfoDeleter> addresses(raw_addresses);
    Error last_error = makeError(ErrorCode::UpstreamUnreachable, "upstream is unreachable");
    for (const addrinfo* current = addresses.get(); current != nullptr; current = current->ai_next) {
        const auto probed = probeAddress(*current, timeout);
        if (probed.ok()) {
            return Result<ResolvedUpstream>::success(ResolvedUpstream{upstream, probed.value()});
        }
        last_error = probed.error();
    }
    return Result<ResolvedUpstream>::failure(std::move(last_error));
}

} // namespace tunproxy
