#include "tunproxy/ipc.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <limits>

namespace tunproxy {
namespace {

constexpr std::size_t kFrameMetadataSize = 1U + sizeof(std::uint32_t);

Result<void> sendAll(int descriptor, const void* data, std::size_t size) {
    const auto* bytes = static_cast<const char*>(data);
    std::size_t sent = 0;
    while (sent < size) {
        const ssize_t count = ::write(descriptor, bytes + sent, size - sent);
        if (count > 0) {
            sent += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        return Result<void>::failure(makeError(
            ErrorCode::StateError, "control connection write failed: " + std::string(std::strerror(errno))));
    }
    return Result<void>::success();
}

Result<void> receiveAll(int descriptor, void* data, std::size_t size) {
    auto* bytes = static_cast<char*>(data);
    std::size_t received = 0;
    while (received < size) {
        const ssize_t count = ::recv(descriptor, bytes + received, size - received, 0);
        if (count > 0) {
            received += static_cast<std::size_t>(count);
            continue;
        }
        if (count < 0 && errno == EINTR) {
            continue;
        }
        const std::string detail = count == 0 ? "connection closed" : std::strerror(errno);
        return Result<void>::failure(makeError(
            ErrorCode::StateError, "control connection read failed: " + detail));
    }
    return Result<void>::success();
}

} // namespace

Result<Command> decodeCommand(std::uint32_t code) {
    if ((code >> 16U) != kIpcProtocolVersion) {
        return Result<Command>::failure(makeError(ErrorCode::InvalidArguments, "unsupported IPC protocol version"));
    }
    const std::uint32_t command_code = code & 0xffffU;
    if (command_code < static_cast<std::uint32_t>(Command::On) ||
        command_code > static_cast<std::uint32_t>(Command::Bypass)) {
        return Result<Command>::failure(makeError(ErrorCode::InvalidArguments, "unknown IPC command"));
    }
    return Result<Command>::success(static_cast<Command>(command_code));
}

Result<void> sendIpcFrame(int descriptor, const IpcFrame& frame) {
    if (frame.payload.size() > kIpcMaximumPayload) {
        return Result<void>::failure(makeError(ErrorCode::InvalidArguments, "IPC payload is too large"));
    }
    const std::size_t body_size = kFrameMetadataSize + frame.payload.size();
    if (body_size > std::numeric_limits<std::uint32_t>::max()) {
        return Result<void>::failure(makeError(ErrorCode::InvalidArguments, "IPC frame is too large"));
    }
    const std::uint32_t network_size = htonl(static_cast<std::uint32_t>(body_size));
    const std::uint8_t type = static_cast<std::uint8_t>(frame.type);
    const std::uint32_t network_code = htonl(frame.code);
    auto sent = sendAll(descriptor, &network_size, sizeof(network_size));
    if (!sent.ok()) {
        return sent;
    }
    sent = sendAll(descriptor, &type, sizeof(type));
    if (!sent.ok()) {
        return sent;
    }
    sent = sendAll(descriptor, &network_code, sizeof(network_code));
    if (!sent.ok() || frame.payload.empty()) {
        return sent;
    }
    return sendAll(descriptor, frame.payload.data(), frame.payload.size());
}

Result<IpcFrame> receiveIpcFrame(int descriptor) {
    std::uint32_t network_size = 0;
    auto received = receiveAll(descriptor, &network_size, sizeof(network_size));
    if (!received.ok()) {
        return Result<IpcFrame>::failure(received.error());
    }
    const std::uint32_t body_size = ntohl(network_size);
    if (body_size < kFrameMetadataSize || body_size > kFrameMetadataSize + kIpcMaximumPayload) {
        return Result<IpcFrame>::failure(makeError(ErrorCode::InvalidArguments, "invalid IPC frame size"));
    }
    std::uint8_t type = 0;
    std::uint32_t network_code = 0;
    received = receiveAll(descriptor, &type, sizeof(type));
    if (!received.ok()) {
        return Result<IpcFrame>::failure(received.error());
    }
    received = receiveAll(descriptor, &network_code, sizeof(network_code));
    if (!received.ok()) {
        return Result<IpcFrame>::failure(received.error());
    }
    if (type < static_cast<std::uint8_t>(IpcFrameType::Request) ||
        type > static_cast<std::uint8_t>(IpcFrameType::Error)) {
        return Result<IpcFrame>::failure(makeError(ErrorCode::InvalidArguments, "invalid IPC frame type"));
    }
    IpcFrame frame;
    frame.type = static_cast<IpcFrameType>(type);
    frame.code = ntohl(network_code);
    frame.payload.resize(body_size - kFrameMetadataSize);
    if (!frame.payload.empty()) {
        received = receiveAll(descriptor, frame.payload.data(), frame.payload.size());
        if (!received.ok()) {
            return Result<IpcFrame>::failure(received.error());
        }
    }
    return Result<IpcFrame>::success(std::move(frame));
}

Result<int> connectControlSocket(const std::filesystem::path& path) {
    const std::string path_string = path.string();
    sockaddr_un address{};
    if (path_string.empty() || path_string.size() >= sizeof(address.sun_path)) {
        return Result<int>::failure(makeError(ErrorCode::InvalidArguments, "control socket path is invalid"));
    }
    const int descriptor = ::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
        return Result<int>::failure(makeError(ErrorCode::StateError, "cannot create control socket"));
    }
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, path_string.c_str(), path_string.size() + 1U);
    if (::connect(descriptor, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        const int saved_errno = errno;
        (void)::close(descriptor);
        std::string message;
        if (saved_errno == EACCES) {
            message = "permission denied connecting to tunproxyd; the user must belong to the sudo group";
        } else {
            message = "cannot connect to tunproxyd at " + path_string + ": " + std::strerror(saved_errno);
        }
        return Result<int>::failure(makeError(ErrorCode::StateError, std::move(message)));
    }
    return Result<int>::success(descriptor);
}

} // namespace tunproxy
