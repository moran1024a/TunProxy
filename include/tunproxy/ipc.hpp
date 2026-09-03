#pragma once

#include "tunproxy/result.hpp"

#include <cstdint>
#include <filesystem>
#include <string>

namespace tunproxy {

constexpr std::uint32_t kIpcProtocolVersion = 1;
constexpr std::uint32_t kIpcMaximumPayload = 64U * 1024U;

enum class IpcFrameType : std::uint8_t {
    Request = 1,
    Log = 2,
    Result = 3,
    Error = 4,
};

enum class Command : std::uint32_t {
    On = 1,
    Off = 2,
    Status = 3,
    GetSetting = 4,
    SetSetting = 5,
    Bypass = 6,
};

constexpr std::uint32_t encodeCommand(Command command) {
    return (kIpcProtocolVersion << 16U) | static_cast<std::uint32_t>(command);
}

// Rejects codes carrying a different protocol version or an unknown command.
Result<Command> decodeCommand(std::uint32_t code);

struct IpcFrame {
    IpcFrameType type{IpcFrameType::Error};
    std::uint32_t code{0};
    std::string payload;
};

Result<void> sendIpcFrame(int descriptor, const IpcFrame& frame);
Result<IpcFrame> receiveIpcFrame(int descriptor);
Result<int> connectControlSocket(const std::filesystem::path& path);

} // namespace tunproxy
