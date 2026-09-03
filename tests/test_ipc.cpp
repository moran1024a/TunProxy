#include "framework.hpp"

#include "tunproxy/ipc.hpp"
#include "tunproxy/log.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace tunproxy;

namespace {

struct SocketPair {
    int descriptors[2]{-1, -1};
    SocketPair() { (void)::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, descriptors); }
    ~SocketPair() {
        (void)::close(descriptors[0]);
        (void)::close(descriptors[1]);
    }
};

} // namespace

TEST_CASE(ipc_round_trips_frames) {
    const SocketPair pair;
    REQUIRE(pair.descriptors[0] >= 0);
    const IpcFrame sent{IpcFrameType::Log, static_cast<std::uint32_t>(LogLevel::Progress), "progress\rwith\nline boundaries"};
    REQUIRE(sendIpcFrame(pair.descriptors[0], sent).ok());
    const auto received = receiveIpcFrame(pair.descriptors[1]);
    REQUIRE(received.ok());
    CHECK(received.value().type == sent.type);
    CHECK(received.value().code == sent.code);
    CHECK(received.value().payload == sent.payload);

    REQUIRE(sendIpcFrame(pair.descriptors[0], IpcFrame{IpcFrameType::Result, 0, {}}).ok());
    const auto empty = receiveIpcFrame(pair.descriptors[1]);
    REQUIRE(empty.ok());
    CHECK(empty.value().payload.empty());
}

TEST_CASE(ipc_rejects_oversized_and_malformed_frames) {
    const SocketPair pair;
    REQUIRE(pair.descriptors[0] >= 0);
    CHECK(!sendIpcFrame(pair.descriptors[0], IpcFrame{
        IpcFrameType::Request, 0, std::string(kIpcMaximumPayload + 1U, 'x')}).ok());

    const std::uint32_t oversized = htonl(kIpcMaximumPayload + 6U);
    REQUIRE(::write(pair.descriptors[0], &oversized, sizeof(oversized)) == static_cast<ssize_t>(sizeof(oversized)));
    CHECK(!receiveIpcFrame(pair.descriptors[1]).ok());

    const std::uint32_t undersized = htonl(2U);
    REQUIRE(::write(pair.descriptors[0], &undersized, sizeof(undersized)) == static_cast<ssize_t>(sizeof(undersized)));
    CHECK(!receiveIpcFrame(pair.descriptors[1]).ok());

    const unsigned char bad_type[] = {0, 0, 0, 5, 9, 0, 0, 0, 0};
    REQUIRE(::write(pair.descriptors[0], bad_type, sizeof(bad_type)) == static_cast<ssize_t>(sizeof(bad_type)));
    CHECK(!receiveIpcFrame(pair.descriptors[1]).ok());
}

TEST_CASE(ipc_reports_closed_connection) {
    const SocketPair pair;
    REQUIRE(pair.descriptors[0] >= 0);
    (void)::shutdown(pair.descriptors[0], SHUT_WR);
    const auto received = receiveIpcFrame(pair.descriptors[1]);
    CHECK(!received.ok());
    CHECK(received.error().message.find("connection closed") != std::string::npos);
}

TEST_CASE(ipc_decodes_commands_with_protocol_version) {
    for (const Command command : {Command::On, Command::Off, Command::Status, Command::GetSetting, Command::SetSetting, Command::Bypass}) {
        const auto decoded = decodeCommand(encodeCommand(command));
        REQUIRE(decoded.ok());
        CHECK(decoded.value() == command);
    }
    CHECK(!decodeCommand(static_cast<std::uint32_t>(Command::On)).ok());
    CHECK(!decodeCommand(((kIpcProtocolVersion + 1U) << 16U) | 1U).ok());
    CHECK(!decodeCommand((kIpcProtocolVersion << 16U) | 0U).ok());
    CHECK(!decodeCommand((kIpcProtocolVersion << 16U) | 7U).ok());
}

TEST_CASE(ipc_connect_reports_missing_socket) {
    const auto connected = connectControlSocket("/nonexistent/tunproxy-test.sock");
    CHECK(!connected.ok());
    CHECK(!connectControlSocket("").ok());
}
