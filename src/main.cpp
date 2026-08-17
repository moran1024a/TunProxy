#include "tunproxy/config.hpp"
#include "tunproxy/controller.hpp"
#include "tunproxy/ipc.hpp"
#include "tunproxy/log.hpp"
#include "tunproxy/paths.hpp"
#include "tunproxy/result.hpp"
#include "tunproxy/version.hpp"

#include <unistd.h>

#include <csignal>
#include <iostream>
#include <string>

namespace {

int printError(const tunproxy::Error& error) {
    std::cerr << "Error: " << error.message << '\n';
    return static_cast<int>(error.code);
}

void printUsage() {
    std::cout << "Usage: tunproxy [--direct] <on|off|status|bypass|setting> [socks5://host:port]\n";
}

void printLog(tunproxy::LogLevel level, std::string_view message) {
    if (level == tunproxy::LogLevel::Progress) {
        std::cerr << message << std::flush;
        return;
    }
    std::ostream& output = level == tunproxy::LogLevel::Warning ? std::cerr : std::cout;
    output << (level == tunproxy::LogLevel::Warning ? "[WARN] " : "[INFO] ")
           << message << '\n' << std::flush;
}

tunproxy::Result<std::string> executeRemote(
    tunproxy::Command command, const std::string& argument, const tunproxy::AppPaths& paths) {
    const auto connected = tunproxy::connectControlSocket(paths.control_socket());
    if (!connected.ok()) {
        return tunproxy::Result<std::string>::failure(connected.error());
    }
    const int descriptor = connected.value();
    const auto sent = tunproxy::sendIpcFrame(descriptor, tunproxy::IpcFrame{
        tunproxy::IpcFrameType::Request, tunproxy::encodeCommand(command), argument});
    if (!sent.ok()) {
        (void)::close(descriptor);
        return tunproxy::Result<std::string>::failure(sent.error());
    }
    for (;;) {
        const auto frame = tunproxy::receiveIpcFrame(descriptor);
        if (!frame.ok()) {
            (void)::close(descriptor);
            return tunproxy::Result<std::string>::failure(frame.error());
        }
        if (frame.value().type == tunproxy::IpcFrameType::Log) {
            if (frame.value().code > static_cast<std::uint32_t>(tunproxy::LogLevel::Progress)) {
                (void)::close(descriptor);
                return tunproxy::Result<std::string>::failure(tunproxy::makeError(
                    tunproxy::ErrorCode::StateError, "tunproxyd returned an invalid log level"));
            }
            printLog(static_cast<tunproxy::LogLevel>(frame.value().code), frame.value().payload);
            continue;
        }
        (void)::close(descriptor);
        if (frame.value().type == tunproxy::IpcFrameType::Result) {
            return tunproxy::Result<std::string>::success(frame.value().payload);
        }
        if (frame.value().type == tunproxy::IpcFrameType::Error &&
            frame.value().code >= static_cast<std::uint32_t>(tunproxy::ErrorCode::Generic) &&
            frame.value().code <= static_cast<std::uint32_t>(tunproxy::ErrorCode::StateError)) {
            return tunproxy::Result<std::string>::failure(tunproxy::makeError(
                static_cast<tunproxy::ErrorCode>(frame.value().code), frame.value().payload));
        }
        return tunproxy::Result<std::string>::failure(tunproxy::makeError(
            tunproxy::ErrorCode::StateError, "tunproxyd returned an invalid response"));
    }
}

tunproxy::Result<std::string> execute(
    bool direct, tunproxy::Command command, const std::string& argument, const tunproxy::AppPaths& paths) {
    if (!direct) {
        return executeRemote(command, argument, paths);
    }
    if (::geteuid() != 0) {
        return tunproxy::Result<std::string>::failure(tunproxy::makeError(
            tunproxy::ErrorCode::InsufficientPrivileges, "--direct requires root privileges"));
    }
    return tunproxy::CommandController(paths).execute(command, argument, printLog);
}

int interactiveSetting(bool direct, const tunproxy::AppPaths& paths) {
    const auto current_result = execute(direct, tunproxy::Command::GetSetting, {}, paths);
    if (!current_result.ok()) {
        return printError(current_result.error());
    }
    const auto parsed = tunproxy::parseUpstreamUri(current_result.value());
    if (!parsed.ok()) {
        return printError(parsed.error());
    }
    tunproxy::Upstream updated = parsed.value();
    std::cout << "Current upstream:\n"
              << "  Protocol: " << updated.protocol << '\n'
              << "  Host:     " << updated.host << '\n'
              << "  Port:     " << updated.port << "\n\n";
    std::string input;
    std::cout << "New host [" << updated.host << "]: " << std::flush;
    std::getline(std::cin, input);
    if (!input.empty()) {
        updated.host = input;
    }
    std::cout << "New port [" << updated.port << "]: " << std::flush;
    std::getline(std::cin, input);
    if (!input.empty()) {
        const auto with_port = tunproxy::parseUpstreamUri(
            "socks5://" +
            (updated.host.find(':') == std::string::npos ? updated.host : "[" + updated.host + "]") +
            ":" + input);
        if (!with_port.ok()) {
            return printError(with_port.error());
        }
        updated.port = with_port.value().port;
    }
    const auto saved = execute(
        direct, tunproxy::Command::SetSetting, tunproxy::formatUpstreamUri(updated), paths);
    if (!saved.ok()) {
        return printError(saved.error());
    }
    std::cout << saved.value();
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    (void)::signal(SIGPIPE, SIG_IGN);
    if (argc == 2 && (std::string(argv[1]) == "--version" || std::string(argv[1]) == "version")) {
        std::cout << "TunProxy " << tunproxy::kTunProxyVersion << '\n'
                  << "Managed core: sing-box 1.13.18\n";
        return 0;
    }
    bool direct = false;
    int command_index = 1;
    if (argc > 1 && std::string(argv[1]) == "--direct") {
        direct = true;
        command_index = 2;
    }
    const int remaining = argc - command_index;
    if (remaining < 1 || remaining > 2) {
        printUsage();
        return static_cast<int>(tunproxy::ErrorCode::InvalidArguments);
    }
    const std::string command = argv[command_index];
    const std::string argument = remaining == 2 ? argv[command_index + 1] : std::string{};
    tunproxy::Command parsed_command{};
    if (command == "on") {
        parsed_command = tunproxy::Command::On;
    } else if (command == "off") {
        parsed_command = tunproxy::Command::Off;
    } else if (command == "status") {
        parsed_command = tunproxy::Command::Status;
    } else if (command == "bypass") {
        parsed_command = tunproxy::Command::Bypass;
    } else if (command == "setting") {
        if (remaining == 1) {
            return interactiveSetting(direct, tunproxy::AppPaths{});
        }
        parsed_command = tunproxy::Command::SetSetting;
    } else {
        printUsage();
        return static_cast<int>(tunproxy::ErrorCode::InvalidArguments);
    }
    const auto result = execute(direct, parsed_command, argument, tunproxy::AppPaths{});
    if (!result.ok()) {
        return printError(result.error());
    }
    std::cout << result.value();
    return 0;
}
