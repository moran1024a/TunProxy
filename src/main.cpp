#include "tunproxy/config.hpp"
#include "tunproxy/proxy_manager.hpp"
#include "tunproxy/result.hpp"
#include "tunproxy/runtime_state.hpp"
#include "tunproxy/version.hpp"

#include <unistd.h>

#include <iostream>
#include <string>

namespace {

int printError(const tunproxy::Error& error) {
    std::cerr << "Error: " << error.message << '\n';
    return static_cast<int>(error.code);
}

void printUsage() {
    std::cout << "Usage: tunproxy <on|off|status|setting> [socks5://host:port]\n";
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2 || argc > 3) {
        printUsage();
        return static_cast<int>(tunproxy::ErrorCode::InvalidArguments);
    }

    const std::string command = argv[1];
    if (command == "--version" || command == "version") {
        if (argc != 2) {
            printUsage();
            return static_cast<int>(tunproxy::ErrorCode::InvalidArguments);
        }
        std::cout << "TunProxy " << tunproxy::kTunProxyVersion << '\n'
                  << "Managed core: sing-box 1.13.18\n";
        return 0;
    }
    tunproxy::AppPaths paths;
    tunproxy::ConfigManager config;
    if (command == "setting") {
        if (::geteuid() != 0) {
            return printError(tunproxy::makeError(
                tunproxy::ErrorCode::InsufficientPrivileges, "setting requires root privileges"));
        }
        const auto lock = tunproxy::FileLock::acquire(paths.lock_file());
        if (!lock.ok()) {
            return printError(lock.error());
        }
        if (argc == 3) {
            const auto upstream = tunproxy::parseUpstreamUri(argv[2]);
            if (!upstream.ok()) {
                return printError(upstream.error());
            }
            const auto saved = config.save(upstream.value());
            if (!saved.ok()) {
                return printError(saved.error());
            }
            std::cout << "Saved: " << tunproxy::formatUpstreamUri(upstream.value()) << '\n';
            return 0;
        }
        const auto current = config.load();
        if (!current.ok()) {
            return printError(current.error());
        }
        tunproxy::Upstream updated = current.value();
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
            const auto parsed = tunproxy::parseUpstreamUri(
                "socks5://" +
                (updated.host.find(':') == std::string::npos ? updated.host : "[" + updated.host + "]") +
                ":" + input);
            if (!parsed.ok()) {
                return printError(parsed.error());
            }
            updated.port = parsed.value().port;
        }
        const auto saved = config.save(updated);
        if (!saved.ok()) {
            return printError(saved.error());
        }
        std::cout << "Saved: " << tunproxy::formatUpstreamUri(updated) << '\n';
        return 0;
    }

    if (command == "status") {
        if (argc != 2) {
            printUsage();
            return static_cast<int>(tunproxy::ErrorCode::InvalidArguments);
        }
        tunproxy::ProxyManager manager(paths);
        const auto status = manager.status();
        if (!status.ok()) {
            return printError(status.error());
        }
        std::cout << "Status: " << (status.value().running ? "ON" : "OFF") << '\n';
        if (!status.value().upstream.empty()) {
            std::cout << "Upstream: " << status.value().upstream << '\n';
        }
        if (status.value().running) {
            std::cout << "Core: sing-box " << status.value().core_version << '\n'
                      << "PID: " << status.value().pid << '\n'
                      << "Routing: " << status.value().routing_mode << '\n';
        }
        return 0;
    }

    if (command == "on" || command == "off") {
        if (argc != 2) {
            printUsage();
            return static_cast<int>(tunproxy::ErrorCode::InvalidArguments);
        }
        if (::geteuid() != 0) {
            return printError(tunproxy::makeError(
                tunproxy::ErrorCode::InsufficientPrivileges, command + " requires root privileges"));
        }
        const auto lock = tunproxy::FileLock::acquire(paths.lock_file());
        if (!lock.ok()) {
            return printError(lock.error());
        }
        tunproxy::ProxyManager manager(paths);
        if (command == "off") {
            const auto stopped = manager.stop();
            if (!stopped.ok()) {
                return printError(stopped.error());
            }
            std::cout << "TunProxy: OFF\n";
            return 0;
        }
        const auto started = manager.start();
        if (!started.ok()) {
            return printError(started.error());
        }
        std::cout << "TunProxy: ON\n"
                  << "Upstream: " << started.value().upstream << '\n'
                  << "Core: sing-box " << started.value().core_version << '\n'
                  << "Mode: TUN\n"
                  << "Routing: " << started.value().routing_mode << '\n';
        return 0;
    }

    printUsage();
    return static_cast<int>(tunproxy::ErrorCode::InvalidArguments);
}
