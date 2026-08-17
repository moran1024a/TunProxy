#include "tunproxy/controller.hpp"

#include "tunproxy/bypass_policy.hpp"
#include "tunproxy/config.hpp"
#include "tunproxy/proxy_manager.hpp"
#include "tunproxy/runtime_state.hpp"

#include <sstream>

namespace tunproxy {

CommandController::CommandController(AppPaths paths) : paths_(std::move(paths)) {}

Result<std::string> CommandController::execute(
    Command command, const std::string& argument, LogCallback logger) const {
    if (command == Command::Status) {
        if (!argument.empty()) {
            return Result<std::string>::failure(makeError(ErrorCode::InvalidArguments, "status takes no argument"));
        }
        ProxyManager manager(paths_, std::move(logger));
        const auto status = manager.status();
        if (!status.ok()) {
            return Result<std::string>::failure(status.error());
        }
        std::ostringstream output;
        output << "Status: " << (status.value().running ? "ON" : "OFF") << '\n';
        if (!status.value().upstream.empty()) {
            output << "Upstream: " << status.value().upstream << '\n';
        }
        if (status.value().running) {
            output << "Core: sing-box " << status.value().core_version << '\n'
                   << "PID: " << status.value().pid << '\n'
                   << "Routing: " << status.value().routing_mode << '\n'
                   << "Bypass: fixed + upstream host + interface hosts (" << status.value().bypass_cidrs.size()
                   << " effective CIDRs)\n";
            if (!status.value().upstream_address.empty()) {
                output << "Upstream bypass: " << status.value().upstream_address << '\n';
            }
        } else {
            output << "Bypass: fixed + upstream host + interface hosts (applied on next on)\n";
        }
        return Result<std::string>::success(output.str());
    }

    if (command == Command::Bypass) {
        if (!argument.empty()) {
            return Result<std::string>::failure(
                makeError(ErrorCode::InvalidArguments, "bypass takes no argument"));
        }
        ProxyManager manager(paths_, std::move(logger));
        const auto status = manager.status();
        if (!status.ok()) {
            return Result<std::string>::failure(status.error());
        }
        std::vector<std::string> cidrs;
        if (status.value().running && !status.value().bypass_cidrs.empty()) {
            cidrs = status.value().bypass_cidrs;
        } else {
            const auto preview = collectBypassPolicy();
            if (!preview.ok()) {
                return Result<std::string>::failure(preview.error());
            }
            cidrs = preview.value().allCidrs();
        }
        std::ostringstream output;
        output << "Bypass policy: ALWAYS ON (internal, not configurable)\n"
               << "State: " << (status.value().running ? "ACTIVE" : "INACTIVE; current-network preview") << '\n';
        if (status.value().running && !status.value().upstream_address.empty()) {
            output << "Upstream address: " << status.value().upstream_address << " (mandatory direct)\n";
        } else {
            output << "Upstream address: selected and pinned during tunproxy on\n";
        }
        output << "Effective CIDRs (" << cidrs.size() << "):\n";
        for (const auto& cidr : cidrs) {
            output << "  " << cidr << '\n';
        }
        output << "Routing order:\n"
               << "  1. Selected SOCKS5 upstream address -> direct\n"
               << "  2. Fixed ranges and active interface host addresses -> direct\n"
               << "  3. Other DNS traffic -> hijack-dns\n"
               << "  4. Other UDP traffic -> reject\n"
               << "  5. Other traffic -> SOCKS5\n";
        return Result<std::string>::success(output.str());
    }

    if (command == Command::GetSetting) {
        if (!argument.empty()) {
            return Result<std::string>::failure(makeError(ErrorCode::InvalidArguments, "setting query takes no argument"));
        }
        ConfigManager config(paths_);
        const auto current = config.load();
        if (!current.ok()) {
            return Result<std::string>::failure(current.error());
        }
        return Result<std::string>::success(formatUpstreamUri(current.value()));
    }

    emitLog(logger, LogLevel::Info, "Waiting for operation lock...");
    const auto lock = FileLock::acquire(paths_.lock_file());
    if (!lock.ok()) {
        return Result<std::string>::failure(lock.error());
    }
    emitLog(logger, LogLevel::Info, "Operation lock acquired");

    if (command == Command::SetSetting) {
        if (argument.empty()) {
            return Result<std::string>::failure(makeError(ErrorCode::InvalidArguments, "setting requires an upstream URI"));
        }
        const auto upstream = parseUpstreamUri(argument);
        if (!upstream.ok()) {
            return Result<std::string>::failure(upstream.error());
        }
        ConfigManager config(paths_);
        const auto saved = config.save(upstream.value());
        if (!saved.ok()) {
            return Result<std::string>::failure(saved.error());
        }
        return Result<std::string>::success("Saved: " + formatUpstreamUri(upstream.value()) + "\n");
    }

    if (!argument.empty()) {
        return Result<std::string>::failure(makeError(ErrorCode::InvalidArguments, "command takes no argument"));
    }
    ProxyManager manager(paths_, std::move(logger));
    if (command == Command::Off) {
        const auto stopped = manager.stop();
        if (!stopped.ok()) {
            return Result<std::string>::failure(stopped.error());
        }
        return Result<std::string>::success("TunProxy: OFF\n");
    }
    if (command == Command::On) {
        const auto started = manager.start();
        if (!started.ok()) {
            return Result<std::string>::failure(started.error());
        }
        std::ostringstream output;
        output << "TunProxy: ON\n"
               << "Upstream: " << started.value().upstream << '\n'
               << "Core: sing-box " << started.value().core_version << '\n'
               << "Mode: TUN\n"
               << "Routing: " << started.value().routing_mode << '\n'
               << "Bypass: fixed + upstream host + interface hosts (" << started.value().bypass_cidrs.size()
               << " effective CIDRs)\n"
               << "Upstream bypass: " << started.value().upstream_address << '\n';
        return Result<std::string>::success(output.str());
    }
    return Result<std::string>::failure(makeError(ErrorCode::InvalidArguments, "unknown command"));
}

} // namespace tunproxy
