#include "tunproxy/controller.hpp"

#include "tunproxy/bypass_policy.hpp"
#include "tunproxy/config.hpp"
#include "tunproxy/proxy_manager.hpp"
#include "tunproxy/runtime_state.hpp"

#include <sstream>

namespace tunproxy {
namespace {

std::string formatStatus(const ProxyStatus& status) {
    std::ostringstream output;
    output << "Status: " << (status.running ? "ON" : "OFF") << '\n';
    if (!status.upstream.empty()) {
        output << "Upstream: " << status.upstream;
        if (status.running && !status.upstream_address.empty()) {
            output << " (" << status.upstream_address << ')';
        }
        output << '\n';
    }
    if (status.running) {
        output << "Core: sing-box " << status.core_version << '\n'
               << "PID: " << status.pid << '\n'
               << "Routing: " << status.routing_mode << '\n'
               << "Bypass: " << status.bypass_cidrs.size() << " CIDRs\n";
    } else if (status.core_installed) {
        output << "Core: sing-box " << status.core_version << '\n';
    } else {
        output << "Core: not installed\n";
    }
    return output.str();
}

Result<std::string> rejectArgument(const std::string& argument, const char* command) {
    if (!argument.empty()) {
        return Result<std::string>::failure(
            makeError(ErrorCode::InvalidArguments, std::string(command) + " takes no argument"));
    }
    return Result<std::string>::success({});
}

} // namespace

CommandController::CommandController(AppPaths paths) : paths_(std::move(paths)) {}

Result<std::string> CommandController::execute(
    Command command, const std::string& argument, LogCallback logger) const {
    if (command == Command::Status) {
        const auto checked = rejectArgument(argument, "status");
        if (!checked.ok()) {
            return checked;
        }
        ProxyManager manager(paths_, std::move(logger));
        const auto status = manager.status();
        if (!status.ok()) {
            return Result<std::string>::failure(status.error());
        }
        return Result<std::string>::success(formatStatus(status.value()));
    }

    if (command == Command::Bypass) {
        const auto checked = rejectArgument(argument, "bypass");
        if (!checked.ok()) {
            return checked;
        }
        ProxyManager manager(paths_, std::move(logger));
        const auto status = manager.status();
        if (!status.ok()) {
            return Result<std::string>::failure(status.error());
        }
        std::vector<std::string> cidrs;
        std::string upstream_cidr;
        const bool active = status.value().running && !status.value().bypass_cidrs.empty();
        if (active) {
            cidrs = status.value().bypass_cidrs;
            if (!status.value().upstream_address.empty()) {
                const auto pinned = addressHostCidr(status.value().upstream_address);
                if (pinned.ok()) {
                    upstream_cidr = pinned.value();
                }
            }
        } else {
            const auto preview = collectBypassPolicy({}, paths_.tun_interface);
            if (!preview.ok()) {
                return Result<std::string>::failure(preview.error());
            }
            cidrs = preview.value().allCidrs();
        }
        std::ostringstream output;
        output << "Bypass: " << (active ? "active" : "preview") << ", "
               << cidrs.size() << " CIDRs\n";
        if (!upstream_cidr.empty()) {
            output << "Upstream: " << upstream_cidr << '\n';
        }
        for (const auto& cidr : cidrs) {
            output << "  " << cidr << '\n';
        }
        return Result<std::string>::success(output.str());
    }

    if (command == Command::GetSetting) {
        const auto checked = rejectArgument(argument, "setting query");
        if (!checked.ok()) {
            return checked;
        }
        ConfigManager config(paths_);
        const auto current = config.load();
        if (!current.ok()) {
            return Result<std::string>::failure(current.error());
        }
        return Result<std::string>::success(formatUpstreamUri(current.value()));
    }

    const auto lock = FileLock::acquire(paths_.lock_file(), [&logger] {
        emitLog(logger, LogLevel::Info, "Waiting for another operation to finish");
    });
    if (!lock.ok()) {
        return Result<std::string>::failure(lock.error());
    }

    if (command == Command::SetSetting) {
        if (argument.empty()) {
            return Result<std::string>::failure(
                makeError(ErrorCode::InvalidArguments, "setting requires an upstream URI"));
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
        return Result<std::string>::success("Upstream: " + formatUpstreamUri(upstream.value()) + "\n");
    }

    const auto checked = rejectArgument(argument, "command");
    if (!checked.ok()) {
        return checked;
    }
    ProxyManager manager(paths_, std::move(logger));
    if (command == Command::Off) {
        const auto stopped = manager.stop();
        if (!stopped.ok()) {
            return Result<std::string>::failure(stopped.error());
        }
        return Result<std::string>::success("Status: OFF\n");
    }
    if (command == Command::On) {
        const auto started = manager.start();
        if (!started.ok()) {
            return Result<std::string>::failure(started.error());
        }
        return Result<std::string>::success(formatStatus(started.value()));
    }
    return Result<std::string>::failure(makeError(ErrorCode::InvalidArguments, "unknown command"));
}

} // namespace tunproxy
