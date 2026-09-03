#pragma once

#include "tunproxy/constants.hpp"

#include <filesystem>
#include <string>

namespace tunproxy {

struct AppPaths {
    std::filesystem::path config_file{"/etc/tunproxy/config"};
    std::filesystem::path data_dir{"/var/lib/tunproxy"};
    std::filesystem::path cache_dir{"/var/cache/tunproxy"};
    std::filesystem::path runtime_dir{"/run/tunproxy"};
    std::filesystem::path default_config{"/usr/share/tunproxy/config.default"};
    std::filesystem::path tun_device{"/dev/net/tun"};
    std::filesystem::path tun_sysfs{"/sys/class/misc/tun/dev"};
    std::filesystem::path curl_executable{"/usr/bin/curl"};
    std::filesystem::path tar_executable{"/usr/bin/tar"};
    std::filesystem::path sha256sum_executable{"/usr/bin/sha256sum"};
    // Name of the managed TUN interface. Tests inject a name that does not
    // exist so they never observe or disturb a live instance.
    std::string tun_interface{kTunInterfaceName};

    [[nodiscard]] std::filesystem::path lock_file() const {
        return runtime_dir / "lock";
    }

    [[nodiscard]] std::filesystem::path state_file() const {
        return runtime_dir / "state";
    }

    [[nodiscard]] std::filesystem::path control_socket() const {
        return runtime_dir / "control.sock";
    }

    [[nodiscard]] std::filesystem::path core_config_file() const {
        return runtime_dir / std::string(kCoreConfigFileName);
    }

    [[nodiscard]] std::filesystem::path core_log_file() const {
        return runtime_dir / std::string(kCoreLogFileName);
    }
};

} // namespace tunproxy
