#pragma once

#include <filesystem>

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

    [[nodiscard]] std::filesystem::path lock_file() const {
        return runtime_dir / "lock";
    }

    [[nodiscard]] std::filesystem::path state_file() const {
        return runtime_dir / "state";
    }

    [[nodiscard]] std::filesystem::path control_socket() const {
        return runtime_dir / "control.sock";
    }
};

} // namespace tunproxy
