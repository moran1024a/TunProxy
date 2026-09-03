#include "framework.hpp"

#include "tunproxy/controller.hpp"

#include <string>

using namespace tunproxy;
using tunproxy::test::TempDir;

namespace {

AppPaths isolatedPaths(const TempDir& root) {
    AppPaths paths;
    paths.config_file = root / "etc/config";
    paths.data_dir = root / "data";
    paths.cache_dir = root / "cache";
    paths.runtime_dir = root / "run";
    paths.tun_interface = "tpxtest-none0";
    return paths;
}

bool startsWith(const std::string& text, const std::string& prefix) {
    return text.compare(0, prefix.size(), prefix) == 0;
}

} // namespace

TEST_CASE(controller_updates_and_reports_setting) {
    const TempDir root("controller-setting");
    const CommandController controller(isolatedPaths(root));
    const auto set = controller.execute(Command::SetSetting, "socks5://controller.local:1081");
    REQUIRE(set.ok());
    CHECK(set.value() == "Upstream: socks5://controller.local:1081\n");
    const auto get = controller.execute(Command::GetSetting, {});
    REQUIRE(get.ok());
    CHECK(get.value() == "socks5://controller.local:1081");
    CHECK(!controller.execute(Command::SetSetting, {}).ok());
    CHECK(!controller.execute(Command::SetSetting, "http://x:1").ok());
    CHECK(!controller.execute(Command::GetSetting, "extra").ok());
}

TEST_CASE(controller_status_off_without_core) {
    const TempDir root("controller-status");
    const CommandController controller(isolatedPaths(root));
    REQUIRE(controller.execute(Command::SetSetting, "socks5://127.0.0.1:1080").ok());
    const auto status = controller.execute(Command::Status, {});
    REQUIRE(status.ok());
    CHECK(status.value() == "Status: OFF\nUpstream: socks5://127.0.0.1:1080\nCore: not installed\n");
    CHECK(!controller.execute(Command::Status, "extra").ok());
}

TEST_CASE(controller_off_without_state_is_silent) {
    const TempDir root("controller-off");
    std::string log;
    const CommandController controller(isolatedPaths(root));
    const auto off = controller.execute(Command::Off, {}, [&log](LogLevel, std::string_view message) {
        log.append(message);
    });
    REQUIRE(off.ok());
    CHECK(off.value() == "Status: OFF\n");
    CHECK(log.empty());
    CHECK(!controller.execute(Command::Off, "extra").ok());
}

TEST_CASE(controller_bypass_preview_lists_cidrs) {
    const TempDir root("controller-bypass");
    const CommandController controller(isolatedPaths(root));
    const auto bypass = controller.execute(Command::Bypass, {});
    if (!bypass.ok() && bypass.error().message.find("Operation not permitted") != std::string::npos) {
        SKIP("getifaddrs is not permitted in this environment");
    }
    REQUIRE(bypass.ok());
    CHECK(startsWith(bypass.value(), "Bypass: preview, "));
    CHECK(bypass.value().find("Upstream:") == std::string::npos);
    CHECK(bypass.value().find("  127.0.0.0/8\n") != std::string::npos);
    CHECK(bypass.value().find("ALWAYS") == std::string::npos);
    CHECK(!controller.execute(Command::Bypass, "extra").ok());
}
