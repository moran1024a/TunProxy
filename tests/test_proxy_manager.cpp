#include "framework.hpp"

#include "tunproxy/config.hpp"
#include "tunproxy/proxy_manager.hpp"

#include "support.hpp"

#include <cstdlib>
#include <string>

using namespace tunproxy;
using tunproxy::test::TempDir;
using tunproxy::test::Listener;
using tunproxy::test::FakeCoreManifest;
using tunproxy::test::installFakeCore;
using tunproxy::test::respondOnce;

namespace {

struct Fixture {
    AppPaths paths;
    FakeCoreManifest fake;
    std::string log;

    explicit Fixture(const TempDir& root, std::uint16_t upstream_port) {
        paths.config_file = root / "etc/config";
        paths.data_dir = root / "data";
        paths.cache_dir = root / "cache";
        paths.runtime_dir = root / "run";
        paths.tun_device = "/dev/null"; // a character device; never opened by the fake core
        paths.tun_interface = "tpxtest-none0";
        installFakeCore(paths, fake);
        REQUIRE(ConfigManager(paths).save(Upstream{"socks5", "127.0.0.1", upstream_port}).ok());
    }

    LogCallback logger() {
        return [this](LogLevel level, std::string_view message) {
            if (level != LogLevel::Progress) {
                log.append(level == LogLevel::Warning ? "warning: " : "");
                log.append(message);
                log.push_back('\n');
            }
        };
    }
};

std::size_t countOccurrences(const std::string& text, const std::string& needle) {
    std::size_t count = 0;
    for (std::size_t offset = text.find(needle); offset != std::string::npos; offset = text.find(needle, offset + 1)) {
        ++count;
    }
    return count;
}

void skipIfInterfacesUnavailable(const Error& error) {
    if (error.message.find("Operation not permitted") != std::string::npos) {
        SKIP("getifaddrs is not permitted in this environment");
    }
}

} // namespace

TEST_CASE(proxy_manager_falls_back_to_tun_route_when_core_exits) {
    const TempDir root("pm-fallback");
    const Listener listener;
    if (listener.descriptor < 0) {
        SKIP("cannot bind a loopback TCP socket");
    }
    Fixture fixture(root, listener.port);
    const auto record = root / "record.txt";
    REQUIRE(::setenv("TUNPROXY_FAKE_CORE_RECORD", record.c_str(), 1) == 0);

    std::thread server = respondOnce(listener.descriptor, 0x00);
    ProxyManager manager(fixture.paths, fixture.logger(), fixture.fake.manifest);
    const auto started = manager.start();
    server.join();
    (void)::unsetenv("TUNPROXY_FAKE_CORE_RECORD");

    REQUIRE(!started.ok());
    skipIfInterfacesUnavailable(started.error());
    CHECK(started.error().code == ErrorCode::CoreStartFailure);
    CHECK(started.error().message == "sing-box exited before TUN became ready");

    const auto recorded = readTextFile(record);
    REQUIRE(recorded.ok());
    CHECK(countOccurrences(recorded.value(), "--- run") == 2);
    const auto first_true = recorded.value().find("\"auto_redirect\": true");
    const auto then_false = recorded.value().find("\"auto_redirect\": false");
    CHECK(first_true != std::string::npos);
    CHECK(then_false != std::string::npos);
    CHECK(first_true < then_false);
    CHECK(recorded.value().find("\"interface_name\": \"tpxtest-none0\"") != std::string::npos);

    CHECK(fixture.log.find("warning: auto-redirect failed (sing-box exited before TUN became ready); retrying with tun-route\n") != std::string::npos);
    CHECK(fixture.log.find("no longer running") == std::string::npos);
    CHECK(countOccurrences(fixture.log, "\n") == 1);

    CHECK(!std::filesystem::exists(fixture.paths.state_file()));
    const auto status = manager.status();
    REQUIRE(status.ok());
    CHECK(!status.value().running);
    CHECK(status.value().core_installed);
    CHECK(status.value().core_version == "test-version");
    CHECK(status.value().upstream == "socks5://127.0.0.1:" + std::to_string(listener.port));

    fixture.log.clear();
    CHECK(manager.stop().ok());
    CHECK(fixture.log.empty());
}

TEST_CASE(proxy_manager_refuses_when_interface_already_exists) {
    const TempDir root("pm-exists");
    const Listener listener;
    if (listener.descriptor < 0) {
        SKIP("cannot bind a loopback TCP socket");
    }
    Fixture fixture(root, listener.port);
    fixture.paths.tun_interface = "lo";
    std::thread server = respondOnce(listener.descriptor, 0x00);
    ProxyManager manager(fixture.paths, fixture.logger(), fixture.fake.manifest);
    const auto started = manager.start();
    server.join();
    REQUIRE(!started.ok());
    skipIfInterfacesUnavailable(started.error());
    CHECK(started.error().message == "lo already exists outside TunProxy");
    CHECK(!std::filesystem::exists(fixture.paths.state_file()));
}

TEST_CASE(proxy_manager_reports_unreachable_upstream) {
    const TempDir root("pm-upstream");
    std::uint16_t closed_port = 0;
    {
        const Listener listener;
        if (listener.descriptor < 0) {
            SKIP("cannot bind a loopback TCP socket");
        }
        closed_port = listener.port;
    }
    Fixture fixture(root, closed_port);
    ProxyManager manager(fixture.paths, fixture.logger(), fixture.fake.manifest);
    const auto started = manager.start();
    REQUIRE(!started.ok());
    CHECK(started.error().code == ErrorCode::UpstreamUnreachable);
    CHECK(fixture.log.empty());
}
