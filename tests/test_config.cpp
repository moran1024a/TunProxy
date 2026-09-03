#include "framework.hpp"

#include "tunproxy/config.hpp"
#include "tunproxy/filesystem.hpp"

#include <sys/stat.h>

using namespace tunproxy;
using tunproxy::test::TempDir;

TEST_CASE(config_parse_and_format_upstream_uri) {
    const auto ipv4 = parseUpstreamUri("socks5://127.0.0.1:1080");
    REQUIRE(ipv4.ok());
    CHECK(formatUpstreamUri(ipv4.value()) == "socks5://127.0.0.1:1080");

    const auto ipv6 = parseUpstreamUri("socks5://[::1]:1080");
    REQUIRE(ipv6.ok());
    CHECK(formatUpstreamUri(ipv6.value()) == "socks5://[::1]:1080");
    CHECK(ipv6.value().host == "::1");
}

TEST_CASE(config_rejects_invalid_upstream_uri) {
    CHECK(!parseUpstreamUri("http://127.0.0.1:1080").ok());
    CHECK(!parseUpstreamUri("socks5://127.0.0.1:0").ok());
    CHECK(!parseUpstreamUri("socks5://127.0.0.1").ok());
    CHECK(!parseUpstreamUri("socks5://127.0.0.1:65536").ok());
    CHECK(!parseUpstreamUri("socks5://::1:1080").ok());
    CHECK(!parseUpstreamUri("socks5://[::1]1080").ok());
    CHECK(!parseUpstreamUri("socks5://").ok());
    CHECK(!parseUpstreamUri("socks5://bad host:1080").ok());
    CHECK(!parseUpstreamUri("127.0.0.1:1080").ok());
}

TEST_CASE(config_save_and_load_round_trip) {
    const TempDir root("config");
    AppPaths paths;
    paths.config_file = root / "etc/tunproxy/config";
    const ConfigManager manager(paths);
    REQUIRE(manager.save(Upstream{"socks5", "proxy.home", 7890}).ok());
    const auto loaded = manager.load();
    REQUIRE(loaded.ok());
    CHECK(loaded.value().host == "proxy.home");
    CHECK(loaded.value().port == 7890);
    struct stat status {};
    REQUIRE(::stat(paths.config_file.c_str(), &status) == 0);
    CHECK((status.st_mode & 0777) == 0640);
}

TEST_CASE(config_load_rejects_malformed_files) {
    const TempDir root("config-bad");
    AppPaths paths;
    paths.config_file = root / "config";
    const ConfigManager manager(paths);

    CHECK(!manager.load().ok());

    const auto write = [&paths](const std::string& contents) {
        REQUIRE(writeFileAtomic(paths.config_file, contents, 0640).ok());
    };
    write("protocol=socks5\nhost=127.0.0.1\nport=1080\nextra=1\n");
    CHECK(!manager.load().ok());
    write("protocol=socks5\nhost=127.0.0.1\n");
    CHECK(!manager.load().ok());
    write("protocol=socks5\nhost=127.0.0.1\nport=70000\n");
    CHECK(!manager.load().ok());
    write("protocol=http\nhost=127.0.0.1\nport=1080\n");
    CHECK(!manager.load().ok());
    write("protocol=socks5\nhost=127.0.0.1\nport 1080\n");
    CHECK(!manager.load().ok());
    write("# comment\nprotocol = socks5\n host = 127.0.0.1 \nport=1080\n");
    const auto loaded = manager.load();
    REQUIRE(loaded.ok());
    CHECK(loaded.value().host == "127.0.0.1");
}

TEST_CASE(config_save_rejects_invalid_upstream) {
    const TempDir root("config-save");
    AppPaths paths;
    paths.config_file = root / "config";
    const ConfigManager manager(paths);
    CHECK(!manager.save(Upstream{"http", "127.0.0.1", 1080}).ok());
    CHECK(!manager.save(Upstream{"socks5", "", 1080}).ok());
    CHECK(!manager.save(Upstream{"socks5", "127.0.0.1", 0}).ok());
}
