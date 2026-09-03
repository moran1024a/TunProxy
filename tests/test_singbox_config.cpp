#include "framework.hpp"

#include "tunproxy/filesystem.hpp"
#include "tunproxy/process.hpp"
#include "tunproxy/singbox_config.hpp"

#include <cstdlib>

using namespace tunproxy;
using tunproxy::test::TempDir;

namespace {

SingBoxRuntimeConfig sampleConfig(const std::filesystem::path& log, bool auto_redirect) {
    SingBoxRuntimeConfig config;
    config.log_file = log;
    config.upstream = ResolvedUpstream{Upstream{"socks5", "proxy.home", 7890}, "192.0.2.10"};
    config.bypass_cidrs = {"192.0.2.10/32", "10.0.0.0/8", "fe80::/10"};
    config.auto_redirect = auto_redirect;
    config.interface_name = "tpxtest0";
    return config;
}

} // namespace

TEST_CASE(singbox_config_contains_expected_sections) {
    const TempDir root("singbox");
    const auto generated = buildSingBoxConfig(sampleConfig(root / "sing-box.log", true));
    REQUIRE(generated.ok());
    const std::string& json = generated.value();
    CHECK(json.find("\"auto_redirect\": true") != std::string::npos);
    CHECK(json.find("\"interface_name\": \"tpxtest0\"") != std::string::npos);
    CHECK(json.find("\"server\": \"192.0.2.10\"") != std::string::npos);
    CHECK(json.find("\"server_port\": 7890") != std::string::npos);
    CHECK(json.find("\"route_exclude_address\": [\"192.0.2.10/32\", \"10.0.0.0/8\", \"fe80::/10\"]") != std::string::npos);
    CHECK(json.find("\"type\": \"direct\"") != std::string::npos);
    CHECK(json.find("\"outbound\": \"direct\"") != std::string::npos);
    CHECK(json.find("\"action\": \"hijack-dns\"") != std::string::npos);
    CHECK(json.find("\"network\": \"udp\", \"action\": \"reject\"") != std::string::npos);
    CHECK(json.find("\"ip_cidr\"") < json.find("\"action\": \"hijack-dns\""));
    CHECK(json.find("\"address\": [\"" + std::string(kTunAddress) + "\"]") != std::string::npos);
    CHECK(json.find("\"server_name\": \"" + std::string(kDnsServerName) + "\"") != std::string::npos);

    const auto fallback = buildSingBoxConfig(sampleConfig(root / "sing-box.log", false));
    REQUIRE(fallback.ok());
    CHECK(fallback.value().find("\"auto_redirect\": false") != std::string::npos);
}

TEST_CASE(singbox_config_rejects_incomplete_input) {
    const TempDir root("singbox-bad");
    auto config = sampleConfig(root / "sing-box.log", true);
    config.upstream.address.clear();
    CHECK(!buildSingBoxConfig(config).ok());
    config = sampleConfig(root / "sing-box.log", true);
    config.bypass_cidrs.clear();
    CHECK(!buildSingBoxConfig(config).ok());
}

TEST_CASE(singbox_config_escapes_paths) {
    const TempDir root("singbox-escape");
    auto config = sampleConfig(root / "dir with \"quotes\"/sing-box.log", true);
    const auto generated = buildSingBoxConfig(config);
    REQUIRE(generated.ok());
    CHECK(generated.value().find("dir with \\\"quotes\\\"") != std::string::npos);
}

TEST_CASE(singbox_config_passes_real_core_check) {
    const char* real_core = std::getenv("TUNPROXY_TEST_SINGBOX");
    if (real_core == nullptr) {
        SKIP("TUNPROXY_TEST_SINGBOX is not set");
    }
    const TempDir root("singbox-real");
    for (const bool auto_redirect : {true, false}) {
        auto config = sampleConfig(root / "sing-box.log", auto_redirect);
        config.interface_name = std::string(kTunInterfaceName);
        const auto generated = buildSingBoxConfig(config);
        REQUIRE(generated.ok());
        const auto config_path = root / "sing-box.json";
        REQUIRE(writeFileAtomic(config_path, generated.value(), 0600).ok());
        const auto checked = runCapture(
            {real_core, "check", "--disable-color", "-c", config_path.string()}, std::chrono::seconds(10));
        REQUIRE(checked.ok());
        if (!CHECK(checked.value().exit_code == 0)) {
            std::cerr << checked.value().stderr_text << '\n';
        }
    }
}
