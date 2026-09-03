#include "framework.hpp"

#include "tunproxy/upstream.hpp"

#include "support.hpp"

using namespace tunproxy;
using tunproxy::test::Listener;
using tunproxy::test::respondOnce;

TEST_CASE(upstream_probe_accepts_unauthenticated_socks5) {
    const Listener listener;
    if (listener.descriptor < 0) {
        SKIP("cannot bind a loopback TCP socket");
    }
    std::thread server = respondOnce(listener.descriptor, 0x00);
    const auto probed = resolveAndProbeUpstream(Upstream{"socks5", "127.0.0.1", listener.port});
    server.join();
    REQUIRE(probed.ok());
    CHECK(probed.value().address == "127.0.0.1");
    CHECK(probed.value().configured.port == listener.port);
}

TEST_CASE(upstream_probe_rejects_authentication_required) {
    const Listener listener;
    if (listener.descriptor < 0) {
        SKIP("cannot bind a loopback TCP socket");
    }
    std::thread server = respondOnce(listener.descriptor, 0x02);
    const auto probed = resolveAndProbeUpstream(Upstream{"socks5", "127.0.0.1", listener.port});
    server.join();
    CHECK(!probed.ok());
    CHECK(probed.error().code == ErrorCode::UpstreamUnreachable);
    CHECK(probed.error().message.find("unauthenticated") != std::string::npos);
}

TEST_CASE(upstream_probe_reports_connection_refused) {
    std::uint16_t closed_port = 0;
    {
        const Listener listener;
        if (listener.descriptor < 0) {
            SKIP("cannot bind a loopback TCP socket");
        }
        closed_port = listener.port;
    }
    const auto probed = resolveAndProbeUpstream(
        Upstream{"socks5", "127.0.0.1", closed_port}, std::chrono::seconds(2));
    CHECK(!probed.ok());
    CHECK(probed.error().code == ErrorCode::UpstreamUnreachable);
}

TEST_CASE(upstream_probe_reports_unresolvable_host) {
    const auto probed = resolveAndProbeUpstream(
        Upstream{"socks5", "nonexistent.invalid", 1080}, std::chrono::seconds(2));
    CHECK(!probed.ok());
    CHECK(probed.error().message.find("resolve") != std::string::npos);
}
