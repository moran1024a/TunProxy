#include "framework.hpp"

#include "tunproxy/bypass_policy.hpp"

#include <algorithm>

using namespace tunproxy;

TEST_CASE(bypass_canonicalizes_cidrs) {
    CHECK(canonicalizeCidr("192.168.1.27/24").value() == "192.168.1.0/24");
    CHECK(canonicalizeCidr("fd00::1234/64").value() == "fd00::/64");
    CHECK(canonicalizeCidr("10.0.0.1/32").value() == "10.0.0.1/32");
    CHECK(!canonicalizeCidr("192.168.1.1/33").ok());
    CHECK(!canonicalizeCidr("fd00::/129").ok());
    CHECK(!canonicalizeCidr("192.168.1.1").ok());
    CHECK(!canonicalizeCidr("/24").ok());
    CHECK(!canonicalizeCidr("not-an-address/8").ok());
}

TEST_CASE(bypass_derives_host_cidrs) {
    CHECK(addressHostCidr("192.0.2.10").value() == "192.0.2.10/32");
    CHECK(addressHostCidr("2001:db8::1").value() == "2001:db8::1/128");
    CHECK(!addressHostCidr("0.0.0.0").ok());
    CHECK(!addressHostCidr("::").ok());
    CHECK(!addressHostCidr("proxy.home").ok());
}

TEST_CASE(bypass_orders_and_deduplicates_policy) {
    const BypassPolicy policy{
        {"10.0.0.0/8", "10.0.0.0/8"},
        {"10.1.2.3/32", "192.0.2.44/32", "192.0.2.44/32"},
        "10.9.8.7/32",
    };
    const auto cidrs = policy.allCidrs();
    REQUIRE(cidrs.size() == 3);
    CHECK(cidrs[0] == "10.9.8.7/32");
    CHECK(cidrs[1] == "10.0.0.0/8");
    CHECK(cidrs[2] == "192.0.2.44/32");
}

TEST_CASE(bypass_fixed_ranges_are_canonical) {
    for (const auto& cidr : fixedBypassCidrs()) {
        CHECK(canonicalizeCidr(cidr).value() == cidr);
    }
    CHECK(fixedBypassCidrs().size() == 12);
}

TEST_CASE(bypass_collects_interface_hosts) {
    const auto policy = collectBypassPolicy("192.0.2.10", "tunproxy-test-none");
    if (!policy.ok()) {
        if (policy.error().message.find("Operation not permitted") != std::string::npos) {
            SKIP("getifaddrs is not permitted in this environment");
        }
        REQUIRE(policy.ok());
    }
    CHECK(policy.value().upstream_cidr == "192.0.2.10/32");
    for (const auto& cidr : policy.value().interface_cidrs) {
        CHECK(canonicalizeCidr(cidr).value() == cidr);
        const bool ipv6 = cidr.find(':') != std::string::npos;
        const std::string suffix = ipv6 ? "/128" : "/32";
        CHECK(cidr.size() > suffix.size() &&
            cidr.compare(cidr.size() - suffix.size(), suffix.size(), suffix) == 0);
        CHECK(cidr.compare(0, 7, "198.18.") != 0 && cidr.compare(0, 7, "198.19.") != 0);
    }
    const auto cidrs = policy.value().allCidrs();
    REQUIRE(!cidrs.empty());
    CHECK(cidrs.front() == "192.0.2.10/32");
    CHECK(std::find(cidrs.begin(), cidrs.end(), "10.0.0.0/8") != cidrs.end());
}

TEST_CASE(bypass_rejects_unspecified_upstream) {
    const auto policy = collectBypassPolicy("0.0.0.0", "tunproxy-test-none");
    if (!policy.ok() && policy.error().message.find("Operation not permitted") != std::string::npos) {
        SKIP("getifaddrs is not permitted in this environment");
    }
    CHECK(!policy.ok());
}
