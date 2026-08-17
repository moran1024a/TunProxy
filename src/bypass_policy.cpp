#include "tunproxy/bypass_policy.hpp"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <set>

namespace tunproxy {
namespace {

constexpr std::size_t kMaximumInterfaceCidrs = 1024;

struct BinaryCidr {
    int family{AF_UNSPEC};
    std::array<unsigned char, 16> address{};
    unsigned int prefix{0};
};

Result<BinaryCidr> parseCidr(std::string_view cidr) {
    const auto separator = cidr.rfind('/');
    if (separator == std::string_view::npos || separator == 0 || separator + 1 >= cidr.size()) {
        return Result<BinaryCidr>::failure(
            makeError(ErrorCode::InvalidConfiguration, "invalid CIDR: " + std::string(cidr)));
    }
    const std::string address_text(cidr.substr(0, separator));
    unsigned int prefix = 0;
    const auto prefix_text = cidr.substr(separator + 1);
    const auto parsed = std::from_chars(
        prefix_text.data(), prefix_text.data() + prefix_text.size(), prefix);
    if (parsed.ec != std::errc{} || parsed.ptr != prefix_text.data() + prefix_text.size()) {
        return Result<BinaryCidr>::failure(
            makeError(ErrorCode::InvalidConfiguration, "invalid CIDR prefix: " + std::string(cidr)));
    }

    BinaryCidr output;
    if (::inet_pton(AF_INET, address_text.c_str(), output.address.data()) == 1) {
        output.family = AF_INET;
        if (prefix > 32U) {
            return Result<BinaryCidr>::failure(
                makeError(ErrorCode::InvalidConfiguration, "invalid IPv4 CIDR prefix"));
        }
    } else if (::inet_pton(AF_INET6, address_text.c_str(), output.address.data()) == 1) {
        output.family = AF_INET6;
        if (prefix > 128U) {
            return Result<BinaryCidr>::failure(
                makeError(ErrorCode::InvalidConfiguration, "invalid IPv6 CIDR prefix"));
        }
    } else {
        return Result<BinaryCidr>::failure(
            makeError(ErrorCode::InvalidConfiguration, "invalid CIDR address: " + address_text));
    }
    output.prefix = prefix;
    const std::size_t bytes = output.family == AF_INET ? 4U : 16U;
    const std::size_t full_bytes = prefix / 8U;
    const unsigned int remaining_bits = prefix % 8U;
    if (remaining_bits != 0U && full_bytes < bytes) {
        output.address[full_bytes] &= static_cast<unsigned char>(0xffU << (8U - remaining_bits));
    }
    const std::size_t clear_from = full_bytes + (remaining_bits == 0U ? 0U : 1U);
    std::fill(output.address.begin() + static_cast<std::ptrdiff_t>(clear_from),
        output.address.begin() + static_cast<std::ptrdiff_t>(bytes), 0U);
    return Result<BinaryCidr>::success(output);
}

std::string formatCidr(const BinaryCidr& cidr) {
    std::array<char, INET6_ADDRSTRLEN> text{};
    if (::inet_ntop(cidr.family, cidr.address.data(), text.data(), text.size()) == nullptr) {
        return {};
    }
    return std::string(text.data()) + "/" + std::to_string(cidr.prefix);
}

bool overlapsTunAddressSpace(const BinaryCidr& cidr) {
    if (cidr.family != AF_INET) {
        return false;
    }
    const std::array<unsigned char, 2> reserved{198U, 18U};
    const unsigned int shared_prefix = std::min(cidr.prefix, 15U);
    for (unsigned int bit = 0; bit < shared_prefix; ++bit) {
        const unsigned int shift = 7U - (bit % 8U);
        const unsigned int left = (cidr.address[bit / 8U] >> shift) & 1U;
        const unsigned int right = (reserved[bit / 8U] >> shift) & 1U;
        if (left != right) {
            return false;
        }
    }
    return true;
}

bool containsCidr(const BinaryCidr& outer, const BinaryCidr& inner) {
    if (outer.family != inner.family || outer.prefix > inner.prefix) {
        return false;
    }
    for (unsigned int bit = 0; bit < outer.prefix; ++bit) {
        const unsigned int shift = 7U - (bit % 8U);
        if (((outer.address[bit / 8U] >> shift) & 1U) !=
            ((inner.address[bit / 8U] >> shift) & 1U)) {
            return false;
        }
    }
    return true;
}

bool isUnspecifiedAddress(const BinaryCidr& cidr) {
    const std::size_t bytes = cidr.family == AF_INET ? 4U : 16U;
    return std::all_of(cidr.address.begin(),
        cidr.address.begin() + static_cast<std::ptrdiff_t>(bytes),
        [](unsigned char value) { return value == 0U; });
}

Result<void> appendInterfaceAddress(
    std::vector<std::string>& output, std::set<std::string>& seen, const BinaryCidr& cidr) {
    if (isUnspecifiedAddress(cidr) || overlapsTunAddressSpace(cidr)) {
        return Result<void>::success();
    }
    const std::string formatted = formatCidr(cidr);
    if (formatted.empty()) {
        return Result<void>::failure(
            makeError(ErrorCode::StateError, "cannot format detected network address"));
    }
    for (const auto& existing_text : seen) {
        const auto existing = parseCidr(existing_text);
        if (existing.ok() && containsCidr(existing.value(), cidr)) {
            return Result<void>::success();
        }
    }
    if (seen.insert(formatted).second) {
        if (output.size() >= kMaximumInterfaceCidrs) {
            return Result<void>::failure(makeError(
                ErrorCode::StateError,
                "more than 1024 active interface addresses were detected; refusing an incomplete bypass policy"));
        }
        output.push_back(formatted);
    }
    return Result<void>::success();
}

Result<void> collectInterfaceAddresses(
    std::vector<std::string>& output, std::set<std::string>& seen) {
    ifaddrs* raw_interfaces = nullptr;
    if (::getifaddrs(&raw_interfaces) != 0) {
        return Result<void>::failure(makeError(
            ErrorCode::StateError,
            "cannot enumerate local interface addresses: " + std::string(std::strerror(errno))));
    }
    for (const ifaddrs* current = raw_interfaces; current != nullptr; current = current->ifa_next) {
        if (current->ifa_addr == nullptr || current->ifa_name == nullptr ||
            (current->ifa_flags & IFF_UP) == 0U ||
            std::string_view(current->ifa_name) == "tunproxy0" ||
            (current->ifa_addr->sa_family != AF_INET && current->ifa_addr->sa_family != AF_INET6)) {
            continue;
        }
        BinaryCidr cidr;
        cidr.family = current->ifa_addr->sa_family;
        cidr.prefix = cidr.family == AF_INET ? 32U : 128U;
        const void* source = cidr.family == AF_INET
            ? static_cast<const void*>(&reinterpret_cast<const sockaddr_in*>(current->ifa_addr)->sin_addr)
            : static_cast<const void*>(&reinterpret_cast<const sockaddr_in6*>(current->ifa_addr)->sin6_addr);
        std::memcpy(cidr.address.data(), source, cidr.family == AF_INET ? 4U : 16U);
        const auto appended = appendInterfaceAddress(output, seen, cidr);
        if (!appended.ok()) {
            ::freeifaddrs(raw_interfaces);
            return appended;
        }
    }
    ::freeifaddrs(raw_interfaces);
    return Result<void>::success();
}

} // namespace

const std::vector<std::string>& fixedBypassCidrs() {
    static const std::vector<std::string> cidrs{
        "127.0.0.0/8",
        "::1/128",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "169.254.0.0/16",
        "fe80::/10",
        "fc00::/7",
        "224.0.0.0/4",
        "ff00::/8",
        "255.255.255.255/32",
    };
    return cidrs;
}

Result<std::string> canonicalizeCidr(std::string_view cidr) {
    const auto parsed = parseCidr(cidr);
    if (!parsed.ok()) {
        return Result<std::string>::failure(parsed.error());
    }
    const std::string formatted = formatCidr(parsed.value());
    if (formatted.empty()) {
        return Result<std::string>::failure(
            makeError(ErrorCode::InvalidConfiguration, "cannot format CIDR"));
    }
    return Result<std::string>::success(formatted);
}

Result<std::string> addressHostCidr(std::string_view address) {
    const std::string text(address);
    BinaryCidr cidr;
    if (::inet_pton(AF_INET, text.c_str(), cidr.address.data()) == 1) {
        cidr.family = AF_INET;
        cidr.prefix = 32U;
    } else if (::inet_pton(AF_INET6, text.c_str(), cidr.address.data()) == 1) {
        cidr.family = AF_INET6;
        cidr.prefix = 128U;
    } else {
        return Result<std::string>::failure(
            makeError(ErrorCode::InvalidConfiguration, "upstream address is not an IP address"));
    }
    if (isUnspecifiedAddress(cidr)) {
        return Result<std::string>::failure(
            makeError(ErrorCode::InvalidConfiguration, "upstream address is unspecified"));
    }
    return Result<std::string>::success(formatCidr(cidr));
}

std::vector<std::string> BypassPolicy::allCidrs() const {
    std::vector<std::string> output;
    std::vector<BinaryCidr> parsed_output;
    const auto append = [&output, &parsed_output](const std::string& cidr, bool mandatory) {
        if (cidr.empty()) {
            return;
        }
        const auto parsed = parseCidr(cidr);
        if (!parsed.ok()) {
            return;
        }
        if (!mandatory && std::any_of(parsed_output.begin(), parsed_output.end(),
                [&parsed](const BinaryCidr& existing) {
                    return containsCidr(existing, parsed.value());
                })) {
            return;
        }
        if (std::none_of(parsed_output.begin(), parsed_output.end(),
                [&parsed](const BinaryCidr& existing) {
                    return existing.family == parsed.value().family &&
                        existing.prefix == parsed.value().prefix &&
                        existing.address == parsed.value().address;
                })) {
            output.push_back(cidr);
            parsed_output.push_back(parsed.value());
        }
    };
    if (!upstream_cidr.empty()) {
        append(upstream_cidr, true);
    }
    for (const auto& cidr : fixed_cidrs) {
        append(cidr, false);
    }
    for (const auto& cidr : interface_cidrs) {
        append(cidr, false);
    }
    return output;
}

Result<BypassPolicy> collectBypassPolicy(std::string_view upstream_address) {
    BypassPolicy policy;
    policy.fixed_cidrs = fixedBypassCidrs();
    std::set<std::string> seen(policy.fixed_cidrs.begin(), policy.fixed_cidrs.end());
    const auto interfaces = collectInterfaceAddresses(policy.interface_cidrs, seen);
    if (!interfaces.ok()) {
        return Result<BypassPolicy>::failure(interfaces.error());
    }
    if (!upstream_address.empty()) {
        const auto upstream = addressHostCidr(upstream_address);
        if (!upstream.ok()) {
            return Result<BypassPolicy>::failure(upstream.error());
        }
        policy.upstream_cidr = upstream.value();
    }
    return Result<BypassPolicy>::success(std::move(policy));
}

} // namespace tunproxy
