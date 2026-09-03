#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace tunproxy {

// TUN interface and address plan.
inline constexpr std::string_view kTunInterfaceName = "tunproxy0";
inline constexpr std::string_view kTunAddress = "198.18.0.1/30";
// 198.18.0.0/15 is reserved for benchmarking (RFC 2544); interface addresses
// inside it are never imported into the bypass policy.
inline constexpr std::array<unsigned char, 2> kTunAddressSpacePrefix{198U, 18U};
inline constexpr unsigned int kTunAddressSpacePrefixBits = 15U;
inline constexpr int kTunMtu = 1500;

// DNS-over-HTTPS resolver reached through the SOCKS5 outbound.
inline constexpr std::string_view kDnsServerAddress = "1.1.1.1";
inline constexpr int kDnsServerPort = 443;
inline constexpr std::string_view kDnsServerPath = "/dns-query";
inline constexpr std::string_view kDnsServerName = "cloudflare-dns.com";

// Runtime files inside AppPaths::runtime_dir.
inline constexpr std::string_view kCoreConfigFileName = "sing-box.json";
inline constexpr std::string_view kCoreLogFileName = "sing-box.log";

// Bypass policy limits.
inline constexpr std::size_t kMaximumInterfaceCidrs = 1024;

// Timeouts and retry counts.
inline constexpr std::chrono::milliseconds kPollInterval{100};
inline constexpr std::chrono::seconds kTunReadyTimeout{8};
inline constexpr std::chrono::seconds kTunReadyQuietPeriod{2};
inline constexpr std::chrono::seconds kTunRemovalTimeout{3};
inline constexpr std::chrono::seconds kCoreExecHandshakeTimeout{5};
inline constexpr std::chrono::seconds kCoreTerminateTimeout{5};
inline constexpr std::chrono::seconds kCoreKillTimeout{2};
inline constexpr std::chrono::seconds kCoreCheckTimeout{10};
inline constexpr std::chrono::seconds kCoreVersionTimeout{10};
inline constexpr std::chrono::seconds kDownloadConnectTimeout{15};
inline constexpr std::chrono::seconds kDownloadMaxTime{600};
inline constexpr std::chrono::seconds kDownloadProcessTimeout{620};
inline constexpr int kDownloadAttempts = 3;
inline constexpr std::chrono::seconds kDownloadRetryDelay{1};
inline constexpr std::chrono::seconds kExtractTimeout{60};
inline constexpr std::chrono::seconds kSha256Timeout{30};
inline constexpr std::chrono::seconds kUpstreamProbeTimeout{3};
inline constexpr std::chrono::seconds kClientSocketTimeout{30};

} // namespace tunproxy
