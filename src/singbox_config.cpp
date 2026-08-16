#include "tunproxy/singbox_config.hpp"

#include <sstream>

namespace tunproxy {
namespace {

std::string jsonEscape(const std::string& input) {
    std::ostringstream escaped;
    for (const char raw_character : input) {
        const auto character = static_cast<unsigned char>(raw_character);
        switch (character) {
        case '"': escaped << "\\\""; break;
        case '\\': escaped << "\\\\"; break;
        case '\b': escaped << "\\b"; break;
        case '\f': escaped << "\\f"; break;
        case '\n': escaped << "\\n"; break;
        case '\r': escaped << "\\r"; break;
        case '\t': escaped << "\\t"; break;
        default:
            if (character < 0x20) {
                const char hex[] = "0123456789abcdef";
                escaped << "\\u00" << hex[character >> 4] << hex[character & 0x0f];
            } else {
                escaped << static_cast<char>(character);
            }
        }
    }
    return escaped.str();
}

} // namespace

Result<std::string> buildSingBoxConfig(const SingBoxRuntimeConfig& config) {
    if (config.upstream.address.empty()) {
        return Result<std::string>::failure(
            makeError(ErrorCode::InvalidConfiguration, "resolved upstream address is empty"));
    }
    std::ostringstream json;
    json << "{\n"
         << "  \"log\": {\"level\": \"info\", \"timestamp\": true, \"output\": \""
         << jsonEscape(config.log_file.string()) << "\"},\n"
         << "  \"dns\": {\n"
         << "    \"servers\": [{\"type\": \"https\", \"tag\": \"proxy-doh\", "
            "\"server\": \"1.1.1.1\", \"server_port\": 443, \"path\": \"/dns-query\", "
            "\"tls\": {\"enabled\": true, \"server_name\": \"cloudflare-dns.com\"}, "
            "\"detour\": \"proxy\"}],\n"
         << "    \"final\": \"proxy-doh\", \"strategy\": \"prefer_ipv4\"\n"
         << "  },\n"
         << "  \"inbounds\": [{\n"
         << "    \"type\": \"tun\", \"tag\": \"tun-in\", \"interface_name\": \"tunproxy0\",\n"
         << "    \"address\": [\"198.18.0.1/30\"], \"mtu\": 1500, \"auto_route\": true,\n"
         << "    \"auto_redirect\": " << (config.auto_redirect ? "true" : "false")
         << ", \"strict_route\": true, \"stack\": \"system\"\n"
         << "  }],\n"
         << "  \"outbounds\": [{\n"
         << "    \"type\": \"socks\", \"tag\": \"proxy\", \"server\": \""
         << jsonEscape(config.upstream.address) << "\", \"server_port\": "
         << config.upstream.configured.port << ", \"version\": \"5\", \"network\": \"tcp\"\n"
         << "  }],\n"
         << "  \"route\": {\n"
         << "    \"rules\": [{\"port\": 53, \"action\": \"hijack-dns\"}, "
            "{\"network\": \"udp\", \"action\": \"reject\"}],\n"
         << "    \"final\": \"proxy\", \"auto_detect_interface\": true\n"
         << "  }\n"
         << "}\n";
    return Result<std::string>::success(json.str());
}

} // namespace tunproxy
