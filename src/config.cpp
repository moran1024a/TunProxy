#include "tunproxy/config.hpp"

#include "tunproxy/filesystem.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <fstream>
#include <limits>
#include <sstream>

namespace tunproxy {
namespace {

std::string trim(std::string value) {
    const auto not_space = [](unsigned char character) { return !std::isspace(character); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
    return value;
}

bool isValidHost(const std::string& host) {
    if (host.empty() || host.size() > 253 || host.find_first_of("\r\n\t ") != std::string::npos) {
        return false;
    }
    return host != "." && host.find('/') == std::string::npos;
}

Result<std::uint16_t> parsePort(const std::string& text) {
    unsigned int value = 0;
    const auto* begin = text.data();
    const auto* end = begin + text.size();
    const auto parsed = std::from_chars(begin, end, value);
    if (parsed.ec != std::errc{} || parsed.ptr != end || value == 0 || value > 65535) {
        return Result<std::uint16_t>::failure(makeError(ErrorCode::InvalidConfiguration, "port must be 1..65535"));
    }
    return Result<std::uint16_t>::success(static_cast<std::uint16_t>(value));
}

} // namespace

Result<Upstream> validateUpstream(const Upstream& upstream) {
    if (upstream.protocol != "socks5") {
        return Result<Upstream>::failure(
            makeError(ErrorCode::InvalidConfiguration, "only socks5 upstream is supported"));
    }
    if (!isValidHost(upstream.host)) {
        return Result<Upstream>::failure(
            makeError(ErrorCode::InvalidConfiguration, "host is empty or contains invalid characters"));
    }
    if (upstream.port == 0) {
        return Result<Upstream>::failure(
            makeError(ErrorCode::InvalidConfiguration, "port must be 1..65535"));
    }
    return Result<Upstream>::success(upstream);
}

Result<Upstream> parseUpstreamUri(const std::string& uri) {
    const std::size_t scheme_end = uri.find("://");
    if (scheme_end == std::string::npos) {
        return Result<Upstream>::failure(makeError(ErrorCode::InvalidConfiguration, "upstream must be protocol://host:port"));
    }
    Upstream upstream;
    upstream.protocol = uri.substr(0, scheme_end);
    const std::string authority = uri.substr(scheme_end + 3);
    if (authority.empty()) {
        return Result<Upstream>::failure(makeError(ErrorCode::InvalidConfiguration, "upstream host is empty"));
    }

    std::string host;
    std::string port_text;
    if (authority.front() == '[') {
        const std::size_t closing = authority.find(']');
        if (closing == std::string::npos || closing + 2 > authority.size() || authority[closing + 1] != ':') {
            return Result<Upstream>::failure(makeError(ErrorCode::InvalidConfiguration, "invalid bracketed IPv6 upstream"));
        }
        host = authority.substr(1, closing - 1);
        port_text = authority.substr(closing + 2);
    } else {
        const std::size_t separator = authority.rfind(':');
        if (separator == std::string::npos) {
            return Result<Upstream>::failure(makeError(ErrorCode::InvalidConfiguration, "upstream port is missing"));
        }
        host = authority.substr(0, separator);
        port_text = authority.substr(separator + 1);
        if (host.find(':') != std::string::npos) {
            return Result<Upstream>::failure(makeError(
                ErrorCode::InvalidConfiguration,
                "IPv6 upstream addresses must be enclosed in brackets"));
        }
    }
    upstream.host = host;
    const auto port = parsePort(port_text);
    if (!port.ok()) {
        return Result<Upstream>::failure(port.error());
    }
    upstream.port = port.value();
    return validateUpstream(upstream);
}

std::string formatUpstreamUri(const Upstream& upstream) {
    const bool ipv6 = upstream.host.find(':') != std::string::npos;
    std::ostringstream result;
    result << upstream.protocol << "://";
    if (ipv6) {
        result << '[' << upstream.host << ']';
    } else {
        result << upstream.host;
    }
    result << ':' << upstream.port;
    return result.str();
}

ConfigManager::ConfigManager(AppPaths paths) : paths_(std::move(paths)) {}

Result<Upstream> ConfigManager::load() const {
    const auto contents = readTextFile(paths_.config_file);
    if (!contents.ok()) {
        return Result<Upstream>::failure(makeError(ErrorCode::InvalidConfiguration, "cannot read config: " + contents.error().message));
    }
    Upstream upstream;
    bool protocol_seen = false;
    bool host_seen = false;
    bool port_seen = false;
    std::istringstream lines(contents.value());
    std::string line;
    while (std::getline(lines, line)) {
        line = trim(line);
        if (line.empty() || line.front() == '#') {
            continue;
        }
        const std::size_t separator = line.find('=');
        if (separator == std::string::npos) {
            return Result<Upstream>::failure(makeError(ErrorCode::InvalidConfiguration, "invalid config line"));
        }
        const std::string key = trim(line.substr(0, separator));
        const std::string value = trim(line.substr(separator + 1));
        if (key == "protocol") {
            upstream.protocol = value;
            protocol_seen = true;
        } else if (key == "host") {
            upstream.host = value;
            host_seen = true;
        } else if (key == "port") {
            const auto port = parsePort(value);
            if (!port.ok()) {
                return Result<Upstream>::failure(port.error());
            }
            upstream.port = port.value();
            port_seen = true;
        } else {
            return Result<Upstream>::failure(makeError(ErrorCode::InvalidConfiguration, "unknown config key: " + key));
        }
    }
    if (!protocol_seen || !host_seen || !port_seen) {
        return Result<Upstream>::failure(makeError(
            ErrorCode::InvalidConfiguration,
            "config must contain protocol, host, and port"));
    }
    return validateUpstream(upstream);
}

Result<void> ConfigManager::save(const Upstream& upstream) const {
    const auto validated = validateUpstream(upstream);
    if (!validated.ok()) {
        return Result<void>::failure(validated.error());
    }
    const auto directory = ensureDirectory(paths_.config_file.parent_path(), 0755);
    if (!directory.ok()) {
        return directory;
    }
    std::ostringstream contents;
    contents << "protocol=" << upstream.protocol << '\n'
             << "host=" << upstream.host << '\n'
             << "port=" << upstream.port << '\n';
    return writeFileAtomic(paths_.config_file, contents.str(), 0644);
}

} // namespace tunproxy
