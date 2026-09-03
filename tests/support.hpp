#pragma once

// Shared fixtures: fake core installation and a one-shot SOCKS5 responder.

#include "framework.hpp"

#include "tunproxy/core_manifest.hpp"
#include "tunproxy/filesystem.hpp"
#include "tunproxy/paths.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>

namespace tunproxy::test {

inline const std::string kFakeVersion = "test-version";
inline const std::string kFakeRevision = "test-revision";

inline std::filesystem::path fakeCorePath() {
    const char* path = std::getenv("TUNPROXY_FAKE_CORE");
    if (path == nullptr) {
        SKIP("TUNPROXY_FAKE_CORE is not set");
    }
    return path;
}

// A manifest together with the strings its string_views point into.
struct FakeCoreManifest {
    std::string binary_sha256;
    std::string license_sha256;
    CoreReleaseManifest manifest{};

    FakeCoreManifest() = default;
    FakeCoreManifest(const FakeCoreManifest&) = delete;
    FakeCoreManifest& operator=(const FakeCoreManifest&) = delete;
};

// Copies the fake core to data_dir/cores/<version>/sing-box with a LICENSE and
// fills `out` with a manifest whose sizes and hashes match the installed files.
inline void installFakeCore(const AppPaths& paths, FakeCoreManifest& out) {
    const auto core_dir = paths.data_dir / "cores" / kFakeVersion;
    REQUIRE(ensureDirectory(core_dir, 0750).ok());
    std::error_code error;
    std::filesystem::copy_file(fakeCorePath(), core_dir / "sing-box",
        std::filesystem::copy_options::overwrite_existing, error);
    REQUIRE(!error);
    REQUIRE(writeFileAtomic(core_dir / "LICENSE", "installed test license\n", 0644).ok());
    const auto binary_hash = sha256File(core_dir / "sing-box");
    const auto license_hash = sha256File(core_dir / "LICENSE");
    REQUIRE(binary_hash.ok() && license_hash.ok());
    out.binary_sha256 = binary_hash.value();
    out.license_sha256 = license_hash.value();
    out.manifest = CoreReleaseManifest{
        kFakeVersion,
        kFakeRevision,
        "unused.tar.gz",
        "https://invalid.example/unused.tar.gz",
        0,
        "unused",
        "unused/sing-box",
        std::filesystem::file_size(core_dir / "sing-box"),
        out.binary_sha256,
        "unused/LICENSE",
        out.license_sha256,
    };
}

struct Listener {
    int descriptor{-1};
    std::uint16_t port{0};

    Listener() {
        descriptor = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
        if (descriptor < 0) {
            return;
        }
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::bind(descriptor, reinterpret_cast<sockaddr*>(&address), sizeof(address)) != 0 ||
            ::listen(descriptor, 1) != 0) {
            (void)::close(descriptor);
            descriptor = -1;
            return;
        }
        socklen_t length = sizeof(address);
        (void)::getsockname(descriptor, reinterpret_cast<sockaddr*>(&address), &length);
        port = ntohs(address.sin_port);
    }
    ~Listener() {
        if (descriptor >= 0) {
            (void)::close(descriptor);
        }
    }
    Listener(const Listener&) = delete;
    Listener& operator=(const Listener&) = delete;
};

// Accepts one client, reads the SOCKS5 greeting, and answers with the given method byte.
inline std::thread respondOnce(int listener, unsigned char method) {
    return std::thread([listener, method] {
        const int client = ::accept4(listener, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) {
            return;
        }
        std::array<unsigned char, 3> greeting{};
        const ssize_t received = ::recv(client, greeting.data(), greeting.size(), MSG_WAITALL);
        CHECK(received == 3);
        CHECK(greeting[0] == 0x05 && greeting[1] == 0x01 && greeting[2] == 0x00);
        const std::array<unsigned char, 2> response{0x05, method};
        (void)::send(client, response.data(), response.size(), MSG_NOSIGNAL);
        (void)::close(client);
    });
}

} // namespace tunproxy::test
