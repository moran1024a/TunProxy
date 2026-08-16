#include "tunproxy/config.hpp"
#include "tunproxy/core_manager.hpp"
#include "tunproxy/filesystem.hpp"
#include "tunproxy/process.hpp"
#include "tunproxy/runtime_state.hpp"
#include "tunproxy/singbox_config.hpp"
#include "tunproxy/upstream.hpp"

#include <arpa/inet.h>
#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

int main() {
    using namespace tunproxy;
    const auto ipv4 = parseUpstreamUri("socks5://127.0.0.1:1080");
    assert(ipv4.ok());
    assert(formatUpstreamUri(ipv4.value()) == "socks5://127.0.0.1:1080");

    const auto ipv6 = parseUpstreamUri("socks5://[::1]:1080");
    assert(ipv6.ok());
    assert(formatUpstreamUri(ipv6.value()) == "socks5://[::1]:1080");

    assert(!parseUpstreamUri("http://127.0.0.1:1080").ok());
    assert(!parseUpstreamUri("socks5://127.0.0.1:0").ok());
    assert(!parseUpstreamUri("socks5://127.0.0.1").ok());

    const auto root = std::filesystem::temp_directory_path() /
        ("tunproxy-config-test-" + std::to_string(static_cast<long long>(::getpid())));
    std::error_code error;
    std::filesystem::remove_all(root, error);
    AppPaths paths;
    paths.config_file = root / "etc" / "tunproxy" / "config";
    ConfigManager manager(paths);
    const auto saved = manager.save(Upstream{"socks5", "proxy.home", 7890});
    assert(saved.ok());
    const auto loaded = manager.load();
    assert(loaded.ok());
    assert(loaded.value().host == "proxy.home");
    assert(loaded.value().port == 7890);

    const auto symlink_parent = root / "symlink-parent";
    assert(std::filesystem::create_directories(root / "real-parent"));
    assert(::symlink((root / "real-parent").c_str(), symlink_parent.c_str()) == 0);
    assert(!ensureDirectory(symlink_parent / "child", 0750).ok());

    const auto generated = buildSingBoxConfig(SingBoxRuntimeConfig{
        root / "sing-box.log",
        ResolvedUpstream{Upstream{"socks5", "proxy.home", 7890}, "192.0.2.10"},
        true,
    });
    assert(generated.ok());
    assert(generated.value().find("\"auto_redirect\": true") != std::string::npos);
    assert(generated.value().find("\"server\": \"192.0.2.10\"") != std::string::npos);
    assert(generated.value().find("\"action\": \"hijack-dns\"") != std::string::npos);
    if (const char* real_core = std::getenv("TUNPROXY_TEST_SINGBOX"); real_core != nullptr) {
        const auto real_config = root / "real-sing-box.json";
        assert(writeFileAtomic(real_config, generated.value(), 0600).ok());
        const auto checked = runCapture(
            {real_core, "check", "--disable-color", "-c", real_config.string()},
            std::chrono::seconds(10));
        assert(checked.ok());
        if (checked.value().exit_code != 0) {
            std::cerr << checked.value().stderr_text << '\n';
        }
        assert(checked.value().exit_code == 0);

        if (const char* real_archive = std::getenv("TUNPROXY_TEST_SINGBOX_ARCHIVE");
            real_archive != nullptr) {
            AppPaths real_paths;
            real_paths.data_dir = root / "real-core" / "data";
            real_paths.cache_dir = root / "real-core" / "cache";
            real_paths.curl_executable = root / "real-core" / "fake-curl";
            assert(ensureDirectory(real_paths.curl_executable.parent_path(), 0750).ok());
            const std::string real_fake_curl =
                "#!/bin/sh\n"
                "output=\n"
                "while [ \"$#\" -gt 0 ]; do\n"
                "  if [ \"$1\" = \"--output\" ]; then output=$2; shift 2; else shift; fi\n"
                "done\n"
                "cp '" + std::string(real_archive) + "' \"$output\"\n";
            assert(writeFileAtomic(real_paths.curl_executable, real_fake_curl, 0755).ok());
            CoreManager real_manager(real_paths);
            const auto repaired = real_manager.repairCore();
            if (!repaired.ok()) {
                std::cerr << repaired.error().message << '\n';
            }
            assert(repaired.ok());
            assert(repaired.value().version == "1.13.18");
        }
    }

    std::string observed_process_output;
    const auto process = runCapture(
        {"/usr/bin/printf", "%s", "process-ok"},
        std::chrono::seconds(1),
        [&observed_process_output](ProcessStream stream, std::string_view chunk) {
            if (stream == ProcessStream::Stdout) {
                observed_process_output.append(chunk);
            }
        });
    assert(process.ok());
    assert(process.value().exit_code == 0);
    assert(process.value().stdout_text == "process-ok");
    assert(observed_process_output == "process-ok");

    const int server = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, IPPROTO_TCP);
    if (server >= 0) {
        sockaddr_in listen_address{};
        listen_address.sin_family = AF_INET;
        listen_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        listen_address.sin_port = 0;
        assert(::bind(server, reinterpret_cast<sockaddr*>(&listen_address), sizeof(listen_address)) == 0);
        assert(::listen(server, 1) == 0);
        socklen_t listen_length = sizeof(listen_address);
        assert(::getsockname(server, reinterpret_cast<sockaddr*>(&listen_address), &listen_length) == 0);
        std::thread socks_server([server] {
            const int client = ::accept4(server, nullptr, nullptr, SOCK_CLOEXEC);
            assert(client >= 0);
            unsigned char greeting[3]{};
            assert(::recv(client, greeting, sizeof(greeting), MSG_WAITALL) == 3);
            assert(greeting[0] == 0x05 && greeting[1] == 0x01 && greeting[2] == 0x00);
            const unsigned char response[2]{0x05, 0x00};
            assert(::send(client, response, sizeof(response), MSG_NOSIGNAL) == 2);
            (void)::close(client);
            (void)::close(server);
        });
        const auto probed = resolveAndProbeUpstream(Upstream{
            "socks5",
            "127.0.0.1",
            ntohs(listen_address.sin_port),
        });
        assert(probed.ok());
        assert(probed.value().address == "127.0.0.1");
        socks_server.join();
    }

    AppPaths state_paths;
    state_paths.runtime_dir = root / "run";
    RuntimeStateStore state_store(state_paths);
    const auto ticks = state_store.processStartTicks(::getpid());
    assert(ticks.ok());
    const auto executable = std::filesystem::read_symlink("/proc/self/exe");
    RuntimeState runtime_state{
        ::getpid(), ticks.value(), executable, "test", "socks5://127.0.0.1:1080", "test-mode", "running"};
    assert(state_store.save(runtime_state).ok());
    const auto state_loaded = state_store.load();
    assert(state_loaded.ok());
    const auto managed = state_store.isManagedProcessRunning(state_loaded.value());
    assert(managed.ok() && managed.value());

    RuntimeState invalid_state = runtime_state;
    invalid_state.phase = "stopped";
    assert(state_store.save(invalid_state).ok());
    assert(!state_store.load().ok());
    assert(state_store.save(runtime_state).ok());

    const auto timed_out = runCapture({"/bin/sleep", "1"}, std::chrono::milliseconds(50));
    assert(!timed_out.ok());

    AppPaths core_paths;
    core_paths.data_dir = root / "data";
    core_paths.cache_dir = root / "cache";
    const std::string fake_version = "test-version";
    const std::string fake_revision = "test-revision";
    const auto fake_core_dir = core_paths.data_dir / "cores" / fake_version;
    assert(ensureDirectory(fake_core_dir, 0750).ok());
    const auto fake_core = fake_core_dir / "sing-box";
    const std::string fake_script =
        "#!/bin/sh\n"
        "printf 'sing-box version test-version\\nRevision: test-revision\\n'\n";
    assert(writeFileAtomic(fake_core, fake_script, 0755).ok());
    const std::string installed_fake_license = "installed test license\n";
    assert(writeFileAtomic(fake_core_dir / "LICENSE", installed_fake_license, 0644).ok());
    const auto fake_hash = sha256File(fake_core);
    const auto installed_fake_license_hash = sha256File(fake_core_dir / "LICENSE");
    assert(fake_hash.ok() && installed_fake_license_hash.ok());
    const CoreReleaseManifest fake_manifest{
        fake_version,
        fake_revision,
        "unused.tar.gz",
        "https://invalid.example/unused.tar.gz",
        0,
        "unused",
        "unused/sing-box",
        fake_script.size(),
        fake_hash.value(),
        "unused/LICENSE",
        installed_fake_license_hash.value(),
    };
    CoreManager core_manager(core_paths, fake_manifest);
    const auto verified_core = core_manager.verifyInstalledCore();
    assert(verified_core.ok());
    assert(verified_core.value().version == fake_version);

    const auto repair_root = root / "repair";
    AppPaths repair_paths;
    repair_paths.data_dir = repair_root / "data";
    repair_paths.cache_dir = repair_root / "cache";
    repair_paths.curl_executable = repair_root / "fake-curl";
    const auto archive_source = repair_root / "archive-source" / fake_version;
    assert(ensureDirectory(archive_source, 0750).ok());
    assert(writeFileAtomic(archive_source / "sing-box", fake_script, 0755).ok());
    const std::string fake_license = "test license\n";
    assert(writeFileAtomic(archive_source / "LICENSE", fake_license, 0644).ok());
    const auto archive_path = repair_root / "fixture.tar.gz";
    const auto archive_result = runCapture({
        "/usr/bin/tar",
        "-czf",
        archive_path.string(),
        "-C",
        (repair_root / "archive-source").string(),
        fake_version,
    }, std::chrono::seconds(5));
    assert(archive_result.ok() && archive_result.value().exit_code == 0);
    const auto archive_hash = sha256File(archive_path);
    const auto license_hash = sha256File(archive_source / "LICENSE");
    assert(archive_hash.ok() && license_hash.ok());
    const std::string fake_curl =
        "#!/bin/sh\n"
        "output=\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  if [ \"$1\" = \"--output\" ]; then output=$2; shift 2; else shift; fi\n"
        "done\n"
        "cp '" + archive_path.string() + "' \"$output\"\n";
    assert(writeFileAtomic(repair_paths.curl_executable, fake_curl, 0755).ok());
    const std::string archive_name = "fixture.tar.gz";
    const std::string binary_member = fake_version + "/sing-box";
    const std::string license_member = fake_version + "/LICENSE";
    const CoreReleaseManifest repair_manifest{
        fake_version,
        fake_revision,
        archive_name,
        "https://invalid.example/fixture.tar.gz",
        std::filesystem::file_size(archive_path),
        archive_hash.value(),
        binary_member,
        fake_script.size(),
        fake_hash.value(),
        license_member,
        license_hash.value(),
    };
    std::string repair_log;
    CoreManager repair_manager(
        repair_paths,
        repair_manifest,
        [&repair_log](LogLevel level, std::string_view message) {
            if (level != LogLevel::Progress) {
                repair_log.append(message);
                repair_log.push_back('\n');
            }
        });
    const auto repaired_core = repair_manager.repairCore();
    assert(repaired_core.ok());
    assert(std::filesystem::exists(repair_manager.corePath()));
    assert(std::filesystem::exists(repair_manager.coreDirectory() / "LICENSE"));
    assert(repair_log.find("sing-box download completed") != std::string::npos);
    assert(repair_log.find("sing-box archive SHA-256 verified") != std::string::npos);
    assert(repair_log.find("installed successfully") != std::string::npos);

    std::filesystem::remove_all(root, error);

    std::cout << "core tests passed\n";
    return 0;
}
