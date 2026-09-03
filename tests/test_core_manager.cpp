#include "framework.hpp"

#include "tunproxy/core_manager.hpp"
#include "tunproxy/filesystem.hpp"
#include "tunproxy/process.hpp"

#include "support.hpp"

#include <cstdlib>
#include <filesystem>

using namespace tunproxy;
using tunproxy::test::TempDir;
using tunproxy::test::FakeCoreManifest;
using tunproxy::test::fakeCorePath;
using tunproxy::test::installFakeCore;
using tunproxy::test::kFakeRevision;
using tunproxy::test::kFakeVersion;

TEST_CASE(core_manager_verifies_installed_core) {
    const TempDir root("core-verify");
    AppPaths paths;
    paths.data_dir = root / "data";
    paths.cache_dir = root / "cache";
    FakeCoreManifest fake;
    installFakeCore(paths, fake);
    const CoreManager manager(paths, fake.manifest);
    const auto verified = manager.verifyInstalledCore();
    REQUIRE(verified.ok());
    CHECK(verified.value().version == kFakeVersion);
    CHECK(verified.value().revision == kFakeRevision);
    CHECK(verified.value().executable == manager.corePath());
}

TEST_CASE(core_manager_detects_tampered_core) {
    const TempDir root("core-tamper");
    AppPaths paths;
    paths.data_dir = root / "data";
    paths.cache_dir = root / "cache";
    FakeCoreManifest fake;
    installFakeCore(paths, fake);
    CoreReleaseManifest manifest = fake.manifest;
    const CoreManager manager(paths, manifest);
    REQUIRE(manager.verifyInstalledCore().ok());

    REQUIRE(writeFileAtomic(manager.coreDirectory() / "LICENSE", "changed\n", 0644).ok());
    const auto bad_license = manager.verifyInstalledCore();
    CHECK(!bad_license.ok());
    CHECK(bad_license.error().code == ErrorCode::CoreVerificationFailure);

    manifest.binary_sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
    const CoreManager wrong_hash(paths, manifest);
    CHECK(!wrong_hash.verifyInstalledCore().ok());
}

TEST_CASE(core_manager_repairs_from_archive_and_cleans_stale_artifacts) {
    const TempDir root("core-repair");
    AppPaths paths;
    paths.data_dir = root / "data";
    paths.cache_dir = root / "cache";
    paths.curl_executable = root / "fake-curl";

    const auto archive_source = root.path() / "archive-source" / kFakeVersion;
    REQUIRE(ensureDirectory(archive_source, 0750).ok());
    std::error_code error;
    std::filesystem::copy_file(fakeCorePath(), archive_source / "sing-box", error);
    REQUIRE(!error);
    REQUIRE(writeFileAtomic(archive_source / "LICENSE", "test license\n", 0644).ok());
    const auto archive_path = root / "fixture.tar.gz";
    const auto archived = runCapture({
        "/usr/bin/tar", "-czf", archive_path.string(), "-C",
        (root.path() / "archive-source").string(), kFakeVersion,
    }, std::chrono::seconds(10));
    REQUIRE(archived.ok() && archived.value().exit_code == 0);

    const auto archive_hash = sha256File(archive_path);
    const auto binary_hash = sha256File(archive_source / "sing-box");
    const auto license_hash = sha256File(archive_source / "LICENSE");
    REQUIRE(archive_hash.ok() && binary_hash.ok() && license_hash.ok());
    const std::string fake_curl =
        "#!/bin/sh\n"
        "output=\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  if [ \"$1\" = \"--output\" ]; then output=$2; shift 2; else shift; fi\n"
        "done\n"
        "cp '" + archive_path.string() + "' \"$output\"\n";
    REQUIRE(writeFileAtomic(paths.curl_executable, fake_curl, 0755).ok());

    const std::string asset_name = "fixture.tar.gz";
    const std::string binary_member = kFakeVersion + "/sing-box";
    const std::string license_member = kFakeVersion + "/LICENSE";
    const CoreReleaseManifest manifest{
        kFakeVersion,
        kFakeRevision,
        asset_name,
        "https://invalid.example/fixture.tar.gz",
        std::filesystem::file_size(archive_path),
        archive_hash.value(),
        binary_member,
        std::filesystem::file_size(archive_source / "sing-box"),
        binary_hash.value(),
        license_member,
        license_hash.value(),
    };

    std::string log;
    CoreManager manager(paths, manifest, [&log](LogLevel level, std::string_view message) {
        if (level != LogLevel::Progress) {
            log.append(message);
            log.push_back('\n');
        }
    });

    // Leftovers from an interrupted repair must not block a new one, while
    // symbolic links are left alone.
    REQUIRE(ensureDirectory(manager.coreDirectory() / ".staging.999999", 0700).ok());
    REQUIRE(ensureDirectory(paths.cache_dir, 0700).ok());
    REQUIRE(writeFileAtomic(paths.cache_dir / (asset_name + ".part.999999"), "partial", 0600).ok());
    const auto link = manager.coreDirectory() / ".staging.link";
    std::filesystem::create_directory_symlink(root.path(), link, error);
    REQUIRE(!error);

    const auto repaired = manager.repairCore();
    if (!CHECK(repaired.ok())) {
        std::cerr << repaired.error().message << '\n';
        return;
    }
    CHECK(repaired.value().version == kFakeVersion);
    CHECK(std::filesystem::exists(manager.corePath()));
    CHECK(std::filesystem::exists(manager.coreDirectory() / "LICENSE"));
    CHECK(!std::filesystem::exists(manager.coreDirectory() / ".staging.999999"));
    CHECK(!std::filesystem::exists(paths.cache_dir / (asset_name + ".part.999999")));
    CHECK(std::filesystem::is_symlink(link));
    CHECK(std::filesystem::exists(root.path()));
    CHECK(log.find("Downloading sing-box " + kFakeVersion) != std::string::npos);
    CHECK(log.find("sing-box " + kFakeVersion + " installed") != std::string::npos);
    CHECK(log.find("verified") == std::string::npos);

    // ensureCore is silent once the core is installed.
    log.clear();
    CHECK(manager.ensureCore().ok());
    CHECK(log.empty());
}

TEST_CASE(core_manager_repair_rejects_corrupt_download) {
    const TempDir root("core-corrupt");
    AppPaths paths;
    paths.data_dir = root / "data";
    paths.cache_dir = root / "cache";
    paths.curl_executable = root / "fake-curl";
    const std::string fake_curl =
        "#!/bin/sh\n"
        "output=\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  if [ \"$1\" = \"--output\" ]; then output=$2; shift 2; else shift; fi\n"
        "done\n"
        "printf 'garbage' > \"$output\"\n";
    REQUIRE(writeFileAtomic(paths.curl_executable, fake_curl, 0755).ok());
    const CoreReleaseManifest manifest{
        kFakeVersion, kFakeRevision, "fixture.tar.gz", "https://invalid.example/fixture.tar.gz",
        7, "0000000000000000000000000000000000000000000000000000000000000000",
        "x/sing-box", 1, "0000000000000000000000000000000000000000000000000000000000000000",
        "x/LICENSE", "0000000000000000000000000000000000000000000000000000000000000000",
    };
    CoreManager manager(paths, manifest);
    const auto repaired = manager.repairCore();
    CHECK(!repaired.ok());
    CHECK(repaired.error().code == ErrorCode::CoreVerificationFailure);
    CHECK(!std::filesystem::exists(manager.corePath()));
    CHECK(std::filesystem::directory_iterator(paths.cache_dir) == std::filesystem::directory_iterator());
}

TEST_CASE(core_manager_repairs_real_release_archive) {
    const char* real_archive = std::getenv("TUNPROXY_TEST_SINGBOX_ARCHIVE");
    if (real_archive == nullptr) {
        SKIP("TUNPROXY_TEST_SINGBOX_ARCHIVE is not set");
    }
    const TempDir root("core-real");
    AppPaths paths;
    paths.data_dir = root / "data";
    paths.cache_dir = root / "cache";
    paths.curl_executable = root / "fake-curl";
    const std::string fake_curl =
        "#!/bin/sh\n"
        "output=\n"
        "while [ \"$#\" -gt 0 ]; do\n"
        "  if [ \"$1\" = \"--output\" ]; then output=$2; shift 2; else shift; fi\n"
        "done\n"
        "cp '" + std::string(real_archive) + "' \"$output\"\n";
    REQUIRE(writeFileAtomic(paths.curl_executable, fake_curl, 0755).ok());
    CoreManager manager(paths);
    const auto repaired = manager.repairCore();
    if (!CHECK(repaired.ok())) {
        std::cerr << repaired.error().message << '\n';
        return;
    }
    CHECK(repaired.value().version == std::string(kSingBoxRelease.version));
    CHECK(repaired.value().revision == std::string(kSingBoxRelease.revision));
}
