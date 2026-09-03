#include "tunproxy/core_manager.hpp"

#include "tunproxy/constants.hpp"
#include "tunproxy/filesystem.hpp"
#include "tunproxy/process.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <chrono>
#include <filesystem>
#include <sstream>
#include <thread>

namespace tunproxy {
namespace {

std::string processFailureDetail(const Result<ProcessOutput>& process) {
    if (!process.ok()) {
        return process.error().message;
    }
    if (!process.value().stderr_text.empty()) {
        return process.value().stderr_text;
    }
    return "process exited with status " + std::to_string(process.value().exit_code);
}

class TemporaryTree {
public:
    explicit TemporaryTree(std::filesystem::path path) : path_(std::move(path)) {}
    ~TemporaryTree() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    TemporaryTree(const TemporaryTree&) = delete;
    TemporaryTree& operator=(const TemporaryTree&) = delete;

private:
    std::filesystem::path path_;
};

Result<std::uintmax_t> regularFileSize(const std::filesystem::path& path) {
    struct stat status {};
    if (::lstat(path.c_str(), &status) != 0 || !S_ISREG(status.st_mode)) {
        return Result<std::uintmax_t>::failure(
            makeError(ErrorCode::CoreVerificationFailure, "core file is missing or is not a regular file"));
    }
    if (status.st_uid != 0 && ::geteuid() == 0) {
        return Result<std::uintmax_t>::failure(
            makeError(ErrorCode::CoreVerificationFailure, "core file is not owned by root"));
    }
    return Result<std::uintmax_t>::success(static_cast<std::uintmax_t>(status.st_size));
}

Result<void> renameReplacing(
    const std::filesystem::path& source,
    const std::filesystem::path& destination) {
    if (::rename(source.c_str(), destination.c_str()) != 0) {
        return Result<void>::failure(
            makeError(ErrorCode::CoreVerificationFailure, "atomic core replacement failed"));
    }
    const int directory = ::open(destination.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory >= 0) {
        (void)::fsync(directory);
        (void)::close(directory);
    }
    return Result<void>::success();
}

bool startsWith(const std::string& text, const std::string& prefix) {
    return text.compare(0, prefix.size(), prefix) == 0;
}

// Removes leftovers of interrupted repairs. Symbolic links are never followed:
// only real directories and regular files matching the expected names go.
void removeStaleArtifacts(
    const std::filesystem::path& directory,
    const std::string& prefix,
    std::filesystem::file_type expected_type) {
    std::error_code error;
    std::filesystem::directory_iterator entries(directory, error);
    if (error) {
        return;
    }
    for (const auto& entry : entries) {
        if (!startsWith(entry.path().filename().string(), prefix)) {
            continue;
        }
        std::error_code status_error;
        const auto status = entry.symlink_status(status_error);
        if (status_error || status.type() != expected_type) {
            continue;
        }
        std::error_code remove_error;
        if (expected_type == std::filesystem::file_type::directory) {
            std::filesystem::remove_all(entry.path(), remove_error);
        } else {
            std::filesystem::remove(entry.path(), remove_error);
        }
    }
}

} // namespace

CoreManager::CoreManager(AppPaths paths, CoreReleaseManifest manifest, LogCallback logger)
    : paths_(std::move(paths)), manifest_(manifest), logger_(std::move(logger)) {}

std::filesystem::path CoreManager::coreDirectory() const {
    return paths_.data_dir / "cores" / std::string(manifest_.version);
}

std::filesystem::path CoreManager::corePath() const {
    return coreDirectory() / "sing-box";
}

Result<CoreInfo> CoreManager::verifyCandidate(const std::filesystem::path& executable) const {
    const auto size = regularFileSize(executable);
    if (!size.ok() || size.value() != manifest_.binary_size) {
        return Result<CoreInfo>::failure(makeError(
            ErrorCode::CoreVerificationFailure,
            "sing-box binary size mismatch"));
    }

    const auto hash = sha256File(executable, paths_.sha256sum_executable);
    if (!hash.ok() || hash.value() != manifest_.binary_sha256) {
        return Result<CoreInfo>::failure(makeError(
            ErrorCode::CoreVerificationFailure,
            "sing-box binary checksum mismatch"));
    }

    const auto version = runCapture(
        {executable.string(), "version"},
        kCoreVersionTimeout);
    if (!version.ok() || version.value().exit_code != 0) {
        return Result<CoreInfo>::failure(makeError(
            ErrorCode::CoreVerificationFailure,
            "cannot execute verified sing-box version command"));
    }
    const std::string expected_version = "sing-box version " + std::string(manifest_.version);
    const std::string expected_revision = "Revision: " + std::string(manifest_.revision);
    if (version.value().stdout_text.find(expected_version) == std::string::npos ||
        version.value().stdout_text.find(expected_revision) == std::string::npos) {
        return Result<CoreInfo>::failure(makeError(
            ErrorCode::CoreVerificationFailure,
            "sing-box version or revision mismatch"));
    }
    return Result<CoreInfo>::success(CoreInfo{
        executable,
        std::string(manifest_.version),
        std::string(manifest_.revision),
    });
}

Result<CoreInfo> CoreManager::verifyInstalledCore() const {
    const auto license_hash = sha256File(coreDirectory() / "LICENSE", paths_.sha256sum_executable);
    if (!license_hash.ok() || license_hash.value() != manifest_.license_sha256) {
        return Result<CoreInfo>::failure(makeError(
            ErrorCode::CoreVerificationFailure,
            "sing-box license is missing or invalid"));
    }
    return verifyCandidate(corePath());
}

Result<CoreInfo> CoreManager::ensureCore() {
    const auto installed = verifyInstalledCore();
    if (installed.ok()) {
        return installed;
    }
    emitLog(logger_, LogLevel::Warning,
        "sing-box " + std::string(manifest_.version) +
        " missing or failed verification: " + installed.error().message);
    return repairCore();
}

Result<CoreInfo> CoreManager::repairCore() {
    const auto cache_directory = ensureDirectory(paths_.cache_dir, 0700);
    if (!cache_directory.ok()) {
        return Result<CoreInfo>::failure(cache_directory.error());
    }
    const auto cores_directory = ensureDirectory(paths_.data_dir / "cores", 0750);
    if (!cores_directory.ok()) {
        return Result<CoreInfo>::failure(cores_directory.error());
    }
    const auto version_directory = ensureDirectory(coreDirectory(), 0750);
    if (!version_directory.ok()) {
        return Result<CoreInfo>::failure(version_directory.error());
    }

    // The caller holds the operation lock, so leftovers cannot belong to a
    // concurrent repair.
    removeStaleArtifacts(coreDirectory(), ".staging.", std::filesystem::file_type::directory);
    removeStaleArtifacts(
        paths_.cache_dir, std::string(manifest_.asset_name) + ".part.", std::filesystem::file_type::regular);

    const std::string suffix = std::to_string(static_cast<long long>(::getpid()));
    const auto archive = paths_.cache_dir / (std::string(manifest_.asset_name) + ".part." + suffix);
    const auto staging = coreDirectory() / (".staging." + suffix);
    if (::mkdir(staging.c_str(), 0700) != 0) {
        return Result<CoreInfo>::failure(makeError(
            ErrorCode::CoreDownloadFailure, "cannot create core staging directory"));
    }
    TemporaryTree cleanup_staging(staging);
    TemporaryTree cleanup_archive(archive);

    Result<ProcessOutput> download = Result<ProcessOutput>::failure(
        makeError(ErrorCode::CoreDownloadFailure, "download not attempted"));
    for (int attempt = 0; attempt < kDownloadAttempts; ++attempt) {
        emitLog(logger_, LogLevel::Info,
            "Downloading sing-box " + std::string(manifest_.version) +
            (attempt == 0
                ? std::string{}
                : " (attempt " + std::to_string(attempt + 1) + "/" + std::to_string(kDownloadAttempts) + ")"));
        std::error_code ignored;
        std::filesystem::remove(archive, ignored);
        download = runCapture({
            paths_.curl_executable.string(),
            "--fail",
            "--progress-bar",
            "--location",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--connect-timeout",
            std::to_string(kDownloadConnectTimeout.count()),
            "--max-time",
            std::to_string(kDownloadMaxTime.count()),
            "--output",
            archive.string(),
            std::string(manifest_.download_url),
        }, kDownloadProcessTimeout, [this](ProcessStream stream, std::string_view chunk) {
            if (stream == ProcessStream::Stderr) {
                emitLog(logger_, LogLevel::Progress, std::string(chunk));
            }
        });
        emitLog(logger_, LogLevel::Progress, "\n");
        if (download.ok() && download.value().exit_code == 0) {
            break;
        }
        emitLog(logger_, LogLevel::Warning, "download failed: " + processFailureDetail(download));
        if (attempt + 1 < kDownloadAttempts) {
            std::this_thread::sleep_for(kDownloadRetryDelay);
        }
    }
    if (!download.ok() || download.value().exit_code != 0) {
        const std::string detail = processFailureDetail(download);
        return Result<CoreInfo>::failure(makeError(
            ErrorCode::CoreDownloadFailure,
            "sing-box download failed: " + detail));
    }

    const auto archive_size = regularFileSize(archive);
    if (!archive_size.ok() || archive_size.value() != manifest_.archive_size) {
        return Result<CoreInfo>::failure(makeError(
            ErrorCode::CoreVerificationFailure,
            "sing-box archive size mismatch"));
    }
    const auto archive_hash = sha256File(archive, paths_.sha256sum_executable);
    if (!archive_hash.ok() || archive_hash.value() != manifest_.archive_sha256) {
        return Result<CoreInfo>::failure(makeError(
            ErrorCode::CoreVerificationFailure,
            "sing-box archive checksum mismatch"));
    }
    const auto extract = runCapture({
        paths_.tar_executable.string(),
        "--extract",
        "--gzip",
        "--file",
        archive.string(),
        "--directory",
        staging.string(),
        "--strip-components=1",
        "--no-same-owner",
        "--no-same-permissions",
        "--",
        std::string(manifest_.binary_member),
        std::string(manifest_.license_member),
    }, kExtractTimeout);
    if (!extract.ok() || extract.value().exit_code != 0) {
        const std::string detail = extract.ok() ? extract.value().stderr_text : extract.error().message;
        return Result<CoreInfo>::failure(makeError(
            ErrorCode::CoreVerificationFailure,
            "cannot extract verified sing-box archive: " + detail));
    }

    const auto candidate = staging / "sing-box";
    if (::chmod(candidate.c_str(), 0755) != 0) {
        return Result<CoreInfo>::failure(makeError(
            ErrorCode::CoreVerificationFailure,
            "cannot set sing-box executable permissions"));
    }
    const auto verified = verifyCandidate(candidate);
    if (!verified.ok()) {
        return verified;
    }
    const auto license_hash = sha256File(staging / "LICENSE", paths_.sha256sum_executable);
    if (!license_hash.ok() || license_hash.value() != manifest_.license_sha256) {
        return Result<CoreInfo>::failure(makeError(
            ErrorCode::CoreVerificationFailure,
            "sing-box license checksum mismatch"));
    }
    const auto installed_license = renameReplacing(staging / "LICENSE", coreDirectory() / "LICENSE");
    if (!installed_license.ok()) {
        return Result<CoreInfo>::failure(installed_license.error());
    }
    const auto installed = renameReplacing(candidate, corePath());
    if (!installed.ok()) {
        return Result<CoreInfo>::failure(installed.error());
    }
    emitLog(logger_, LogLevel::Info, "sing-box " + std::string(manifest_.version) + " installed");
    return verifyInstalledCore();
}

} // namespace tunproxy
