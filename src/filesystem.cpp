#include "tunproxy/filesystem.hpp"

#include "tunproxy/constants.hpp"
#include "tunproxy/process.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <fstream>
#include <random>
#include <sstream>
#include <system_error>

namespace tunproxy {
namespace {

std::string errnoMessage(const char* operation) {
    return std::string(operation) + ": " + std::strerror(errno);
}

std::filesystem::path temporaryPath(const std::filesystem::path& target) {
    static std::mt19937_64 generator{std::random_device{}()};
    std::ostringstream name;
    name << target.filename().string() << ".tmp." << static_cast<unsigned long long>(generator());
    return target.parent_path() / name.str();
}

} // namespace

Result<std::string> readTextFile(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) {
        return Result<std::string>::failure(makeError(ErrorCode::Generic, errnoMessage("open")));
    }
    std::ostringstream contents;
    contents << input.rdbuf();
    if (!input.good() && !input.eof()) {
        return Result<std::string>::failure(makeError(ErrorCode::Generic, "read failed"));
    }
    return Result<std::string>::success(contents.str());
}

Result<void> writeFileAtomic(
    const std::filesystem::path& path,
    const std::string& contents,
    int mode) {
    if (path.parent_path().empty()) {
        return Result<void>::failure(makeError(ErrorCode::Generic, "target has no parent directory"));
    }

    const auto temporary = temporaryPath(path);
    const int fd = ::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode);
    if (fd < 0) {
        return Result<void>::failure(makeError(ErrorCode::Generic, errnoMessage("create temporary file")));
    }
    if (::fchmod(fd, static_cast<mode_t>(mode)) != 0) {
        (void)::close(fd);
        (void)::unlink(temporary.c_str());
        return Result<void>::failure(makeError(ErrorCode::Generic, errnoMessage("chmod")));
    }

    const char* data = contents.data();
    std::size_t remaining = contents.size();
    while (remaining > 0) {
        const ssize_t written = ::write(fd, data, remaining);
        if (written < 0 && errno == EINTR) {
            continue;
        }
        if (written <= 0) {
            (void)::close(fd);
            (void)::unlink(temporary.c_str());
            return Result<void>::failure(makeError(ErrorCode::Generic, errnoMessage("write")));
        }
        data += written;
        remaining -= static_cast<std::size_t>(written);
    }
    if (::fsync(fd) != 0 || ::close(fd) != 0) {
        (void)::unlink(temporary.c_str());
        return Result<void>::failure(makeError(ErrorCode::Generic, errnoMessage("sync")));
    }
    if (::rename(temporary.c_str(), path.c_str()) != 0) {
        (void)::unlink(temporary.c_str());
        return Result<void>::failure(makeError(ErrorCode::Generic, errnoMessage("rename")));
    }

    const int directory = ::open(path.parent_path().c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory >= 0) {
        (void)::fsync(directory);
        (void)::close(directory);
    }
    return Result<void>::success();
}

Result<std::string> sha256File(
    const std::filesystem::path& path,
    const std::filesystem::path& sha256sum) {
    const auto result = runCapture({sha256sum.string(), "--", path.string()}, kSha256Timeout);
    if (!result.ok()) {
        return Result<std::string>::failure(result.error());
    }
    if (result.value().exit_code != 0) {
        return Result<std::string>::failure(
            makeError(ErrorCode::Generic, "sha256sum failed: " + result.value().stderr_text));
    }
    const std::string& output = result.value().stdout_text;
    const std::size_t separator = output.find("  ");
    if (separator != 64 || output.size() < 64) {
        return Result<std::string>::failure(makeError(ErrorCode::Generic, "invalid sha256sum output"));
    }
    return Result<std::string>::success(output.substr(0, 64));
}

Result<void> ensureDirectory(const std::filesystem::path& path, int mode) {
    if (path.empty()) {
        return Result<void>::failure(makeError(ErrorCode::Generic, "directory path is empty"));
    }
    std::error_code absolute_error;
    const auto absolute_path = path.is_absolute() ? path : std::filesystem::absolute(path, absolute_error);
    if (absolute_error) {
        return Result<void>::failure(makeError(ErrorCode::Generic, absolute_error.message()));
    }
    if (absolute_path == absolute_path.root_path()) {
        return Result<void>::failure(makeError(ErrorCode::Generic, "refusing to change root directory permissions"));
    }

    // Walk each component explicitly so an existing symlink cannot redirect a
    // root-owned runtime/data path outside its intended tree.
    std::filesystem::path current = absolute_path.root_path();
    for (const auto& component : absolute_path.relative_path()) {
        if (component == "." || component == "..") {
            return Result<void>::failure(makeError(
                ErrorCode::Generic, "directory path contains traversal components"));
        }
        current /= component;
        struct stat status {};
        if (::lstat(current.c_str(), &status) == 0) {
            if (S_ISLNK(status.st_mode) || !S_ISDIR(status.st_mode)) {
                return Result<void>::failure(makeError(
                    ErrorCode::Generic, "path component is not a real directory: " + current.string()));
            }
            continue;
        }
        if (errno != ENOENT) {
            return Result<void>::failure(makeError(ErrorCode::Generic, errnoMessage("stat directory")));
        }
        if (::mkdir(current.c_str(), static_cast<mode_t>(mode)) != 0 && errno != EEXIST) {
            return Result<void>::failure(makeError(ErrorCode::Generic, errnoMessage("create directory")));
        }
        if (::lstat(current.c_str(), &status) != 0 || S_ISLNK(status.st_mode) || !S_ISDIR(status.st_mode)) {
            return Result<void>::failure(makeError(
                ErrorCode::Generic, "created path component is not a real directory: " + current.string()));
        }
    }
    if (::chmod(absolute_path.c_str(), static_cast<mode_t>(mode)) != 0) {
        return Result<void>::failure(makeError(ErrorCode::Generic, errnoMessage("chmod directory")));
    }
    return Result<void>::success();
}

} // namespace tunproxy
