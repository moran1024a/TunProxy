#pragma once

#include "tunproxy/result.hpp"

#include <filesystem>
#include <string>

namespace tunproxy {

Result<std::string> readTextFile(const std::filesystem::path& path);
Result<void> writeFileAtomic(
    const std::filesystem::path& path,
    const std::string& contents,
    int mode = 0644);
Result<std::string> sha256File(
    const std::filesystem::path& path,
    const std::filesystem::path& sha256sum = "/usr/bin/sha256sum");
Result<void> ensureDirectory(const std::filesystem::path& path, int mode);

} // namespace tunproxy
