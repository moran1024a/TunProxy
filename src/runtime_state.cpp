#include "tunproxy/runtime_state.hpp"

#include "tunproxy/filesystem.hpp"

#include <fcntl.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <unordered_map>

namespace tunproxy {
namespace {

Result<long long> parseInteger(const std::string& text, const char* name) {
    long long value = 0;
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), value);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        return Result<long long>::failure(makeError(ErrorCode::StateError, std::string("invalid state ") + name));
    }
    return Result<long long>::success(value);
}

std::string readLink(const std::filesystem::path& path) {
    std::error_code error;
    const auto value = std::filesystem::read_symlink(path, error);
    return error ? std::string{} : value.string();
}

std::vector<std::string> splitCidrs(const std::string& text) {
    std::vector<std::string> output;
    std::size_t offset = 0;
    while (offset < text.size()) {
        const auto separator = text.find(',', offset);
        const auto length = separator == std::string::npos ? std::string::npos : separator - offset;
        const std::string value = text.substr(offset, length);
        if (!value.empty()) {
            output.push_back(value);
        }
        if (separator == std::string::npos) {
            break;
        }
        offset = separator + 1;
    }
    return output;
}

std::string joinCidrs(const std::vector<std::string>& values) {
    std::ostringstream output;
    for (std::size_t index = 0; index < values.size(); ++index) {
        if (index != 0) {
            output << ',';
        }
        output << values[index];
    }
    return output.str();
}

} // namespace

RuntimeStateStore::RuntimeStateStore(AppPaths paths) : paths_(std::move(paths)) {}

Result<RuntimeState> RuntimeStateStore::load() const {
    const auto content = readTextFile(paths_.state_file());
    if (!content.ok()) {
        return Result<RuntimeState>::failure(makeError(ErrorCode::StateError, "runtime state is absent"));
    }
    std::unordered_map<std::string, std::string> values;
    std::istringstream lines(content.value());
    std::string line;
    while (std::getline(lines, line)) {
        const auto separator = line.find('=');
        if (separator == std::string::npos) {
            return Result<RuntimeState>::failure(makeError(ErrorCode::StateError, "invalid runtime state"));
        }
        values.emplace(line.substr(0, separator), line.substr(separator + 1));
    }
    const auto pid = parseInteger(values["pid"], "pid");
    const auto start_ticks = parseInteger(values["start_ticks"], "start_ticks");
    if (!pid.ok() || !start_ticks.ok() || pid.value() <= 0 || start_ticks.value() <= 0) {
        return Result<RuntimeState>::failure(makeError(ErrorCode::StateError, "invalid runtime process identity"));
    }
    RuntimeState state;
    state.pid = static_cast<pid_t>(pid.value());
    state.start_ticks = static_cast<std::uint64_t>(start_ticks.value());
    state.executable = values["executable"];
    state.core_version = values["core_version"];
    state.upstream = values["upstream"];
    state.routing_mode = values["routing_mode"];
    state.upstream_address = values["upstream_address"];
    state.bypass_cidrs = splitCidrs(values["bypass_cidrs"]);
    state.phase = values["phase"];
    if (state.executable.empty() || state.core_version.empty() || state.upstream.empty() ||
        (state.phase != "starting" && state.phase != "running") || state.routing_mode.empty()) {
        return Result<RuntimeState>::failure(makeError(ErrorCode::StateError, "runtime state is incomplete"));
    }
    return Result<RuntimeState>::success(std::move(state));
}

Result<void> RuntimeStateStore::save(const RuntimeState& state) const {
    const auto directory = ensureDirectory(paths_.runtime_dir, 0755);
    if (!directory.ok()) {
        return directory;
    }
    std::ostringstream content;
    content << "pid=" << state.pid << '\n'
            << "start_ticks=" << state.start_ticks << '\n'
            << "executable=" << state.executable.string() << '\n'
            << "core_version=" << state.core_version << '\n'
            << "upstream=" << state.upstream << '\n'
            << "routing_mode=" << state.routing_mode << '\n'
            << "upstream_address=" << state.upstream_address << '\n'
            << "bypass_cidrs=" << joinCidrs(state.bypass_cidrs) << '\n'
            << "phase=" << state.phase << '\n';
    return writeFileAtomic(paths_.state_file(), content.str(), 0644);
}

Result<void> RuntimeStateStore::clear() const {
    std::error_code error;
    std::filesystem::remove(paths_.state_file(), error);
    if (error && error != std::errc::no_such_file_or_directory) {
        return Result<void>::failure(makeError(ErrorCode::StateError, error.message()));
    }
    return Result<void>::success();
}

Result<std::uint64_t> RuntimeStateStore::processStartTicks(pid_t pid) const {
    const auto content = readTextFile("/proc/" + std::to_string(pid) + "/stat");
    if (!content.ok()) {
        return Result<std::uint64_t>::failure(makeError(ErrorCode::StateError, "process does not exist"));
    }
    const std::size_t command_end = content.value().rfind(')');
    if (command_end == std::string::npos || command_end + 2 >= content.value().size()) {
        return Result<std::uint64_t>::failure(makeError(ErrorCode::StateError, "invalid process stat"));
    }
    std::istringstream fields(content.value().substr(command_end + 2));
    std::string field;
    // The substring starts at field 3 (state); starttime is field 22.
    for (int number = 3; number <= 22; ++number) {
        if (!(fields >> field)) {
            return Result<std::uint64_t>::failure(makeError(ErrorCode::StateError, "short process stat"));
        }
        if (number == 22) {
            const auto ticks = parseInteger(field, "process start time");
            if (!ticks.ok() || ticks.value() <= 0) {
                return Result<std::uint64_t>::failure(makeError(ErrorCode::StateError, "invalid process start time"));
            }
            return Result<std::uint64_t>::success(static_cast<std::uint64_t>(ticks.value()));
        }
    }
    return Result<std::uint64_t>::failure(makeError(ErrorCode::StateError, "process start time missing"));
}

Result<bool> RuntimeStateStore::isManagedProcessRunning(const RuntimeState& state) const {
    if (::kill(state.pid, 0) != 0 && errno != EPERM) {
        return Result<bool>::success(false);
    }
    const auto ticks = processStartTicks(state.pid);
    if (!ticks.ok() || ticks.value() != state.start_ticks) {
        return Result<bool>::success(false);
    }
    std::string actual_executable = readLink("/proc/" + std::to_string(state.pid) + "/exe");
    constexpr std::string_view deleted_suffix = " (deleted)";
    if (actual_executable.size() >= deleted_suffix.size() &&
        actual_executable.compare(
            actual_executable.size() - deleted_suffix.size(),
            deleted_suffix.size(),
            deleted_suffix) == 0) {
        actual_executable.resize(actual_executable.size() - deleted_suffix.size());
    }
    std::error_code error;
    const auto expected = std::filesystem::weakly_canonical(state.executable, error);
    if (error || actual_executable != expected.string()) {
        return Result<bool>::success(false);
    }
    return Result<bool>::success(true);
}

FileLock::~FileLock() {
    if (descriptor_ >= 0) {
        (void)::flock(descriptor_, LOCK_UN);
        (void)::close(descriptor_);
    }
}

FileLock::FileLock(FileLock&& other) noexcept : descriptor_(other.descriptor_) {
    other.descriptor_ = -1;
}

FileLock& FileLock::operator=(FileLock&& other) noexcept {
    if (this != &other) {
        if (descriptor_ >= 0) {
            (void)::flock(descriptor_, LOCK_UN);
            (void)::close(descriptor_);
        }
        descriptor_ = other.descriptor_;
        other.descriptor_ = -1;
    }
    return *this;
}

Result<FileLock> FileLock::acquire(
    const std::filesystem::path& path, const std::function<void()>& on_wait) {
    const auto directory = ensureDirectory(path.parent_path(), 0755);
    if (!directory.ok()) {
        return Result<FileLock>::failure(directory.error());
    }
    const int descriptor = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (descriptor < 0) {
        return Result<FileLock>::failure(makeError(ErrorCode::StateError, "cannot open operation lock"));
    }
    if (::flock(descriptor, LOCK_EX | LOCK_NB) == 0) {
        return Result<FileLock>::success(FileLock(descriptor));
    }
    if (errno == EWOULDBLOCK && on_wait) {
        on_wait();
    }
    while (::flock(descriptor, LOCK_EX) != 0) {
        if (errno == EINTR) {
            continue;
        }
        (void)::close(descriptor);
        return Result<FileLock>::failure(makeError(ErrorCode::StateError, "cannot acquire operation lock"));
    }
    return Result<FileLock>::success(FileLock(descriptor));
}

} // namespace tunproxy
