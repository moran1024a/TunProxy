#pragma once

// Minimal self-contained test framework.
//
//   TEST_CASE(name) { ... }      registers a case; all cases run, failures are collected.
//   CHECK(expr)                  records a failure and continues (safe from any thread).
//   REQUIRE(expr)                records a failure and aborts the current case (main thread only).
//   SKIP(reason)                 marks the current case as skipped.
//   TempDir dir("label");        unique scratch directory removed on destruction.

#include <atomic>
#include <filesystem>
#include <functional>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

#include <unistd.h>

namespace tunproxy::test {

struct RequireFailure {};

struct Skip {
    std::string reason;
};

struct Case {
    const char* name;
    void (*function)();
};

inline std::vector<Case>& registry() {
    static std::vector<Case> cases;
    return cases;
}

struct Registrar {
    Registrar(const char* name, void (*function)()) {
        registry().push_back(Case{name, function});
    }
};

inline std::mutex& outputMutex() {
    static std::mutex mutex;
    return mutex;
}

inline std::atomic<int>& currentFailures() {
    static std::atomic<int> failures{0};
    return failures;
}

inline bool check(bool condition, const char* expression, const char* file, int line) {
    if (condition) {
        return true;
    }
    currentFailures().fetch_add(1);
    const std::lock_guard<std::mutex> lock(outputMutex());
    std::cerr << "    " << file << ':' << line << ": CHECK(" << expression << ") failed\n";
    return false;
}

class TempDir {
public:
    explicit TempDir(const std::string& label)
        : path_(std::filesystem::temp_directory_path() /
              ("tunproxy-test-" + label + "-" + std::to_string(static_cast<long long>(::getpid())))) {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
        std::filesystem::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    TempDir(const TempDir&) = delete;
    TempDir& operator=(const TempDir&) = delete;

    [[nodiscard]] const std::filesystem::path& path() const { return path_; }
    std::filesystem::path operator/(const char* child) const { return path_ / child; }

private:
    std::filesystem::path path_;
};

} // namespace tunproxy::test

#define TUNPROXY_TEST_CONCAT_INNER(a, b) a##b
#define TUNPROXY_TEST_CONCAT(a, b) TUNPROXY_TEST_CONCAT_INNER(a, b)

#define TEST_CASE(name)                                                                        \
    static void name();                                                                        \
    static const ::tunproxy::test::Registrar TUNPROXY_TEST_CONCAT(name, _registrar)(#name, &name); \
    static void name()

#define CHECK(expr) ::tunproxy::test::check(static_cast<bool>(expr), #expr, __FILE__, __LINE__)

#define REQUIRE(expr)                                                                          \
    do {                                                                                       \
        if (!::tunproxy::test::check(static_cast<bool>(expr), #expr, __FILE__, __LINE__)) {     \
            throw ::tunproxy::test::RequireFailure{};                                          \
        }                                                                                      \
    } while (0)

#define SKIP(reason) throw ::tunproxy::test::Skip{reason}
