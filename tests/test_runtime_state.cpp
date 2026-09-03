#include "framework.hpp"

#include "tunproxy/runtime_state.hpp"

#include <poll.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <filesystem>

using namespace tunproxy;
using tunproxy::test::TempDir;

namespace {

RuntimeState selfState(const RuntimeStateStore& store) {
    const auto ticks = store.processStartTicks(::getpid());
    REQUIRE(ticks.ok());
    RuntimeState state;
    state.pid = ::getpid();
    state.start_ticks = ticks.value();
    state.executable = std::filesystem::read_symlink("/proc/self/exe");
    state.core_version = "test";
    state.upstream = "socks5://127.0.0.1:1080";
    state.routing_mode = "test-mode";
    state.upstream_address = "127.0.0.1";
    state.bypass_cidrs = {"127.0.0.0/8", "127.0.0.1/32"};
    state.phase = "running";
    return state;
}

} // namespace

TEST_CASE(runtime_state_round_trips_and_validates_identity) {
    const TempDir root("state");
    AppPaths paths;
    paths.runtime_dir = root / "run";
    const RuntimeStateStore store(paths);
    const RuntimeState state = selfState(store);
    REQUIRE(store.save(state).ok());
    const auto loaded = store.load();
    REQUIRE(loaded.ok());
    CHECK(loaded.value().upstream_address == "127.0.0.1");
    CHECK(loaded.value().bypass_cidrs.size() == 2);
    CHECK(loaded.value().routing_mode == "test-mode");
    const auto managed = store.isManagedProcessRunning(loaded.value());
    REQUIRE(managed.ok());
    CHECK(managed.value());

    RuntimeState wrong_ticks = state;
    wrong_ticks.start_ticks += 1;
    CHECK(!store.isManagedProcessRunning(wrong_ticks).value());
    RuntimeState wrong_executable = state;
    wrong_executable.executable = "/bin/sh";
    CHECK(!store.isManagedProcessRunning(wrong_executable).value());

    REQUIRE(store.clear().ok());
    CHECK(!store.load().ok());
    CHECK(store.clear().ok());
}

TEST_CASE(runtime_state_rejects_invalid_files) {
    const TempDir root("state-bad");
    AppPaths paths;
    paths.runtime_dir = root / "run";
    const RuntimeStateStore store(paths);
    RuntimeState state = selfState(store);
    state.phase = "stopped";
    REQUIRE(store.save(state).ok());
    CHECK(!store.load().ok());
    state.phase = "running";
    state.pid = 0;
    REQUIRE(store.save(state).ok());
    CHECK(!store.load().ok());
}

TEST_CASE(runtime_state_process_start_ticks_for_missing_pid) {
    const RuntimeStateStore store;
    CHECK(!store.processStartTicks(2147483647).ok());
}

TEST_CASE(runtime_state_file_lock_reports_waiting) {
    const TempDir root("lock");
    const auto lock_path = root / "run/lock";
    int ready_pipe[2]{-1, -1};
    REQUIRE(::pipe(ready_pipe) == 0);
    bool waited = false;
    pid_t child = -1;
    {
        const auto first = FileLock::acquire(lock_path, [&waited] { waited = true; });
        REQUIRE(first.ok());
        CHECK(!waited);
        // A second open file description on the same path contends for the
        // lock. The child reports through the pipe once on_wait fired, then
        // blocks until the parent releases.
        child = ::fork();
        REQUIRE(child >= 0);
        if (child == 0) {
            (void)::close(ready_pipe[0]);
            const auto second = FileLock::acquire(lock_path, [&ready_pipe] {
                const char byte = 'w';
                (void)!::write(ready_pipe[1], &byte, 1);
            });
            _exit(second.ok() ? 0 : 1);
        }
        (void)::close(ready_pipe[1]);
        pollfd waiter{ready_pipe[0], POLLIN, 0};
        const int polled = ::poll(&waiter, 1, 5000);
        char byte = 0;
        CHECK(polled == 1 && ::read(ready_pipe[0], &byte, 1) == 1 && byte == 'w');
        // Releasing `first` lets the child's blocking flock succeed.
    }
    (void)::close(ready_pipe[0]);
    int status = 0;
    while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {
    }
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
