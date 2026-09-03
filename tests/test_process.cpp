#include "framework.hpp"

#include "tunproxy/process.hpp"

#include <chrono>

using namespace tunproxy;

TEST_CASE(process_captures_output_and_streams_chunks) {
    std::string streamed;
    const auto result = runCapture(
        {"/usr/bin/printf", "%s", "process-ok"},
        std::chrono::seconds(2),
        [&streamed](ProcessStream stream, std::string_view chunk) {
            if (stream == ProcessStream::Stdout) {
                streamed.append(chunk);
            }
        });
    REQUIRE(result.ok());
    CHECK(result.value().exit_code == 0);
    CHECK(result.value().stdout_text == "process-ok");
    CHECK(streamed == "process-ok");
}

TEST_CASE(process_reports_stderr_and_exit_code) {
    const auto result = runCapture({"/bin/sh", "-c", "echo out; echo err >&2; exit 3"}, std::chrono::seconds(2));
    REQUIRE(result.ok());
    CHECK(result.value().exit_code == 3);
    CHECK(result.value().stdout_text == "out\n");
    CHECK(result.value().stderr_text == "err\n");
}

TEST_CASE(process_times_out) {
    const auto result = runCapture({"/bin/sleep", "2"}, std::chrono::milliseconds(50));
    CHECK(!result.ok());
    CHECK(result.error().message.find("timed out") != std::string::npos);
}

TEST_CASE(process_rejects_empty_command_and_missing_binary) {
    CHECK(!runCapture({}, std::chrono::seconds(1)).ok());
    const auto missing = runCapture({"/nonexistent/tunproxy-binary"}, std::chrono::seconds(1));
    REQUIRE(missing.ok());
    CHECK(missing.value().exit_code == 127);
}
