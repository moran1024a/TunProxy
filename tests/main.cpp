#include "framework.hpp"

#include <cstring>
#include <exception>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char** argv) {
    using namespace tunproxy::test;
    const std::string filter = argc > 1 ? argv[1] : "";
    int passed = 0;
    int skipped = 0;
    std::vector<std::string> failed;
    std::vector<std::string> skipped_names;

    for (const Case& test_case : registry()) {
        if (!filter.empty() && std::strstr(test_case.name, filter.c_str()) == nullptr) {
            continue;
        }
        currentFailures().store(0);
        bool skip = false;
        std::string skip_reason;
        try {
            test_case.function();
        } catch (const Skip& request) {
            skip = true;
            skip_reason = request.reason;
        } catch (const RequireFailure&) {
        } catch (const std::exception& error) {
            check(false, error.what(), test_case.name, 0);
        }
        if (skip) {
            ++skipped;
            skipped_names.push_back(std::string(test_case.name) + ": " + skip_reason);
            std::cout << "[skip] " << test_case.name << " (" << skip_reason << ")\n";
        } else if (currentFailures().load() == 0) {
            ++passed;
            std::cout << "[ ok ] " << test_case.name << '\n';
        } else {
            failed.push_back(test_case.name);
            std::cout << "[FAIL] " << test_case.name << '\n';
        }
    }

    std::cout << '\n' << passed << " passed, " << failed.size() << " failed, " << skipped << " skipped\n";
    for (const auto& name : failed) {
        std::cout << "  failed: " << name << '\n';
    }
    return failed.empty() ? 0 : 1;
}
