// Stand-in for the sing-box executable used by the unit tests.
//
//   version   prints a fixed version and revision line
//   check     exits 0
//   run       appends its arguments and the contents of the -c config file to
//             the file named by TUNPROXY_FAKE_CORE_RECORD, then exits 0
//
// It is a real ELF binary because ProxyManager starts the core with fexecve on
// an O_CLOEXEC descriptor, which the kernel refuses for interpreter scripts.

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

int main(int argc, char** argv) {
    const std::string command = argc > 1 ? argv[1] : "";
    if (command == "version") {
        std::cout << "sing-box version test-version\nRevision: test-revision\n";
        return 0;
    }
    if (command == "check") {
        return 0;
    }
    if (command == "run") {
        const char* record_path = std::getenv("TUNPROXY_FAKE_CORE_RECORD");
        if (record_path == nullptr) {
            return 0;
        }
        std::string config_path;
        for (int index = 2; index + 1 < argc; ++index) {
            if (std::string(argv[index]) == "-c") {
                config_path = argv[index + 1];
            }
        }
        std::ofstream record(record_path, std::ios::app);
        record << "--- run";
        for (int index = 1; index < argc; ++index) {
            record << ' ' << argv[index];
        }
        record << '\n';
        if (!config_path.empty()) {
            std::ifstream config(config_path);
            std::ostringstream contents;
            contents << config.rdbuf();
            record << contents.str();
            if (contents.str().empty() || contents.str().back() != '\n') {
                record << '\n';
            }
        }
        record << "--- end\n";
        return 0;
    }
    std::cerr << "fake core: unknown command\n";
    return 2;
}
