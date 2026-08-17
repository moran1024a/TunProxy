#pragma once

#include "tunproxy/ipc.hpp"
#include "tunproxy/log.hpp"
#include "tunproxy/paths.hpp"
#include "tunproxy/result.hpp"

#include <string>

namespace tunproxy {

class CommandController {
public:
    explicit CommandController(AppPaths paths = {});

    Result<std::string> execute(Command command, const std::string& argument, LogCallback logger = {}) const;

private:
    AppPaths paths_;
};

} // namespace tunproxy
