#pragma once

#include <string_view>

#include <sys/types.h>

namespace tunproxy {

// Returns true when uid is root or belongs to group_name, either as the
// primary group or through supplementary membership.
bool isAuthorizedUser(uid_t uid, gid_t primary_gid, std::string_view group_name);

} // namespace tunproxy
