#include "tunproxy/authorization.hpp"

#include <grp.h>
#include <pwd.h>
#include <unistd.h>

#include <string>
#include <vector>

namespace tunproxy {

bool isAuthorizedUser(uid_t uid, gid_t primary_gid, std::string_view group_name) {
    if (uid == 0) {
        return true;
    }
    const std::string name(group_name);
    const group* admin_group = ::getgrnam(name.c_str());
    if (admin_group == nullptr) {
        return false;
    }
    const gid_t admin_gid = admin_group->gr_gid;
    if (primary_gid == admin_gid) {
        return true;
    }
    const passwd* account = ::getpwuid(uid);
    if (account == nullptr) {
        return false;
    }
    int count = 16;
    std::vector<gid_t> groups(static_cast<std::size_t>(count));
    if (::getgrouplist(account->pw_name, account->pw_gid, groups.data(), &count) < 0) {
        if (count <= 0 || count > 1024) {
            return false;
        }
        groups.resize(static_cast<std::size_t>(count));
        if (::getgrouplist(account->pw_name, account->pw_gid, groups.data(), &count) < 0) {
            return false;
        }
    }
    if (count <= 0 || count > static_cast<int>(groups.size())) {
        return false;
    }
    for (int index = 0; index < count; ++index) {
        if (groups[static_cast<std::size_t>(index)] == admin_gid) {
            return true;
        }
    }
    return false;
}

} // namespace tunproxy
