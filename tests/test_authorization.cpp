#include "framework.hpp"

#include "tunproxy/authorization.hpp"

#include <grp.h>
#include <pwd.h>
#include <unistd.h>

using namespace tunproxy;

TEST_CASE(authorization_root_is_always_authorized) {
    CHECK(isAuthorizedUser(0, 0, "sudo"));
    CHECK(isAuthorizedUser(0, 12345, "no-such-group-tunproxy"));
}

TEST_CASE(authorization_rejects_unknown_group) {
    CHECK(!isAuthorizedUser(::getuid(), ::getgid(), "no-such-group-tunproxy"));
}

TEST_CASE(authorization_accepts_primary_group_membership) {
    if (::getuid() == 0) {
        SKIP("running as root");
    }
    const group* primary = ::getgrgid(::getgid());
    const passwd* account = ::getpwuid(::getuid());
    if (primary == nullptr || account == nullptr) {
        SKIP("current user or primary group is not resolvable");
    }
    CHECK(isAuthorizedUser(::getuid(), ::getgid(), primary->gr_name));
    // Membership must also be found through supplementary lookup when the
    // primary gid reported by the peer differs.
    CHECK(isAuthorizedUser(::getuid(), 4294967294U, primary->gr_name));
}
