#include "framework.hpp"

#include "tunproxy/filesystem.hpp"

#include <sys/stat.h>
#include <unistd.h>

#include <filesystem>

using namespace tunproxy;
using tunproxy::test::TempDir;

TEST_CASE(filesystem_atomic_write_sets_mode_and_replaces) {
    const TempDir root("fs-write");
    const auto target = root / "file";
    REQUIRE(writeFileAtomic(target, "first\n", 0600).ok());
    REQUIRE(writeFileAtomic(target, "second\n", 0600).ok());
    const auto contents = readTextFile(target);
    REQUIRE(contents.ok());
    CHECK(contents.value() == "second\n");
    struct stat status {};
    REQUIRE(::stat(target.c_str(), &status) == 0);
    CHECK((status.st_mode & 0777) == 0600);
    // No temporary files are left behind.
    int entries = 0;
    for (const auto& entry : std::filesystem::directory_iterator(root.path())) {
        (void)entry;
        ++entries;
    }
    CHECK(entries == 1);
    CHECK(!writeFileAtomic("relative-file", "x", 0600).ok());
    CHECK(!readTextFile(root / "missing").ok());
}

TEST_CASE(filesystem_sha256_matches_known_digest) {
    const TempDir root("fs-sha");
    const auto target = root / "abc";
    REQUIRE(writeFileAtomic(target, "abc", 0600).ok());
    const auto digest = sha256File(target);
    REQUIRE(digest.ok());
    CHECK(digest.value() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(!sha256File(root / "missing").ok());
}

TEST_CASE(filesystem_ensure_directory_rejects_symlinks_and_traversal) {
    const TempDir root("fs-dir");
    REQUIRE(std::filesystem::create_directories(root / "real-parent"));
    const auto link = root / "symlink-parent";
    REQUIRE(::symlink((root / "real-parent").c_str(), link.c_str()) == 0);
    CHECK(!ensureDirectory(link / "child", 0750).ok());
    CHECK(!ensureDirectory(root / "a/../b", 0750).ok());
    CHECK(!ensureDirectory("/", 0755).ok());
    CHECK(!ensureDirectory("", 0755).ok());

    const auto nested = root / "a/b/c";
    REQUIRE(ensureDirectory(nested, 0750).ok());
    struct stat status {};
    REQUIRE(::stat(nested.c_str(), &status) == 0);
    CHECK(S_ISDIR(status.st_mode));
    CHECK((status.st_mode & 0777) == 0750);
    REQUIRE(writeFileAtomic(root / "file", "x", 0600).ok());
    CHECK(!ensureDirectory(root / "file", 0750).ok());
}
