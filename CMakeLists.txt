cmake_minimum_required(VERSION 3.16)

# debian/changelog is the single source of truth for the package version.
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/debian/changelog" TUNPROXY_CHANGELOG_HEAD LIMIT_COUNT 1)
if(NOT TUNPROXY_CHANGELOG_HEAD MATCHES "^tunproxy \\(([0-9]+\\.[0-9]+\\.[0-9]+)(~[a-z0-9]+)?(-[0-9]+)?\\)")
    message(FATAL_ERROR "cannot parse version from debian/changelog: '${TUNPROXY_CHANGELOG_HEAD}'")
endif()
set(TUNPROXY_BASE_VERSION "${CMAKE_MATCH_1}")
set(TUNPROXY_VERSION_SUFFIX "${CMAKE_MATCH_2}")
if(TUNPROXY_VERSION_SUFFIX STREQUAL "")
    set(TUNPROXY_VERSION_STRING "${TUNPROXY_BASE_VERSION}")
elseif(TUNPROXY_VERSION_SUFFIX MATCHES "^~rc([0-9]+)$")
    set(TUNPROXY_VERSION_STRING "${TUNPROXY_BASE_VERSION}-rc.${CMAKE_MATCH_1}")
else()
    message(FATAL_ERROR "unsupported version suffix in debian/changelog: '${TUNPROXY_VERSION_SUFFIX}'")
endif()

project(tunproxy VERSION ${TUNPROXY_BASE_VERSION} LANGUAGES CXX)

set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/debian/changelog")

include(GNUInstallDirs)

option(TUNPROXY_BUILD_TESTS "Build unit tests" ON)
option(TUNPROXY_STATIC_CXX_RUNTIME "Statically link libstdc++ and libgcc" OFF)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

set(TUNPROXY_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/include")
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/include/tunproxy/version.hpp.in"
    "${TUNPROXY_GENERATED_INCLUDE_DIR}/tunproxy/version.hpp"
    @ONLY)
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/docs/tunproxy.8.in"
    "${CMAKE_CURRENT_BINARY_DIR}/tunproxy.8"
    @ONLY)

set(TUNPROXY_WARNINGS
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>)

add_library(tunproxy_core
    src/authorization.cpp
    src/bypass_policy.cpp
    src/config.cpp
    src/controller.cpp
    src/core_manager.cpp
    src/filesystem.cpp
    src/ipc.cpp
    src/process.cpp
    src/proxy_manager.cpp
    src/runtime_state.cpp
    src/singbox_config.cpp
    src/upstream.cpp
)

target_include_directories(tunproxy_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${TUNPROXY_GENERATED_INCLUDE_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_compile_features(tunproxy_core PUBLIC cxx_std_17)
target_compile_options(tunproxy_core PRIVATE ${TUNPROXY_WARNINGS})

add_executable(tunproxy src/main.cpp)
target_link_libraries(tunproxy PRIVATE tunproxy_core)
target_compile_features(tunproxy PRIVATE cxx_std_17)
target_compile_options(tunproxy PRIVATE ${TUNPROXY_WARNINGS})

add_executable(tunproxyd src/daemon_main.cpp)
target_link_libraries(tunproxyd PRIVATE tunproxy_core Threads::Threads)
target_compile_features(tunproxyd PRIVATE cxx_std_17)
target_compile_options(tunproxyd PRIVATE ${TUNPROXY_WARNINGS})

if(TUNPROXY_STATIC_CXX_RUNTIME AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_options(tunproxy PRIVATE -static-libstdc++ -static-libgcc)
    target_link_options(tunproxyd PRIVATE -static-libstdc++ -static-libgcc)
endif()

install(TARGETS tunproxy RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS tunproxyd RUNTIME DESTINATION lib/tunproxy)
install(FILES config.default DESTINATION ${CMAKE_INSTALL_DATADIR}/tunproxy)
install(FILES README.md THIRD_PARTY_NOTICES.md LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/tunproxy.8" DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)

if(TUNPROXY_BUILD_TESTS)
    enable_testing()

    add_executable(tunproxy_fake_core tests/fake_core.cpp)
    target_compile_features(tunproxy_fake_core PRIVATE cxx_std_17)
    target_compile_options(tunproxy_fake_core PRIVATE ${TUNPROXY_WARNINGS})

    file(GLOB TUNPROXY_TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/tests/test_*.cpp")
    add_executable(tunproxy_tests tests/main.cpp ${TUNPROXY_TEST_SOURCES})
    target_link_libraries(tunproxy_tests PRIVATE tunproxy_core Threads::Threads)
    target_compile_features(tunproxy_tests PRIVATE cxx_std_17)
    target_compile_options(tunproxy_tests PRIVATE ${TUNPROXY_WARNINGS})
    add_dependencies(tunproxy_tests tunproxy_fake_core)

    add_test(NAME tunproxy_tests COMMAND tunproxy_tests)
    set_tests_properties(tunproxy_tests PROPERTIES
        ENVIRONMENT "TUNPROXY_FAKE_CORE=$<TARGET_FILE:tunproxy_fake_core>")
endif()
