cmake_minimum_required(VERSION 3.16)

project(tunproxy VERSION 0.2.0 LANGUAGES CXX)

include(GNUInstallDirs)

option(TUNPROXY_BUILD_TESTS "Build unit tests" ON)
option(TUNPROXY_STATIC_CXX_RUNTIME "Statically link libstdc++ and libgcc" OFF)

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)

add_library(tunproxy_core
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
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_compile_features(tunproxy_core PUBLIC cxx_std_17)
target_compile_options(tunproxy_core PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>
)

add_executable(tunproxy src/main.cpp)
target_link_libraries(tunproxy PRIVATE tunproxy_core)
target_compile_features(tunproxy PRIVATE cxx_std_17)

add_executable(tunproxyd src/daemon_main.cpp)
target_link_libraries(tunproxyd PRIVATE tunproxy_core Threads::Threads)
target_compile_features(tunproxyd PRIVATE cxx_std_17)
target_compile_options(tunproxyd PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall;-Wextra;-Wpedantic;-Wconversion;-Wshadow>
)
if(TUNPROXY_STATIC_CXX_RUNTIME AND CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_link_options(tunproxy PRIVATE -static-libstdc++ -static-libgcc)
    target_link_options(tunproxyd PRIVATE -static-libstdc++ -static-libgcc)
endif()

install(TARGETS tunproxy RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(TARGETS tunproxyd RUNTIME DESTINATION lib/tunproxy)
install(FILES config.default DESTINATION ${CMAKE_INSTALL_DATADIR}/tunproxy)
install(FILES README.md THIRD_PARTY_NOTICES.md LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES docs/tunproxy.8 DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)

if(TUNPROXY_BUILD_TESTS)
    enable_testing()
    add_executable(tunproxy_tests tests/core_tests.cpp)
    target_link_libraries(tunproxy_tests PRIVATE tunproxy_core Threads::Threads)
    target_compile_features(tunproxy_tests PRIVATE cxx_std_17)
    target_compile_options(tunproxy_tests PRIVATE
        $<$<CXX_COMPILER_ID:GNU,Clang>:-UNDEBUG>
    )
    add_test(NAME tunproxy_tests COMMAND tunproxy_tests)
endif()
