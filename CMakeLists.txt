
cmake_minimum_required(VERSION 3.9)

project(detsign LANGUAGES C)

set(CMAKE_C_STANDARD 11)

find_package(PkgConfig REQUIRED)
pkg_check_modules(libsodium REQUIRED IMPORTED_TARGET libsodium)

add_executable(detsign detsign.c)
target_link_libraries(detsign PkgConfig::libsodium)
