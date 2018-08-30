
cmake_minimum_required(VERSION 3.1)

project(detsign)

set(CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR} ${CMAKE_MODULE_PATH})
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

find_package(libsodium QUIET)
if(TARGET libsodium::libsodium)
  set(libsodium_tgt libsodium::libsodium)
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(libsodium REQUIRED IMPORTED_TARGET libsodium)
  set(libsodium_tgt PkgConfig::libsodium)
endif()

add_executable(detsign detsign.c)
target_link_libraries(detsign ${libsodium_tgt})
