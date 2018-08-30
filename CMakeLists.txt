
cmake_minimum_required(VERSION 2.8.11)

project(detsign)

set(CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR} ${CMAKE_MODULE_PATH})

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
