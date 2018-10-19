
cmake_minimum_required(VERSION 3.1)

project(detsign)

set(CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR} ${CMAKE_MODULE_PATH})
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

message(STATUS "MSVC_TOOLSET_VERSION=${MSVC_TOOLSET_VERSION}")

find_package(libsodium QUIET)
if(TARGET libsodium::libsodium)
  set(libsodium_tgt libsodium::libsodium)
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
  add_library(ext-libsodium INTERFACE)
  set(libsodium_dir "${PROJECT_SOURCE_DIR}/external/win-msvc-libsodium")
  target_include_directories(ext-libsodium
    INTERFACE "${libsodium_dir}/include")
  set(libsodium_tgt ext-libsodium)
  message(STATUS "libsodium_dir=${libsodium_dir}")
  if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    set(sodium_libdir "Win32")
  else()
    set(sodium_libdir "x64")
  endif()
  #set(sodium_libdir "${sodium_libdir}/$<IF:$<CONFIG:DEBUG>,Debug,Release>")
  if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(sodium_libdir "${sodium_libdir}/Debug")
  else()
    set(sodium_libdir "${sodium_libdir}/Release")
  endif()
  set(sodium_libdir "${libsodium_dir}/${sodium_libdir}/v${MSVC_TOOLSET_VERSION}/dynamic")
  message(STATUS "sodium_libdir=${sodium_libdir}")
  file(GLOB sodium_libfiles "${sodium_libdir}/*")
  message(STATUS "sodum_libfiles=${sodium_libfiles}")
  file(COPY ${sodium_libfiles} DESTINATION "${CMAKE_BINARY_DIR}")
  target_link_libraries(ext-libsodium
    INTERFACE "${sodium_libdir}/libsodium.lib")
  # target_compile_definitions(ext-libsodium
  #   INTERFACE "SODIUM_STATIC=1")
else()
  find_package(PkgConfig REQUIRED)
  pkg_check_modules(libsodium REQUIRED IMPORTED_TARGET libsodium)
  set(libsodium_tgt PkgConfig::libsodium)
endif()

# find_program(
#   CLANG_TIDY_EXE
#   NAMES "clang-tidy"
#   DOC "Path to clang-tidy executable")

add_executable(detsign detsign.c)
target_link_libraries(detsign ${libsodium_tgt})
if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
    target_compile_definitions(detsign PRIVATE
        _CRT_SECURE_NO_WARNINGS=1)
endif()

# if(CLANG_TIDY_EXE)
#   set_target_properties(detsign PROPERTIES
#     C_CLANG_TIDY ${CLANG_TIDY_EXE})
# endif()
