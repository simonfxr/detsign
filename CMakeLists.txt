cmake_minimum_required(VERSION 3.9)

project(detsign)

set(CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR} ${CMAKE_MODULE_PATH})
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED TRUE)

# message(STATUS "MSVC_TOOLSET_VERSION=${MSVC_TOOLSET_VERSION}")

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake/Modules")

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
  if(MSVC)
    set(libsodium_download_suf "-msvc.zip")
    set(libsodium_download_sha1 "ba5dff90cfa2540a11d09afd8488a8fc8e543f71")
  else()
    set(libsodium_download_suf "-mingw.tar.gz")
    set(libsodium_download_sha1 "22fb52e54f611095978424bd57a4a939e3ac859d")
  endif()
else()
  set(libsodium_download_suf ".tar.gz")
  set(libsodium_download_sha1 "c7ea321d7b8534e51c5e3d86055f6c1aa1e48ee9")
endif()

set(sodium_USE_STATIC_LIBS True CACHE BOOL "" FORCE)
find_package(sodium QUIET)

if(NOT sodium_FOUND)
  message(WARNING "fetching libsodium")

  include(FetchContent)

  fetchcontent_declare(
    libsodium
    URL
    "https://download.libsodium.org/libsodium/releases/libsodium-1.0.16${libsodium_download_suf}"
    URL_HASH
    "SHA1=${libsodium_download_sha1}")

  fetchcontent_populate(libsodium)

  set(sodium_DIR "${libsodium_SOURCE_DIR}" CACHE FILEPATH "" FORCE)
  find_package(sodium REQUIRED)
endif()

set(libsodium_tgt sodium)

# if(TARGET libsodium::libsodium) set(libsodium_tgt libsodium::libsodium)
# elseif(CMAKE_SYSTEM_NAME MATCHES "Windows") add_library(ext-libsodium
# INTERFACE) set(libsodium_dir "${PROJECT_SOURCE_DIR}/external/win-msvc-
# libsodium") target_include_directories(ext-libsodium INTERFACE
# "${libsodium_dir}/include") set(libsodium_tgt ext-libsodium) message(STATUS
# "libsodium_dir=${libsodium_dir}") if(CMAKE_SIZEOF_VOID_P EQUAL 4)
# set(sodium_libdir "Win32") else() set(sodium_libdir "x64") endif()
# #set(sodium_libdir "${sodium_libdir}/$<IF:$<CONFIG:DEBUG>,Debug,Release>")
# if(CMAKE_BUILD_TYPE STREQUAL "Debug") set(sodium_libdir
# "${sodium_libdir}/Debug") else() set(sodium_libdir "${sodium_libdir}/Release")
# endif() set(sodium_libdir
# "${libsodium_dir}/${sodium_libdir}/v${MSVC_TOOLSET_VERSION}/dynamic")
# message(STATUS "sodium_libdir=${sodium_libdir}") file(GLOB sodium_libfiles
# "${sodium_libdir}/*") message(STATUS "sodum_libfiles=${sodium_libfiles}")
# file(COPY ${sodium_libfiles} DESTINATION "${CMAKE_BINARY_DIR}")
# target_link_libraries(ext-libsodium INTERFACE
# "${sodium_libdir}/libsodium.lib") # target_compile_definitions(ext-libsodium #
# INTERFACE "SODIUM_STATIC=1") else() find_package(PkgConfig REQUIRED)
# pkg_check_modules(libsodium REQUIRED IMPORTED_TARGET libsodium)
# set(libsodium_tgt PkgConfig::libsodium) endif()

if(NOT TARGET header-utils::header-utils)
  add_subdirectory(deps/cxx-header-utils)
endif()

set(cflags)
if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU|Intel")
  list(APPEND cflags -Wall -Wextra)
elseif(CMAKE_C_COMPILER_ID MATCHES "MSVC")
  list(APPEND cflags "/W3")
endif()

if(CMAKE_C_COMPILER_ID MATCHES "Intel")
  list(APPEND cflags -diag-disable=11074,11076)
endif()

add_executable(detsign detsign.c)
target_link_libraries(detsign ${libsodium_tgt} header-utils::header-utils)
target_compile_options(detsign PRIVATE ${cflags})
if(CMAKE_C_COMPILER_ID MATCHES "MSVC")
  target_compile_definitions(detsign PRIVATE _CRT_SECURE_NO_WARNINGS=1)
endif()
