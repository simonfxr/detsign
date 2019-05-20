cmake_minimum_required(VERSION 3.5)

option(HUNTER_STATUS_DEBUG "Enable Hunter debug output" True)
#set(HUNTER_CONFIGURATION_TYPES Release CACHE STRING)
#option(HUNTER_BUILD_SHARED_LIBS "Build Hunter package shared libs" True)

include("cmake/HunterGate.cmake")

set(CMAKE_C_STANDARD 99)

huntergate(URL
           "https://github.com/ruslo/hunter/archive/v0.23.171.tar.gz"
           SHA1
           "5d68bcca78eee347239ca5f4d34f4b6c12683154"
           LOCAL)

project(detsign LANGUAGES C CXX)

#include("${CMAKE_SOURCE_DIR}/cmake/cmake-utils/cmake-utils.cmake")

# find_package(PkgConfig QUIET)

# if(PkgConfig_FOUND)
#   if(CMAKE_VERSION VERSION_GREATER 3.7)
#     pkg_check_modules(libsodium
#                       QUIET
#                       IMPORTED_TARGET
#                       libsodium>=1.0.12)
#     if(TARGET PkgConfig::libsodium)
#       set(libsodium_tgt PkgConfig::libsodium)
#     endif()
#   else()
#     pkg_check_modules(SODIUM QUIET libsodium>=1.0.12)
#     if(SODIUM_FOUND)
#       add_library(libsodium INTERFACE)
#       target_link_libraries(libsodium INTERFACE ${SODIUM_LIBRARIES})
#       target_include_directories(libsodium INTERFACE ${SODIUM_INCLUDE_DIRS})
#       target_compile_options(libsodium INTERFACE ${SODIUM_CFLAGS})
#       set(libsodium_tgt libsodium)
#     endif()
#   endif()
# endif()

if(NOT libsodium_tgt)
  hunter_add_package(libsodium)
  find_package(libsodium CONFIG REQUIRED)
  set(libsodium_tgt libsodium::libsodium)
endif()

add_subdirectory(deps/cxx-header-utils)

# if(CMU_COMP_MSVC)
#   list(APPEND CMU_DEFINES _CRT_SECURE_NO_WARNINGS=1)
# endif()

# cmu_configure()

# cmu_add_executable(detsign
#                    SOURCES
#                    detsign.c
#                    DEPEND
#                    ${libsodium_tgt}
#                    header-utils::header-utils)

add_executable(detsign detsign.c)
target_link_libraries(detsign ${libsodium_tgt} header-utils::header-utils)

find_package(PythonInterp 3.6 QUIET)

if(NOT PythonInterp_FOUND)
  message(WARNING "Python 3.6 or higher not found, cannot run tests")
else()
  enable_testing()

  add_test(NAME detsign-tests
           WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
           COMMAND "${PYTHON_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/test.py"
                   "${CMAKE_CURRENT_BINARY_DIR}/detsign")
endif()
