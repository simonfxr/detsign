# Sets the following variables:
#
# Architecture:
# - CMU_ARCH_ARM
# - CMU_ARCH_AVR
# - CMU_ARCH_EMSCRIPTEN
# - CMU_ARCH_MIPS
# - CMU_ARCH_MSP430
# - CMU_ARCH_PPC
# - CMU_ARCH_RISCV
# - CMU_ARCH_X86
#
# (Pointer) Bitness:
# - CMU_BITS_{16,32,64,128}
#
# OS Families:
# - CMU_OS_POSIX
# - CMU_OS_BSD
# - CMU_OS_APPLE
#
# Specific OS:
# - CMU_OS_ANDROID
# - CMU_OS_DRAGONFLY
# - CMU_OS_EMSCRIPTEN
# - CMU_OS_FREEBSD
# - CMU_OS_IOS
# - CMU_OS_LINUX
# - CMU_OS_NETBSD
# - CMU_OS_OPENBSD
# - CMU_OS_OSX
# - CMU_OS_SOLARIS
# - CMU_OS_FREESTANDING
# - CMU_OS_UNKNOWN
# - CMU_OS_WINDOWS
#
# Compilers:
# - CMU_COMP_CLANG
# - CMU_COMP_COMPCERT
# - CMU_COMP_GCC
# - CMU_COMP_GNUC
# - CMU_COMP_IBMXL
# - CMU_COMP_INTEL
# - CMU_COMP_MSVC
# - CMU_COMP_UNKNOWN
# - CMU_COMP_ZAPCC
#
# Endianess:
# - CMU_LITTLE_ENDIAN
# - CMU_BIG_ENDIAN
#
# Other:
# - CMU_BUILD_TYPE: uppercase version of CMAKE_BUILD_TYPE
# - CMU_SIZEOF_VOID_P
# - CMU_LANG_C
# - CMU_LANG_CXX

if(COMMAND include_guard)
  include_guard(GLOBAL)
endif()

set(CMU_SIZEOF_VOID_P "${CMAKE_SIZEOF_VOID_P}")

if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|amd64|AMD64|(^i.86$)")
  set(CMU_LITTLE_ENDIAN True)
  if(CMAKE_SYSTEM_NAME MATCHES "Emscripten")
    set(CMU_ARCH_EMSCRIPTEN True)
    if(NOT CMU_SIZEOF_VOID_P)
      set(CMU_SIZEOF_VOID_P 4)
    endif()
  else()
    set(CMU_ARCH_X86 True)
  endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|^arm")
  set(CMU_ARCH_ARM True)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "riscv")
  set(CMU_LITTLE_ENDIAN True)
  set(CMU_ARCH_RISCV True)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "ppc|powerpc")
  set(CMU_ARCH_PPC True)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "mips")
  set(CMU_ARCH_MIPS True)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "msp430")
  set(CMU_LITTLE_ENDIAN True)
  set(CMU_ARCH_MSP430 True)
  if(NOT CMU_SIZEOF_VOID_P)
    set(CMU_SIZEOF_VOID_P 2)
  endif()
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "avr")
  set(CMU_LITTLE_ENDIAN True)
  set(CMU_ARCH_AVR True)
  if(NOT CMU_SIZEOF_VOID_P)
    set(CMU_SIZEOF_VOID_P 2)
  endif()
else()
  message(
    ERROR
    "Unsupported architecture: CMAKE_SYSTEM_PROCESSOR=${CMAKE_SYSTEM_PROCESSOR}"
    )
endif()

if(NOT (CMU_LITTLE_ENDIAN OR CMU_BIG_ENDIAN))
  include(TestBigEndian)
  test_big_endian(cmu_test_big_endian_result)
  if(cmu_test_big_endian_result)
    set(CMU_BIG_ENDIAN True)
  else()
    set(CMU_LITTLE_ENDIAN True)
  endif()
endif()

if(UNIX)
  set(CMU_OS_POSIX True)
endif()

if(WIN32)
  set(CMU_OS_WINDOWS True)
elseif(Apple)
  set(CMU_OS_APPLE True)
  set(CMU_OS_POSIX True)
  if(CMAKE_SYSTEM_NAME STREQUAL "iOS" OR IOS)
    set(CMU_OS_IOS True)
  else()
    set(CMU_OS_OSX True)
  endif()
elseif(CMAKE_SYSTEM_NAME MATCHES "Emscripten")
  set(CMU_OS_EMSCRIPTEN True)
elseif(CMAKE_SYSTEM_NAME MATCHES "Linux")
  set(CMU_OS_LINUX True)
  set(CMU_OS_POSIX True)
elseif(CMAKE_SYSTEM_NAME MATCHES "FreeBSD")
  set(CMU_OS_POSIX True)
  set(CMU_OS_BSD True)
  set(CMU_OS_FREEBSD True)
elseif(CMAKE_SYSTEM_NAME MATCHES "OpenBSD")
  set(CMU_OS_POSIX True)
  set(CMU_OS_BSD True)
  set(CMU_OS_OPENBSD True)
elseif(CMAKE_SYSTEM_NAME MATCHES "DragonFly")
  set(CMU_OS_POSIX True)
  set(CMU_OS_BSD True)
  set(CMU_OS_DRAGONFLY True)
elseif(CMAKE_SYSTEM_NAME MATCHES "NetBSD")
  set(CMU_OS_POSIX True)
  set(CMU_OS_BSD True)
  set(CMU_OS_NETBSD True)
elseif(CMAKE_SYSTEM_NAME MATCHES "SunOS|Solaris")
  set(CMU_OS_POSIX True)
  set(CMU_OS_SOLARIS True)
elseif(CMAKE_SYSTEM_NAME MATCHES Generic)
  if(CMU_ARCH_AVR OR CMU_ARCH_MSP430)
    set(CMU_OS_FREESTANDING)
  else()
    set(CMU_OS_UNKNOWN True)
  endif()
else()
  set(CMU_OS_UNKNOWN True)
endif()

get_property(languages GLOBAL PROPERTY ENABLED_LANGUAGES)
foreach(lang ${languages})
  if(lang STREQUAL "CXX")
    set(CMU_LANG_CXX True)
  elseif(lang STREQUAL "C")
    set(CMU_LANG_C True)
  endif()
endforeach()

if(NOT (CMU_LANG_C OR CMU_LANG_CXX))
  message(FATAL_ERROR "Neither C nor C++ is enabled")
endif()

if(CMU_LANG_CXX)
  set(comp_id "${CMAKE_CXX_COMPILER_ID}")
  set(comp_name "${CMAKE_CXX_COMPILER}")
  set(comp_version "${CMAKE_CXX_COMPILER_VERSION}")
else()
  set(comp_id "${CMAKE_C_COMPILER_ID}")
  set(comp_name "${CMAKE_C_COMPILER}")
  set(comp_version "${CMAKE_C_COMPILER_VERSION}")
endif()

if(CMU_LANG_CXX AND CMU_LANG_C)
  if(NOT (CMAKE_C_COMPILER_ID STREQUAL CMAKE_CXX_COMPILER_ID))
    message(
      FATAL_ERROR
        "C and C++ compilers inconsistent: ${CMAKE_C_COMPILER_ID} vs. ${CMAKE_CXX_COMPILER_ID}"
      )
  endif()
endif()

message(STATUS "comp_id=${comp_id}")
message(STATUS "comp_name=${comp_name}")
message(STATUS "comp_version=${comp_version}")

if(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
  set(CMU_COMP_GNUC True)
endif()

set(CMU_COMP_CLANG_VERSION 0)
set(CMU_COMP_COMPCERT_VERSION 0)
set(CMU_COMP_GCC_VERSION 0)
set(CMU_COMP_GNUC_VERSION 0)
set(CMU_COMP_IBMXL_VERSION 0)
set(CMU_COMP_INTEL_VERSION 0)
set(CMU_COMP_MSVC_VERSION 0)
set(CMU_COMP_ZAPCC_VERSION 0)

if(comp_id MATCHES "clang-cl")
  set(CMU_COMP_CLANG True)
  set(CMU_COMP_MSVC True)
  set(CMU_COMP_GNUC True)
elseif(MSVC OR MSVC_IDE OR CMAKE_COMPILER_2005 OR comp_id STREQUAL "MSVC")
  set(CMU_COMP_MSVC True)
  if(NOT comp_version)
    message(FATAL_ERROR "Failed to detect MSVC version")
  endif()
  set(CMU_COMP_MSVC_VERSION "${comp_version}")
elseif(comp_name MATCHES "zapcc[+]?[+]?")
  set(CMU_COMP_ZAPCC True)
  set(CMU_COMP_CLANG True)
  set(CMU_COMP_GNUC True)
  if(NOT comp_version)
    message(FATAL_ERROR "Failed to detect zapcc version")
  endif()
  set(CMU_COMP_CLANG_VERSION "${comp_version}")
  set(CMU_COMP_ZAPCC_VERSION "${comp_version}")
  set(CMU_COMP_GNUC_VERSION 4.2.1)
elseif(comp_name MATCHES "clang[+]?[+]?" OR comp_id STREQUAL "Clang")
  set(CMU_COMP_CLANG True)
  set(CMU_COMP_GNUC True)
  if(NOT comp_version)
    message(FATAL_ERROR "Failed to detect clang version")
  endif()
  set(CMU_COMP_CLANG_VERSION "${comp_version}")
  set(CMU_COMP_GNUC_VERSION 4.2.1)
elseif(comp_name MATCHES "icp?c" OR comp_id STREQUAL "Intel")
  set(CMU_COMP_INTEL True)
  set(CMU_COMP_GNUC True)
  if(NOT comp_version)
    #FIXME: detect __GNUC__, __GNUC_MINOR__...
    message(FATAL_ERROR "Failed to detect intel compiler version")
  endif()
  set(CMU_COMP_INTEL_VERSION "${comp_version}")
  # set(CMU_COMP_GNUC_VERSION 4.2.1)
elseif(comp_id STREQUAL "GNU")
  set(CMU_COMP_GCC True)
  set(CMU_COMP_GNUC True)
  if(NOT comp_version)
    message(FATAL_ERROR "Failed to detect gcc version")
  endif()
  set(CMU_COMP_GCC_VERSION "${comp_version}")
  set(CMU_COMP_GNUC_VERSION "${comp_version}")
elseif(comp_name MATCHES "ccomp")
  set(CMU_COMP_COMPCERT True)
  #FIXME: detect compiler version
elseif(comp_id STREQUAL "XL")
  set(CMU_COMP_IBMXL True)
  set(CMU_COMP_GNUC True)
  if(NOT comp_version)
    message(FATAL_ERROR "Failed to detect IBM XL version")
  endif()
  set(CMU_IBMXL_VERSION "${comp_version}")
else()
  set(CMU_COMP_UNKNOWN True)
endif()

if(CMU_SIZEOF_VOID_P EQUAL 2)
  set(CMU_BITS_16 True)
elseif(CMU_SIZEOF_VOID_P EQUAL 4)
  set(CMU_BITS_32 True)
elseif(CMU_SIZEOF_VOID_P EQUAL 8)
  set(CMU_BITS_64 True)
elseif(CMU_SIZEOF_VOID_P EQUAL 16)
  set(CMU_BITS_128 True)
else()
  message(FATAL_ERROR "Failed to detect bitness of architecture")
endif()

string(TOUPPER "${CMAKE_BUILD_TYPE}" CMU_BUILD_TYPE)

if(CMU_BUILD_TYPE STREQUAL DEBUG)
  set(CMU_BUILD_DEBUG True)
elseif(CMU_BUILD_TYPE STREQUAL RELWITHDEBINFO)
  set(CMU_BUILD_OPT True)
  set(CMU_BUILD_DEBUG True)
elseif(CMU_BUILD_TYPE STREQUAL RELEASE OR BUILD_TYPE STREQUAL MINSIZEREL)
  set(CMU_BUILD_OPT True)
else()
  message(WARNING "unknown build type: \"${CMAKE_BUILD_TYPE}\"")
endif()
