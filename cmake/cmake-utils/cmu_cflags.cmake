if(COMMAND include_guard)
  include_guard(GLOBAL)
endif()

if(CMU_BUILD_OPT)
  set(CMU_OPT_LEVEL 2)
  set(CMU_OPT_NATIVE True)
  set(CMU_IPO True)
else()
  set(CMU_OPT_LEVEL 0)
  set(CMU_OPT_NATIVE False)
  set(CMU_IPO False)
endif()

set(CMU_PREFERRED_LINKERS lld gold)
set(CMU_PIC True)
set(CMU_SANITIZERS)
set(CMU_WARN_LEVEL 4)
set(CMU_WARN_DATE_TIME True)
set(CMU_FP_MODE IEEE)
set(CMU_PREFERRED_CXX_STDLIB libc++ libstdc++)
set(CMU_THREADS False)
set(CMU_NO_EXCEPTIONS False)
set(CMU_NO_RTTI False)
set(CMU_FORTIFY_SOURCE 2)
set(CMU_STACK_PROTECTION True)
set(CMU_EAGER_LOADING True)
set(CMU_STRICT_LINKING True)
set(CMU_RELRO True)
set(CMU_CFI True)

set(CMU_GLIBCXX_SANITIZE_VECTOR False)
set(CMU_GLIBCXX_DEBUG False)
set(CMU_GLIBCXX_DEBUG_PEDANTIC False)
set(CMU_LIBCPP_ABI_VERSION 2)
set(CMU_LIBCPP_ENABLE_NODISCARD True)
set(CMU_LIBCPP_DEBUG False)

if(CMU_BUILD_DEBUG)
  set(CMU_GLIBCXX_SANITIZE_VECTOR True)
  set(CMU_GLIBCXX_DEBUG True)
  set(CMU_GLIBCXX_DEBUG_PEDANTIC True)
  set(CMU_LIBCPP_DEBUG True)
  set(CMU_SANITIZERS ubsan)
endif()

set(CMU_FLAGS)
set(CMU_C_FLAGS)
set(CMU_CXX_FLAGS)
set(CMU_DEFINES)
set(CMU_FLAGS_BOTH)
set(CMU_LINK_FLAGS)

set(CMU_FLAGS_O0)
set(CMU_FLAGS_O1)
set(CMU_FLAGS_O2)
set(CMU_FLAGS_O3)
set(CMU_FLAGS_OPT_NATIVE)

set(CMU_FLAGS_FP_IEEE)
set(CMU_FLAGS_FP_FAST)
set(CMU_FLAGS_FP_ASSOC)
set(CMU_FLAGS_FP_FINITE)

set(CMU_FLAGS_CFI)

set(CMU_FLAGS_EAGER_LOADING)
set(CMU_FLAGS_STRICT_LINKING)
set(CMU_FLAGS_RELRO)

set(CMU_FLAGS_NO_EXCEPTIONS)
set(CMU_FLAGS_NO_RTTI)

set(CMU_FLAGS_W0)
set(CMU_FLAGS_W1)
set(CMU_FLAGS_W2)
set(CMU_FLAGS_W3)
set(CMU_FLAGS_W4)
set(CMU_FLAGS_WARN_DATE_TIME)

if(CMU_COMP_MSVC)

  set(CMU_FLAGS_O1 /O)
  set(CMU_FLAGS_O2 /O2)
  set(CMU_FLAGS_O3 /Ox /O2 /Ob3)
  set(CMU_FLAGS_FP_IEEE /fp:precise)
  set(CMU_FLAGS_FP_FAST /fp:precise)
  set(CMU_FLAGS_FP_ASSOC /fp:precise)
  set(CMU_FLAGS_FP_FINITE /fp:fast)
  set(CMU_FLAGS_CFI /guard:cf)
  set(CMU_FLAGS_NO_EXCEPTIONS "/EHs-")
  set(CMU_FLAGS_NO_RTTI "/GR-")
  set(CMU_FLAGS_W1 /W1)
  set(CMU_FLAGS_W2 /W2)
  set(CMU_FLAGS_W3 /W3)
  set(CMU_FLAGS_W4 /W4)

elseif(CMU_COMP_GNUC)
  set(CMU_FLAGS_O1 -O1)
  set(CMU_FLAGS_O2 -O2)
  set(CMU_FLAGS_O3 -O3)

  cmu_add_flag_if_available("-march=native" CMU_HAVE_MARCH_NATIVE
                            CMU_FLAGS_OPT_NATIVE)

  cmu_add_flag_if_available("-fcf-protection" CMU_HAVE_CF_PROTECTION
                            CMU_FLAGS_CFI)

  if(CMU_OS_POSIX)
    set(CMU_FLAGS_STRICT_LINKING "-Wl,-z,defs")
    set(CMU_FLAGS_EAGER_LOADING "-Wl,-z,now")
    set(CMU_FLAGS_RELRO "-Wl,-z,relro")
  endif()

  if(CMU_COMP_INTEL)
    if(CMU_OS_WINDOWS)
      set(CMU_FLAGS_O1 /O1)
      set(CMU_FLAGS_O2 /O2)
      set(CMU_FLAGS_O3 /O3 /Qipo)
      set(CMU_FLAGS_OPT_NATIVE /QxHost)
    else()
      set(CMU_FLAGS_O3 -ipo -O3)
      set(CMU_FLAGS_OPT_NATIVE -xHost)
    endif()
  endif()

  set(CMU_FLAGS_FP_IEEE)
  cmu_add_flag_if_available("-fexcess-precision=standard"
                            CMU_HAVE_FP_NO_EXCESS_PRECISION CMU_FLAGS_FP_IEEE)
  cmu_add_flag_if_available("-fno-fast-math" CMU_HAVE_FNO_FAST_MATH
                            CMU_FLAGS_FP_IEEE)
  cmu_add_flag_if_available("-ffp-contract=off" CMU_HAVE_FNO_FFP_CONTRACT
                            CMU_FLAGS_FP_IEEE)

  set(CMU_FLAGS_FP_FAST
      -ffp-contract=fast
      -fno-math-errno
      -fexcess-precision=fast
      -fcx-limited-range
      -fno-trapping-math)
  set(CMU_FLAGS_FP_ASSOC ${CMU_FLAGS_FP_FAST} -funsafe-math-optimizations)
  set(CMU_FLAGS_FP_FINITE -ffast-math)

  set(CMU_FLAGS_NO_EXCEPTIONS "-fno-exceptions")
  set(CMU_FLAGS_NO_RTTI "-fno-rtti")

  set(CMU_FLAGS_W1 -Wall -Werror=return-type
                   -Werror=implicit-function-declaration)
  set(CMU_FLAGS_W2 ${CMU_FLAGS_W1} -Wextra)

  cmu_check_compiler_flag("-Wdate-time" CMU_HAVE_WARN_DATE_TIME)
  if(CMU_HAVE_WARN_DATE_TIME)
    set(CMU_FLAGS_WARN_DATE_TIME -Wdate-time -Werror=date-time)
  endif()

  if(CMU_COMP_INTEL)
    list(APPEND CMU_FLAGS_W2 -Wcheck)
  endif()

  set(CMU_FLAGS_W3 ${CMU_FLAGS_W2} -Wswitch)

  if(CMU_COMP_GCC)
    list(APPEND CMU_FLAGS_W3
                -Wcast-align
                -Wcast-qual
                -Wchar-subscripts
                -Wcomment
                -Wdisabled-optimization
                -Wformat
                -Wformat-nonliteral
                -Wformat-security
                -Wformat-y2k
                -Wformat=2
                -Wimport
                -Winit-self
                -Winline
                -Winvalid-pch
                -Wmissing-field-initializers
                -Wmissing-format-attribute
                -Wmissing-include-dirs
                -Wmissing-noreturn
                -Wparentheses
                -Wpointer-arith
                -Wredundant-decls
                -Wreturn-type
                -Wsequence-point
                -Wsign-compare
                -Wstack-protector
                -Wstrict-aliasing
                -Wswitch
                -Wswitch-enum
                -Wtrigraphs
                -Wuninitialized
                -Wunknown-pragmas
                -Wunreachable-code
                -Wunsafe-loop-optimizations
                -Wunused
                -Wunused-function
                -Wunused-label
                -Wunused-parameter
                -Wunused-value
                -Wunused-variable
                -Wvariadic-macros
                -Wvolatile-register-var
                -Wwrite-strings)
  elseif(CMU_COMP_INTEL)
    list(APPEND CMU_FLAGS_W3
                -Wcast-qual
                -Wchar-subscripts
                -Wcomment
                -Wdisabled-optimization
                -Wformat
                -Wformat-security
                -Wformat=2
                -Winit-self
                -Winline
                -Winvalid-pch
                -Wmissing-field-initializers
                -Wmissing-include-dirs
                -Wparentheses
                -Wpointer-arith
                -Wreturn-type
                -Wsequence-point
                -Wsign-compare
                -Wstrict-aliasing
                -Wswitch
                -Wswitch-enum
                -Wtrigraphs
                -Wuninitialized
                -Wunknown-pragmas
                -Wunreachable-code
                -Wunused
                -Wunused-function
                -Wunused-parameter
                -Wunused-variable
                -Wwrite-strings)
  elseif(CMU_COMP_CLANG)
    list(APPEND CMU_FLAGS_W3
                -Weverything
                -Wno-c++98-compat
                -Wno-c++98-compat-pedantic
                -Wno-conversion
                -Wno-documentation
                -Wno-documentation-unknown-command
                -Wno-double-promotion
                -Wno-float-equal
                -Wno-gnu-anonymous-struct
                -Wno-gnu-zero-variadic-macro-arguments
                -Wno-missing-noreturn
                -Wno-missing-prototypes
                -Wno-nested-anon-types
                -Wno-packed
                -Wno-padded
                -Wno-gnu-statement-expression
                -Wno-assume
                -Wno-disabled-macro-expansion
                -Wno-return-std-move-in-c++11)
  endif()
  set(CMU_FLAGS_W4 "${CMU_FLAGS_W3}")
endif()

macro(cmu_replace_global_cmake_flags pat repl)
  set(types ${CMAKE_CONFIGURATION_TYPES})
  if(NOT types)
    set(types
        DEBUG
        RELEASE
        RELWITHDEBINFO
        MINSIZEREL)
  endif()

  foreach(ty "" ${types})
    if(ty)
      set(ty "_${ty}")
    endif()
    foreach(pref
            ""
            _C_FLAGS
            _CXX_FLAGS)
      set(v "CMAKE${pref}${ty}")
      if(DEFINED "${v}")
        string(REGEX
               REPLACE "${pat}"
                       "${repl}"
                       "${v}"
                       "${${v}}")
      endif()
    endforeach()
  endforeach()
endmacro()

macro(cmu_add_global_cmake_linker_flags)
  set(types ${CMAKE_CONFIGURATION_TYPES})
  if(NOT types)
    set(types
        DEBUG
        RELEASE
        RELWITHDEBINFO
        MINSIZEREL)
  endif()

  foreach(ty "" ${types})
    if(ty)
      set(ty "_${ty}")
    endif()
    foreach(kind
            EXE
            SHARED
            STATIC
            MODULE)
      set(v "CMAKE_${kind}_LINKER_FLAGS${ty}")
      list(APPEND "${v}" ${ARGN})
    endforeach()
  endforeach()
endmacro()

macro(cmu_enable_sanitizers)
  set(need_no_omit_fp False)
  foreach(san ${ARGV})
    if(san STREQUAL "asan")
      cmu_add_flag_if_available(-fsanitize=address CMU_HAVE_ASAN CMU_FLAGS_BOTH)
    elseif(san STREQUAL "ubsan")
      cmu_add_flag_if_available(-fsanitize=undefined CMU_HAVE_UBSAN
                                CMU_FLAGS_BOTH)
    elseif(san STREQUAL "tsan")
      cmu_add_flag_if_available(-fsanitize=thread CMU_HAVE_TSAN CMU_FLAGS_BOTH)
    elseif(san STREQUAL "lsan")
      cmu_add_flag_if_available(-fsanitize=leak CMU_HAVE_LSAN CMU_FLAGS_BOTH)
    else()
      message(WARNING "unknown sanitizer: \"${san}\"")
    endif()
  endforeach()
  if(CMU_HAVE_ASAN OR CMU_HAVE_UBSAN OR CMU_HAVE_TSAN OR CMU_HAVE_LSAN)
    list(APPEND CMU_FLAGS "-fno-omit-frame-pointer")
  endif()
endmacro()

macro(cmu_add_global_cmake_flags flags)
  set(types ${CMAKE_CONFIGURATION_TYPES})
  if(NOT types)
    set(types
        DEBUG
        RELEASE
        RELWITHDEBINFO
        MINSIZEREL)
  endif()

  foreach(ty "" ${types})
    if(ty)
      set(ty "_${ty}")
    endif()
    foreach(pref
            ""
            _C_FLAGS
            _CXX_FLAGS)
      set(v "CMAKE${pref}${ty}")
      if(DEFINED ${v})
        set($v "${${v}} ${flags}")
        message(STATUS "${v}=${${v}}")
      endif()
    endforeach()
  endforeach()
endmacro()

macro(cmu_configure_preferred_linkers)
  set(CMU_LINKER)
  foreach(ld ${ARGV})
    if(NOT (ld MATCHES "^(gold|lld|bfd)$"))
      message(WARNING "Ignoring unknown linker: ${ld}")
    elseif(NOT CMU_LINKER AND CMU_COMP_CLANG)
      list(APPEND CMU_LINK_FLAGS "-fuse-ld=${ld}")
      set(CMU_LINKER ${ld})
    elseif(NOT CMU_LINKER AND CMU_COMP_GNUC)
      cmu_add_flag_if_available("-fuse-ld=${ld}" "CMU_HAVE_LD_${ld}"
                                CMU_LINK_FLAGS)
      if(CMU_HAVE_LD_${ld})
        set(CMU_LINKER ${ld})
      endif()
    endif()
  endforeach()
endmacro()

macro(cmu_configure_preferred_cxx_stdlib)
  set(CMU_CXX_STDLIB)
  foreach(stdlib ${ARGV})
    if(stdlib STREQUAL "libc++")
      if(CMU_LANG_CXX AND CMU_COMP_CLANG)
        list(APPEND CMU_CXX_FLAGS -stdlib=libc++)
        list(APPEND CMU_LINK_FLAGS -stdlib=libc++)
        set(CMU_CXX_STDLIB libc++)
      endif()
    elseif(stdlib STREQUAL "libstdc++")
      if(CMU_LANG_CXX AND CMU_COMP_GNUC)
        set(CMU_CXX_STDLIB libstdc++)
      endif()
    else()
      message(WARNING "Ignoring unknown C++ standard library: ${stdlib}")
    endif()
  endforeach()
endmacro()

macro(cmu_configure)

  list(APPEND CMU_FLAGS ${CMU_FLAGS_O${CMU_OPT_LEVEL}})
  if(CMU_OPT_NATIVE)
    list(APPEND CMU_FLAGS ${CMU_FLAGS_OPT_NATIVE})
  endif()

  if(CMU_IPO)
    find_package(CheckIPOSupported QUIET)
    if(CheckIPOSupported_FOUND)
      check_ipo_supported(RESULT CMU_IPO)
    else()
      unset(CMU_IPO)
    endif()
  endif()

  cmu_configure_preferred_linkers(${CMU_PREFERRED_LINKERS})

  if(CMU_PIC)
    set(CMAKE_POSITION_INDEPENDENT_CODE True)
  else()
    set(CMAKE_POSITION_INDEPENDENT_CODE False)
  endif()

  cmu_enable_sanitizers(${CMU_SANITIZERS})

  list(APPEND CMU_FLAGS ${CMU_FLAGS_W${CMU_WARN_LEVEL}})
  if(CMU_WARN_DATE_TIME)
    list(APPEND CMU_FLAGS ${CMU_FLAGS_WARN_DATE_TIME})
  endif()

  list(APPEND CMU_FLAGS ${CMU_FLAGS_FP_${CMU_FP_MODE}})
  if(CMU_LANG_CXX)
    cmu_configure_preferred_cxx_stdlib(${CMU_PREFERRED_CXX_STDLIB})
  endif()

  if(CMU_THREADS)
    set(CMAKE_THREAD_PREFER_PTHREAD True)
    set(THREADS_PREFER_PTHREAD_FLAG True)
    find_package(Threads REQUIRED)
  endif()

  if(CMU_NO_EXCEPTIONS)
    list(APPEND CMU_FLAGS ${CMU_FLAGS_NO_EXCEPTIONS})
  endif()

  if(CMU_LANG_CXX AND CMU_NO_RTTI)
    list(APPEND CMU_FLAGS ${CMU_FLAGS_NO_RTTI})
  endif()

  if(CMU_FORTIFY_SOURCE GREATER 0 AND CMU_OPT_LEVEL GREATER 0)
    list(APPEND CMU_DEFINES "_FORTIFY_SOURCE=${CMU_FORTIFY_SOURCE}")
  endif()

  if(CMU_CFI)
    list(APPEND CMU_FLAGS_BOTH ${CMU_FLAGS_CFI})
  endif()

  if(CMU_EAGER_LOADING)
    list(APPEND CMU_LINK_FLAGS ${CMU_FLAGS_EAGER_LOADING})
  endif()

  if(CMU_STRICT_LINKING)
    list(APPEND CMU_LINK_FLAGS ${CMU_FLAGS_STRICT_LINKING})
  endif()

  if(CMU_RELRO)
    list(APPEND CMU_LINK_FLAGS ${CMU_FLAGS_RELRO})
  endif()

  if(CMU_STACK_PROTECTION)
    if(CMU_COMP_GNUC)
      cmu_add_flag_if_available("-fstack-protector-strong"
                                CMU_HAVE_STACK_PROTECTOR_STRONG CMU_FLAGS)

      if(NOT CMU_HAVE_STACK_PROTECTOR_STRONG)
        cmu_add_flag_if_available("-fstack-protector" CMU_HAVE_STACK_PROTECTOR
                                  CMU_FLAGS)
      endif()

      cmu_add_flag_if_available("-fstack-clash-protection"
                                CMU_HAVE_STACK_CLASH_PROTECTION CMU_FLAGS)
    endif()
  endif()

  if(CMU_CXX_STDLIB STREQUAL "libstdc++")
    if(CMU_GLIBCXX_SANITIZE_VECTOR)
      list(APPEND CMU_DEFINES "-D_GLIBCXX_SANITIZE_VECTOR=1")
    endif()
    if(CMU_GLIBCXX_DEBUG_PEDANTIC)
      set(CMU_GLIBCXX_DEBUG True)
      list(APPEND CMU_DEFINES "-D_GLIBCXX_DEBUG_PEDANTIC=1")
    endif()
    if(CMU_GLIBCXX_DEBUG)
      list(APPEND CMU_DEFINES "-D_GLIBCXX_DEBUG=1")
    endif()
  elseif(CMU_CXX_STDLIB STREQUAL "libc++")
    list(APPEND CMU_DEFINES "_LIBCPP_ABI_VERSION=${CMU_LIBCPP_ABI_VERSION}")
    if(CMU_LIBCPP_ENABLE_NODISCARD)
      list(APPEND CMU_DEFINES "_LIBCPP_ENABLE_NODISCARD=1")
    endif()
    if(CMU_LIBCPP_DEBUG)
      list(APPEND CMU_DEFINES "_LIBCPP_DEBUG=1")
    endif()
  endif()
endmacro()
