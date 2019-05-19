if(COMMAND include_guard)
  include_guard(GLOBAL)
endif()

include("${CMAKE_CURRENT_LIST_DIR}/cmu_detect_env.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/cmu_macros.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/cmu_cflags.cmake")
