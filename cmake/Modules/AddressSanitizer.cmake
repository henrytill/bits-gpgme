include(CheckIncludeFile)

get_property(isMultiConfig GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)

if(isMultiConfig)
  if(NOT "DebugAsan" IN_LIST CMAKE_CONFIGURATION_TYPES)
    list(APPEND CMAKE_CONFIGURATION_TYPES DebugAsan)
  endif()
else()
  set(allowedBuildTypes Debug Release RelWithDebInfo MinSizeRel DebugAsan)
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "${allowedBuildTypes}")

  if(CMAKE_BUILD_TYPE AND NOT CMAKE_BUILD_TYPE IN_LIST allowedBuildTypes)
    message(FATAL_ERROR "Invalid build type: ${CMAKE_BUILD_TYPE}")
  endif()
endif()

set(CMAKE_C_FLAGS_DEBUGASAN
    "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address -fno-omit-frame-pointer"
    CACHE STRING "Flags used by the C compiler for DebugAsan build type or configuration." FORCE)

set(CMAKE_CXX_FLAGS_DEBUGASAN
    "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address -fno-omit-frame-pointer"
    CACHE STRING "Flags used by the C++ compiler for DebugAsan build type or configuration." FORCE)

set(CMAKE_EXE_LINKER_FLAGS_DEBUGASAN
    "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} -fsanitize=address"
    CACHE STRING "Linker flags to be used to create executables for DebugAsan build type." FORCE)

set(CMAKE_SHARED_LINKER_FLAGS_DEBUGASAN
    "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} -fsanitize=address"
    CACHE STRING "Linker lags to be used to create shared libraries for DebugAsan build type." FORCE)

### Some other helpful config

if("${CMAKE_BUILD_TYPE}" STREQUAL "DebugAsan")
  SET(ASAN TRUE)
endif()

if(("${CMAKE_C_COMPILER_ID}" MATCHES "Clang") OR ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang"))
  SET(CLANG TRUE)
endif()

CHECK_INCLUDE_FILE(sanitizer/asan_interface.h HAS_ASAN_INTERFACE)

if(HAS_ASAN_INTERFACE)
  find_library(LIBASAN NAMES asan libasan.so.6)

  if(CLANG AND UNIX)
    execute_process(COMMAND clang -print-file-name=libclang_rt.asan-x86_64.so
                    OUTPUT_STRIP_TRAILING_WHITESPACE
                    OUTPUT_VARIABLE LIBASAN)
  else()
    find_library(LIBASAN NAMES asan libasan.so.6)
  endif()

  message(STATUS "libasan: ${LIBASAN}")

  get_filename_component(LIBASAN_DIRECTORY ${LIBASAN} DIRECTORY)
endif()
