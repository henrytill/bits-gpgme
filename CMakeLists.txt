cmake_minimum_required(VERSION 3.13)
enable_testing()
include(CheckIncludeFile)

project(gpgme-bits C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

# https://stackoverflow.com/a/58711983
string(REGEX REPLACE "/W3" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

macro(SET_COMPILER_OPTIONS target)
  target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
endmacro(SET_COMPILER_OPTIONS)

if("${CMAKE_C_COMPILER_ID}" MATCHES "Clang")
  SET(CLANG TRUE)
  MESSAGE(STATUS "clang town")
endif()

CHECK_INCLUDE_FILE(sanitizer/asan_interface.h HAS_ASAN_INTERFACE)

if(HAS_ASAN_INTERFACE)
  message(STATUS "Using address sanitizer")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
  if(CLANG)
    message(STATUS "Using shared libasan")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -shared-libasan")
  endif()
  if(CLANG)
    execute_process(COMMAND clang -print-file-name=libclang_rt.asan-x86_64.so OUTPUT_STRIP_TRAILING_WHITESPACE OUTPUT_VARIABLE LIBASAN)
  else()
    find_library(LIBASAN NAMES asan libasan.so.6)
  endif()
  message(STATUS "libasan found: ${LIBASAN}")
endif()

# https://blog.kitware.com/cmake-and-the-default-build-type/
set(default_build_type "Debug")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(STATUS "Setting build type to '${default_build_type}' as none was specified.")

  set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)

  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

set(MINGW_PATH C:/msys64/mingw64)

if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  set(LINUX TRUE)
endif()

if(MINGW)
  set(Python3_ROOT_DIR ${MINGW_PATH})
endif()

find_package(PkgConfig REQUIRED)
find_package(Python3 REQUIRED)

pkg_check_modules(GPGME REQUIRED gpgme IMPORTED_TARGET)

add_library(cipher cipher.c)
SET_COMPILER_OPTIONS(cipher)
set_property(TARGET cipher
             PROPERTY POSITION_INDEPENDENT_CODE ${BUILD_SHARED_LIBS})
target_include_directories(cipher INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cipher PRIVATE PkgConfig::GPGME)

add_executable(decrypt decrypt.c)
SET_COMPILER_OPTIONS(decrypt)
target_link_libraries(decrypt PRIVATE cipher)

add_executable(encrypt encrypt.c)
SET_COMPILER_OPTIONS(encrypt)
target_link_libraries(encrypt PRIVATE cipher)

add_executable(roundtrip roundtrip.c)
SET_COMPILER_OPTIONS(roundtrip)
target_link_libraries(roundtrip PRIVATE cipher)

add_test(NAME roundtrip
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
         COMMAND roundtrip)

if(HAS_ASAN_INTERFACE)
  get_filename_component(LIBASAN_DIR ${LIBASAN} DIRECTORY)
  set_tests_properties(roundtrip PROPERTIES
                       ENVIRONMENT "LD_LIBRARY_PATH=${LIBASAN_DIR}")
endif()

if(LINUX)
  set(CFFI_ARTIFACT_NAME _cipher_cffi.cpython-39-x86_64-linux-gnu.so)
elseif(MINGW)
  set(CFFI_ARTIFACT_NAME _cipher_cffi.cp39-mingw_x86_64.pyd)
endif()

set(CFFI_OUTPUT_PATH ${CMAKE_BINARY_DIR}/${CFFI_ARTIFACT_NAME})

add_custom_command(OUTPUT ${CFFI_OUTPUT_PATH}
                   COMMAND ${Python3_EXECUTABLE} ARGS ${CMAKE_SOURCE_DIR}/cipher_build.py
                   WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                   DEPENDS cipher)

add_custom_target(cffi ALL DEPENDS ${CFFI_OUTPUT_PATH})

if((NOT HAS_ASAN_INTERFACE) OR CLANG)
  add_test(NAME test_roundtrip
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/roundtrip.py -v
           WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
endif()

if(HAS_ASAN_INTERFACE AND CLANG)
  set_tests_properties(test_roundtrip PROPERTIES
                       ENVIRONMENT "PYTHONPATH=${CMAKE_BINARY_DIR};LD_LIBRARY_PATH=${CMAKE_BINARY_DIR};LD_PRELOAD=${LIBASAN}")
elseif(NOT HAS_ASAN_INTERFACE)
  set_tests_properties(test_roundtrip PROPERTIES
                       ENVIRONMENT "PYTHONPATH=${CMAKE_BINARY_DIR};LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}")
endif()
