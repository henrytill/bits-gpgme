cmake_minimum_required(VERSION 3.13)
enable_testing()

project(gpgme-bits C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

# https://stackoverflow.com/a/58711983
string(REGEX REPLACE "/W3" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

macro(SET_COMPILER_OPTIONS target)
  target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion)
endmacro(SET_COMPILER_OPTIONS)

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

add_test(NAME test_roundtrip
         COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/roundtrip.py -v
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

set_tests_properties(test_roundtrip PROPERTIES
                     ENVIRONMENT "PYTHONPATH=${CMAKE_BINARY_DIR};LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}")
