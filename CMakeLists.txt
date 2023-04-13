cmake_minimum_required(VERSION 3.13)

project(gpgme-bits C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED True)

enable_testing()

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(Platform)
include(AddressSanitizer)
include(UndefinedBehaviorSanitizer)

# https://stackoverflow.com/a/58711983
string(REGEX REPLACE "/W3" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")

macro(SET_COMPILER_OPTIONS target)
  target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
endmacro(SET_COMPILER_OPTIONS)

option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

if(MINGW)
  set(Python3_ROOT_DIR ${MINGW_DIRECTORY})
endif()

find_package(PkgConfig REQUIRED)
find_package(Python3 REQUIRED)

pkg_check_modules(GPGME REQUIRED gpgme IMPORTED_TARGET)

add_subdirectory(src)

add_subdirectory(test)
