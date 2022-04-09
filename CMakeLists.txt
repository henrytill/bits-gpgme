cmake_minimum_required(VERSION 3.13)

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

find_package(PkgConfig REQUIRED)

pkg_check_modules(GPGME REQUIRED gpgme)

add_library(crypto crypto.c)
SET_COMPILER_OPTIONS(crypto)
target_include_directories(crypto INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(crypto PRIVATE ${GPGME_INCLUDE_DIRS})
target_link_libraries(crypto PRIVATE ${GPGME_LIBRARIES})

add_executable(decrypt decrypt.c)
SET_COMPILER_OPTIONS(decrypt)
target_include_directories(decrypt PRIVATE ${GPGME_INCLUDE_DIRS})
target_link_libraries(decrypt PRIVATE ${GPGME_LIBRARIES} crypto)

add_executable(encrypt encrypt.c)
SET_COMPILER_OPTIONS(encrypt)
target_include_directories(encrypt PRIVATE ${GPGME_INCLUDE_DIRS})
target_link_libraries(encrypt PRIVATE ${GPGME_LIBRARIES} crypto)
