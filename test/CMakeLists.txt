add_executable(roundtrip roundtrip.c)
SET_COMPILER_OPTIONS(roundtrip)
target_link_libraries(roundtrip PRIVATE cipher)

add_test(NAME roundtrip.c
         WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
         COMMAND roundtrip)

if(UNIX)
  set_tests_properties(roundtrip.c PROPERTIES
                       ENVIRONMENT "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/src")
elseif(MSVC OR MINGW)
  set_tests_properties(roundtrip.c PROPERTIES
                       ENVIRONMENT "PATH=${CMAKE_BINARY_DIR}/src\;$ENV{PATH}")
endif()

if(NOT ASAN)
  if(LINUX)
    set(CFFI_ARTIFACT_NAME _cipher_cffi.cpython-39-x86_64-linux-gnu.so)
  elseif(MINGW)
    set(CFFI_ARTIFACT_NAME _cipher_cffi.cp39-mingw_x86_64.pyd)
  endif()

  set(CFFI_OUTPUT_PATH ${CMAKE_BINARY_DIR}/${CFFI_ARTIFACT_NAME})

  add_custom_command(OUTPUT ${CFFI_OUTPUT_PATH}
                     COMMAND ${Python3_EXECUTABLE} ARGS ${CMAKE_CURRENT_SOURCE_DIR}/cipher_build.py
                     WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
                     DEPENDS cipher)

  add_custom_target(cffi ALL DEPENDS ${CFFI_OUTPUT_PATH})

  add_test(NAME roundtrip.py
           COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/roundtrip.py -v
           WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})

  if(UNIX)
    set_tests_properties(roundtrip.py PROPERTIES
                         ENVIRONMENT "PYTHONPATH=${CMAKE_BINARY_DIR};LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}/src")
  elseif(MSVC OR MINGW)
    set_tests_properties(roundtrip.py PROPERTIES
                         ENVIRONMENT "PYTHONPATH=${CMAKE_BINARY_DIR};PATH=${CMAKE_BINARY_DIR}/src\;$ENV{PATH}")
  endif()
endif()
