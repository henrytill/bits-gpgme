add_library(cipher cipher.c)
SET_COMPILER_OPTIONS(cipher)
set_property(TARGET cipher PROPERTY POSITION_INDEPENDENT_CODE ${BUILD_SHARED_LIBS})
target_include_directories(cipher INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cipher PRIVATE PkgConfig::GPGME)

add_executable(decrypt decrypt.c)
SET_COMPILER_OPTIONS(decrypt)
target_link_libraries(decrypt PRIVATE cipher)

add_executable(encrypt encrypt.c)
SET_COMPILER_OPTIONS(encrypt)
target_link_libraries(encrypt PRIVATE cipher)
