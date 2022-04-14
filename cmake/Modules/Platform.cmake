if(${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  set(LINUX TRUE)
endif()

if(("${CMAKE_C_COMPILER_ID}" MATCHES "Clang") OR ("${CMAKE_CXX_COMPILER_ID}" MATCHES "Clang"))
  SET(CLANG TRUE)
endif()

if(("${CMAKE_C_COMPILER_ID}" STREQUAL "GNU") OR ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU"))
  SET(GCC TRUE)
endif()

if(MINGW)
  set(MINGW_DIRECTORY C:/msys64/mingw64 CACHE PATH "Path to mingw directory" FORCE)
endif()
