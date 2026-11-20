# Toolchain file for cross-compiling GmSSL native runner to Linux x86_64 via Zig
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

get_filename_component(TOOLCHAIN_DIR "${CMAKE_CURRENT_LIST_FILE}" DIRECTORY)

set(CMAKE_C_COMPILER "${TOOLCHAIN_DIR}/zig-cc.sh")
set(CMAKE_ASM_COMPILER "${TOOLCHAIN_DIR}/zig-cc.sh")

set(CMAKE_AR "${TOOLCHAIN_DIR}/zig-ar.sh" CACHE FILEPATH "Archiver" FORCE)
set(CMAKE_RANLIB "${TOOLCHAIN_DIR}/zig-ranlib.sh" CACHE FILEPATH "Ranlib" FORCE)

set(CMAKE_C_FLAGS_INIT "-static -D_GNU_SOURCE")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static")

# Portable baseline defaults matching ops/engine.Dockerfile
set(ENABLE_SM2_AMD64 OFF CACHE BOOL "Portable software profile" FORCE)
set(ENABLE_SM3_SSE OFF CACHE BOOL "Portable software profile" FORCE)
set(ENABLE_SM4_AVX2 OFF CACHE BOOL "Portable software profile" FORCE)
set(ENABLE_SM4_AESNI OFF CACHE BOOL "Portable software profile" FORCE)
set(ENABLE_SM4_CTR_AESNI_AVX OFF CACHE BOOL "Portable software profile" FORCE)

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
