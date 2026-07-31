cmake_minimum_required(VERSION 3.13)
project(fireblocks_mpc_hunt LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "The cloud fuzzer build requires Clang")
endif()

add_compile_options(
    -fsanitize=fuzzer-no-link,address,undefined
    -fno-omit-frame-pointer
)
add_link_options(-fsanitize=address,undefined)

add_subdirectory(harness/cmp_ecdsa_online)

add_executable(opus_cmp_fuzzer
    harness/cmp_ecdsa_online/src/fuzzer.cpp
)
target_compile_options(opus_cmp_fuzzer PRIVATE -fsanitize=fuzzer)
target_link_options(opus_cmp_fuzzer PRIVATE -fsanitize=fuzzer)
target_link_libraries(opus_cmp_fuzzer PRIVATE opus_core)
