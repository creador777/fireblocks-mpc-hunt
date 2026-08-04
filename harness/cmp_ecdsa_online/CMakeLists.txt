cmake_minimum_required(VERSION 3.13)
project(opus_cmp_harness LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --------------------------------------------------------------------------
# Upstream location. NEVER written to. Passed in by the runner script and
# mounted read-only inside the container.
# --------------------------------------------------------------------------
set(OPUS_UPSTREAM_DIR "/work/upstream" CACHE PATH "Read-only fireblocks/mpc-lib source tree")

if(NOT EXISTS "${OPUS_UPSTREAM_DIR}/CMakeLists.txt")
    message(FATAL_ERROR "OPUS_UPSTREAM_DIR=${OPUS_UPSTREAM_DIR} does not look like the mpc-lib source tree")
endif()

# --------------------------------------------------------------------------
# CRITICAL for determinism: resolve OpenSSL BEFORE add_subdirectory().
#
# upstream/CMakeLists.txt:9 guards its OpenSSL block with `if(NOT TARGET
# OpenSSL::Crypto)` and, when it runs, sets OPENSSL_USE_STATIC_LIBS TRUE
# (:10). A statically-absorbed libcrypto inside libcosigner.so would own a
# private RNG that our RAND_set_rand_method() override cannot reach, and the
# harness would be silently non-deterministic.
#
# By defining OpenSSL::Crypto here first, upstream adopts ours verbatim.
# --------------------------------------------------------------------------
set(OPENSSL_USE_STATIC_LIBS FALSE)
find_package(OpenSSL 1.1.1 REQUIRED)

# Upstream auto-skips its test tree when consumed as a subdirectory
# (CMakeLists.txt:17 compares CMAKE_SOURCE_DIR to PROJECT_SOURCE_DIR).
# Set the flag explicitly so the intent is not implicit.
set(MPC_LIB_SKIP_TESTS ON CACHE BOOL "" FORCE)

# Source dir is read-only; ALL build output goes under our binary dir.
add_subdirectory("${OPUS_UPSTREAM_DIR}" "${CMAKE_BINARY_DIR}/mpc-lib-build")

# --------------------------------------------------------------------------
# libcosigner references five OpenSSL-PRIVATE symbols that the shared library
# does not export:
#     SHA3_absorb, SHA3_squeeze          -> keccak1600-x86_64.o
#     x25519_fe64_eligible/_sqr/_mul121666 -> x25519-x86_64.o
# That is why upstream forces OPENSSL_USE_STATIC_LIBS.
#
# Linking the whole static archive would also absorb rand_lib.o and give the
# library a private RNG our override could never reach. Instead we append the
# archive AFTER the shared lib: the linker resolves everything it can from
# libcrypto.so first and pulls only the still-unresolved members -- exactly the
# two self-contained assembly objects, neither of which defines RAND_bytes.
#
# scripts/in_container.sh asserts afterwards that RAND_bytes is still an
# undefined DYNAMIC symbol. That assertion, not this comment, is the guarantee.
# --------------------------------------------------------------------------
target_link_libraries(cosigner PRIVATE -l:libcrypto.a)

# --------------------------------------------------------------------------
# Harness core
# --------------------------------------------------------------------------
add_library(opus_core STATIC
    src/det_rand.cpp
    src/fixtures.cpp
    src/snapshot.cpp
    src/driver.cpp
    src/mutators.cpp
    src/oracles.cpp
)

target_include_directories(opus_core PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

# `cosigner` propagates -I<upstream>/include and -I<build>/mpc-lib-build/src/common
# (for the generated cosigner_export.h) plus OpenSSL::Crypto, transitively.
target_link_libraries(opus_core PUBLIC cosigner OpenSSL::Crypto)

target_compile_options(opus_core PRIVATE -Wall -Wextra -g -fno-omit-frame-pointer)

# --------------------------------------------------------------------------
# Executables
# --------------------------------------------------------------------------

# One-shot snapshot generator. Never runs inside a test loop.
add_executable(mk_snapshot tools/mk_snapshot.cpp)
target_link_libraries(mk_snapshot PRIVATE opus_core)

# Synthetic self-tests of the harness itself (honest control + benign tamper).
add_executable(opus_selftest tests/selftest.cpp)
target_link_libraries(opus_selftest PRIVATE opus_core)

# Unit tests of the EXTRA_MAP_KEY mutation contract (no session required).
add_executable(opus_test_extra_map_key tests/test_extra_map_key.cpp)
target_link_libraries(opus_test_extra_map_key PRIVATE opus_core)

# Case runner.
add_executable(opus_cmp_harness src/main.cpp)
target_link_libraries(opus_cmp_harness PRIVATE opus_core)

# Bounded deterministic local hunting smoke.
add_executable(opus_cmp_smoke src/smoke.cpp)
target_link_libraries(opus_cmp_smoke PRIVATE opus_core)

enable_testing()
add_test(NAME selftest COMMAND opus_selftest)
add_test(NAME extra_map_key COMMAND opus_test_extra_map_key)

# --------------------------------------------------------------------------
# V2 candidate: SEPARATE binary, corpus and artifacts. The V1 fuzzer build
# inputs (fuzzer.cpp, mutators.cpp, driver.cpp, opus_core) are NOT touched,
# so the V1 build stays byte-for-byte intact. The -fsanitize=fuzzer link
# flags for the V2 target belong in the image build (docker/Dockerfile.fuzzer).
# --------------------------------------------------------------------------
add_library(opus_telemetry_v2 STATIC
    src/telemetry_v2.cpp
)
target_link_libraries(opus_telemetry_v2 PUBLIC opus_core)

add_executable(opus_cmp_fuzzer_reachability_v2 src/fuzzer_reachability_v2.cpp)
target_compile_options(opus_cmp_fuzzer_reachability_v2 PRIVATE -fsanitize=fuzzer)
target_link_options(opus_cmp_fuzzer_reachability_v2 PRIVATE -fsanitize=fuzzer)
target_link_libraries(opus_cmp_fuzzer_reachability_v2 PRIVATE opus_telemetry_v2)
