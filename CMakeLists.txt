cmake_minimum_required(VERSION 3.10)
project(TrezorCrypto C)

# Set C standard
set(CMAKE_C_STANDARD 99)

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(CHECK IMPORTED_TARGET check)
set(CHECK_FOUND ${CHECK_FOUND})

# Get compiler info
execute_process(
    COMMAND ${CMAKE_C_COMPILER} --version
    OUTPUT_VARIABLE COMPILER_VERSION_OUTPUT
)

string(REGEX MATCH "clang version ([0-9]+\\.[0-9]+)" CLANG_VERSION_MATCH "${COMPILER_VERSION_OUTPUT}")
if(CLANG_VERSION_MATCH)
    string(REGEX REPLACE "clang version ([0-9]+)\\.[0-9]+" "\\1" CLANG_VERSION_MAJOR "${CLANG_VERSION_MATCH}")
    if(CLANG_VERSION_MAJOR GREATER_EQUAL 13)
        set(CLANG_AT_LEAST_13 TRUE)
    else()
        set(CLANG_AT_LEAST_13 FALSE)
    endif()
endif()

# Setup compiler flags similar to the Makefile
set(COMMON_FLAGS 
    -W
    -Wall
    -Wextra
    -Wimplicit-function-declaration
    -Wredundant-decls
    -Wstrict-prototypes
    -Wundef
    -Wshadow
    -Wpointer-arith
    -Wformat
    -Wreturn-type
    -Wsign-compare
    -Wmultichar
    -Wformat-nonliteral
    -Winit-self
    -Wuninitialized
    -Wformat-security
    -Wno-missing-braces
    -Werror
)

# Check compiler type
if(CMAKE_C_COMPILER_ID MATCHES "Clang")
    set(IS_CLANG TRUE)
else()
    set(IS_CLANG FALSE)
endif()

# Add ftrivial-auto-var-init=zero only for Clang
option(FUZZER "Enable fuzzer" OFF)
if(NOT FUZZER AND IS_CLANG)
    list(APPEND COMMON_FLAGS -ftrivial-auto-var-init=zero)
endif()

option(ADDRESS_SANITIZER "Enable address sanitizer" OFF)
if(FUZZER)
    # Fuzzer specific options
    set(CMAKE_C_COMPILER clang)
    list(APPEND COMMON_FLAGS -fsanitize=fuzzer)
    
    if(CLANG_AT_LEAST_13)
        message(STATUS "Using -fsanitize-ignorelist")
        list(APPEND COMMON_FLAGS -fsanitize-ignorelist=${CMAKE_SOURCE_DIR}/crypto/fuzzer/sanitizer_ignorelist.txt)
    else()
        message(STATUS "Not using -fsanitize-ignorelist")
    endif()
elseif(ADDRESS_SANITIZER)
    list(APPEND COMMON_FLAGS -fsanitize=address,undefined)
endif()

# Optimization flags
set(OPT_FLAGS -O3 -g)

# Set Valgrind flag
option(VALGRIND "Enable Valgrind support" ON)
if(VALGRIND)
    add_definitions(-DVALGRIND)
endif()

# Set feature flags
add_definitions(
    -DUSE_ETHEREUM=1
    -DUSE_KECCAK=1
    -DUSE_MONERO=1
    -DUSE_NEM=1
    -DUSE_CARDANO=1
    -DUSE_INSECURE_PRNG=1
    -DAES_128
    -DAES_192
    -DAES_VAR
    -DSECP256K1_CONTEXT_SIZE=208
)

# Optional small footprint
option(SMALL "Enable small footprint" OFF)
if(SMALL)
    add_definitions(-DUSE_PRECOMPUTED_CP=0)
endif()

# Check if secp256k1-zkp is available
set(SECP256K1_ZKP_SRC ${CMAKE_SOURCE_DIR}/crypto/vendor/secp256k1-zkp/src/secp256k1.c)
if(EXISTS ${SECP256K1_ZKP_SRC})
    set(SECP256K1_ZKP_AVAILABLE TRUE)
    message(STATUS "secp256k1-zkp found at ${SECP256K1_ZKP_SRC}")
    # Setup ZKP flags
    set(ZKP_CFLAGS
        -DECMULT_GEN_PREC_BITS=4
        -DECMULT_WINDOW_SIZE=2
        -DENABLE_MODULE_GENERATOR
        -DENABLE_MODULE_RECOVERY
        -DENABLE_MODULE_SCHNORRSIG
        -DENABLE_MODULE_EXTRAKEYS
        -DENABLE_MODULE_ECDH
    )
    set(ZKP_PATH ${CMAKE_SOURCE_DIR}/crypto/vendor/secp256k1-zkp)
    
    # Add ZKP source files if they're available
    list(APPEND CRYPTO_SOURCES
        crypto/zkp_context.c
        crypto/zkp_ecdsa.c
        crypto/zkp_bip340.c
    )
else()
    set(SECP256K1_ZKP_AVAILABLE FALSE)
    message(STATUS "secp256k1-zkp not found, related functionality will be disabled")
    add_definitions(-DUSE_SECP256K1_ZKP=0)
endif()

# Setup include directories
include_directories(
    ${CMAKE_SOURCE_DIR}/crypto
    ${CMAKE_SOURCE_DIR}
    ${OPENSSL_INCLUDE_DIR}
)

# Define all source files
set(CRYPTO_SOURCES
    crypto/bignum.c
    crypto/ecdsa.c
    crypto/curves.c
    crypto/secp256k1.c
    crypto/nist256p1.c
    crypto/rand.c
    crypto/hmac.c
    crypto/bip32.c
    crypto/bip39.c
    crypto/bip39_english.c
    crypto/pbkdf2.c
    crypto/base58.c
    crypto/base32.c
    crypto/address.c
    crypto/script.c
    crypto/ripemd160.c
    crypto/sha2.c
    crypto/sha3.c
    crypto/hasher.c
    crypto/aes/aesccm.c
    crypto/aes/aescrypt.c
    crypto/aes/aesgcm.c
    crypto/aes/aeskey.c
    crypto/aes/aestab.c
    crypto/aes/aes_modes.c
    crypto/aes/gf128mul.c
    crypto/ed25519-donna/curve25519-donna-32bit.c
    crypto/ed25519-donna/curve25519-donna-helpers.c
    crypto/ed25519-donna/modm-donna-32bit.c
    crypto/ed25519-donna/ed25519-donna-basepoint-table.c
    crypto/ed25519-donna/ed25519-donna-32bit-tables.c
    crypto/ed25519-donna/ed25519-donna-impl-base.c
    crypto/ed25519-donna/ed25519.c
    crypto/ed25519-donna/curve25519-donna-scalarmult-base.c
    crypto/ed25519-donna/ed25519-sha3.c
    crypto/ed25519-donna/ed25519-keccak.c
    crypto/monero/base58.c
    crypto/monero/serialize.c
    crypto/monero/xmr.c
    crypto/blake256.c
    crypto/blake2b.c
    crypto/blake2s.c
    crypto/chacha_drbg.c
    crypto/groestl.c
    crypto/chacha20poly1305/chacha20poly1305.c
    crypto/chacha20poly1305/chacha_merged.c
    crypto/chacha20poly1305/poly1305-donna.c
    crypto/chacha20poly1305/rfc7539.c
    crypto/rc4.c
    crypto/nem.c
    crypto/segwit_addr.c
    crypto/cash_addr.c
    crypto/memzero.c
    crypto/shamir.c
    crypto/hmac_drbg.c
    crypto/rfc6979.c
    crypto/slip39.c
    crypto/slip39_english.c
    crypto/cardano.c
    crypto/tls_prf.c
    crypto/hash_to_curve.c
    crypto/buffer.c
    crypto/der.c
    crypto/elligator2.c
)

# Special flags for blake2 files when using fuzzer
if(FUZZER)
    set_source_files_properties(
        crypto/blake2b.c
        crypto/blake2s.c
        PROPERTIES COMPILE_FLAGS "-O0"
    )
endif()

# Create static library
add_library(trezor-crypto STATIC ${CRYPTO_SOURCES})

if(SECP256K1_ZKP_AVAILABLE)
    # Custom commands for secp256k1-zkp files
    add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/precomputed_ecmult.o
        COMMAND ${CMAKE_C_COMPILER} ${COMMON_FLAGS} ${OPT_FLAGS} -Wno-unused-function ${ZKP_CFLAGS} -fPIC -c ${ZKP_PATH}/src/precomputed_ecmult.c -o ${CMAKE_BINARY_DIR}/precomputed_ecmult.o
        DEPENDS ${ZKP_PATH}/src/precomputed_ecmult.c
    )

    add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/precomputed_ecmult_gen.o
        COMMAND ${CMAKE_C_COMPILER} ${COMMON_FLAGS} ${OPT_FLAGS} -Wno-unused-function ${ZKP_CFLAGS} -fPIC -c ${ZKP_PATH}/src/precomputed_ecmult_gen.c -o ${CMAKE_BINARY_DIR}/precomputed_ecmult_gen.o
        DEPENDS ${ZKP_PATH}/src/precomputed_ecmult_gen.c
    )

    add_custom_command(
        OUTPUT ${CMAKE_BINARY_DIR}/secp256k1-zkp.o
        COMMAND ${CMAKE_C_COMPILER} ${COMMON_FLAGS} ${OPT_FLAGS} -Wno-unused-function ${ZKP_CFLAGS} -fPIC -I${ZKP_PATH} -I${ZKP_PATH}/src -c ${ZKP_PATH}/src/secp256k1.c -o ${CMAKE_BINARY_DIR}/secp256k1-zkp.o
        DEPENDS ${ZKP_PATH}/src/secp256k1.c
    )
    
    target_sources(trezor-crypto PRIVATE
        ${CMAKE_BINARY_DIR}/secp256k1-zkp.o
        ${CMAKE_BINARY_DIR}/precomputed_ecmult.o
        ${CMAKE_BINARY_DIR}/precomputed_ecmult_gen.o
    )
endif()

target_compile_options(trezor-crypto PRIVATE ${COMMON_FLAGS} ${OPT_FLAGS})
target_link_libraries(trezor-crypto ${OPENSSL_LIBRARIES})

# Create main executable
add_executable(main main.c utils.c clsag.c pseudo_outputs.c)
# Use less strict flags for main.c
target_compile_options(main PRIVATE ${OPT_FLAGS} -Wall -Wextra)
target_link_libraries(main trezor-crypto ${OPENSSL_LIBRARIES})

# Setup tests
enable_testing()

if(CHECK_FOUND)
    # test_check
    add_executable(test_check 
        crypto/tests/test_check.c
    )
    target_compile_options(test_check PRIVATE ${COMMON_FLAGS} ${OPT_FLAGS})
    target_link_libraries(test_check trezor-crypto PkgConfig::CHECK pthread m)
    add_test(NAME test_check COMMAND test_check)
else()
    message(STATUS "Check framework not found - test_check will not be built")
endif()

# test_openssl
add_executable(test_openssl
    crypto/tests/test_openssl.c
)
target_compile_options(test_openssl PRIVATE ${COMMON_FLAGS} ${OPT_FLAGS})
target_link_libraries(test_openssl trezor-crypto ${OPENSSL_LIBRARIES})
add_test(NAME test_openssl COMMAND test_openssl)

# test_speed
add_executable(test_speed
    crypto/tests/test_speed.c
)
target_compile_options(test_speed PRIVATE ${COMMON_FLAGS} ${OPT_FLAGS})
target_link_libraries(test_speed trezor-crypto)
add_test(NAME test_speed COMMAND test_speed)

# aestst
add_executable(aestst
    crypto/aes/aestst.c
    crypto/aes/aescrypt.c
    crypto/aes/aeskey.c
    crypto/aes/aestab.c
)
target_compile_options(aestst PRIVATE ${COMMON_FLAGS} ${OPT_FLAGS})
add_test(NAME aestst COMMAND aestst)

# Shared library for tests
add_library(trezor-crypto-shared SHARED ${CRYPTO_SOURCES})
if(SECP256K1_ZKP_AVAILABLE)
    target_sources(trezor-crypto-shared PRIVATE
        ${CMAKE_BINARY_DIR}/secp256k1-zkp.o
        ${CMAKE_BINARY_DIR}/precomputed_ecmult.o
        ${CMAKE_BINARY_DIR}/precomputed_ecmult_gen.o
    )
endif()
target_compile_options(trezor-crypto-shared PRIVATE ${COMMON_FLAGS} ${OPT_FLAGS})
target_link_libraries(trezor-crypto-shared ${OPENSSL_LIBRARIES})
set_target_properties(trezor-crypto-shared PROPERTIES OUTPUT_NAME "trezor-crypto")

# Tools
# xpubaddrgen
add_executable(xpubaddrgen
    crypto/tools/xpubaddrgen.c
)
target_compile_options(xpubaddrgen PRIVATE ${COMMON_FLAGS} ${OPT_FLAGS})
target_link_libraries(xpubaddrgen trezor-crypto)

# mktable
add_executable(mktable
    crypto/tools/mktable.c
)
target_compile_options(mktable PRIVATE ${COMMON_FLAGS} ${OPT_FLAGS})
target_link_libraries(mktable trezor-crypto)

# bip39bruteforce
add_executable(bip39bruteforce
    crypto/tools/bip39bruteforce.c
)
target_compile_options(bip39bruteforce PRIVATE ${COMMON_FLAGS} ${OPT_FLAGS})
target_link_libraries(bip39bruteforce trezor-crypto)

# Fuzzer
if(FUZZER)
    add_executable(fuzzer
        crypto/fuzzer/fuzzer.c
    )
    target_compile_options(fuzzer PRIVATE ${COMMON_FLAGS} ${OPT_FLAGS})
    target_link_libraries(fuzzer trezor-crypto)
endif()