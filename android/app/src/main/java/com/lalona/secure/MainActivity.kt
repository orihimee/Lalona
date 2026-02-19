cmake_minimum_required(VERSION 3.22.1)
project(lalona_crypto C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all -D_FORTIFY_SOURCE=2 -fPIC -O2 -fvisibility=hidden")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,-z,relro -Wl,-z,now -Wl,--strip-all")

find_library(log-lib log)
# Android NDK ships BoringSSL-compatible OpenSSL headers via libcrypto
find_library(crypto-lib crypto)

add_library(
    lalona_crypto
    SHARED
    ${CMAKE_CURRENT_SOURCE_DIR}/crypto_core.c
)

target_link_libraries(
    lalona_crypto
    ${log-lib}
    ${crypto-lib}
)

# Prevent export of all symbols except JNI entry points
set_target_properties(lalona_crypto PROPERTIES
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
