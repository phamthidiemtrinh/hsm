cmake_minimum_required(VERSION 3.13)

project(hsm C CXX ASM)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

add_executable(hsm)

set(SOURCES ${SOURCES}
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/hsm.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/hsm_list_keys.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/hsm_read_binary.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/hsm_initialize.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/hsm_key_domain.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/hsm_key_wrap.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/hsm_keypair_gen.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/hsm_key_gen.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/hsm_key_unwrap.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/hsm_decrypt_asym.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/hsm_cipher_sym.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/hsm_derive_asym.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/cvc.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/files.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/kek.c
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm/oid.c

        )
set(USB_ITF_CCID 1)
include(pico-keys-sdk/pico_keys_sdk_import.cmake)

set(INCLUDES ${INCLUDES}
        ${CMAKE_CURRENT_LIST_DIR}/src/hsm
        )

target_sources(hsm PUBLIC ${SOURCES})
target_include_directories(hsm PUBLIC ${INCLUDES})

target_compile_options(hsm PUBLIC
    -Wall
    -Werror
)

