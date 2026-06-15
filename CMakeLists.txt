cmake_minimum_required(VERSION 3.20)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.cmake")

project(Siren
    VERSION      ${SIREN_VERSION_MAJOR}.${SIREN_VERSION_MINOR}.${SIREN_VERSION_PATCH}
    DESCRIPTION  "Siren — Phantom Section Loader"
    LANGUAGES    C
)

include(DetectArch)
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/options.cmake")
include(HardenFlags)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ── Generate encrypted stub (random key each configure) ──────────────────────

set(SR_STUB_BIN "${CMAKE_CURRENT_SOURCE_DIR}/cmake/stub_x64.bin")
set(SR_STUB_GEN "${CMAKE_CURRENT_BINARY_DIR}/sr_stub_gen.h")

find_package(Python3 REQUIRED COMPONENTS Interpreter)

execute_process(
    COMMAND ${Python3_EXECUTABLE}
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/gen_stub.py"
            "${SR_STUB_BIN}"
            "${SR_STUB_GEN}"
    RESULT_VARIABLE _gen_rc
)
if(NOT _gen_rc EQUAL 0)
    message(FATAL_ERROR "gen_stub.py failed (rc=${_gen_rc})")
endif()
message(STATUS "Generated encrypted stub: ${SR_STUB_GEN}")

# ── Injector executable ───────────────────────────────────────────────────────

add_executable(siren_injector
    src/siren.c
    src/siren_injector.rc)

target_include_directories(siren_injector PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(siren_injector PRIVATE user32)
target_link_options(siren_injector PRIVATE -s)

siren_apply_hardening(siren_injector)
siren_apply_defines(siren_injector)
