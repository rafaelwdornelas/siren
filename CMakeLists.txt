cmake_minimum_required(VERSION 3.20)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.cmake")

project(Siren
    VERSION      ${SIREN_VERSION_MAJOR}.${SIREN_VERSION_MINOR}.${SIREN_VERSION_PATCH}
    DESCRIPTION  "Siren Injection — LdrpDllNotificationList Hijacking + Section Slack Carrier"
    LANGUAGES    C ASM
)

include(DetectArch)
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/options.cmake")
include(HardenFlags)

# GNU assembler does not accept -O / -D flags from CMake's Release profile.
# Clear all ASM flag variables so 'as' receives no unexpected options.
set(CMAKE_ASM_FLAGS_DEBUG          "")
set(CMAKE_ASM_FLAGS_RELEASE        "")
set(CMAKE_ASM_FLAGS_RELWITHDEBINFO "")
set(CMAKE_ASM_FLAGS_MINSIZEREL     "")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ── Core library ─────────────────────────────────────────────────────────────

set(SIREN_CORE_SOURCES
    src/pe/pe_parse.c
    src/runtime/peb_walk.c
    src/slack/slack_finder.c
    src/handoff/section_handoff.c
    src/notify/ldr_notify.c
    src/reflective/refl_loader.c
    src/stub/siren_stub.c
    src/core/siren_api.c
    src/core/siren_status.c
)

# Select the right assembly stub: GAS syntax for GCC/MinGW, MASM for MSVC.
if(MSVC)
    list(APPEND SIREN_CORE_SOURCES src/stub/siren_stub_x64.S)
else()
    list(APPEND SIREN_CORE_SOURCES src/stub/siren_stub_x64_gas.S)
endif()

add_library(siren STATIC ${SIREN_CORE_SOURCES})

target_include_directories(siren
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

siren_apply_hardening(siren)
siren_apply_defines(siren)

# ── PoC executables ───────────────────────────────────────────────────────────

if(SIREN_BUILD_POC)
    add_subdirectory(poc)
endif()

# ── Unit tests ────────────────────────────────────────────────────────────────

if(SIREN_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
