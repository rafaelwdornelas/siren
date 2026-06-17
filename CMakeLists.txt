cmake_minimum_required(VERSION 3.20)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.cmake")

project(Siren
    VERSION      ${SIREN_VERSION_MAJOR}.${SIREN_VERSION_MINOR}.${SIREN_VERSION_PATCH}
    DESCRIPTION  "Siren — Phantom Section Loader"
    LANGUAGES    C ASM
)

include(DetectArch)
include("${CMAKE_CURRENT_SOURCE_DIR}/cmake/options.cmake")
include(HardenFlags)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# ── Assemble PIC stub from source, then generate encrypted blob ──────────────
# The .S file is the source of truth; stub_x64.bin is regenerated each build.

set(SR_STUB_SRC "${CMAKE_CURRENT_SOURCE_DIR}/src/siren_stub_x64.S")
set(SR_STUB_OBJ "${CMAKE_CURRENT_BINARY_DIR}/siren_stub_x64.o")
set(SR_STUB_BIN "${CMAKE_CURRENT_BINARY_DIR}/stub_x64.bin")
set(SR_STUB_GEN "${CMAKE_CURRENT_BINARY_DIR}/sr_stub_gen.h")

find_package(Python3 REQUIRED COMPONENTS Interpreter)

# Step 1: Assemble .S → .o (using gcc as assembler driver for directives)
add_custom_command(
    OUTPUT  ${SR_STUB_OBJ}
    COMMAND ${CMAKE_ASM_COMPILER} -c ${SR_STUB_SRC} -o ${SR_STUB_OBJ}
    DEPENDS ${SR_STUB_SRC}
    VERBATIM
    COMMENT "Assembling PIC stub (siren_stub_x64.S)"
)

# Step 2: Extract .text section → raw binary blob
add_custom_command(
    OUTPUT  ${SR_STUB_BIN}
    COMMAND ${CMAKE_OBJCOPY} -O binary -j .text ${SR_STUB_OBJ} ${SR_STUB_BIN}
    DEPENDS ${SR_STUB_OBJ}
    VERBATIM
    COMMENT "Extracting PIC stub blob (objcopy)"
)

# Step 3: Encrypt blob → C header (random key each configure)
add_custom_command(
    OUTPUT  ${SR_STUB_GEN}
    COMMAND ${Python3_EXECUTABLE}
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/gen_stub.py"
            "${SR_STUB_BIN}" "${SR_STUB_GEN}"
    DEPENDS ${SR_STUB_BIN} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/gen_stub.py"
    VERBATIM
    COMMENT "Generating encrypted stub header (sr_stub_gen.h)"
)

# Trigger stub generation at configure time too (for IDE metadata)
execute_process(
    COMMAND ${CMAKE_ASM_COMPILER} -c ${SR_STUB_SRC} -o ${SR_STUB_OBJ}
    RESULT_VARIABLE _asm_rc
)
if(NOT _asm_rc EQUAL 0)
    message(FATAL_ERROR "Failed to assemble PIC stub (rc=${_asm_rc})")
endif()
execute_process(
    COMMAND ${CMAKE_OBJCOPY} -O binary -j .text ${SR_STUB_OBJ} ${SR_STUB_BIN}
    RESULT_VARIABLE _obj_rc
)
if(NOT _obj_rc EQUAL 0)
    message(FATAL_ERROR "Failed to extract stub blob (rc=${_obj_rc})")
endif()
execute_process(
    COMMAND ${Python3_EXECUTABLE}
            "${CMAKE_CURRENT_SOURCE_DIR}/cmake/gen_stub.py"
            "${SR_STUB_BIN}" "${SR_STUB_GEN}"
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

# ── Output — copy final binary to dist/ ─────────────────────────────────────
add_custom_command(TARGET siren_injector POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_SOURCE_DIR}/dist
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:siren_injector>
                                     ${CMAKE_SOURCE_DIR}/dist/siren_injector.exe
    COMMENT "Copying siren_injector.exe → dist/"
)
