cmake_minimum_required(VERSION 3.20)

# ── Test payload DLL ──────────────────────────────────────────────────────────

add_library(siren_payload SHARED payload/payload.c)
target_include_directories(siren_payload PRIVATE
    ${CMAKE_SOURCE_DIR}/include)
siren_apply_defines(siren_payload)
set_target_properties(siren_payload PROPERTIES
    OUTPUT_NAME "siren_payload"
    PREFIX      "")

# ── Injector executable ───────────────────────────────────────────────────────

add_executable(siren_injector injector/main.c)
target_link_libraries(siren_injector PRIVATE siren)
siren_apply_hardening(siren_injector)
siren_apply_defines(siren_injector)
