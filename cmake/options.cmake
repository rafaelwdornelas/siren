# cmake/options.cmake
# All SIREN_USE_* / SIREN_BUILD_* compile-time knobs.
# Currently minimal: the core technique has no optional sub-features.

option(SIREN_BUILD_POC   "Build the injector + payload PoC executables" ON)
option(SIREN_BUILD_TESTS "Build unit tests"                              ON)

# Propagate version string as a compile definition.
function(siren_apply_defines target)
    target_compile_definitions(${target} PRIVATE
        SIREN_VERSION_STRING="${SIREN_VERSION_STRING}"
        _WIN32_WINNT=0x0A00
        NTDDI_VERSION=0x0A000007
        WIN32_LEAN_AND_MEAN
    )
endfunction()
