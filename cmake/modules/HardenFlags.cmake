# cmake/modules/HardenFlags.cmake
# Compiler hardening flags for all Siren targets.

function(siren_apply_hardening target)
    if(MSVC)
        target_compile_options(${target} PRIVATE
            /GS /sdl /W4
            /wd4996   # suppress 'deprecated' noise on Windows API
        )
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wshadow
            -Wstrict-prototypes -Wmissing-prototypes
            -Werror=implicit-function-declaration
            -Werror=incompatible-pointer-types
            -fno-strict-aliasing
            -fstack-protector-strong
        )
    endif()
endfunction()
