# cmake/modules/HardenFlags.cmake
# Compiler hardening flags for all Siren targets.

function(siren_apply_hardening target)
    if(MSVC)
        target_compile_options(${target} PRIVATE
            $<$<COMPILE_LANGUAGE:C>:/GS /sdl /W4>
            $<$<COMPILE_LANGUAGE:C>:/wd4996>
        )
    else()
        # Scope all flags to C — GNU assembler (as) rejects compiler options.
        target_compile_options(${target} PRIVATE
            $<$<COMPILE_LANGUAGE:C>:-Wall>
            $<$<COMPILE_LANGUAGE:C>:-Wextra>
            $<$<COMPILE_LANGUAGE:C>:-Wshadow>
            $<$<COMPILE_LANGUAGE:C>:-Wstrict-prototypes>
            $<$<COMPILE_LANGUAGE:C>:-Wmissing-prototypes>
            $<$<COMPILE_LANGUAGE:C>:-Werror=implicit-function-declaration>
            $<$<COMPILE_LANGUAGE:C>:-Werror=incompatible-pointer-types>
            $<$<COMPILE_LANGUAGE:C>:-fno-strict-aliasing>
            $<$<COMPILE_LANGUAGE:C>:-fstack-protector-strong>
            $<$<COMPILE_LANGUAGE:C>:-Wno-array-bounds>
        )
    endif()
endfunction()
