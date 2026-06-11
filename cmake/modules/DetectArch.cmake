# cmake/modules/DetectArch.cmake
# Siren targets x86-64 only.  Abort early on any other architecture.

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR
        "Siren requires a 64-bit toolchain (x86-64).  "
        "Current pointer size: ${CMAKE_SIZEOF_VOID_P} bytes.")
endif()

if(DEFINED CMAKE_SYSTEM_PROCESSOR)
    string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _siren_cpu)
    if(NOT _siren_cpu MATCHES "x86_64|amd64|x64")
        message(WARNING
            "Unexpected processor '${CMAKE_SYSTEM_PROCESSOR}'. "
            "Siren is only tested on x86-64.")
    endif()
    unset(_siren_cpu)
endif()
