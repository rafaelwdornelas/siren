cmake_minimum_required(VERSION 3.20)

function(siren_add_unit_test name src)
    add_executable(${name} unit/${src})
    target_link_libraries(${name} PRIVATE siren)
    target_include_directories(${name} PRIVATE
        ${CMAKE_SOURCE_DIR}/src   # internal headers (slack/, notify/, handoff/)
    )
    siren_apply_defines(${name})
    add_test(NAME ${name} COMMAND ${name})
endfunction()

siren_add_unit_test(test_slack_finder    test_slack_finder.c)
siren_add_unit_test(test_notify_list     test_notify_list.c)
siren_add_unit_test(test_section_handoff test_section_handoff.c)
