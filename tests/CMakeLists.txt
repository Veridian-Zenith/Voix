# Test harness: modular unit tests linked into both the standalone
# test_runner binary (CTest) and the voix binary (`voix --run-tests`)
# when BUILD_TESTING is enabled.

add_library(voix_tests STATIC
    run_tests.cpp
    test_permissions.cpp
    test_config.cpp
    test_security.cpp
    test_command.cpp
    test_file_utils.cpp
    test_logger.cpp
    test_system_utils.cpp
    test_negative_security.cpp
)
target_link_libraries(voix_tests PUBLIC voix_lib)
target_include_directories(voix_tests PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/include)

add_executable(test_runner test_main.cpp)
target_link_libraries(test_runner PRIVATE voix_tests)
add_test(NAME test_runner COMMAND test_runner)

# Custom target to run tests during the build process
add_custom_target(run_tests_target
    COMMAND test_runner
    DEPENDS test_runner
    COMMENT "Running Voix unit tests..."
)
add_dependencies(voix run_tests_target)
