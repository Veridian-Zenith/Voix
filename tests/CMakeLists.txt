add_executable(test_suite
    test_main.cpp
    test_security.cpp
    test_file_utils.cpp
)

target_link_libraries(test_suite PRIVATE voix_lib)
target_include_directories(test_suite PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_suite COMMAND test_suite)
