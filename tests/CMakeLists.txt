add_executable(test_runner test_runner.cpp)
target_link_libraries(test_runner PRIVATE voix_lib)
target_include_directories(test_runner PRIVATE ${CMAKE_SOURCE_DIR}/include)
add_test(NAME test_runner COMMAND test_runner)
