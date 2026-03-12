cmake_minimum_required(VERSION 3.18)
project(Voix VERSION 2.2.0 LANGUAGES CXX)

# ---- Standards ----
set(CMAKE_CXX_STANDARD 26)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ---- Ignore External Flags ----
set(CMAKE_C_FLAGS "")
set(CMAKE_CXX_FLAGS "")
set(CMAKE_EXE_LINKER_FLAGS "")
set(CMAKE_SHARED_LINKER_FLAGS "")

# ---- Compiler Flags ----
# Common optimization and warnings
set(COMMON_FLAGS "-march=native -O3 -pipe -fno-plt \
-Wno-unused-variable -Wno-unused-parameter \
-Wno-unused-function -Wno-unused-but-set-variable \
-Wno-missing-field-initializers -Wno-sign-compare \
-Wno-unused-result")

# Debug / Sanitizers
set(DEBUG_FLAGS "-g -fstandalone-debug \
-fsanitize=undefined,address,leak \
-fsanitize-recover=all \
-fno-omit-frame-pointer \
-fno-optimize-sibling-calls")

# Combine flags for C and C++
set(ALL_C_FLAGS "${COMMON_FLAGS} ${DEBUG_FLAGS}")
set(ALL_CXX_FLAGS "${COMMON_FLAGS} ${DEBUG_FLAGS}")

# Apply flags explicitly
set(CMAKE_C_FLAGS "${ALL_C_FLAGS}" CACHE STRING "C compiler flags" FORCE)
set(CMAKE_CXX_FLAGS "${ALL_CXX_FLAGS}" CACHE STRING "C++ compiler flags" FORCE)

# ---- Linker Flags ----
set(LDFLAGS "-fuse-ld=lld -Wl,-O1,--as-needed,-z,relro,-z,now")
set(CMAKE_EXE_LINKER_FLAGS "${LDFLAGS}" CACHE STRING "Executable linker flags" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS "${LDFLAGS}" CACHE STRING "Shared linker flags" FORCE)

# ---- Options ----
option(VOIX_SETUID_INSTALL "Install voix with setuid bit" ON)

# ---- Dependencies ----
find_package(PkgConfig REQUIRED)
pkg_check_modules(PAM REQUIRED pam)

# ---- Testing ----
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# ---- Sources ----
set(VOIX_SOURCES
    src/main.cpp
    src/voix.cpp
    src/security.cpp
    src/config.cpp
    src/file_utils.cpp
    src/command.cpp
    src/logger.cpp
    src/system_utils.cpp
    src/pam_utils.cpp
    src/authenticator.cpp
    src/permission_checker.cpp
)

add_executable(voix ${VOIX_SOURCES})

target_include_directories(voix PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${PAM_INCLUDE_DIRS}
)

target_link_libraries(voix PRIVATE ${PAM_LIBRARIES})

# ---- Testing Executable ----
enable_testing()
add_executable(
  voix_tests
  tests/main.cpp
  tests/test_security.cpp
  tests/test_config.cpp
  tests/test_file_utils.cpp
  # Link necessary source files for testing
  src/security.cpp
  src/config.cpp
  src/file_utils.cpp
)
target_include_directories(voix_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(
  voix_tests
  GTest::gtest_main
)

include(GoogleTest)
gtest_discover_tests(voix_tests)

# ---- Compiler Hardening ----
target_compile_options(voix PRIVATE
    -Wall
    -Wextra
    -Werror
    -fstack-protector-strong
    -fPIE
)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|AppleClang")
    target_compile_options(voix PRIVATE -fcolor-diagnostics)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(voix PRIVATE -fdiagnostics-color=always)
endif()

# ---- Linker Hardening ----
target_link_options(voix PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    -pie
)
